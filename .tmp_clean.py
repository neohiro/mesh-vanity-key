"""One trustworthy measurement of shipped-worker scaling.

Lesson from the earlier attempts, both discarded:
  * summing each worker's CUMULATIVE `attempts` across reports double-counts
    badly (5k, 10k, 15k, ... summed is many times the real total);
  * taking each worker's MAX sample over-reports when workers contend, which is
    exactly when they do.

So: for each worker take (last cumulative - first cumulative) inside a fixed
wall-clock window, sum the deltas, divide by the window. No per-worker rates, no
max, no sums of cumulative counters. That is the only definition here that is
not biased in a direction that flatters the scaling figure.
"""
import statistics
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import importlib.util

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "check_inline_js", ROOT / "tools" / "check_inline_js.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
WORKER_JS = mod.extract(ROOT)["worker.js"]


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


handler = partial(Quiet, directory=str(ROOT))
httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
PORT = httpd.server_address[1]

WINDOW_MS = 6000
SETTLE_MS = 2500      # let every worker's WASM finish booting first
TRIALS = 3

SETUP = """
(cfg) => {
    window.__err = null;
    window.__ws = [];
    window.__first = [];
    window.__lastSeen = [];
    window.__readyN = 0;
    window.__started = false;
    const u = URL.createObjectURL(new Blob([cfg.src], {type:'application/javascript'}));
    window.__wurl = u;
    for (let i = 0; i < cfg.workers; i++) {
        const w = new Worker(u);
        window.__ws.push(w);
        window.__first.push(null);
        window.__lastSeen.push(0);
        w.onmessage = (e) => {
            if (e.data.type === 'ready') {
                w.postMessage({prefix: 'ffffffffffffffff', suffix: '',
                               matchPrefix: true, matchSuffix: false});
                if (++window.__readyN === cfg.workers) {
                    // All booted: start the sampling window.
                    window.__readyAt = performance.now();
                }
                return;
            }
            if (e.data.type === 'progress') {
                const now = performance.now();
                if (window.__started && window.__first[i] === null) {
                    window.__first[i] = e.data.attempts;
                }
                window.__lastSeen[i] = e.data.attempts;
            }
            if (e.data.type === 'error') window.__err = e.data.message;
            if (e.data.type === 'found') window.__err = 'found unexpectedly';
        };
        w.onerror = (ev) => { window.__err = 'worker error: ' + ev.message; };
    }
}
"""

SAMPLE = """
() => {
    // Wait until every worker has reported at least once post-ready, then take
    // a clean (first, last) pair over the window.
    const go = () => {
        window.__started = true;
        window.__t0 = performance.now();
        setTimeout(() => {
            window.__t1 = performance.now();
            let total = 0, counted = 0;
            for (let i = 0; i < window.__ws.length; i++) {
                const f = window.__first[i], l = window.__lastSeen[i];
                if (f === null) continue;      // worker never reported in window
                total += (l - f); counted++;
            }
            const secs = (window.__t1 - window.__t0) / 1000;
            window.__rate = secs > 0 ? total / secs : 0;
            window.__counted = counted;
            for (const w of window.__ws) w.terminate();
            URL.revokeObjectURL(window.__wurl);
            window.__done = true;
        }, cfg_window);
    };
    cfg_window = WINDOW;
    const wait = setInterval(() => {
        if (window.__readyN === window.__ws.length) {
            clearInterval(wait);
            setTimeout(go, SETTLE);
        }
    }, 100);
}
"""

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    page.goto(f"http://127.0.0.1:{PORT}/index.html", wait_until="load")
    page.wait_for_function("() => typeof sodium !== 'undefined' && sodium.ready")
    lib = page.evaluate("() => new URL('libsodium.js', location.href).href")
    worker_src = WORKER_JS.replace("https://example.test/libsodium.js", lib)
    assert "example.test" not in worker_src
    src = "self.__WORKER_SRC__ = %r;\n%s" % (worker_src, SETUP)

    sample_js = (SAMPLE
                 .replace("cfg_window = WINDOW;", f"cfg_window = {WINDOW_MS};")
                 .replace("}, SETTLE);", f"}}, {SETTLE_MS});"))

    baseline = None
    print(f"{'workers':>8} {'aggregate keys/s':>17} {'speedup':>9}  spread")
    for n in (1, 2, 4, 6, 8):
        rates = []
        for _ in range(TRIALS):
            page.evaluate("() => { window.__done = false; window.__rate = 0; }")
            page.evaluate(SETUP, {"src": src, "workers": n})
            page.evaluate(sample_js)
            try:
                page.wait_for_function(
                    "() => window.__done === true",
                    timeout=WINDOW_MS + SETTLE_MS + 40000)
            except Exception:
                print(f"  !! timeout at n={n}")
                break
            err = page.evaluate("() => window.__err || null")
            if err:
                print(f"  !! {err}")
                break
            rate = page.evaluate("() => window.__rate || 0")
            if rate:
                rates.append(rate)
            time.sleep(0.4)
        if not rates:
            break
        med = statistics.median(rates)
        if baseline is None:
            baseline = med
        spread = (max(rates) - min(rates)) / med * 100
        print(f"{n:>8} {med:>17,.0f} {med/baseline:>8.2f}x  +/-{spread:.1f}%")
        time.sleep(0.6)
    b.close()

httpd.shutdown()