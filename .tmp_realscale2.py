"""Correctly measure scaling of the shipped worker.

The first attempt at this summed each worker's CUMULATIVE `attempts` counter
across every progress report, which double-counts enormously (a worker reports
5k, 10k, 15k... and summing those multiplies the real total several times over).
That is almost certainly where the "2.3x" figure came from, so re-measure with
per-worker deltas: track each worker's last reported value and sum only the
increments.
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
spec = importlib.util.spec_from_file_location("check_inline_js", ROOT / "tools" / "check_inline_js.py")
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

SAMPLE_MS = 5000
TRIALS = 3

# Delta-correct accumulator: each worker keeps its own last-seen cumulative
# count; only the increase since the previous report is added.
MEASURE = """
(cfg) => {
    window.__done = false;
    window.__err = null;
    window.__total = 0;
    window.__t0 = 0;
    window.__ws = [];
    window.__last = [];
    const u = URL.createObjectURL(new Blob([cfg.src], {type:'application/javascript'}));
    for (let i = 0; i < cfg.workers; i++) window.__ws.push(new Worker(u));
    window.__wurl = u;
    window.__start = () => {
        window.__t0 = performance.now();
        window.__last = window.__ws.map(() => 0);
        window.__total = 0;
    };
    window.__handler = (e) => {
        const i = window.__ws.indexOf(e.target);
        if (e.data.type === 'ready') {
            e.target.postMessage({
                prefix: 'ffffffffffffffff', suffix: '',
                matchPrefix: true, matchSuffix: false,
            });
            if (window.__ws.every((w) => w.__ready)) window.__start();
            return;
        }
        if (e.data.type === 'progress') {
            const cur = e.data.attempts;
            const prev = window.__last[i] || 0;
            if (cur >= prev) window.__total += cur - prev;
            window.__last[i] = cur;
        }
        if (e.data.type === 'error' || e.data.type === 'found') {
            window.__err = String(e.data.message || 'found early');
            window.__done = true;
        }
    };
    for (const w of window.__ws) {
        w.__ready = false;
        w.onmessage = (e) => {
            if (e.data.type === 'ready') { w.__ready = true; }
            window.__handler(e);
        };
        w.onerror = (ev) => { window.__err = 'worker error: ' + ev.message; window.__done = true; };
    }
    window.__tick = setInterval(() => {
        if (window.__total > 0 && performance.now() - window.__t0 > cfg.ms) {
            const secs = (performance.now() - window.__t0) / 1000;
            window.__rate = window.__total / secs;
            clearInterval(window.__tick);
            for (const w of window.__ws) w.terminate();
            URL.revokeObjectURL(u);
            window.__done = true;
        }
    }, 200);
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
    src = "self.__WORKER_SRC__ = %r;\n%s" % (worker_src, MEASURE)

    baseline = None
    print(f"{'workers':>8} {'aggregate keys/s':>17} {'speedup':>9}  spread")
    for n in (1, 2, 4, 6, 8):
        rates = []
        for _ in range(TRIALS):
            page.evaluate("(s) => { clearInterval(window.__tick); window.__done=false; }", src)
            page.evaluate(MEASURE, {"src": src, "workers": n, "ms": SAMPLE_MS})
            try:
                page.wait_for_function("() => window.__done === true", timeout=SAMPLE_MS + 40000)
            except Exception:
                pass
            rate = page.evaluate("() => window.__rate || 0")
            err = page.evaluate("() => window.__err || null")
            if err:
                print(f"  !! {err}")
                break
            if rate:
                rates.append(rate)
            time.sleep(0.3)
        if not rates:
            break
        med = statistics.median(rates)
        if baseline is None:
            baseline = med
        spread = (max(rates) - min(rates)) / med * 100
        print(f"{n:>8} {med:>17,.0f} {med/baseline:>8.2f}x  +/-{spread:.1f}%")
        time.sleep(0.5)
    b.close()

httpd.shutdown()