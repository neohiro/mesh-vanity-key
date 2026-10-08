"""Measure scaling of the SHIPPED worker, not a synthetic keygen loop.

The synthetic loop above scales ~7.7x at 8 threads, but the estimate constant
(2.3x) was presumably measured against the real worker, which also does
postMessage reporting and yields on a 30ms wall-clock budget. Those costs are
exactly what a saturation plateau would come from, so the real path has to be
measured before changing the constant.
"""
import statistics
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
sys_path = ROOT / "tools" / "check_inline_js.py"


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


# Import the real extractor so this measures the shipped bytes, not a copy.
import importlib.util
spec = importlib.util.spec_from_file_location("check_inline_js", sys_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
EXTRACTED = mod.extract(ROOT)
WORKER_JS = EXTRACTED["worker.js"]

# The real worker mines until told to stop. Start it with an impossible pattern
# (all 16 nibbles fixed) so it never finds and never exits, then sample the
# attempt counter it reports.
HARNESS = """
const WORKER_SRC = self.__WORKER_SRC__;
const LIB = self.__LIB__;
const url = URL.createObjectURL(new Blob([WORKER_SRC], {type:'application/javascript'}));
const w = new Worker(url);
w.onmessage = (m) => {
    if (m.data.type === 'ready') {
        // The worker destructures the search fields straight off the message;
        // there is no wrapper 'start' type in the shipped protocol.
        w.postMessage({
            prefix: 'ffffffffffffffff', suffix: '',
            matchPrefix: true, matchSuffix: false,
        });
    }
    if (m.data.type === 'progress') {
        self.postMessage({ attempts: m.data.attempts });
    }
    if (m.data.type === 'error' || m.data.type === 'found') {
        self.postMessage({ error: String(m.data.message || 'found') });
    }
};
"""

handler = partial(Quiet, directory=str(ROOT))
httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
port = httpd.server_address[1]

TRIALS = 3
SAMPLE_MS = 4000

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    page.goto(f"http://127.0.0.1:{port}/index.html", wait_until="load")
    lib = page.evaluate("() => new URL('libsodium.js', location.href).href")
    # The extracted worker carries the test harness's placeholder origin; point
    # it at the real libsodium served above, exactly as the page does at runtime.
    worker_src = WORKER_JS.replace("https://example.test/libsodium.js", lib)
    assert "example.test" not in worker_src, "placeholder origin not replaced"
    src = ("self.__WORKER_SRC__ = %r;\nself.__LIB__ = %r;\n%s"
           % (worker_src, lib, HARNESS))

    baseline = None
    print(f"{'workers':>8} {'aggregate keys/s':>17} {'speedup':>9}  spread")
    for n in (1, 2, 4, 6, 8):
        rates = []
        for _ in range(TRIALS):
            page.evaluate("""
                (cfg) => {
                    window.__done = false;
                    window.__last = 0;
                    window.__t0 = performance.now();
                    window.__ws = [];
                    const u = URL.createObjectURL(new Blob([cfg.src], {type:'application/javascript'}));
                    for (let i = 0; i < cfg.workers; i++) window.__ws.push(new Worker(u));
                    window.__wurl = u;
                    window.__handler = (e) => {
                        const n = window.__ws.length;
                        if (e.data.attempts != null) window.__last += e.data.attempts;
                        if (e.data.error) { window.__err = e.data.error; window.__done = true; }
                        if (window.__last > 0 && performance.now() - window.__t0 > cfg.ms) {
                            const secs = (performance.now() - window.__t0) / 1000;
                            window.__rate = window.__last / secs;
                            for (const w of window.__ws) w.terminate();
                            URL.revokeObjectURL(u);
                            window.__done = true;
                        }
                    };
                    for (const w of window.__ws) {
                        w.onmessage = window.__handler;
                        w.onerror = (ev) => { window.__err = 'worker error: ' + ev.message; window.__done = true; };
                    }
                }
            """, {"src": src, "workers": n, "ms": SAMPLE_MS})
            page.wait_for_function("() => window.__done === true",
                                   timeout=(SAMPLE_MS + 30000))
            rate = page.evaluate("() => window.__rate || 0")
            err = page.evaluate("() => window.__err || null")
            if err:
                print(f"  !! {err}")
                break
            if rate:
                rates.append(rate)
        if not rates:
            break
        med = statistics.median(rates)
        if baseline is None:
            baseline = med
        spread = (max(rates) - min(rates)) / med * 100
        print(f"{n:>8} {med:>17,.0f} {med/baseline:>8.2f}x  +/-{spread:.1f}%")
        time.sleep(0.4)
    b.close()

httpd.shutdown()