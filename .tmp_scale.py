"""Re-measure worker scaling carefully, with repeats and warmup.

The first pass reported 7.9x at 8 workers on a 4-core/8-thread host, which
contradicts the 2.3x figure currently hard-coded in the estimate. Before
changing a documented number, confirm it: repeat each worker count, discard the
first run as warmup, and report the spread. Turbo/thermal behaviour and
scheduler noise can both move this a lot on a short run.
"""
import statistics
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


WORKER_JS = """
const LIB = self.__LIB__;
importScripts(LIB);
(async () => {
    await sodium.ready;
    const run = (N) => {
        const seed = new Uint8Array(32);
        const t0 = performance.now();
        for (let i = 0; i < N; i++) {
            seed[0] = i & 0xff; seed[1] = (i >>> 8) & 0xff; seed[2] = (i >>> 16) & 0xff;
            sodium.crypto_sign_seed_keypair(seed);
        }
        return N / ((performance.now() - t0) / 1000);
    };
    run(5000);                       // warmup, discarded
    const N = 40000;
    const samples = [run(N), run(N), run(N)];
    self.postMessage({ kps: Math.max(...samples), samples });
})();
"""

handler = partial(Quiet, directory=str(ROOT))
httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
port = httpd.server_address[1]

TRIALS = 3
with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    page.goto(f"http://127.0.0.1:{port}/index.html", wait_until="load")
    page.wait_for_function("() => typeof sodium !== 'undefined' && sodium.ready")
    lib = page.evaluate("() => new URL('libsodium.js', location.href).href")
    src = "self.__LIB__ = %r;\n%s" % (lib, WORKER_JS)

    baseline = None
    print(f"{'workers':>8} {'aggregate keys/s':>17} {'speedup':>9}  spread")
    for n in (1, 2, 4, 6, 8):
        agg = []
        for _ in range(TRIALS):
            urls = [page.evaluate(
                "(s) => URL.createObjectURL(new Blob([s],{type:'application/javascript'}))",
                src) for _ in range(n)]
            res = [page.evaluate(
                "(u) => new Promise((ok) => { const w = new Worker(u);"
                " w.onmessage = (m) => { ok(m.data); w.terminate(); }; })", u)
                for u in urls]
            for u in urls:
                page.evaluate("(u) => URL.revokeObjectURL(u)", u)
            agg.append(sum(r["kps"] for r in res))
        med = statistics.median(agg)
        if baseline is None:
            baseline = med
        spread = (max(agg) - min(agg)) / med * 100 if med else 0
        print(f"{n:>8} {med:>17,.0f} {med/baseline:>8.2f}x  +/-{spread:.1f}%")
        time.sleep(0.4)
    b.close()

httpd.shutdown()