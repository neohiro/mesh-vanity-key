"""Ad-hoc probe: measure the real WASM linear-memory cost of one mining worker.

performance.memory on the main thread does not account for worker heaps, so the
page-level number barely moves when workers start. The measurement therefore has
to come from inside each worker.

This script also checks the growth ceiling the module declares, because a module
that permits 2 GiB but starts at 4 MiB tells you nothing about steady-state
use. libsodium exposes its heap as `Module.HEAPU8`, whose byteLength is the live
WASM linear-memory size.
"""
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


# Runs inside the worker: import libsodium, do real keygen, report heap size.
WORKER_JS = """
const LIB = self.__LIB__;
importScripts(LIB);
(async () => {
    await sodium.ready;
    const heapBytes = () => {
        try { return Module.HEAPU8 ? Module.HEAPU8.byteLength : 0; } catch (e) { return -1; }
    };
    const base = heapBytes();
    const N = 50000;
    const seed = new Uint8Array(32);
    const t0 = performance.now();
    for (let i = 0; i < N; i++) {
        seed[0] = i & 0xff;
        seed[1] = (i >>> 8) & 0xff;
        seed[2] = (i >>> 16) & 0xff;
        sodium.crypto_sign_seed_keypair(seed);
    }
    const ms = performance.now() - t0;
    self.postMessage({ base, after: heapBytes(), N, ms,
                       keysPerSec: Math.round(N / (ms / 1000)) });
})();
"""

handler = partial(Quiet, directory=str(ROOT))
httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
port = httpd.server_address[1]
url = f"http://127.0.0.1:{port}/index.html"

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    page.goto(url, wait_until="load")
    page.wait_for_function("() => typeof sodium !== 'undefined' && sodium.ready")

    lib = page.evaluate("() => new URL('libsodium.js', location.href).href")
    src = "self.__LIB__ = %r;\n%s" % (lib, WORKER_JS)

    for n in (1, 2, 4, 8):
        results = []
        for _ in range(n):
            wurl = page.evaluate(
                "(s) => URL.createObjectURL(new Blob([s],{type:'application/javascript'}))",
                src,
            )
            results.append((wurl, page.evaluate(
                "(u) => new Promise((res) => { const w = new Worker(u);"
                " w.onmessage = (m) => { res(m.data); w.terminate(); }; })",
                wurl,
            )))
        after = [r[1]["after"] for r in results]
        base = results[0][1]["base"]
        kps = sum(r[1]["keysPerSec"] for r in results)
        print(f"{n} workers: heap base={base/1048576:.2f} MiB "
              f"after={[round(a/1048576,2) for a in after]} MiB "
              f"| aggregate {kps:,} keys/s "
              f"| speedup {kps/results[0][1]['keysPerSec']:.2f}x")
    b.close()

httpd.shutdown()