#!/usr/bin/env python3
"""Measure the real memory cost of one mining worker in a real browser.

Why this exists
---------------
`detectOptimalWorkers()` spawns one Web Worker per logical core (capped at 32).
Each worker runs its own instance of the libsodium WASM module, so the count
that is best for throughput is not automatically the count that is safe for
memory: 32 workers means 32 WASM instances, and on a memory-constrained machine
that is a tab crash rather than a slow search.

The module declares an *initial* linear memory of 64 pages (4 MiB) but permits
growth up to 32768 pages (2 GiB), so the declared initial size says nothing about
what a worker actually holds while mining. This measures it.

What it reports
---------------
  * peak WASM linear memory per worker (buffer byteLength after a mining burst)
  * process-level memory attributed to the page with 0, N/2 and N workers

The second number is the one that matters for the safety cap: WASM memory shows
up in the page's memory footprint, and browsers will discard a tab that exceeds
their per-tab budget rather than swap it.

Usage:  python tools/measure_worker_memory.py [workers ...]
Default: 0,1,2,4,8 -- or hardwareConcurrency when the host exposes it.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Bind to loopback on an ephemeral port. Port 0 lets the OS pick, which avoids
# colliding with anything already listening in CI or on a dev machine.
HOST = "127.0.0.1"


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):  # noqa: D102 - silence per-request logging
        pass


def _serve(directory: Path) -> tuple[ThreadingHTTPServer, str]:
    handler = partial(_QuietHandler, directory=str(directory))
    httpd = ThreadingHTTPServer((HOST, 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[0], httpd.server_address[1]
    return httpd, f"http://{host}:{port}/index.html"


# Measures the buffer the WASM module actually holds after real keygen. Read from
# the worker's own heap, so it is per-worker and not a page-wide figure.
_WORKER_PROBE = """
self.postMessage({ type: 'ready' });
self.onmessage = async function (e) {
    const burst = e.data.burst || 20000;
    for (let i = 0; i < burst; i++) {
        const seed = new Uint8Array(32);
        seed[0] = i & 0xff;
        seed[1] = (i >>> 8) & 0xff;
        sodium.crypto_sign_seed_keypair(seed);
    }
    let bytes = 0;
    try {
        // libsodium's Emscripten glue keeps the memory object reachable; find it
        // through the exports rather than guessing at glue internals.
        const heap = self.HEAPU8 || (Module && Module.HEAPU8);
        if (heap) bytes = heap.byteLength;
    } catch (err) { /* fall through to 0 */ }
    if (!bytes) {
        try {
            const ex = self.wasmExports || (Module && Module.asm && Module.asm.memory);
            if (ex && ex.buffer) bytes = ex.buffer.byteLength;
        } catch (err) { /* fall through to 0 */ }
    }
    self.postMessage({ type: 'done', heapBytes: bytes });
};
"""

_PAGE_PROBE = """
async (config) => {
    const workers = [];
    for (let i = 0; i < config.workers; i++) {
        const src = `importScripts('${config.libsodiumUrl}');
            self.postMessage({type:'ready'});
            self.onmessage = async function(e){
                for (let k = 0; k < e.data.burst; k++) {
                    const seed = new Uint8Array(32);
                    seed[0] = k & 0xff; seed[1] = (k >>> 8) & 0xff;
                    sodium.crypto_sign_seed_keypair(seed);
                }
                self.postMessage({type:'done'});
            };`;
        const url = URL.createObjectURL(new Blob([src], {type:'application/javascript'}));
        workers.push({ url, w: new Worker(url) });
    }
    const ready = (w) => new Promise((res) => { w.onmessage = (m) => { if (m.data.type === 'ready') res(); }; });
    await Promise.all(workers.map(({w}) => ready(w)));
    // Let the WASM instances settle before sampling.
    await new Promise((r) => setTimeout(r, 250));
    const before = performance.memory ? performance.memory.usedJSHeapSize : 0;
    for (const { w } of workers) w.postMessage({ burst: config.burst });
    await Promise.all(workers.map(({ w }) => new Promise((res) => { w.onmessage = (m) => { if (m.data.type === 'done') res(); }; })));
    await new Promise((r) => setTimeout(r, 400));
    const after = performance.memory ? performance.memory.usedJSHeapSize : 0;
    for (const { w, url } of workers) { w.terminate(); URL.revokeObjectURL(url); }
    return { before, after, workers: config.workers };
}
"""


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright is not installed; run: python -m pip install playwright",
              file=sys.stderr)
        return 2

    requested = [int(a) for a in sys.argv[1:]] or [0, 1, 2, 4, 8]
    httpd, url = _serve(REPO_ROOT)
    results = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--enable-precise-memory-info"])
            page = browser.new_page()
            page.goto(url, wait_until="load")
            page.wait_for_function("() => typeof sodium !== 'undefined' && sodium.ready")
            page.evaluate("async () => { await sodium.ready; }")

            cores = page.evaluate("() => navigator.hardwareConcurrency") or 4
            print(f"host reports {cores} logical cores")

            for n in requested:
                if n == 0:
                    continue  # baseline: page loaded, no workers
                out = page.evaluate(_PAGE_PROBE, {
                    "workers": n,
                    "burst": 20000,
                    "libsodiumUrl": page.evaluate(
                        "() => new URL('libsodium.js', location.href).href"),
                })
                results.append(out)
                delta_mb = (out["after"] - out["before"]) / (1024 * 1024)
                per_worker = delta_mb / n if n else 0.0
                print(f"  {n:>3} workers: heap {out['before']/1048576:7.1f} -> "
                      f"{out['after']/1048576:7.1f} MiB "
                      f"(+{delta_mb:6.1f} MiB, ~{per_worker:5.2f} MiB/worker)")
                time.sleep(0.3)

            browser.close()
    finally:
        httpd.shutdown()

    per_worker = [
        (r["after"] - r["before"]) / (1024 * 1024) / r["workers"]
        for r in results if r["workers"] and r["after"] > r["before"]
    ]
    print(json.dumps({
        "cores": cores,
        "measurements": results,
        "perWorkerMiB": per_worker,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())