#!/usr/bin/env python3
"""Measure how the shipped browser miner scales with worker count.

This is the evidence behind WORKER_SCALE in index.html and _worker_scale() in
meshcore_vanity.py. Re-run it when changing the hot loop, because the shape of
this curve is what the pre-flight estimate is built on:

    python tools/measure_scaling.py            # full sweep
    python tools/measure_scaling.py --quick    # 1, 4, 8 only
    python tools/measure_scaling.py --json     # machine-readable

Measurement method (and why it is this one)
--------------------------------------------
Each worker reports a *cumulative* `attempts` counter every 500 ms. For a fixed
wall-clock window, this harness takes (last - first) per worker and sums those
deltas. Two tempting alternatives are both wrong in ways that flatter the result:

  * summing every cumulative report as if it were a delta: a worker reporting
    5k, 10k, 15k ... sums to many times its real total, and the overcount grows
    with the number of reports, so it inflates the multi-worker numbers most.
  * taking each worker's max single-sample rate: under contention workers stall
    unevenly, so the max is the least contended sample and over-reports.

Delta-over-window is unbiased in both directions, which is why it is the one
used. Trials are repeated and the median reported; the spread is printed so a
noisy host is visible rather than silently baked into the constant.

What the curve is measuring
---------------------------
Not libsodium: a bare crypto_sign_seed_keypair loop in this same browser scales
much further (3-8x on an 8-thread host). The shipped loop adds per-candidate JS
work on top of the keygen -- the 32-byte walk, nibble matching, periodic
postMessage, and a 30 ms yield. That wrapper work is the reason the curve is
sublinear, and it is why the estimate cannot assume one worker per core.
"""

from __future__ import annotations

import argparse
import json
import statistics
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The extractor is imported rather than the worker source copied, so this always
# measures the bytes that actually ship.
_EXTRACTOR = REPO_ROOT / "tools" / "check_inline_js.py"
_TEST_ORIGIN = "https://example.test"   # placeholder the extractor injects


def _quiet_handler(directory: Path):
    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *_args):
            pass
    return partial(Quiet, directory=str(directory))


def _serve(directory: Path) -> tuple[ThreadingHTTPServer, str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _quiet_handler(directory))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, port = httpd.server_address[0], httpd.server_address[1]
    return httpd, f"http://{host}:{port}/index.html"


# One worker per count, all started together, sampling over a single window.
_SCALE_JS = """
async (cfg) => {
    const url = URL.createObjectURL(
        new Blob([cfg.src], { type: 'application/javascript' }));
    const workers = [];
    const firstAt = [];
    const lastSeen = [];
    let readyCount = 0;
    let error = null;

    return await new Promise((resolve) => {
        let t0 = 0;
        const finish = () => {
            const elapsed = (performance.now() - t0) / 1000;
            let total = 0;
            let counted = 0;
            for (let i = 0; i < workers.length; i++) {
                if (firstAt[i] === null) continue;
                total += lastSeen[i] - firstAt[i];
                counted++;
            }
            for (const w of workers) w.terminate();
            URL.revokeObjectURL(url);
            resolve({
                rate: elapsed > 0 ? total / elapsed : 0,
                counted,
                requested: workers.length,
                error,
            });
        };

        // A pattern that cannot match, so the workers keep mining and never
        // exit early or change their behaviour mid-window.
        for (let i = 0; i < cfg.workers; i++) {
            const w = new Worker(url);
            workers.push(w);
            firstAt.push(null);
            lastSeen.push(0);
            w.onmessage = (e) => {
                if (e.data.type === 'ready') {
                    w.postMessage({
                        prefix: 'ffffffffffffffff',
                        suffix: '',
                        matchPrefix: true,
                        matchSuffix: false,
                    });
                    if (++readyCount === cfg.workers) {
                        // Let every worker finish booting libsodium before the
                        // window opens, or early WASM compile time is charged to
                        // the sample.
                        setTimeout(() => {
                            for (let k = 0; k < workers.length; k++) firstAt[k] = lastSeen[k];
                            t0 = performance.now();
                            setTimeout(finish, cfg.windowMs);
                        }, cfg.settleMs);
                    }
                    return;
                }
                if (e.data.type === 'progress') lastSeen[i] = e.data.attempts;
                if (e.data.type === 'error') error = e.data.message;
                if (e.data.type === 'found') error = 'found unexpectedly';
            };
            w.onerror = (ev) => { error = 'worker error: ' + ev.message; };
        }
        setTimeout(finish, cfg.windowMs + cfg.settleMs + 45000);
    });
}
"""

# The same measurement, but of a bare crypto_sign_seed_keypair loop with none of
# the per-candidate wrapper. Comparing the two isolates what the wrapper costs in
# parallel scalability: if they scaled the same, the wrapper's JS work would not
# be the reason the shipped curve is sublinear.
_BARE_JS = """
async (cfg) => {
    const src = `
importScripts("${cfg.lib}");
self.postMessage({ type: "ready" });
self.onmessage = function (e) {
    const seed = new Uint8Array(32);
    // Time-boxed, not a fixed key count: under contention a fixed count may not
    // finish before the harness deadline, and a worker that never reports reads
    // as zero throughput rather than as a slow one.
    const runMs = e.data.runMs;
    const t0 = performance.now();
    let done = 0;
    let now = t0;
    while (now - t0 < runMs) {
        seed[0] = done & 0xff;
        seed[1] = (done >>> 8) & 0xff;
        seed[2] = (done >>> 16) & 0xff;
        seed[3] = (done >>> 24) & 0xff;
        sodium.crypto_sign_seed_keypair(seed);
        done++;
        if ((done & 0x3ff) === 0) now = performance.now();
    }
    const secs = (performance.now() - t0) / 1000;
    self.postMessage({ rate: secs > 0 ? done / secs : 0 });
};
`;
    const url = URL.createObjectURL(
        new Blob([src], { type: 'application/javascript' }));
    const workers = [];
    let readyCount = 0;
    return await new Promise((resolve) => {
        const finish = () => {
            for (const w of workers) w.terminate();
            URL.revokeObjectURL(url);
            resolve({
                rate: workers.reduce((a, w) => a + (w.__rate || 0), 0),
                counted: workers.filter((w) => w.__reported).length,
                requested: workers.length,
            });
        };
        for (let i = 0; i < cfg.workers; i++) {
            const w = new Worker(url);
            workers.push(w);
            w.onmessage = (e) => {
                if (e.data.type === 'ready') {
                    if (++readyCount === cfg.workers) {
                        setTimeout(() => {
                            for (const ww of workers) ww.postMessage({ runMs: cfg.runMs });
                        }, cfg.settleMs);
                    }
                    return;
                }
                w.__rate = e.data.rate;
                w.__reported = true;
            };
            w.onerror = () => { w.__rate = 0; w.__reported = true; };
        }
        setTimeout(finish, cfg.settleMs + cfg.runMs + 4000);
    });
}
"""

_CONTRACT_JS = """
async (src) => {
    const url = URL.createObjectURL(
        new Blob([src], { type: 'application/javascript' }));
    return await new Promise((resolve) => {
        const seen = [];
        const w = new Worker(url);
        const finish = (extra) => {
            w.terminate();
            URL.revokeObjectURL(url);
            resolve(Object.assign({ messages: seen }, extra));
        };
        w.onmessage = (e) => {
            seen.push(e.data.type);
            if (e.data.type === 'ready') {
                w.postMessage({ prefix: 'ffffffffffffffff', suffix: '',
                                matchPrefix: true, matchSuffix: false });
            }
            if (seen.length >= 5) finish({});
        };
        w.onerror = (ev) => finish({ error: ev.message });
        setTimeout(() => finish({ timeout: true }), 15000);
    });
}
"""


def _load_worker_source() -> str:
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_inline_js", _EXTRACTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.extract(REPO_ROOT)["worker.js"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true",
                    help="measure only 1, 4 and 8 workers")
    ap.add_argument("--json", action="store_true",
                    help="emit only the measurements as JSON")
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--window", type=int, default=6000,
                    help="sampling window in ms (default 6000)")
    ap.add_argument("--settle", type=int, default=2500,
                    help="ms to wait after all workers report ready (default 2500)")
    ap.add_argument("--bare-run-ms", type=int, default=4000,
                    help="ms each bare-keygen worker mines before reporting")
    ap.add_argument("--skip-bare", action="store_true",
                    help="skip the bare-keygen comparison sweep")
    args = ap.parse_args()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright is required: python -m pip install playwright\n"
              "            then: python -m playwright install chromium",
              file=__import__("sys").stderr)
        return 2

    counts = (1, 4, 8) if args.quick else (1, 2, 3, 4, 5, 6, 7, 8)
    worker_src = _load_worker_source()

    httpd, page_url = _serve(REPO_ROOT)
    out = {}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(page_url, wait_until="load")
            page.wait_for_function(
                "() => typeof sodium !== 'undefined' && sodium.ready")
            lib = page.evaluate("() => new URL('libsodium.js', location.href).href")
            placeholder = f"importScripts('{_TEST_ORIGIN}/libsodium.js')"
            if placeholder not in worker_src:
                print(f"expected the extractor's placeholder {placeholder!r} in "
                      f"the worker source; check tools/check_inline_js.py",
                      file=__import__("sys").stderr)
                return 3
            src = worker_src.replace(placeholder, f"importScripts('{lib}')")

            contract = page.evaluate(_CONTRACT_JS, src)
            if contract.get("error") or contract.get("timeout"):
                print("worker did not start cleanly:",
                      contract.get("error") or "timed out waiting for messages",
                      file=__import__("sys").stderr)
                return 3

            cores = page.evaluate("() => navigator.hardwareConcurrency")
            lib_src = page.evaluate("() => new URL('libsodium.js', location.href).href")

            def sweep(runner, cfg_extra):
                got = {}
                for n in counts:
                    rates = []
                    for _ in range(args.trials):
                        r = page.evaluate(runner, dict(
                            {"workers": n, "settleMs": args.settle}, **cfg_extra))
                        if r.get("error"):
                            print(f"  {n} workers: {r['error']}",
                                  file=__import__("sys").stderr)
                            rates = []
                            break
                        if "counted" in r and r["counted"] < n:
                            print(f"  {n} workers: only {r['counted']}/{n} "
                                  f"reported in the window",
                                  file=__import__("sys").stderr)
                        if r.get("rate"):
                            rates.append(r["rate"])
                        page.wait_for_timeout(300)
                    if rates:
                        got[n] = rates
                    page.wait_for_timeout(400)
                return got

            out["shipped"] = sweep(_SCALE_JS, {
                "src": src, "windowMs": args.window})
            if not args.skip_bare:
                out["bare"] = sweep(_BARE_JS, {
                    "lib": lib_src, "runMs": args.bare_run_ms})
            browser.close()
    finally:
        httpd.shutdown()

    if not out.get("shipped"):
        print("no measurements produced", file=__import__("sys").stderr)
        return 3

    def rows_for(series):
        base = statistics.median(series[min(series)])
        rows = []
        for n in sorted(series):
            med = statistics.median(series[n])
            rows.append({
                "workers": n,
                "medianKeysPerSec": round(med),
                "speedup": round(med / base, 3),
                "spreadPct": round((max(series[n]) - min(series[n])) / med * 100, 1),
                "trials": [round(r) for r in series[n]],
            })
        return rows

    shipped = rows_for(out["shipped"])
    payload = {
        "coresReported": cores,
        "windowMs": args.window,
        "trials": args.trials,
        "measurements": shipped,
        "notes": (
            "Delta-over-window per worker, median of trials. Speedup is "
            "relative to one worker, not to the worker count. The shipped "
            "curve is sublinear; the bare-keygen comparison below shows how "
            "much of that is the per-candidate JS wrapper."
        ),
    }
    bare_rows = None
    if out.get("bare"):
        bare_rows = rows_for(out["bare"])
        payload["bareKeygen"] = bare_rows

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"host reports {cores} logical cores; window {args.window}ms, "
          f"{args.trials} trials\n")
    print(f"{'workers':>8} {'shipped keys/s':>15} {'speedup':>9} {'spread':>8}")
    for row in shipped:
        print(f"{row['workers']:>8} {row['medianKeysPerSec']:>15,} "
              f"{row['speedup']:>8.2f}x {row['spreadPct']:>7.1f}%")

    top = shipped[-1]
    print(f"\nShipped miner: {top['speedup']:.2f}x at {top['workers']} workers.")

    if bare_rows:
        print(f"\n{'workers':>8} {'bare keys/s':>15} {'speedup':>9} {'spread':>8}")
        for row in bare_rows:
            print(f"{row['workers']:>8} {row['medianKeysPerSec']:>15,} "
                  f"{row['speedup']:>8.2f}x {row['spreadPct']:>7.1f}%")
        gap = bare_rows[-1]["speedup"] - top["speedup"]
        print(f"\nBare keygen gains {bare_rows[-1]['speedup']:.2f}x where the "
              f"shipped miner gains {top['speedup']:.2f}x.")
        print(f"That {gap:.2f}x gap is the per-candidate JS wrapper (32-byte "
              f"walk, nibble match, 500ms reporting, 30ms yield) and is why the "
              f"estimate cannot assume one worker per core.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())