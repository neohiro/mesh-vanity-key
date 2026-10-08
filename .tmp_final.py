"""Ground truth for the shipped worker's message contract, then scaling.

Establishes the contract first (what messages arrive, in what order), because
every earlier harness silently returned garbage by mis-reading the evaluate
result rather than the worker output.

Scaling is then measured with the only unbiased definition available here: for
each worker, (last cumulative attempts - first cumulative attempts) inside one
fixed wall-clock window, summed and divided by the window. Summing cumulative
counters double-counts; taking each worker's max sample inflates under exactly
the contention that matters.
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

# Single async arrow, so Playwright gets a function it can call and await.
CONTRACT = """
async (src) => {
    const u = URL.createObjectURL(new Blob([src], {type:'application/javascript'}));
    const log = [];
    return await new Promise((resolve) => {
        const w = new Worker(u);
        const finish = (extra) => {
            w.terminate(); URL.revokeObjectURL(u); resolve(Object.assign({log}, extra));
        };
        w.onmessage = (e) => {
            log.push(e.data.type + (e.data.attempts !== undefined ? ':' + e.data.attempts : ''));
            if (e.data.type === 'ready') {
                w.postMessage({prefix:'ffffffffffffffff', suffix:'',
                               matchPrefix:true, matchSuffix:false});
            }
            if (log.length >= 6) finish({});
        };
        w.onerror = (ev) => finish({error: ev.message});
        setTimeout(() => finish({timeout: true}), 9000);
    });
}
"""

SCALE = """
async (cfg) => {
    const u = URL.createObjectURL(new Blob([cfg.src], {type:'application/javascript'}));
    const ws = [];
    const first = [];
    const lastSeen = [];
    let readyN = 0;
    let err = null;

    return await new Promise((resolve) => {
        const finish = () => {
            const t1 = performance.now();
            let total = 0, counted = 0;
            for (let i = 0; i < ws.length; i++) {
                if (first[i] === null) continue;
                total += lastSeen[i] - first[i];
                counted++;
            }
            const secs = (t1 - t0) / 1000;
            for (const w of ws) w.terminate();
            URL.revokeObjectURL(u);
            resolve({rate: secs > 0 ? total / secs : 0, counted, workers: ws.length, err});
        };

        let t0 = 0;
        let timer = null;
        for (let i = 0; i < cfg.workers; i++) {
            const w = new Worker(u);
            ws.push(w); first.push(null); lastSeen.push(0);
            w.onmessage = (e) => {
                if (e.data.type === 'ready') {
                    w.postMessage({prefix:'ffffffffffffffff', suffix:'',
                                   matchPrefix:true, matchSuffix:false});
                    if (++readyN === cfg.workers) {
                        // Give every worker time to finish booting its WASM
                        // before the sampling window opens.
                        setTimeout(() => {
                            for (let k = 0; k < ws.length; k++) { first[k] = lastSeen[k]; }
                            t0 = performance.now();
                            timer = setTimeout(finish, cfg.windowMs);
                        }, cfg.settleMs);
                    }
                    return;
                }
                if (e.data.type === 'progress') { lastSeen[i] = e.data.attempts; }
                if (e.data.type === 'error') err = e.data.message;
                if (e.data.type === 'found') err = 'found unexpectedly';
            };
            w.onerror = (ev) => { err = 'worker error: ' + ev.message; };
        }
        setTimeout(() => { clearTimeout(timer); finish(); }, cfg.windowMs + cfg.settleMs + 30000);
    });
}
"""

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    page.goto(f"http://127.0.0.1:{PORT}/index.html", wait_until="load")
    page.wait_for_function("() => typeof sodium !== 'undefined' && sodium.ready")
    lib = page.evaluate("() => new URL('libsodium.js', location.href).href")
    ws_src = WORKER_JS.replace("https://example.test/libsodium.js", lib)
    assert "example.test" not in ws_src, "placeholder origin not replaced"

    c = page.evaluate(CONTRACT, ws_src)
    print("contract messages:", c.get("log"))
    if c.get("error"):
        print("  worker error:", c["error"])
    if c.get("timeout"):
        print("  TIMED OUT waiting for messages")
    print()

    WINDOW, SETTLE, TRIALS = 6000, 2500, 3
    baseline = None
    print(f"{'workers':>8} {'aggregate keys/s':>17} {'speedup':>9}  spread")
    for n in (1, 2, 4, 6, 8):
        rates = []
        for _ in range(TRIALS):
            out = page.evaluate(SCALE, {"src": ws_src, "workers": n,
                                        "windowMs": WINDOW, "settleMs": SETTLE})
            if out.get("err"):
                print(f"  !! {out['err']}")
                break
            if out.get("counted", 0) < n:
                print(f"  !! only {out['counted']}/{n} workers reported in window")
            if out.get("rate"):
                rates.append(out["rate"])
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