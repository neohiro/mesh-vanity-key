"""Minimal check of the shipped worker's message contract.

The larger harnesses all timed out, so establish the ground truth first: does the
extracted worker post 'ready', and what exactly does it need in the start
message? Everything downstream depends on getting this right.
"""
import threading
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

PROBE = """
self.__WORKER_SRC__ = %r;
const u = URL.createObjectURL(new Blob([self.__WORKER_SRC__], {type:'application/javascript'}));
const log = [];
const w = new Worker(u);
w.onmessage = (e) => {
    log.push(e.data.type + (e.data.attempts !== undefined ? ':' + e.data.attempts : ''));
    if (e.data.type === 'ready') {
        w.postMessage({prefix:'ffffffffffffffff', suffix:'', matchPrefix:true, matchSuffix:false});
    }
    if (log.length >= 6) { w.terminate(); self.postMessage({log}); }
};
w.onerror = (ev) => { w.terminate(); self.postMessage({error: ev.message, log}); };
setTimeout(() => { w.terminate(); self.postMessage({log, timeout:true}); }, 8000);
"""

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    page.goto(f"http://127.0.0.1:{PORT}/index.html", wait_until="load")
    page.wait_for_function("() => typeof sodium !== 'undefined' && sodium.ready")
    lib = page.evaluate("() => new URL('libsodium.js', location.href).href")
    ws = WORKER_JS.replace("https://example.test/libsodium.js", lib)
    assert "example.test" not in ws, "placeholder origin not replaced"

    out = page.evaluate(PROBE % (ws,))
    print("messages:", out.get("log"))
    if out.get("error"):
        print("worker error:", out["error"])
    if out.get("timeout"):
        print("TIMED OUT")
    b.close()

httpd.shutdown()