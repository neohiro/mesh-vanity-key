"""Ad-hoc probe: which globals expose the WASM linear memory?

performance.memory on the main thread does not account for worker heaps, so the
page-level heap barely moves when workers start. This looks for a per-worker
handle to the module memory so the measurement can be taken from inside each
worker instead.
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


handler = partial(Quiet, directory=str(ROOT))
httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
port = httpd.server_address[1]

with sync_playwright() as p:
    b = p.chromium.launch(args=["--enable-precise-memory-info"])
    page = b.new_page()
    page.goto(f"http://127.0.0.1:{port}/index.html", wait_until="load")
    page.wait_for_function("() => typeof sodium !== 'undefined' && sodium.ready")
    page.evaluate("async () => { await sodium.ready; }")
    out = page.evaluate(Path(".tmp_globals.js").read_text(encoding="utf-8"))
    for k, v in out.items():
        print(f"{k}: {v}")
    b.close()

httpd.shutdown()