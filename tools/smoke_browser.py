#!/usr/bin/env python3
"""Browser smoke test for index.html (runs in CI with Playwright).

Serves the repo over localhost, mines a 1-hex-char pattern with 1 worker
(expected ~16 attempts, i.e. instant), asserts a "Key 1 Found!" frame appears,
reloads, and asserts the frame survived via localStorage.

Usage:
    python tools/smoke_browser.py [--port 8321]
"""

from __future__ import annotations

import argparse
import functools
import http.server
import socketserver
import threading
from pathlib import Path

TCPServer = socketserver.TCPServer


def serve(repo_root: Path, port: int) -> TCPServer:
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(repo_root))
    # Allow immediate rebinding on reruns.
    TCPServer.allow_reuse_address = True
    server = TCPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="Playwright smoke test for index.html")
    parser.add_argument("--port", type=int, default=8321)
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    repo_root = Path(__file__).resolve().parent.parent
    server = serve(repo_root, args.port)
    url = f"http://127.0.0.1:{args.port}/index.html"

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            try:
                page = browser.new_page()
                errors: list[str] = []
                dialogs: list[str] = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                # Worker failures surface via alert(); dismiss so the test
                # fails fast with the message instead of hanging on a modal.
                page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
                page.goto(url, wait_until="load")

                # 1-char hex pattern: ~16 expected attempts, instant even headless.
                page.fill("#prefix", "a")
                page.fill("#workers", "1")
                page.click("#start-btn")

                page.wait_for_selector(".result-frame", timeout=120_000)
                heading = page.text_content(".result-frame h2")
                assert heading and "Key 1 Found!" in heading, f"unexpected heading: {heading!r}"

                codes = page.eval_on_selector_all(
                    ".result-frame code", "els => els.map(e => e.textContent)"
                )
                assert len(codes) == 2, f"expected public+private key, got: {codes!r}"
                assert all(len(c) == 64 for c in codes), f"keys must be 64 hex chars: {codes!r}"

                # Reload: history must survive via localStorage.
                page.reload(wait_until="load")
                page.wait_for_selector(".result-frame", timeout=30_000)
                heading = page.text_content(".result-frame h2")
                assert heading and "Key 1 Found!" in heading, "history lost across reload"

                worker_errors = [e for e in errors if "Worker" in e]
                assert not worker_errors, f"worker errors: {worker_errors!r}"
                assert not dialogs, f"unexpected dialogs: {dialogs!r}"
            finally:
                browser.close()
    finally:
        server.shutdown()
    print("smoke OK: mined, rendered, and persisted Key 1 across reload")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
