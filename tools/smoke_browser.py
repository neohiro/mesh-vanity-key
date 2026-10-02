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
import re
import socketserver
import threading
from pathlib import Path

TCPServer = socketserver.TCPServer

# Must match HISTORY_KEY in index.html.
HISTORY_KEY = "meshcoreVanityKeys"


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
# Worker failures surface via alert(). Record the message so an unexpected
                # modal fails the test with context instead of hanging, and
                # ACCEPT it: dialogs are auto-dismissed by this handler, so a
                # confirm() would always return false and any step that
                # legitimately needs confirming (Clear All Keys) would silently
                # do nothing. Unexpected dialogs are still asserted at the end.
                def handle_dialog(d) -> None:
                    dialogs.append(d.message)
                    d.accept()

                page.on("dialog", handle_dialog)
                page.goto(url, wait_until="load")

                # 1-char hex pattern: ~16 expected attempts, instant even headless.
                page.fill("#prefix", "a")
                page.click("#start-btn")

                page.wait_for_selector(".result-frame", timeout=120_000)
                heading = page.text_content(".result-frame h2")
                assert heading and "Key 1 Found!" in heading, f"unexpected heading: {heading!r}"

                codes = page.eval_on_selector_all(
                    ".result-frame code", "els => els.map(e => e.textContent)"
                )
                assert len(codes) == 2, f"expected public+private key, got: {codes!r}"
                assert all(len(c) == 64 for c in codes), f"keys must be 64 hex chars: {codes!r}"

                # Elapsed renders via formatElapsed() ("45.20s" / "2m 10s" / "1h 2m 9s"),
                # never a raw float or NaN.
                stats = page.text_content(".result-frame .result-stats") or ""
                assert "attempts (" in stats, f"unexpected stats line: {stats!r}"
                assert "NaN" not in stats and "undefined" not in stats, (
                    f"unformatted time in stats: {stats!r}"
                )
                # A RAW float looks like "(0.04)" - digits then a closing
                # paren, with no unit. The previous pattern also matched the
                # correctly humanized "(0.00s)", so every search finishing under
                # a minute failed here. This was latent until CI first ran the
                # smoke test to completion.
                assert not re.search(r"\(\d+\.\d+\)", stats), (
                    f"elapsed should be humanized, not a raw float: {stats!r}"
                )
                # And it must carry a real unit or a compound duration.
                assert re.search(r"\((\d+\.\d+s|[\dhm ]*s)\)", stats), (
                    f"elapsed lacks a unit: {stats!r}"
                )

                # "Clear All Keys" must match the export buttons' height.
                heights = page.eval_on_selector_all(
                    ".history-bar button",
                    "els => els.map(e => Math.round(e.getBoundingClientRect().height))",
                )
                assert len(set(heights)) == 1, f"history buttons differ in height: {heights!r}"
                labels = page.eval_on_selector_all(
                    ".history-bar button", "els => els.map(e => e.textContent.trim())"
                )
                assert "Clear All Keys" in labels, f"unexpected button labels: {labels!r}"

                # A pattern longer than a 64-hex-digit key can never match, so
                # it must be refused rather than burning every core forever.
                page.fill("#prefix", "ab" * 40)
                page.fill("#suffix", "cd" * 40)
                notice = page.text_content("#reserved-notice") or ""
                assert "Impossible pattern" in notice, (
                    f"over-length pattern must be flagged: {notice!r}"
                )
                page.click("#start-btn")
                page.wait_for_timeout(500)
                assert "Impossible pattern" in (page.text_content("#reserved-notice") or ""), (
                    "start must not proceed for an impossible pattern"
                )
                assert "Key 2 Found!" not in (page.text_content("#results") or ""), (
                    "an impossible search must not produce a result"
                )
                # Dismiss the refusal dialog so the reload below is not blocked.
                page.fill("#prefix", "a")
                page.fill("#suffix", "")

                # Singular/plural worker count in the estimate.
                page.fill("#prefix", "ab")
                est = page.text_content("#estimate") or ""
                assert re.search(r"\d+ workers?,", est), f"malformed worker label: {est!r}"

                # Reload: history must survive via localStorage. loadHistory() is
                # now async (it derives the obfuscation key with SHA-256), so
                # this also proves that path resolves in a real browser.
                page.reload(wait_until="load")
                page.wait_for_selector(".result-frame", timeout=30_000)
                heading = page.text_content(".result-frame h2")
                assert heading and "Key 1 Found!" in heading, "history lost across reload"

                # The derived obfuscation key must never be persisted next to
                # the ciphertext: that would hand an attacker who lifts
                # localStorage everything needed to decode it.
                obf_key = page.evaluate(
                    "() => localStorage.getItem('meshcoreVanityObfKey')"
                )
                assert obf_key is None, (
                    f"obfuscation key must not be stored in localStorage: {obf_key!r}"
                )

                # The install secret lives in IndexedDB, never localStorage.
                secret = page.evaluate(
                    "async () => await getOrCreateObfuscationSecret()"
                )
                assert secret and len(secret) == 64, (
                    f"expected a 32-byte secret in IndexedDB: {secret!r}"
                )
                dumped = page.evaluate(
                    "() => JSON.stringify(Object.entries(localStorage))"
                )
                assert secret not in dumped, (
                    "the obfuscation secret leaked into localStorage"
                )

                # Past the expected mean the ETA must not vanish or go
                # negative: the overshoot has to be stated.
                over = page.evaluate("() => formatProgressLine(1500, 10, 1000)")
                assert "Progress: +150.00%" in over, f"no overshoot marker: {over!r}"
                assert "past expected" in over, f"overshoot not explained: {over!r}"
                assert "ETA: -" not in over, f"negative ETA rendered: {over!r}"

                # Long waits carry an approximate day hint, in half-day steps.
                assert page.evaluate("() => formatEta(86400)") == "24h 0m 0s (~1 day)", (
                    "one-day ETA hint"
                )
                assert page.evaluate("() => formatEta(86400 * 2.5)") == (
                    "60h 0m 0s (~2.5 days)"
                ), "half-day ETA hint"
                assert page.evaluate("() => formatEta(3600)") == "1h 0m 0s", (
                    "sub-day ETA must carry no hint"
                )

                # The live panel is a titled 2x2 grid, and the redundant
                # "Live estimate: ... at .../s" line must be gone.
                assert page.text_content(".live-logs-title").strip() == "Live Logs:", (
                    "live panel title"
                )
                for cell_id in ("live-attempts", "live-rate", "live-progress", "live-eta"):
                    assert page.query_selector(f"#{cell_id}"), f"missing #{cell_id}"
                assert page.query_selector("#live-estimate") is None, (
                    "redundant live-estimate line still present"
                )
                cols = page.evaluate(
                    "() => getComputedStyle(document.querySelector('.live-logs-grid'))"
                    ".gridTemplateColumns.split(' ').length"
                )
                assert cols == 2, f"live logs must be 2 columns, got {cols}"
                colour = page.evaluate(
                    "() => getComputedStyle(document.querySelector('#live-rate')).color"
                )
                assert colour == "rgb(126, 231, 135)", f"live values should be green: {colour}"

                # An undecodable stored history must not be silently overwritten by the
                # next mined key: that blob may be the only copy of the user's
                # existing keys.
                page.evaluate(
                    "() => localStorage.setItem('meshcoreVanityKeys', '7b3d6a7f8271615b')"
                )
                page.reload(wait_until="load")
                page.wait_for_timeout(500)
                warn = page.text_content("#history-warn") or ""
                assert "could not be decoded" in warn, (
                    f"decode failure must be explained: {warn!r}"
                )
                assert page.evaluate(
                    "() => localStorage.getItem('meshcoreVanityKeys')"
                ) == "7b3d6a7f8271615b", "unreadable history must not be deleted"

                # Persist the new key while the unreadable blob is present: the write must
                # be refused so the only copy of the old keys survives.
                page.evaluate(
                    "() => addKeyToHistory({publicKey: 'a'.repeat(64),"
                    " privateKey: 'b'.repeat(64), attempts: 1, elapsed: 1})"
                )
                page.wait_for_timeout(300)
                assert page.evaluate(
                    "() => localStorage.getItem('meshcoreVanityKeys')"
                ) == "7b3d6a7f8271615b", (
                    "a new key must not clobber unreadable stored history"
                )

                # Clear All Keys is the documented escape hatch and must work
                # even though the decoded in-memory list is empty.
                # The shared handler already accepts dialogs, so the confirm() in
                # clearHistory() resolves true without a second handler.
                page.click(".clear-all-btn")
                page.wait_for_timeout(300)
                after_clear = page.evaluate(
                    "() => localStorage.getItem('meshcoreVanityKeys')"
                )
                assert after_clear != "7b3d6a7f8271615b", (
                    f"Clear All Keys must discard unreadable history: {after_clear!r}"
                )

                # With a decodable history present again, the stored value must
                # be ciphertext rather than readable JSON.
                stored = page.evaluate(
                    f"() => localStorage.getItem('{HISTORY_KEY}')"
                )
                assert stored and not stored.lstrip().startswith("["), (
                    f"history must be obfuscated at rest: {stored[:80]!r}"
                )
                assert "publicKey" not in stored, "history plaintext leaked to storage"

                worker_errors = [e for e in errors if "Worker" in e]
                assert not worker_errors, f"worker errors: {worker_errors!r}"
                # The one dialog this test deliberately provokes is the Clear All Keys
                # confirmation. Anything else means a worker or library error.
                unexpected = [d for d in dialogs if "Delete" not in d]
                assert not unexpected, f"unexpected dialogs: {unexpected!r}"
            finally:
                browser.close()
    finally:
        server.shutdown()
    print("smoke OK: mined, rendered, and persisted Key 1 across reload")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
