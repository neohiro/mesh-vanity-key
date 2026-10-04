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

                # 'Starting...' was written once and never cleared, so it sat
                # above the figures for the whole run. Assert the invariant
                # rather than a specific moment: whatever the search's timing,
                # once it has finished there must be no stale status text left
                # in the DOM. Waiting for the clear DURING the run would be
                # wrong - a 1-char pattern can match inside the first batch and
                # finish before any progress report fires. The result frame
                # appearing is the signal that the search has finished.
                page.click("#start-btn")
                page.wait_for_selector(".result-frame", timeout=120_000)
                assert page.evaluate(
                    "() => { const el = document.getElementById('progress-text');"
                    " return el && (el.textContent || '').trim() === ''; }"
                ), (
                    "the startup status must not linger in the DOM after a search"
                )

                # The rate graph is a backdrop on the ETA row. The panel is
                # display:none once the search ends, and a hidden box measures
                # 0x0, so reveal it, measure, then put the page back - the same
                # approach the ETA-slot metrics below use.
                graph = page.evaluate(
                    "() => {"
                    "  const panel = document.getElementById('progress');"
                    "  const wasHidden = panel.classList.contains('hidden');"
                    "  if (wasHidden) panel.classList.remove('hidden');"
                    "  const c = document.getElementById('rate-graph');"
                    "  const r = c.getBoundingClientRect();"
                    "  const out = {"
                    "    w: r.width, h: r.height,"
                    "    cw: c.width, ch: c.height,"
                    "    position: getComputedStyle(c).position,"
                    "    pointerEvents: getComputedStyle(c).pointerEvents,"
                    "  };"
                    "  if (wasHidden) panel.classList.add('hidden');"
                    "  return out;"
                    "}"
                )
                assert graph["w"] > 0 and graph["h"] > 0, (
                    f"the rate graph must be laid out with a real box, got "
                    f"{graph['w']}x{graph['h']}"
                )
                assert graph["cw"] > 0 and graph["ch"] > 0, (
                    f"the canvas backing store must be sized, got "
                    f"{graph['cw']}x{graph['ch']}"
                )
                # Absolutely positioned, or it would sit in flow and make the
                # live panel taller instead of being a backdrop.
                assert graph["position"] == "absolute", (
                    f"the rate graph must be taken out of flow, got {graph['position']}"
                )
                # Decorative: it must never intercept a click aimed at the
                # figures sitting on top of it.
                assert graph["pointerEvents"] == "none", (
                    f"the rate graph must not intercept clicks, got {graph['pointerEvents']}"
                )

                # Layout alone does not prove the graph works. A canvas that is
                # present, sized and positioned can still be blank - which is
                # exactly the failure a "does the element exist" check cannot
                # see, and exactly the one nobody has looked for.
                #
                # Rather than assert on a screenshot (a baseline that breaks on
                # any unrelated pixel, and that nobody here can regenerate),
                # read the pixels back and assert ink is present. The trace is
                # drawn only once there are at least two samples, and a 1-char
                # search can finish inside the first batch, so samples are fed
                # explicitly - that also makes the assertion independent of how
                # fast the host is.
                #
                # NOTE: no `//` comments in this snippet. Python concatenates
                # adjacent string literals with no newline between them, so a
                # line comment would swallow everything after it - including the
                # closing braces - and the whole arrow function would arrive as
                # one unterminated comment. Block comments are used instead.
                painted = page.evaluate(
                    "() => {"
                    "  const panel = document.getElementById('progress');"
                    "  const wasHidden = panel.classList.contains('hidden');"
                    "  if (wasHidden) panel.classList.remove('hidden');"
                    # pushRateGraphSample is a top-level declaration in a
                    # classic (non-module) script, so it is a window global.
                    # Checked explicitly so a failure says why, rather than
                    # surfacing as a bare ReferenceError.
                    "  if (typeof pushRateGraphSample !== 'function') {"
                    "    if (wasHidden) panel.classList.add('hidden');"
                    "    return { error: 'pushRateGraphSample is not a global' };"
                    "  }"
                    # The JS block comment below has to live inside a Python string
                    # literal, or Python tries to parse `/*` as an expression.
                    "  /* Date.now is frozen so every sample carries the SAME"
                    "     timestamp. That is deliberate and it is the regression:"
                    "     with no time spread the x-axis has nothing to scale by,"
                    "     and an earlier version pinned every point to the right"
                    "     edge, collapsing the trace into a vertical line."
                    "     Freezing the clock makes that degenerate path"
                    "     deterministic, so the check cannot depend on how fast the"
                    "     host happens to be. */"
                    "  const realNow = Date.now;"
                    "  const frozen = realNow.call(Date);"
                    "  Date.now = () => frozen;"
                    "  try {"
                    "    for (let i = 0; i < 12; i++) {"
                    "      pushRateGraphSample(1000 + (i % 4) * 300);"
                    "    }"
                    "  } finally {"
                    "    Date.now = realNow;"
                    "  }"
                    "  const c = document.getElementById('rate-graph');"
                    "  const ctx = c.getContext('2d');"
                    "  const d = ctx.getImageData(0, 0, c.width, c.height).data;"
                    "  const W = c.width;"
                    "  let inked = 0, total = 0;"
                    # Also has to be inside a Python string literal.
                    "  /* The stroke is drawn at 0.85 alpha and the fill at 0.16,"
                    "     so a high-alpha threshold isolates the trace line itself."
                    "     That distinction is what makes the span check meaningful:"
                    "     a regression that collapsed the trace into a vertical line"
                    "     at the right edge still filled a large wedge of the canvas,"
                    "     so total coverage alone would have passed while showing"
                    "     nothing useful. */"
                    "  const strokeCols = new Set();"
                    "  for (let i = 0; i < d.length; i += 4) {"
                    "    total++;"
                    "    if (d[i + 3] > 0) inked++;"
                    "    if (d[i + 3] > 150) strokeCols.add(Math.floor((i / 4) / W));"
                    "  }"
                    "  if (wasHidden) panel.classList.add('hidden');"
                    "  return {"
                    "    inked, total, ratio: total ? inked / total : 0,"
                    "    strokeCols: strokeCols.size,"
                    "  };"
                    "}"
                )
                assert not painted.get("error"), (
                    f"could not exercise the rate graph: {painted['error']}"
                )
                assert painted["total"] > 0, (
                    "the rate graph canvas has no pixels to read; backing store "
                    f"is unsized ({painted['total']})"
                )
                assert painted["inked"] > 0, (
                    "the rate graph canvas is blank after drawing a varying "
                    "series - present and sized, but nothing was painted"
                )
                # A trace plus a soft fill should cover a real but minority
                # share of the box. A near-full fill means the scale or the
                # background is wrong; near-zero means the line is too faint.
                assert 0.01 < painted["ratio"] < 0.95, (
                    "the rate graph coverage is implausible: "
                    f"{painted['inked']}/{painted['total']} = {painted['ratio']:.3f}"
                )
                # The decisive check. Coverage alone is not enough: a trace
                # collapsed into a single vertical line still fills a wide wedge
                # and would sail past the ratio test while conveying nothing.
                # The stroke line must be spread across the width, which is what
                # makes this a graph rather than a smear at the right edge.
                assert painted["strokeCols"] >= 20, (
                    "the rate trace must span the canvas horizontally, but its "
                    f"stroke covers only {painted['strokeCols']} column(s) - the "
                    "graph has collapsed to a vertical line"
                )

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

                # Two distinct brights: the labels one green, the live values a
                # hotter one so the figures read as the important half.
                value_colour = page.evaluate(
                    "() => getComputedStyle(document.querySelector('#live-rate')).color"
                )
                assert value_colour == "rgb(126, 247, 160)", (
                    f"live values should be the brighter green: {value_colour}"
                )
                label_colour = page.evaluate(
                    "() => getComputedStyle(document.querySelector('.live-k')).color"
                )
                assert label_colour == "rgb(86, 211, 100)", (
                    f"live labels should be their own green: {label_colour}"
                )
                assert label_colour != value_colour, (
                    "labels and values must be visually distinguishable"
                )

                # The title scales with the viewport and is right-aligned with
                # the figures beneath it.
                assert page.evaluate(
                    "() => getComputedStyle(document.querySelector('.live-logs-title'))"
                    ".textAlign"
                ) == "right", "live title must be right-aligned with the metrics"

                # The ETA is split into digit slots, each reserving its width so
                # the figures cannot hop as a field gains or loses a digit.
                # Asserted against a real layout engine, which is the only place
                # the reserved widths actually mean anything.
                for slot in ("live-eta-days", "live-eta-h", "live-eta-m", "live-eta-s"):
                    assert page.query_selector(f"#{slot}"), f"missing ETA slot #{slot}"
                assert page.evaluate(
                    "() => getComputedStyle(document.querySelector('.eta-fields'))"
                    ".fontVariantNumeric"
                ).replace(" ", "") == "tabular-nums", (
                    "ETA must use tabular figures or digit widths vary"
                )

                # Compare reserved widths against the width a single glyph
                # actually takes. That is what makes the reservation meaningful:
                # the hour slot must fit many more digits than the 2ch slots, so
                # it stays put while the minutes and seconds tick over.
                metrics = page.evaluate(
                    "() => {"
                    "  const panel = document.getElementById('progress');"
                    "  const wasHidden = panel.classList.contains('hidden');"
                    # Reserved widths only mean anything once the panel is laid
                    # out, and #progress is display:none until mining starts, so
                    # every box would measure 0. Reveal it, measure, then put
                    # the page back exactly as it was.
                    "  if (wasHidden) panel.classList.remove('hidden');"
                    "  const widths = ['live-eta-h', 'live-eta-m', 'live-eta-s', 'live-eta-days']"
                    "    .map((id) => document.getElementById(id)"
                    "      .getBoundingClientRect().width);"
                    # Probe inside .eta-fields so it inherits the ETA's own
                    # monospace font; measured against document.body it would
                    # compare the reserved widths to a digit of another face.
                    "  const host = document.querySelector('.eta-fields');"
                    "  const probe = document.createElement('span');"
                    "  probe.style.cssText = 'position:absolute;visibility:hidden;"
                    "    white-space:pre;font:inherit';"
                    "  probe.textContent = '0';"
                    "  host.appendChild(probe);"
                    "  const glyph = probe.getBoundingClientRect().width;"
                    "  probe.remove();"
                    "  if (wasHidden) panel.classList.add('hidden');"
                    "  return { widths, glyph };"
                    "}"
                )
                reserved, glyph = metrics["widths"], metrics["glyph"]
                assert glyph > 0, (
                    f"could not measure a digit width: {metrics!r}"
                )
                assert all(w > 0 for w in reserved), (
                    f"ETA slots must be laid out, got {reserved!r}"
                )
                assert reserved[1] >= glyph * 1.5 and reserved[2] >= glyph * 1.5, (
                    f"2ch slots must fit two digits: minute/second reserved "
                    f"{reserved[1]}/{reserved[2]} for a {glyph}px glyph"
                )
                # Hours no longer need extra headroom: the days slot carries
                # the magnitude, so hours is the hours WITHIN the day and is
                # never more than two digits. What must hold is that the hour
                # slot is wide enough for those two digits, the same as minutes
                # and seconds, and that the days slot has room for a multi-digit
                # day count -- that is now the field that grows.
                assert reserved[0] >= glyph * 1.5, (
                    f"hour slot must fit two digits (0-23), got {reserved[0]} "
                    f"for a {glyph}px glyph"
                )
                # And the day slot must not be the field that clips. Measured in
                # the same evaluate that reveals the panel: #progress is
                # display:none until mining starts, so measuring it afterwards
                # would read 0 for every slot.
                day_reserved = reserved[3]
                assert day_reserved >= glyph * 2, (
                    f"the day slot must fit a multi-digit day count, got {day_reserved} "
                    f"for a {glyph}px glyph"
                )
                assert page.evaluate(
                    "() => getComputedStyle(document.querySelector('.live-cell-eta'))"
                    ".gridColumnStart"
                ).startswith("1"), "the ETA must span the full panel width"

                # The day estimate must actually precede the hours in the DOM,
                # or the multi-week reading appears after the digit it qualifies.
                eta_order = page.evaluate(
                    # Descendants, not children: the digit slots sit inside
                    # .eta-unit wrappers, so '#live-eta > span' would miss them.
                    "() => [...document.querySelectorAll('#live-eta span')]"
                    ".map((el) => el.id).filter(Boolean)"
                )
                for wanted in ("live-eta-days", "live-eta-h", "live-eta-m", "live-eta-s"):
                    assert wanted in eta_order, (
                        f"{wanted} missing from the ETA slot order: {eta_order}"
                    )
                assert eta_order.index("live-eta-days") < eta_order.index("live-eta-h"), (
                    f"the day estimate must precede the hours: {eta_order}"
                )

                # The counter badge is a third-party image, so its presence and
                # URL are asserted but the fetch is NOT: CI runners can be
                # offline or blocked, and a flaky assertion about someone
                # else's uptime would take the whole build down for it.
                badge = page.query_selector(".visitor-counter img")
                assert badge, "visitor counter badge is missing"
                assert "visitorbadge.io/api/visitors" in (badge.get_attribute("src") or ""), (
                    "the badge must use the visitorbadge.io endpoint"
                )
                assert page.evaluate(
                    "() => getComputedStyle(document.querySelector('.visitor-counter'))"
                    ".textAlign"
                ) == "center", "the counter badge must be centred"
                # The badge was declared 120x20 for a ~123.5x28 SVG, stretching
                # it wide and squashing it short. Assert the RENDERED box keeps
                # the SVG's own proportions, not merely the declared attributes.
                badge_ratio = page.evaluate(
                    "() => { const r = document.querySelector('.visitor-counter img')"
                    ".getBoundingClientRect(); return r.height ? r.width / r.height : 0; }"
                )
                assert 4.0 < badge_ratio < 5.0, (
                    f"the badge should keep its ~4.4:1 aspect ratio, rendered {badge_ratio:.2f}:1"
                )

                # The whitespace above the badge must EQUAL the whitespace below
                # it, measured rather than assumed. It was 28px above against the
                # frame's bottom padding below - 40px, dropping to 16px under the
                # 480px breakpoint - so the footer leaned to one side and the
                # mismatch moved with the viewport. Both edges now come from one
                # custom property; this asserts the rendered result, at BOTH
                # widths, because a CSS-only equality can still be broken by the
                # badge's own box, by margin collapsing, or by the breakpoint.
                for label, width, height in (
                    ("desktop", 1280, 900),
                    ("phone", 390, 844),
                ):
                    page.set_viewport_size({"width": width, "height": height})
                    page.wait_for_timeout(150)
                    gap = page.evaluate(
                        "() => {"
                        " const counter = document.querySelector('.visitor-counter');"
                        " const badge = counter.querySelector('img');"
                        " const frame = document.querySelector('.container');"
                        " const cs = getComputedStyle(frame);"
                        " const cr = counter.getBoundingClientRect();"
                        " const br = badge.getBoundingClientRect();"
                        " /* The gap above is measured from whatever sits directly"
                        "    above the badge, NOT from the frame's top edge - that"
                        "    would include the entire height of the tool. */"
                        " const prev = counter.previousElementSibling;"
                        " const above = prev"
                        "   ? cr.top - prev.getBoundingClientRect().bottom"
                        "   : br.top - (frame.getBoundingClientRect().top"
                        "       + parseFloat(cs.borderTopWidth));"
                        " /* Below it is the frame's own bottom padding. */"
                        " const fRect = frame.getBoundingClientRect();"
                        " const below = (fRect.bottom - parseFloat(cs.borderBottomWidth))"
                        "   - br.bottom;"
                        " return { above: above, below: below };"
                        "}"
                    )
                    assert abs(gap["above"] - gap["below"]) <= 1.0, (
                        f"{label}: whitespace around the visitor badge is uneven -"
                        f" {gap['above']:.1f}px above vs {gap['below']:.1f}px below"
                    )
                page.set_viewport_size({"width": 1280, "height": 900})
                page.wait_for_timeout(150)

                # The back link and the repository link share one row, with the
                # repository link pushed to the right edge.
                assert page.eval_on_selector_all(
                    ".info-row a", "els => els.length"
                ) == 2, "the info row must carry exactly the two links"
                row_layout = page.evaluate(
                    "() => { const a = document.querySelectorAll('.info-row a');"
                    " const f = document.querySelector('.info-row');"
                    " const fr = f.getBoundingClientRect();"
                    " const l = a[0].getBoundingClientRect();"
                    " const r = a[1].getBoundingClientRect();"
                    " return { sameRow: Math.abs(l.top - r.top) < 2,"
                    "          rightAligned: Math.abs((fr.right - r.right)) < 2,"
                    "          href: a[1].getAttribute('href') };"
                    "}"
                )
                assert row_layout["sameRow"], (
                    "the repository link must sit on the same row as the back link"
                )
                assert row_layout["rightAligned"], (
                    "the repository link must be aligned to the right edge"
                )
                assert row_layout["href"] == (
                    "https://github.com/neohiro/meshcore-vanity-key"
                ), row_layout["href"]

                # A single transient status line, above the panel. Two of these
                # is what left 'Starting...' stranded under the figures.
                assert page.eval_on_selector_all(
                    "#progress-text", "els => els.length"
                ) == 1, "there must be exactly one status line"
                assert page.evaluate(
                    "() => document.querySelector('#progress-text')"
                    ".compareDocumentPosition(document.querySelector('#live-logs'))"
                    " & Node.DOCUMENT_POSITION_FOLLOWING"
                ), "the status line must sit above the live panel"

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
                # This test deliberately provokes two dialogs, and nothing else:
                #   * the impossible-pattern alert (start must be refused);
                #   * the Clear All Keys confirmation.
                # Anything else means a worker or library error, which is what
                # this assertion is for.
                deliberate = ("Delete", "can never match")
                unexpected = [d for d in dialogs if not any(k in d for k in deliberate)]
                assert not unexpected, f"unexpected dialogs: {unexpected!r}"
                assert any("can never match" in d for d in dialogs), (
                    "the impossible-pattern alert should have fired"
                )
            finally:
                browser.close()
    finally:
        server.shutdown()
    print("smoke OK: mined, rendered, and persisted Key 1 across reload")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
