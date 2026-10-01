#!/usr/bin/env python3
"""CI self-test for index.html inline JavaScript.

Extracts the Web Worker source and the main inline <script> block and writes
them to files for `node --check` syntax validation. Also fails on known-bad
leftovers from past incidents (e.g. references to undefined variables that
crashed the progress handler at runtime, which syntax checks cannot catch).

Usage:
    python tools/check_inline_js.py --out-dir <dir>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Patterns that must NOT appear in the shipped page (past runtime crashes).
BANNED_PATTERNS = (
    "liveEtaStr",  # undefined variable crashed first progress update
    "matchBoth",  # stale checkbox variable after independent prefix/suffix
)


def extract(repo_root: Path) -> dict[str, str]:
    try:
        html = (repo_root / "index.html").read_text(encoding="utf-8")
    except OSError as e:
        raise SystemExit(f"FAIL: cannot read index.html: {e}")

    marker = "const workerCode = `"
    try:
        start = html.index(marker) + len(marker)
        end = html.index("`;", start)
        worker_js = html[start:end]

        # Make worker.js standalone-parseable by replacing template interpolation
        # with a valid URL literal.
        import re
        worker_js = re.sub(
            r"\$\{new URL\([^)]+\)\.href\}",
            "https://example.test/libsodium.js",
            worker_js,
        )

        # Main inline script: the <script> block without a src attribute.
        script_start = html.index("<script>", html.index("</style>")) + len("<script>")
        script_end = html.index("</script>", script_start)
        main_js = html[script_start:script_end]
    except ValueError as e:
        raise SystemExit(f"FAIL: extraction marker missing or malformed: {e}")

    for pat in BANNED_PATTERNS:
        if pat in html:
            raise SystemExit(f"FAIL: banned pattern {pat!r} found in index.html")

    if "await new Promise" not in worker_js:
        raise SystemExit("FAIL: worker lost its event-loop yield (progress stalls)")

    # A stray backtick inside the worker template literal silently terminates the
    # string and corrupts the extracted source. Catch it at the source.
    if "`" in worker_js:
        raise SystemExit(
            "FAIL: backtick inside the workerCode template literal "
            "(it terminates the string); use quotes in worker comments"
        )

    return {"worker.js": worker_js, "main.js": main_js}


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract inline JS for node --check")
    parser.add_argument("--out-dir", required=True, help="Directory for extracted files")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    extracted = extract(repo_root)
    for name, src in extracted.items():
        (out_dir / name).write_text(src, encoding="utf-8")
        print(f"wrote {out_dir / name} ({len(src)} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
