#!/usr/bin/env python3
"""Validate the JavaScript embedded in smoke_browser.py's page.evaluate calls.

`tools/check_eval_snippets.mjs` parses the snippets in index.html itself. This
covers the other half: the snippets the smoke test builds, which are Python
adjacent string literals concatenated at runtime.

That construction has a failure mode that is invisible until a browser runs it.
Python joins adjacent literals with NO newline between them, so a `//` line
comment inside one swallows everything after it - including the closing braces -
and the arrow function arrives as a single unterminated comment. The symptom is
Playwright's `SyntaxError: Unexpected end of input`, which is what happened to
the rate-graph pixel check.

So this walks every `page.evaluate("...")` and asserts the result is balanced
JS, and explicitly rejects `//` line comments. Use `/* */` block comments in
those snippets instead.

Usage:
    python tools/check_smoke_snippets.py [path-to-smoke_browser.py]
"""
import ast
import sys
from pathlib import Path

path = Path(sys.argv[1] if len(sys.argv) > 1 else "tools/smoke_browser.py")
src = path.read_text(encoding="utf-8")
tree = ast.parse(src)

fails = 0
total = 0
for node in ast.walk(tree):
    if not isinstance(node, ast.Call):
        continue
    fn = node.func
    if not (isinstance(fn, ast.Attribute) and fn.attr == "evaluate"):
        continue
    if not node.args:
        continue
    first = node.args[0]
    # Only the "() => {...}" form is JS; a bare expression is also fine.
    if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
        continue
    code = first.value
    if "=>" not in code:
        continue
    total += 1
    line = first.lineno
    # Balance check, ignoring braces inside strings and comments.
    # NOTE: the value is a SINGLE concatenated Python string, so it contains no
    # newlines between the original literals. A `//` line comment therefore
    # swallows everything after it - which is exactly how a real browser
    # mis-parses it, and the reason this check exists. That is why the snippets
    # use /* */ comments instead.
    depth = {"{": 0, "(": 0, "[": 0}
    pairs = {"}": "{", ")": "(", "]": "["}
    i = 0
    in_str = None
    err = None
    while i < len(code):
        ch = code[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in "'\"":
            in_str = ch
        elif ch == "/" and i + 1 < len(code) and code[i + 1] == "/":
            # A line comment with no terminating newline runs to the end of the
            # concatenated string: flag it, because it silently eats the rest.
            err = "line comment in a concatenated snippet (no newline follows)"
            break
        elif ch == "/" and i + 1 < len(code) and code[i + 1] == "*":
            end = code.find("*/", i + 2)
            if end == -1:
                err = "unterminated block comment"
                break
            i = end + 2
            continue
        elif ch in depth:
            depth[ch] += 1
        elif ch in pairs:
            depth[pairs[ch]] -= 1
            if depth[pairs[ch]] < 0:
                err = f"unbalanced '{ch}'"
                break
        i += 1
    if in_str and not err:
        err = f"unterminated string {in_str!r}"
    if err is None:
        for k, v in depth.items():
            if v != 0:
                err = f"{v} unclosed '{k}'"
                break
    if err:
        fails += 1
        print(f"FAIL line {line}: {err}")
        print("      " + code[:160].replace("\n", "\\n"))

print(f"\n{total} evaluate snippet(s) checked, {fails} malformed")
sys.exit(1 if fails else 0)
