#!/usr/bin/env python3
"""One command to install the CLI's dependencies and run it.

Why this exists: the tool was a PyNaCl dependency plus a long argument list,
and the two most common first-run outcomes were "ModuleNotFoundError: nacl" and
"which flags does it take?". This does both.

    python meshcore_vanity.py            # no, still the long form

Usage
-----
    ./run.sh <pattern> [extra args...]        (Linux/macOS)
    run.bat <pattern> [extra args...]        (Windows)

Examples:
    ./run.sh abcd                            # fastest; hex prefix
    ./run.sh abc --suffix 7f                  # prefix AND suffix
    ./run.sh mc1q --encoding bech32           # a MeshCore address
    ./run.sh abcd --encoding base58 --workers 8

Arguments after the pattern are passed straight through to meshcore_vanity.py,
so anything documented there works here:

    ./run.sh abcd --help

PyNaCl is installed automatically on first run into a local virtual
environment (.venv), which keeps the install out of the system Python and
means `rm -rf .venv` is a complete uninstall. Set MESH_VANITY_NO_VENV=1 to
install into the ambient interpreter instead.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
CLI = ROOT / "meshcore_vanity.py"
REQ = ROOT / "requirements.txt"


def die(msg: str) -> NoReturn:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(2)


def venv_python() -> Path:
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def have_nacl(python: str | Path) -> bool:
    """True when PyNaCl is importable, so the install can be skipped."""
    try:
        subprocess.run(
            [str(python), "-c", "import nacl"],
            check=True,
            capture_output=True,
        )
        return True
    except (subprocess.CalledProcessError, OSError):
        return False


def ensure_deps() -> str:
    """Return a Python that can import nacl, creating .venv if needed."""
    if os.environ.get("MESH_VANITY_NO_VENV") == "1":
        if have_nacl(sys.executable):
            return sys.executable
        print("installing PyNaCl into the current interpreter...", file=sys.stderr)
        subprocess.run([sys.executable, "-m", "pip", "install", "PyNaCl>=1.5.0"], check=True)
        return sys.executable

    if not VENV.exists():
        print(f"creating virtual environment in {VENV}", file=sys.stderr)
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)

    py = venv_python()
    if have_nacl(py):
        return str(py)

    print("installing PyNaCl (first run only)...", file=sys.stderr)
    subprocess.run([str(py), "-m", "pip", "install", "--upgrade", "pip"], check=True)
    subprocess.run([str(py), "-m", "pip", "install", "-r", str(REQ)], check=True)
    return str(py)


def main(argv: list[str]) -> int:
    if not CLI.exists():
        die(f"{CLI} is missing - run this from inside the project directory")

    args = argv[1:]
    if args and args[0] in {"-h", "--help", "help"}:
        print(__doc__.strip())
        print("\nThe miner itself documents every option:")
        print(f"    python {CLI.name} --help\n")
        return 0

    if not args:
        print(__doc__.strip())
        die("no pattern given")

    python = ensure_deps()

    # subprocess, not execv: os.execv passes argv as raw bytes and on Windows
    # a path containing spaces ("C:\Users\...\Default Project") gets split.
    # subprocess takes a list on both platforms, and no shell, so the pattern
    # is never word-split or globbed.
    try:
        return subprocess.call([python, str(CLI), *args])
    except KeyboardInterrupt:
        return 130
    except OSError as e:
        die(f"could not start {python}: {e}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
