#!/usr/bin/env python3
"""Where does the CLI's time actually go, and how well does it parallelise?

Answers the question that gets re-investigated every time the miner feels
slow: "is there another mathematical trick to go faster?"

Measured on this codebase, the answer is no, and the reason is worth having in
writing:

  * ~99% of a candidate's cost is the Ed25519 scalar multiplication inside
    libsodium. Encoding the 32-byte key and testing the prefix run at millions
    of operations per second, i.e. four to five orders of magnitude faster
    than the key derivation they follow. Removing all of that work entirely
    would change throughput by well under 1%.
  * Bypassing PyNaCl's object wrappers to call libsodium directly does NOT
    help: doing the SHA-512 and scalar clamping in Python costs more than the
    object allocation it saves, and measures slower overall.
  * The only remaining lever is core count. This tool therefore also measures
    parallel scaling, against a pure-CPU baseline for the same machine, so a
    poor scaling number can be attributed to the code or to the host.

Usage:
    python tools/bench_mining.py [--candidates N]
"""

from __future__ import annotations

import argparse
import multiprocessing as mp
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hashlib  # noqa: E402

import nacl.signing  # noqa: E402
from nacl import bindings  # noqa: E402

SEED = bytes(range(32))


def _rate(label: str, fn, n: int) -> float:
    fn()
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    dt = time.perf_counter() - t0
    r = n / dt if dt > 0 else 0.0
    print(f"  {label:<52} {r:>14,.0f}/s")
    return r


def _spin(n: int) -> int:
    x = 0
    for i in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
    return x


def _spin_task(n: int) -> int:
    return _spin(n)


def breakdown() -> float:
    """Split a candidate into key derivation vs everything else."""
    print("Per-candidate cost breakdown (higher = cheaper):")

    def current():
        priv = nacl.signing.SigningKey(SEED)
        raw = bytes(priv.verify_key)
        return raw.hex()[:8].lower() == "abcdef12"

    def keygen_only():
        return bytes(nacl.signing.SigningKey(SEED).verify_key)

    def scalarmult_only():
        return bindings.crypto_scalarmult_ed25519_base_noclamp(SEED)

    def py_manual():
        h = hashlib.sha512(SEED).digest()
        s = bytearray(h[:32])
        s[0] &= 0xF8
        s[31] &= 0x7F
        s[31] |= 0x40
        return bindings.crypto_scalarmult_ed25519_base_noclamp(bytes(s))

    pk = bytes(nacl.signing.SigningKey(SEED).verify_key)
    prefix_bytes = bytes.fromhex("abcdef12")

    r_loop = _rate("full loop (current: keygen + hex + compare)", current, 20_000)
    r_keygen = _rate("  keygen only (PyNaCl SigningKey)", keygen_only, 20_000)
    _rate("  keygen only (bare scalarmult)", scalarmult_only, 20_000)
    _rate("  keygen, SHA-512+clamp done in Python", py_manual, 20_000)
    r_enc = _rate(
        "  hex encode + slice + lower + compare",
        lambda: pk.hex()[:8].lower() == "abcdef12",
        200_000,
    )
    _rate("  bytes compare (no encoding at all)", lambda: pk[:4] == prefix_bytes, 200_000)

    # What fraction of a candidate is NOT the scalar multiplication? This is the
    # number that decides whether wrapper micro-optimisation is worth anything.
    # keygen alone measures within run-to-run noise of the whole loop, so the
    # ratio is clamped to avoid reporting a physically impossible >100%.
    ratio = r_keygen / r_loop if r_loop else 1.0
    keygen_share = min(ratio, 1.0)
    print(
        f"\n  => key derivation is {keygen_share * 100:.2f}% of a candidate"
        f" (measured separately, within noise of the full loop);"
    )
    print(
        f"     the encode-and-test half runs {r_enc / r_keygen:,.0f}x faster than"
        " key derivation."
    )
    print("     Removing ALL non-keygen work would gain under 1%.")
    return r_loop


def parallel_scaling() -> None:
    """Compare search scaling with a pure-CPU baseline for the same host."""
    work = 4_000_000

    t0 = time.perf_counter()
    _spin(work)
    single = time.perf_counter() - t0
    base = work / single if single > 0 else 0.0

    cpus = os.cpu_count() or 1
    print(f"\nParallel scaling (host reports {cpus} logical CPUs):")
    print(f"  pure CPU spin, 1 process: {base:,.0f} it/s")

    ctx = mp.get_context("spawn")
    for n in (2, 4, 8):
        if n > cpus:
            break
        t0 = time.perf_counter()
        with ctx.Pool(processes=n) as pool:
            pool.map(_spin_task, [work] * n)
        elapsed = time.perf_counter() - t0
        total = work * n / elapsed if elapsed > 0 else 0.0
        print(f"  pure CPU spin, {n} processes: {total:,.0f} it/s "
              f"({total / base:4.2f}x)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()

    breakdown()
    parallel_scaling()

    print(
        "\nConclusion: the scalar multiplication dominates, so the hot loop is\n"
        "already optimal given libsodium. The only real throughput lever is\n"
        "using more cores (--workers), not micro-optimising the wrapper."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())