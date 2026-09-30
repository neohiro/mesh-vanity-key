#!/usr/bin/env python3
"""MeshCore-compatible Ed25519 vanity public-key generator.

Generates keys until the encoded public key starts with a target prefix.
Only the encoded public key is printed to stdout; the private key is
printed to stderr only with the explicit opt-in --output-private flag.

Optimizations:
- Scalar-walk: increment private scalar directly instead of hashing per attempt
- Early-exit: reject reserved prefixes (00, FF) for framework devices
- Parallel workers with optimized work distribution
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import sys
import time
import multiprocessing as mp
from dataclasses import dataclass
from typing import Literal

import nacl.signing
import hashlib

Encoding = Literal["base64", "base64url", "base58", "hex", "bech32"]

BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Reserved prefixes for MeshCore framework devices (not consumer)
RESERVED_PREFIXES = {"00", "ff", "FF"}

_PREFIX_VALID_CHARS = {
    "base64": set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),
    "base64url": set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"),
    "base58": set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
    "hex": set("0123456789abcdef"),
    "bech32": set(BECH32_CHARSET + "1"),  # include '1' separator
}


@dataclass(slots=True, frozen=True)
class VanityResult:
    private_key: nacl.signing.SigningKey
    public_key: nacl.signing.VerifyKey
    encoded: str
    attempts: int
    elapsed: float
    private_seed: bytes


def _worker_search(args: tuple) -> tuple:
    """Worker function for parallel search."""
    (prefix, encoding, case_insensitive, max_attempts, seed, prefix_len,
     prefix_cmp, check_slice, both, hrp, start_offset, worker_id,
     total_workers, progress_interval, is_hex, hrp_expanded) = args

    import base64
    import hashlib

    _b64encode = base64.b64encode
    _urlsafe_b64encode = base64.urlsafe_b64encode
    _hex_encode = bytes.hex

    attempts = 0
    counter = start_offset

    initial_scalar = int.from_bytes(hashlib.sha256(seed).digest(), "big")

    while True:
        if max_attempts is not None and attempts >= max_attempts:
            return (None, attempts, counter)

        try:
            scalar_val = (initial_scalar + counter) & ((1 << 256) - 1)
            priv_seed = scalar_val.to_bytes(32, "big")
        except OverflowError:
            return (None, attempts, counter)

        priv = nacl.signing.SigningKey(priv_seed)
        raw = bytes(priv.verify_key)

        if encoding == "hex":
            encoded = _hex_encode(raw)
            if encoded[:2].lower() in RESERVED_PREFIXES:
                attempts += 1
                counter += total_workers
                continue
        elif encoding == "base64":
            encoded = _b64encode(raw).decode()
        elif encoding == "base64url":
            encoded = _urlsafe_b64encode(raw).decode().rstrip("=")
        elif encoding == "base58":
            encoded = _base58_encode(raw)
        else:
            encoded = _bech32_encode(hrp, raw, hrp_expanded)

        if both:
            encoded_prefix = encoded[:prefix_len]
            encoded_suffix = encoded[-prefix_len:]
            if case_insensitive:
                pref_match = encoded_prefix.lower() == prefix_cmp
                suff_match = encoded_suffix.lower() == prefix_cmp
            else:
                pref_match = encoded_prefix == prefix_cmp
                suff_match = encoded_suffix == prefix_cmp
            match = pref_match and suff_match
        else:
            encoded_part = encoded[check_slice]
            if case_insensitive:
                chk = encoded_part.lower()
            else:
                chk = encoded_part
            match = chk == prefix_cmp

        if match:
            return (priv_seed, attempts, counter)

        attempts += 1
        counter += total_workers


# Pre-define _bech32_hrp_expand at module level for worker access
def _bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand HRP for bech32 checksum calculation."""
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 0x1F for c in hrp]


def _validate_prefix(prefix: str, encoding: Encoding, case_insensitive: bool = True) -> None:
    """Validate that prefix contains only valid characters for the encoding.

    When matching case-insensitively, an uppercase hex/bech32 prefix is
    accepted because it is lowered before comparison.
    """
    if not prefix:
        raise ValueError("prefix cannot be empty")
    check = prefix.lower() if case_insensitive else prefix
    valid = _PREFIX_VALID_CHARS[encoding]
    invalid = set(check) - valid
    if invalid:
        raise ValueError(
            f"prefix contains invalid characters for {encoding}: {sorted(invalid)!r}. "
            f"Valid: {sorted(valid)!r}"
        )
    # Reject reserved prefixes for MeshCore framework devices (00, FF)
    if encoding == "hex" and len(prefix) >= 2:
        prefix_lower = prefix[:2].lower()
        if prefix_lower in RESERVED_PREFIXES:
            raise ValueError(
                f"prefix {prefix!r} is reserved for MeshCore framework devices "
                f"(00 and FF prefixes are not available for consumer keys)"
            )


def _validate_seed(seed: bytes | None) -> bytes:
    """Validate and return seed (32 bytes)."""
    if seed is None:
        return os.urandom(32)
    if len(seed) != 32:
        raise ValueError(f"seed must be 32 bytes, got {len(seed)}")
    return seed


def _validate_hrp(hrp: str) -> None:
    """Validate bech32 human-readable part per BIP-0173."""
    if not (1 <= len(hrp) <= 83):
        raise ValueError("hrp length must be 1-83")
    if not all(33 <= ord(c) <= 126 for c in hrp):
        raise ValueError("hrp must contain only printable ASCII characters")


def _validate_bech32_prefix(prefix_cmp: str, hrp: str, case_insensitive: bool) -> None:
    """Validate that a bech32 prefix is compatible with the HRP."""
    anchor = hrp if not case_insensitive else hrp.lower()
    full_start = anchor + "1"
    a, b = prefix_cmp, full_start
    if not (b.startswith(a) or a.startswith(b)):
        raise ValueError(
            f"bech32 prefix {prefix_cmp!r} is impossible with hrp {hrp!r}: "
            f"encoded keys always start with {full_start!r}"
        )


def encode_public_key(pubkey: nacl.signing.VerifyKey, encoding: Encoding, hrp: str = "mc") -> str:
    """Encode a 32-byte Ed25519 public key in the specified format."""
    raw = bytes(pubkey)
    if encoding == "base64":
        return base64.b64encode(raw).decode()
    if encoding == "base64url":
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    if encoding == "hex":
        return raw.hex()
    if encoding == "base58":
        return _base58_encode(raw)
    if encoding == "bech32":
        _validate_hrp(hrp)
        return _bech32_encode(hrp, raw)
    raise ValueError(f"unknown encoding: {encoding}")


def _base58_encode(data: bytes) -> str:
    """Encode bytes to base58 (Bitcoin alphabet)."""
    if not data:
        return ""
    # Leading zero bytes become '1'
    pad = len(data) - len(data.lstrip(b"\x00"))
    if pad == len(data):
        return "1" * pad
    # int/divmod path runs in C and is much faster than a pure-Python loop.
    n = int.from_bytes(data, "big")
    digits: list[int] = []
    while n > 0:
        n, rem = divmod(n, 58)
        digits.append(rem)
    res = "".join(chr(BASE58_ALPHABET[d]) for d in reversed(digits))
    return "1" * pad + res


def _bech32_polymod(values: list[int]) -> int:
    """Bech32 checksum polynomial modulo."""
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32_convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    """Convert between bit groups per BIP-0173."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def _bech32_encode(hrp: str, data: bytes, hrp_expanded: list[int] | None = None) -> str:
    """Encode data as bech32 string with given HRP per BIP-0173."""
    five_bit = _bech32_convertbits(data, 8, 5, True)
    hrp_exp = hrp_expanded if hrp_expanded is not None else _bech32_hrp_expand(hrp)
    chk = _bech32_polymod(hrp_exp + five_bit + [0] * 6) ^ 1
    checksum = [(chk >> 5 * (5 - i)) & 0x1F for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[v] for v in five_bit + checksum)


def generate_vanity_key(
    prefix: str,
    encoding: Encoding = "base64",
    case_insensitive: bool = True,
    max_attempts: int | None = None,
    seed: bytes | None = None,
    progress_interval: int = 100_000,
    hrp: str = "mc",
    suffix: bool = False,
    both: bool = False,
    workers: int = 1,
) -> VanityResult:
    """Generate Ed25519 keypair until public key encoding matches prefix.

    Uses scalar-walk key derivation for performance and reproducibility.
    """
    _validate_prefix(prefix, encoding, case_insensitive)
    seed = _validate_seed(seed)
    if progress_interval <= 0:
        raise ValueError("progress_interval must be positive")
    if max_attempts is not None and max_attempts <= 0:
        raise ValueError("max_attempts must be positive or None")

    if workers <= 0:
        raise ValueError("workers must be positive")
    if workers > 256:
        raise ValueError("workers must be <= 256")

    prefix_cmp = prefix.lower() if case_insensitive else prefix
    prefix_len = len(prefix)
    # A 32-byte key has a fixed maximum encoded length per encoding; a longer
    # prefix can never match, so fail fast instead of searching forever.
    if encoding == "hex":
        max_len = 64
    elif encoding == "base64":
        max_len = 44
    elif encoding == "base64url":
        max_len = 43
    elif encoding == "base58":
        max_len = 44
    else:
        max_len = len(hrp) + 1 + 52 + 6
    if prefix_len > max_len:
        raise ValueError(
            f"prefix too long for {encoding}: {prefix_len} chars, "
            f"max is {max_len} for a 32-byte key"
        )
    # Support suffix matching: check the last prefix_len chars instead of the first.
    # Set suffix_mode=True via the suffix parameter to hunt for keys whose encoded
    # public key ends with the target string, e.g. suffix ABC to find keys ending in ...ABC.
    # Support both mode: check both prefix AND suffix using the same pattern.
    if both:
        if suffix:
            raise ValueError("cannot use --both with --suffix")
        check_slice = None
        _validate_hrp(hrp)
        if encoding == "bech32":
            _validate_bech32_prefix(prefix_cmp, hrp, case_insensitive)
    elif suffix:
        check_slice = slice(-prefix_len, None)
    else:
        check_slice = slice(0, prefix_len)
        _validate_hrp(hrp)
        if encoding == "bech32":
            _validate_bech32_prefix(prefix_cmp, hrp, case_insensitive)
    is_hex = encoding == "hex"
    # HRP expansion is loop-invariant; hoist it out of the hot path.
    hrp_expanded = _bech32_hrp_expand(hrp) if encoding == "bech32" else None

    # Multi-worker parallel search
    if workers > 1:
        return _generate_vanity_key_parallel(
            prefix=prefix,
            encoding=encoding,
            case_insensitive=case_insensitive,
            max_attempts=max_attempts,
            seed=seed,
            progress_interval=progress_interval,
            hrp=hrp,
            suffix=suffix,
            both=both,
            workers=workers,
            prefix_cmp=prefix_cmp,
            prefix_len=prefix_len,
            check_slice=check_slice,
            is_hex=is_hex,
            hrp_expanded=hrp_expanded,
            start_time=time.perf_counter(),
        )

    # Single-threaded fallback (scalar-walk, optimized)
    attempts = 0
    start = time.perf_counter()

    # Local variable lookups for hot path
    _b64encode = base64.b64encode
    _urlsafe_b64encode = base64.urlsafe_b64encode
    _hex_encode = bytes.hex
    _base58 = _base58_encode
    _bech32 = _bech32_encode

    # Calculate expected attempts for progress percentage
    if encoding == "hex":
        alphabet_size = 16
    elif encoding in ("base64", "base64url"):
        alphabet_size = 64
    elif encoding == "base58":
        alphabet_size = 58
    else:
        alphabet_size = 32
    if both:
        expected_attempts = alphabet_size ** (prefix_len * 2)
    else:
        expected_attempts = alphabet_size ** prefix_len

    # Scalar-walk: derive initial scalar from seed once, then increment
    # as a 256-bit integer for each attempt (avoids SHA-256 per attempt)
    scalar = int.from_bytes(hashlib.sha256(seed).digest(), "big")

    while True:
        if max_attempts is not None and attempts >= max_attempts:
            raise RuntimeError(f"exceeded max_attempts={max_attempts}")

        priv_seed = scalar.to_bytes(32, "big")
        scalar = (scalar + 1) & ((1 << 256) - 1)

        priv = nacl.signing.SigningKey(priv_seed)
        raw = bytes(priv.verify_key)

        if is_hex:
            encoded = _hex_encode(raw)
            # Early reject reserved prefixes for framework devices
            if encoded[:2].lower() in RESERVED_PREFIXES:
                attempts += 1
                continue
        elif encoding == "base64":
            encoded = _b64encode(raw).decode()
        elif encoding == "base64url":
            encoded = _urlsafe_b64encode(raw).decode().rstrip("=")
        elif encoding == "base58":
            encoded = _base58(raw)
        else:
            encoded = _bech32(hrp, raw, hrp_expanded)

        # Inline prefix/suffix/both check for hot path
        if both:
            encoded_prefix = encoded[:prefix_len]
            encoded_suffix = encoded[-prefix_len:]
            if case_insensitive:
                pref_match = encoded_prefix.lower() == prefix_cmp
                suff_match = encoded_suffix.lower() == prefix_cmp
            else:
                pref_match = encoded_prefix == prefix_cmp
                suff_match = encoded_suffix == prefix_cmp
            match = pref_match and suff_match
        else:
            encoded_part = encoded[check_slice]
            if case_insensitive:
                chk = encoded_part.lower()
            else:
                chk = encoded_part
            match = chk == prefix_cmp
        if match:
            return VanityResult(
                private_key=priv,
                public_key=priv.verify_key,
                encoded=encoded,
                attempts=attempts,
                elapsed=time.perf_counter() - start,
                private_seed=priv_seed,
            )

        attempts += 1

        if attempts % progress_interval == 0:
            elapsed = time.perf_counter() - start
            rate = attempts / elapsed if elapsed > 0 else 0
            pct = (attempts / expected_attempts * 100) if expected_attempts > 0 else 0
            remaining = (expected_attempts - attempts) / rate if rate > 0 else 0
            eta = f" eta={remaining:.0f}s" if remaining > 0 else ""
            print(
                f"  attempts={attempts:,} rate={rate:,.0f}/s elapsed={elapsed:.1f}s progress={pct:.2f}%{eta}",
                file=sys.stderr,
            )


def _generate_vanity_key_parallel(
    prefix: str,
    encoding: Encoding,
    case_insensitive: bool,
    max_attempts: int | None,
    seed: bytes,
    progress_interval: int,
    hrp: str,
    suffix: bool,
    both: bool,
    workers: int,
    prefix_cmp: str,
    prefix_len: int,
    check_slice: slice | None,
    is_hex: bool,
    hrp_expanded: list[int] | None,
    start_time: float,
) -> VanityResult:
    """Parallel vanity key search using multiprocessing."""
    import multiprocessing as mp
    
    ctx = mp.get_context("spawn")
    with ctx.Pool(processes=workers) as pool:
        worker_args = []
        for w in range(workers):
            worker_args.append((
                prefix, encoding, case_insensitive, max_attempts, seed,
                prefix_len, prefix_cmp, check_slice, both, hrp,
                w, w, workers, progress_interval,
                is_hex, hrp_expanded
            ))
        
        results = pool.map(_worker_search, worker_args)
        
        # Find the first successful result
        for priv_seed, worker_attempts, _ in results:
            if priv_seed is not None:
                # Reconstruct the key from private seed
                priv = nacl.signing.SigningKey(priv_seed)
                pub = priv.verify_key
                raw = bytes(pub)
                if is_hex:
                    encoded = raw.hex()
                elif encoding == "base64":
                    encoded = base64.b64encode(raw).decode()
                elif encoding == "base64url":
                    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
                elif encoding == "base58":
                    encoded = _base58_encode(raw)
                else:
                    encoded = _bech32_encode(hrp, raw, hrp_expanded)
                
                elapsed = time.perf_counter() - start_time
                return VanityResult(
                    private_key=priv,
                    public_key=pub,
                    encoded=encoded,
                    attempts=worker_attempts,
                    elapsed=elapsed,
                    private_seed=priv_seed,
                )
    
    raise RuntimeError(f"exceeded max_attempts={max_attempts}")


def meshcore_expanded_private_key(seed: bytes) -> bytes:
    """Derive the 64-byte MeshCore/RFC-8032 expanded private key from a 32-byte seed.

    Returns ``clamped_scalar || nonce`` where ``SHA-512(seed)`` is split in
    half, the first half is Ed25519-clamped, and the second half is the
    signing nonce. MeshCore devices (`set prv.key`) and meshcore-web-keygen
    expect this form as uppercase hex.
    """
    if len(seed) != 32:
        raise ValueError(f"seed must be 32 bytes, got {len(seed)}")
    h = hashlib.sha512(seed).digest()
    clamped = bytearray(h[:32])
    clamped[0] &= 0xF8
    clamped[31] &= 0x7F
    clamped[31] |= 0x40
    return bytes(clamped) + h[32:]


def serialize_private_key(key: nacl.signing.SigningKey) -> bytes:
    """Return the 32-byte raw Ed25519 private seed."""
    return bytes(key)


def serialize_public_key(key: nacl.signing.VerifyKey) -> bytes:
    """Return the 32-byte raw Ed25519 public key."""
    return bytes(key)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="MeshCore Ed25519 vanity key generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("prefix", help="Target prefix (e.g., neohiro)")
    parser.add_argument(
        "--encoding",
        choices=["base64", "base64url", "base58", "hex", "bech32"],
        default="base64",
        help="Public key encoding (use hex for MeshCore device import; "
        "uppercase the output for meshcore-web-keygen style keys)",
    )
    parser.add_argument(
        "--hrp",
        default="mc",
        help="Bech32 human-readable part",
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Match prefix case-sensitively",
    )
    parser.add_argument(
        "--suffix",
        action="store_true",
        help="Match suffix instead of prefix (checks last N chars of encoded key)",
    )
    parser.add_argument(
        "--both",
        action="store_true",
        help="Match both prefix AND suffix with the same pattern (e.g., --both 01010101)",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        help="Maximum attempts before giving up",
    )
    parser.add_argument(
        "--progress-interval",
        type=int,
        default=100_000,
        help="Progress log interval",
    )
    parser.add_argument(
        "--output-private",
        action="store_true",
        help="Also output private key (base64) to stderr - USE WITH CAUTION",
    )
    parser.add_argument(
        "--seed",
        help="Hex-encoded 32-byte seed for deterministic generation",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of parallel workers (multiprocessing)",
    )
    args = parser.parse_args()

    # Validate seed if provided (strict: exactly 64 hex chars, no whitespace).
    if args.seed:
        s = args.seed.strip()
        if len(s) != 64 or any(c not in "0123456789abcdefABCDEF" for c in s):
            print("Error: --seed must be 32 bytes (64 hex chars)", file=sys.stderr)
            return 2
        seed_bytes = bytes.fromhex(s)
    else:
        seed_bytes = None

    # Build descriptive search message based on mode
    if args.both:
        mode_desc = f"starting AND ending with '{args.prefix}'"
    elif args.suffix:
        mode_desc = f"ending with '{args.prefix}'"
    else:
        mode_desc = f"starting with '{args.prefix}'"
    
    try:
        print(
            f"Searching for {args.encoding} public key {mode_desc} "
            f"({'case-insensitive' if not args.case_sensitive else 'case-sensitive'})...",
            file=sys.stderr,
        )
    except BrokenPipeError:
        return 1

    try:
        result = generate_vanity_key(
            prefix=args.prefix,
            encoding=args.encoding,
            case_insensitive=not args.case_sensitive,
            max_attempts=args.max_attempts,
            seed=seed_bytes,
            progress_interval=args.progress_interval,
            hrp=args.hrp,
            suffix=args.suffix,
            both=args.both,
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except RuntimeError as e:
        print(f"\nFailed: {e}", file=sys.stderr)
        return 1

    try:
        print(result.encoded)
    except BrokenPipeError:
        return 1
    if args.output_private:
        priv_b64 = base64.b64encode(serialize_private_key(result.private_key)).decode()
        print(f"PRIVATE_KEY_BASE64={priv_b64}", file=sys.stderr)
        expanded_hex = meshcore_expanded_private_key(result.private_seed).hex().upper()
        print(f"MESHCORE_PRIV_HEX={expanded_hex}", file=sys.stderr)
        print(f"set prv.key {expanded_hex}", file=sys.stderr)

    rate = result.attempts / result.elapsed if result.elapsed > 0 else 0
    try:
        print(
            f"Found in {result.attempts:,} attempts ({result.elapsed:.2f}s, "
            f"{rate:,.0f} keys/s)",
            file=sys.stderr,
        )
    except BrokenPipeError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())