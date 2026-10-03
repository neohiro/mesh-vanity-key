#!/usr/bin/env python3
"""MeshCore-compatible Ed25519 vanity public-key generator.

Generates keys until the encoded public key starts with a target prefix.
Only the encoded public key is printed to stdout; the private key is printed
to stderr, on three lines, by DEFAULT - re-running a search to recover it is
wasteful and people did exactly that. Pass --no-output-private to suppress it
where the output is captured somewhere a secret should not land (CI logs, a
shared terminal, a piped dashboard).

Optimizations:
- Scalar-walk: increment private scalar directly instead of hashing per attempt
- Warns on reserved prefixes (00, FF) for framework devices (strict with
  MESHCORE_VANITY_STRICT_RESERVED=1)
- Parallel workers with optimized work distribution
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import math
import os
import sys
import threading
import time
import warnings
import multiprocessing as mp
from dataclasses import dataclass
from typing import Literal

import nacl.signing

Encoding = Literal["base64", "base64url", "base58", "hex", "bech32"]

# Bumped when behaviour changes in a way that matters to a caller (output
# format, defaults, validation rules). Surfaced by --version, which also prints
# the resolved file path so a stale copy elsewhere is obvious immediately.
__version__ = "1.1.0"

BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Reserved prefixes for MeshCore framework devices (not consumer).
# These are skipped during mining by default, but may be explicitly requested.
RESERVED_PREFIXES = {"00", "ff"}

# Sentinel for `--suffix` given with no value. argparse gives no way to tell
# "flag absent" from "flag present, no value" when both default to None, and the
# two mean different things here: absent, and bare --suffix (match at the end
# instead of the start), and --suffix PATTERN (a separate second pattern).
_SUFFIX_MEANS_END = "--suffix"


_warned_reserved: set[str] = set()


def _warn_reserved_once(message: str) -> None:
    """Emit ``message`` as a warning, at most once per process."""
    if message in _warned_reserved:
        return
    _warned_reserved.add(message)
    warnings.warn(message, stacklevel=3)


def _allow_reserved(prefix: str, encoding: str) -> bool:
    """True when the caller deliberately asked for a reserved 00/FF prefix.

    Only a hex pattern beginning with a reserved prefix can select one, so any
    other encoding (or a non-reserved hex prefix) never opts in.
    """
    return (
        encoding == "hex"
        and len(prefix) >= 2
        and prefix[:2].lower() in RESERVED_PREFIXES
    )

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


# Shared live-progress counter for parallel workers. Under the "spawn" start
# method synchronized objects cannot be passed as pool task args — they must
# be inherited — so the pool initializer sets this global in each child.
_PROGRESS_COUNTER = None


def _init_worker_counter(counter) -> None:
    """Pool initializer: inherit the shared progress counter in each child."""
    global _PROGRESS_COUNTER
    _PROGRESS_COUNTER = counter


def _worker_search(args: tuple) -> tuple:
    """Worker function for parallel search."""
    (prefix, encoding, case_insensitive, max_attempts, seed, prefix_len,
     prefix_cmp, suffix_cmp, suffix_slice, two_ended, check_slice, hrp,
     start_offset, _worker_id, total_workers, is_hex, hrp_expanded) = args

    # NOTE: base64/hashlib/nacl are already imported at module level; under
    # the "spawn" start method the module is re-imported in each child, so no
    # re-imports are needed here. Locals are bound for the hot loop.
    _b64encode = base64.b64encode
    _urlsafe_b64encode = base64.urlsafe_b64encode
    _hex_encode = bytes.hex
    # Only the raw public key is needed per candidate; the SigningKey object is
    # rebuilt by the parent only once, on a match.
    _seed_keypair = nacl.bindings.crypto_sign_seed_keypair

    attempts = 0
    counter = start_offset

    initial_scalar = int.from_bytes(hashlib.sha256(seed).digest(), "big")

    BATCH_SIZE = 16

    while True:
        if max_attempts is not None and attempts >= max_attempts:
            return (None, attempts, counter)

        for _ in range(BATCH_SIZE):
            # Scalar is masked to 256 bits, so to_bytes(32) cannot overflow.
            scalar_val = (initial_scalar + counter) & ((1 << 256) - 1)
            priv_seed = scalar_val.to_bytes(32, "big")

            # Only the raw public key is needed to test the pattern; the
            # SigningKey object is rebuilt once by the parent on a match.
            raw = _seed_keypair(priv_seed)[0]

            if encoding == "hex":
                encoded = _hex_encode(raw)
                # Skip reserved prefixes unless the user explicitly asked for
                # one (mirrors the warning-and-continue CLI behaviour).
                if (
                    encoded[:2].lower() in RESERVED_PREFIXES
                    and not _allow_reserved(prefix, encoding)
                ):
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

            if two_ended:
                # Mirrors the single-threaded hot loop: --both and
                # --suffix PATTERN differ only in what the end must equal.
                if case_insensitive:
                    match = (
                        encoded[:prefix_len].lower() == prefix_cmp
                        and encoded[suffix_slice].lower() == suffix_cmp
                    )
                else:
                    match = (
                        encoded[:prefix_len] == prefix_cmp
                        and encoded[suffix_slice] == suffix_cmp
                    )
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

        # Feed the shared live-progress counter once per batch (not per key)
        # to keep lock contention negligible on the hot path.
        if _PROGRESS_COUNTER is not None:
            with _PROGRESS_COUNTER.get_lock():
                _PROGRESS_COUNTER.value += BATCH_SIZE


# Pre-define _bech32_hrp_expand at module level for worker access
def _bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand HRP for bech32 checksum calculation."""
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 0x1F for c in hrp]


# Human-readable description of what each encoding can contain, used to explain
# rejections instead of just naming the offending character.
_ALLOWED_HELP = {
    "hex": "0-9 and a-f (uppercase A-F is also accepted)",
    "base64": "A-Z, a-z, 0-9, + and /",
    "base64url": "A-Z, a-z, 0-9, - and _",
    "base58": "1-9 and A-Z (0, O, I and l are excluded)",
    "bech32": "qpzry9x8gf2tvdw0s3jn54khce6mua7l (plus the '1' separator)",
}

_WHY_HEX = (
    "An Ed25519 public key is exactly 32 bytes, written as 64 hexadecimal "
    "digits, so every character at every position must be a hex digit; "
    "letters g-z, spaces and symbols such as '0x' or ':' can never occur."
)


def _validate_prefix(
    prefix: str, encoding: Encoding, case_insensitive: bool = True, label: str = "prefix"
) -> None:
    """Validate that prefix contains only valid characters for the encoding.

    When matching case-insensitively, an uppercase hex/bech32 prefix is
    accepted because it is lowered before comparison.

    ``label`` names the argument in the error message ("prefix" or "suffix").
    """
    if not prefix:
        raise ValueError(f"{label} cannot be empty")
    check = prefix.lower() if case_insensitive else prefix
    valid = _PREFIX_VALID_CHARS[encoding]
    invalid = set(check) - valid
    if invalid:
        allowed = _ALLOWED_HELP[encoding]
        why = f" {_WHY_HEX}" if encoding == "hex" else ""
        raise ValueError(
            f"{label} contains invalid characters: {sorted(invalid)!r}. "
            f"Allowed for {encoding}: {allowed}.{why}"
        )
    # Warn (not reject) on reserved prefixes for MeshCore framework devices
    # (00, FF). They are still mineable - some users deliberately want one -
    # so the CLI matches the browser's behaviour of allowing it with a clear
    # warning. Set MESHCORE_VANITY_STRICT_RESERVED=1 to restore hard rejection.
    if encoding == "hex" and len(prefix) >= 2:
        prefix_lower = prefix[:2].lower()
        if prefix_lower in RESERVED_PREFIXES:
            message = (
                f"{label} {prefix!r} starts with a prefix reserved for MeshCore "
                f"framework devices (00 and FF are not available for consumer "
                f"nodes). It will still be mined, but the key may not work with "
                f"standard MeshCore clients."
            )
            if os.environ.get("MESHCORE_VANITY_STRICT_RESERVED"):
                raise ValueError(
                    f"{message} (MESHCORE_VANITY_STRICT_RESERVED is set)"
                )
            # Warn once per distinct pattern, so repeated validation of the same
            # search (library use, retries) cannot spam the output.
            _warn_reserved_once(message)
    # A 32-byte key encodes to 44 base64 chars with a single '=' pad at index
    # 43; '=' anywhere else can never match, so fail fast instead of searching
    # forever. (base64url strips padding, so '=' is already rejected above.)
    if encoding == "base64" and "=" in prefix:
        if not (len(prefix) == 44 and prefix.endswith("=") and prefix.count("=") == 1):
            raise ValueError(
                f"{label} {prefix!r} can never match {encoding}: "
                f"'=' padding occurs only as the last character"
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


def _expected_attempts(encoding: Encoding, *pattern_lengths: int) -> int:
    """Brute-force search space size for the stderr progress line.

    Takes the length of every independently-constrained end of the key, so a
    prefix and a separate suffix cost what they actually cost: constraining both
    ends multiplies the search space, it does not add to it.
    """
    if encoding == "hex":
        alphabet_size = 16
    elif encoding in ("base64", "base64url"):
        alphabet_size = 64
    elif encoding == "base58":
        alphabet_size = 58
    else:
        alphabet_size = 32
    return alphabet_size ** sum(pattern_lengths)


def _max_encoded_len(encoding: Encoding, hrp: str) -> int:
    """Longest possible encoding of a 32-byte public key, in characters.

    Two patterns longer than this must overlap, and overlapping patterns can
    never both match, so callers fail fast instead of searching forever.
    """
    if encoding == "hex":
        return 64
    if encoding == "base64":
        return 44
    if encoding == "base64url":
        return 43
    if encoding == "base58":
        return 44
    return len(hrp) + 1 + 52 + 6


# Encodings whose alphabet is case-SENSITIVE. A key beginning "AB" is a
# different key from one beginning "ab", so these must be matched exactly or
# the tool returns keys that do not match the request. hex and bech32 are
# conventionally case-insensitive and keep the friendly default.
CASE_SENSITIVE_ENCODINGS = ("base64", "base64url", "base58")


def _effective_case_insensitive(encoding: Encoding, case_insensitive: bool) -> bool:
    """Case-insensitive matching, forced off for case-sensitive alphabets.

    Asking for a base64 key starting ``ab`` and being handed one starting
    ``aB`` is not a near miss, it is the wrong key - and for a vanity search
    the whole point is that the result matches the pattern that was typed.
    Callers cannot opt back in: there is no correct case-insensitive match for
    these alphabets, only a misleading one.
    """
    return case_insensitive and encoding not in CASE_SENSITIVE_ENCODINGS


def _data_len(encoding: Encoding, hrp: str) -> int:
    """Length of the encoded key's *data*, excluding base64's ``=`` padding.

    A 32-byte key is 44 base64 characters, the last of which is always the
    ``=`` pad. Suffix matching must look at the end of the key data, not at the
    padding: matching ``encoded[-1:]`` compares against ``"="`` on every single
    candidate, so a short base64 suffix could never match and the search ran
    forever. This is the window the tail is actually drawn from.
    """
    if encoding == "base64":
        return 43
    return _max_encoded_len(encoding, hrp)


def format_elapsed(seconds: float) -> str:
    """Human-readable duration: ``0.04s`` / ``42.3s`` / ``2m 10s`` / ``1h 2m 9s``.

    Long searches routinely run for hours, so a bare seconds figure stops
    being readable ("127453.4s"). Matches the browser's formatElapsed().

    Precision follows magnitude: two decimals below 10s (a search that found a
    key in 40ms used to render as a useless "0.0s"), one decimal below a
    minute, whole seconds inside a compound duration.
    """
    if seconds != seconds or seconds in (float("inf"), float("-inf")) or seconds < 0:
        return "unknown"
    if seconds < 10:
        return f"{seconds:.2f}s"
    if seconds < 60:
        return f"{seconds:.1f}s"
    total = int(round(seconds))
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    out = ""
    if h:
        out += f"{h}h "
    if h or m:
        out += f"{m}m "
    return (out + f"{s}s").strip()


def format_day_hint(seconds: float) -> str:
    """Approximate whole/half-day suffix for long waits, e.g. ``(~2.5 days)``.

    "127h 24m" is precise but hard to judge at a glance; the day hint is the
    scale that tells someone whether to wait or walk away. Nothing is added
    below a day, and beyond ~10 days the estimate is too uncertain to state as
    false precision, so it is withheld. Mirrors formatDayHint() in the page.
    """
    if seconds != seconds or seconds in (float("inf"), float("-inf")) or seconds <= 0:
        return ""
    days = seconds / 86400
    if days < 1 or days >= 10:
        return ""
    rounded = round(days * 2) / 2
    label = str(int(rounded)) if rounded == int(rounded) else f"{rounded:.1f}"
    return f" (~{label} day)" if rounded == 1 else f" (~{label} days)"


def format_eta(seconds: float) -> str:
    """Human duration with the day hint appended."""
    return format_elapsed(seconds) + format_day_hint(seconds)


def _format_progress(attempts: int, elapsed: float, expected_attempts: int) -> str:
    """Single stderr progress-line format shared by all search paths.

    Progress is NOT capped at 100. The expectation is the mean of a geometric
    distribution, so ~37% of searches legitimately run past it; showing the
    overshoot as +100.01%, +105.00% conveys how far into the tail the search
    has reached, which a hard 100% ceiling threw away.
    """
    rate = attempts / elapsed if elapsed > 0 else 0
    have_expected = expected_attempts > 0 and math.isfinite(expected_attempts)
    pct = (attempts / expected_attempts * 100) if have_expected else 0.0
    # Prefix "+" once past the expected mean so the overshoot is unmistakable.
    progress = f"+{pct:.2f}%" if pct > 100.0 else f"{pct:.2f}%"
    remaining = (expected_attempts - attempts) / rate if (have_expected and rate > 0) else None
    if remaining is None:
        # Either the rate is not yet known or the expectation overflowed to
        # infinity; say so instead of implying "no time remaining".
        eta = " eta=unknown"
    elif remaining > 0:
        eta = f" eta={format_eta(remaining)}"
    else:
        # Past the mean the naive remaining figure is negative and meaningless,
        # and dropping it silently left the user with no sense of progress.
        # Report how far past the mean the search has gone instead.
        pct_over = (-remaining) / (attempts / rate) * 100 if attempts > 0 else 0.0
        eta = f" ({pct_over:.0f}% past expected, {format_elapsed(-remaining)} over)"
    return (
        f"  attempts={attempts:,} rate={rate:,.0f}/s "
        f"elapsed={format_elapsed(elapsed)} progress={progress}{eta}"
    )


def _benchmark_rate(sample_keys: int = 200) -> float:
    """Measure local single-worker keygen rate (keys/s) for the estimator.

    Runs a handful of real Ed25519 derivations; takes milliseconds.
    Returns 0.0 if timing fails.
    """
    try:
        seed = os.urandom(32)
        start = time.perf_counter()
        for _ in range(sample_keys):
            priv = nacl.signing.SigningKey(seed)
            bytes(priv.verify_key)
        elapsed = time.perf_counter() - start
        return sample_keys / elapsed if elapsed > 0 else 0.0
    except Exception:
        return 0.0


def _human_duration(seconds: float) -> str:
    """Compact duration mirroring the web estimator (s/m/h/d)."""
    if seconds != seconds or seconds <= 0:  # NaN or non-positive
        return "unknown"
    if seconds == float("inf"):
        return "very long"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def generate_vanity_key(
    prefix: str,
    encoding: Encoding = "base64",
    case_insensitive: bool = True,
    max_attempts: int | None = None,
    seed: bytes | None = None,
    progress_interval: int = 100_000,
    hrp: str = "mc",
    suffix: bool = False,
    suffix_pattern: str | None = None,
    both: bool = False,
    workers: int = 1,
) -> VanityResult:
    """Generate Ed25519 keypair until the public key encoding matches.

    Uses scalar-walk key derivation for performance and reproducibility.

    Matching modes, in precedence order:

    - ``suffix_pattern`` given: require ``prefix`` at the start **and**
      ``suffix_pattern`` at the end, as two independent patterns. This is what
      the browser does with its two input boxes, and it is the only mode that
      can ask for a prefix and a *different* suffix.
    - ``suffix=True``: require ``prefix`` at the end instead of the start.
    - ``both=True``: require ``prefix`` at both ends (the same pattern twice).
    - otherwise: require ``prefix`` at the start.
    """
    if suffix_pattern is not None:
        if suffix:
            raise ValueError(
                "cannot combine --suffix (match at the end) with a separate "
                "suffix pattern; pass one or the other"
            )
        if both:
            raise ValueError(
                "cannot combine --both with a separate suffix pattern: --both "
                "uses one pattern for both ends, which is what a separate "
                "suffix pattern replaces"
            )
        if not suffix_pattern:
            raise ValueError("suffix pattern must not be empty")
        _validate_prefix(
            suffix_pattern, encoding, case_insensitive, label="suffix"
        )
    if both and suffix:
        raise ValueError("cannot use --both with --suffix")
    # An empty pattern is only meaningful when a separate suffix pattern
    # supplies the constraint - that is the suffix-only mode. On its own an
    # empty prefix would match every key, which _validate_prefix rejects.
    if prefix or suffix_pattern is None:
        _validate_prefix(
            prefix,
            encoding,
            case_insensitive,
            label="suffix" if suffix else "prefix",
        )
    seed = _validate_seed(seed)
    if progress_interval <= 0:
        raise ValueError("progress_interval must be positive")
    if max_attempts is not None and max_attempts <= 0:
        raise ValueError("max_attempts must be positive or None")

    if workers <= 0:
        raise ValueError("workers must be positive")
    if workers > 256:
        raise ValueError("workers must be <= 256")

    case_insensitive = _effective_case_insensitive(encoding, case_insensitive)
    prefix_cmp = prefix.lower() if case_insensitive else prefix
    prefix_len = len(prefix)
    # A 32-byte key has a fixed maximum encoded length per encoding; a longer
    # prefix can never match, so fail fast instead of searching forever.
    max_len = _max_encoded_len(encoding, hrp)
    if prefix_len > max_len:
        raise ValueError(
            f"{'suffix' if suffix else 'prefix'} too long for {encoding}: "
            f"{prefix_len} chars, max is {max_len} for a 32-byte key"
        )
    # Suffix matching checks the last N chars instead of the first. Both-ends
    # modes check the first N against `prefix` AND the last M against
    # `suffix_cmp`, which is `prefix_cmp` itself for --both and a separate
    # pattern for --suffix PATTERN.
    suffix_len = 0
    suffix_cmp = ""
    two_ended = both or suffix_pattern is not None
    data_len = _data_len(encoding, hrp)
    if two_ended:
        if both:
            suffix_cmp, suffix_len = prefix_cmp, prefix_len
        else:
            suffix_cmp = (
                suffix_pattern.lower() if case_insensitive else suffix_pattern
            )
            suffix_len = len(suffix_pattern)
        if suffix_len > data_len:
            raise ValueError(
                f"suffix too long for {encoding}: {suffix_len} chars, max is "
                f"{data_len} for a 32-byte key"
            )
        # The prefix covers [0, prefix_len) and the suffix the last
        # `suffix_len` data characters. If those regions touch, the same
        # characters would have to satisfy both patterns, which is impossible
        # for all but a few patterns - so refuse rather than search forever.
        # The browser rejects the same case.
        suffix_start = data_len - suffix_len
        if prefix_len > suffix_start:
            raise ValueError(
                f"prefix ({prefix_len} chars) + suffix ({suffix_len} chars) "
                f"overlap: a {encoding} key has only {data_len} characters, so "
                f"the two patterns would have to be satisfied by the same ones "
                f"and can never both match"
            )
        suffix_slice = slice(suffix_start, data_len)
        check_slice = None
        _validate_hrp(hrp)
        if encoding == "bech32":
            _validate_bech32_prefix(prefix_cmp, hrp, case_insensitive)
    elif suffix:
        if prefix_len > data_len:
            raise ValueError(
                f"suffix too long for {encoding}: {prefix_len} chars, max is "
                f"{data_len} for a 32-byte key"
            )
        suffix_slice = slice(data_len - prefix_len, data_len)
        check_slice = suffix_slice
    else:
        suffix_slice = None
        check_slice = slice(0, prefix_len)
        _validate_hrp(hrp)
        if encoding == "bech32":
            _validate_bech32_prefix(prefix_cmp, hrp, case_insensitive)
    is_hex = encoding == "hex"
    # HRP expansion is loop-invariant; hoist it out of the hot path.
    hrp_expanded = _bech32_hrp_expand(hrp) if encoding == "bech32" else None
    # Cost of the search: every constrained end multiplies the space. An empty
    # pattern constrains nothing and contributes a factor of 1, which
    # _expected_attempts gets right on its own via sum().
    if two_ended:
        expected_attempts = _expected_attempts(encoding, prefix_len, suffix_len)
    else:
        expected_attempts = _expected_attempts(encoding, prefix_len)

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
            workers=workers,
            prefix_cmp=prefix_cmp,
            prefix_len=prefix_len,
            suffix_cmp=suffix_cmp,
            suffix_len=suffix_len,
            suffix_slice=suffix_slice,
            two_ended=two_ended,
            expected_attempts=expected_attempts,
            check_slice=check_slice,
            is_hex=is_hex,
            hrp_expanded=hrp_expanded,
            start_time=time.perf_counter(),
        )

    # Single-threaded fallback (scalar-walk, batch verification)
    attempts = 0
    start = time.perf_counter()

    # Local variable lookups for hot path
    _b64encode = base64.b64encode
    _urlsafe_b64encode = base64.urlsafe_b64encode
    _hex_encode = bytes.hex
    _base58 = _base58_encode
    _bech32 = _bech32_encode
    _SigningKey = nacl.signing.SigningKey
    _seed_keypair = nacl.bindings.crypto_sign_seed_keypair

    # Calculate expected attempts for progress percentage
    expected_attempts = _expected_attempts(encoding, prefix_len, suffix_len) if two_ended else _expected_attempts(encoding, prefix_len)

    # Scalar-walk: derive initial scalar from seed once, then increment
    # as a 256-bit integer for each attempt (avoids SHA-256 per attempt)
    scalar = int.from_bytes(hashlib.sha256(seed).digest(), "big")

    # Batch verification: check multiple candidates per iteration
    BATCH_SIZE = 16
    next_report = progress_interval

    while True:
        if max_attempts is not None and attempts >= max_attempts:
            raise RuntimeError(f"exceeded max_attempts={max_attempts}")

        for _ in range(BATCH_SIZE):
            priv_seed = scalar.to_bytes(32, "big")
            scalar = (scalar + 1) & ((1 << 256) - 1)

            # Only the raw public key is needed to test the pattern, so ask
            # libsodium for exactly that instead of building a PyNaCl
            # SigningKey and its VerifyKey for every candidate. The function
            # benchmark in tools/bench_mining.py shows this consistently ahead
            # (~3%), but end-to-end that is smaller than the run-to-run
            # variance on a loaded host, so treat it as a wash on a quiet
            # machine rather than a headline speedup. The object is still
            # built below, once, on a match, because VanityResult exposes it.
            raw = _seed_keypair(priv_seed)[0]

            if is_hex:
                encoded = _hex_encode(raw)
                # Skip reserved prefixes unless the user explicitly asked for
                # one (mirrors the warning-and-continue CLI behaviour).
                if (
                    encoded[:2].lower() in RESERVED_PREFIXES
                    and not _allow_reserved(prefix, encoding)
                ):
                    attempts += 1
                    if max_attempts is not None and attempts >= max_attempts:
                        raise RuntimeError(f"exceeded max_attempts={max_attempts}")
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
            if two_ended:
                # One branch covers --both and --suffix PATTERN: both require a
                # match at each end, differing only in what the end must equal.
                if case_insensitive:
                    match = (
                        encoded[:prefix_len].lower() == prefix_cmp
                        and encoded[suffix_slice].lower() == suffix_cmp
                    )
                else:
                    match = (
                        encoded[:prefix_len] == prefix_cmp
                        and encoded[suffix_slice] == suffix_cmp
                    )
            else:
                # check_slice is always a slice here (both=False branch)
                encoded_part = encoded[check_slice]  # type: ignore[index]
                if case_insensitive:
                    chk = encoded_part.lower()
                else:
                    chk = encoded_part
                match = chk == prefix_cmp
            if match:
                priv = _SigningKey(priv_seed)
                return VanityResult(
                    private_key=priv,
                    public_key=priv.verify_key,
                    encoded=encoded,
                    attempts=attempts,
                    elapsed=time.perf_counter() - start,
                    private_seed=priv_seed,
                )

            attempts += 1

        if attempts >= next_report:
            next_report += progress_interval
            elapsed = time.perf_counter() - start
            print(_format_progress(attempts, elapsed, expected_attempts), file=sys.stderr)


def _generate_vanity_key_parallel(
    prefix: str,
    encoding: Encoding,
    case_insensitive: bool,
    max_attempts: int | None,
    seed: bytes,
    progress_interval: int,
    hrp: str,
    suffix: bool,
    workers: int,
    prefix_cmp: str,
    prefix_len: int,
    suffix_cmp: str,
    suffix_len: int,
    suffix_slice: slice,
    two_ended: bool,
    expected_attempts: int,
    check_slice: slice | None,
    is_hex: bool,
    hrp_expanded: list[int] | None,
    start_time: float,
) -> VanityResult:
    """Parallel vanity key search using multiprocessing with early exit.

    Live progress combines the standard stderr echo format with a shared
    counter fed by the workers once per batch, so long unbounded searches
    report continuously instead of only on worker completion.
    """
    ctx = mp.get_context("spawn")
    # Split the total attempt budget across workers so --max-attempts keeps
    # its documented meaning (total, not per-worker).
    if max_attempts is not None:
        per_worker_max = (max_attempts + workers - 1) // workers
    else:
        per_worker_max = None
    expected_attempts = _expected_attempts(
        encoding, prefix_len, suffix_len
    ) if two_ended else _expected_attempts(encoding, prefix_len)
    progress_counter = ctx.Value("Q", 0)
    with ctx.Pool(processes=workers, initializer=_init_worker_counter,
                   initargs=(progress_counter,)) as pool:
        worker_args = []
        for w in range(workers):
            worker_args.append((
                prefix, encoding, case_insensitive, per_worker_max, seed,
                prefix_len, prefix_cmp, suffix_cmp, suffix_slice,
                two_ended, check_slice, hrp,
                w, w, workers,
                is_hex, hrp_expanded
            ))

        # Monitor thread: same echo format as the single-threaded path,
        # driven by the shared counter. Daemon so it can never hang exit.
        stop_monitor = threading.Event()
        next_report = progress_interval

        def _monitor() -> None:
            nonlocal next_report
            last_heartbeat = start_time
            while not stop_monitor.wait(0.5):
                total = progress_counter.value
                now = time.perf_counter()
                if total >= next_report or now - last_heartbeat >= 5.0:
                    next_report = max(next_report + progress_interval, total + 1)
                    print(
                        _format_progress(total, now - start_time, expected_attempts),
                        file=sys.stderr,
                    )
                    last_heartbeat = now

        monitor = threading.Thread(target=_monitor, name="progress-monitor", daemon=True)
        monitor.start()

        # Use imap_unordered for early exit on first result
        # Track exact total across workers from their returned counts.
        total_attempts = 0

        try:
            for priv_seed, worker_attempts, _ in pool.imap_unordered(_worker_search, worker_args):
                total_attempts += worker_attempts

                if priv_seed is not None:
                    pool.terminate()
                    # True total work includes the killed workers' partial
                    # batches (only visible via the shared counter); the
                    # returned counts cover only completed workers. Take the
                    # max so the final figure agrees with the progress lines.
                    total_attempts = max(progress_counter.value, total_attempts)
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
                        attempts=total_attempts,
                        elapsed=elapsed,
                        private_seed=priv_seed,
                    )
        except KeyboardInterrupt:
            pool.terminate()
            raise
        finally:
            stop_monitor.set()
            monitor.join(timeout=2.0)

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


# Serial seconds of expected work below which spawning a multiprocessing pool
# is not worth it. Measured: the "spawn" pool costs ~0.3s to create (fresh
# interpreter plus re-importing PyNaCl in every child), and a 1-hex-char search
# finishes in under 10ms serially -- so going parallel made those ~40x SLOWER.
# Only pay the startup when the search is expected to outlast it.
_PARALLEL_MIN_SECONDS = 1.0


# Aggregate throughput multiplier vs. worker count.
#
# The benchmark measures ONE worker on ONE core, but the pool then runs
# `workers` processes concurrently, so a flat multiplication overstates the
# result. Measured on the reference host (8 logical CPUs / 4 physical cores):
# pure-CPU keygen saturated at ~2.3x the single-worker rate across 8 threads,
# not 8x -- SMT siblings share one core's execution units, and the processes
# contend for memory bandwidth.
#
# Only the 8-thread end point was measured directly, so intermediate points use
# a power-law fit anchored to it: scale(n) = n ** (log(2.3) / log(8)). The fit
# is concave and capped at the measured ceiling, so it cannot predict more
# speedup than was observed.
#
# Kept in sync with WORKER_SCALE_MEASURED / WORKER_SCALE_EXPONENT in
# index.html. See README "Worker scaling: 2 -> 8 threads". The value is
# hardware-specific: re-measure before trusting it elsewhere.
_WORKER_SCALE_MEASURED = {8: 2.3}
_WORKER_SCALE_EXPONENT = math.log(_WORKER_SCALE_MEASURED[8]) / math.log(8)


def _worker_scale(workers: int) -> float:
    """Aggregate speedup vs. one worker, for `workers` concurrent workers."""
    n = int(workers)
    if n <= 1:
        return 1.0
    return float(n) ** _WORKER_SCALE_EXPONENT


def _default_workers() -> int:
    """Worker count used when --workers is not given.

    Every core: the search is ~99% Ed25519 scalar multiplication (measured in
    tools/bench_mining.py), which is independent per candidate and shares
    nothing, so it scales with cores. Capped to stay inside the pool's own
    limit and to leave the machine responsive.
    """
    try:
        cpus = mp.cpu_count() or 1
    except NotImplementedError:  # pragma: no cover - platform dependent
        cpus = 1
    return max(1, min(cpus, 64))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="MeshCore Ed25519 vanity key generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # nargs="?" so `--version` works standalone; validated below when omitted.
    parser.add_argument(
        "prefix",
        nargs="?",
        metavar="pattern",
        help="The text to match (e.g., neohiro). Matched against the START of "
        "the encoded key unless --suffix or --both says otherwise.",
    )
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
        help="Match the pattern case-sensitively",
    )
    parser.add_argument(
        "--suffix",
        nargs="?",
        const=_SUFFIX_MEANS_END,
        default=None,
        metavar="PATTERN",
        help="With no value, match the positional pattern against the END of "
        "the key instead of the start. With a value, require that value at the "
        "end IN ADDITION TO the positional prefix - two independent patterns "
        "checked in the same search, as the browser's two input boxes do. "
        "e.g. `--suffix ab --suffix cd` matches a key starting 'ab' and ending "
        "'cd'.",
    )
    parser.add_argument(
        "--both",
        action="store_true",
        help="Require the pattern at BOTH the start and the end, using that "
        "SAME pattern for each end (e.g. `--both 0101` matches keys starting "
        "and ending with 0101). A switch, not a value, and it cannot express a "
        "prefix and a different suffix. Costs multiply, so keep it short.",
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
        "--no-output-private",
        action="store_true",
        help=(
            "Suppress the private key, which is printed by default. Use this "
            "where output is captured somewhere you would not want a secret: a "
            "CI log, a shared terminal, a piped dashboard."
        ),
    )
    parser.add_argument(
        "--seed",
        help="Hex-encoded 32-byte seed for deterministic generation",
    )
    parser.add_argument(
        "--workers",
        type=int,
        # Default to every core. The search is ~99% Ed25519 scalar
        # multiplication (see tools/bench_mining.py), which is pure CPU work
        # with no shared state, so it scales almost linearly. Defaulting to 1
        # left the machine's remaining cores completely idle -- the browser
        # app has always auto-detected. Pass --workers 1 to force serial mode.
        default=None,
        help="Number of parallel workers (default: all CPU cores)",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Skip the pre-search estimate confirmation",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and the file's own location, then exit",
    )
    args = parser.parse_args()

    # --version exists because a stale copy of this script in a parent
    # directory is an easy and very confusing mistake: it runs, produces
    # plausible output, and silently uses an older code path (for example a
    # single worker instead of all cores). Printing the resolved path makes
    # that immediately visible instead of showing up as "it got slower".
    if args.version:
        print(f"meshcore-vanity {__version__}")
        print(f"loaded from: {os.path.abspath(__file__)}")
        return 0

    # --suffix takes an optional value, so the three states have to be told
    # apart before anything is validated or printed.
    suffix_at_end = args.suffix == _SUFFIX_MEANS_END
    suffix_pattern = args.suffix if args.suffix not in (None, _SUFFIX_MEANS_END) else None
    use_suffix = suffix_at_end

    # argparse leaves an omitted positional as None; the rest of main() (and
    # generate_vanity_key) treat "no pattern" as an empty string, and the mode
    # where that is legal is a suffix-only search. Normalise once, here.
    args.prefix = args.prefix or ""

    # A separate suffix pattern can stand on its own: `--suffix cd` asks for a
    # key ending in cd, which is the same thing the browser allows with only
    # its suffix box filled in. The bare `--suffix` still needs a positional
    # pattern, because there it is a modifier and not the pattern itself.
    if not args.prefix and suffix_pattern is None:
        print(
            "Error: a target pattern is required: pass it as the positional "
            "argument, or use --suffix PATTERN to match only the end",
            file=sys.stderr,
        )
        return 2

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
    elif suffix_pattern is not None:
        # An empty prefix means "only constrain the end", which is what
        # `--suffix cd` with no positional argument asks for.
        if args.prefix:
            mode_desc = (
                f"starting with '{args.prefix}' AND ending with "
                f"'{suffix_pattern}'"
            )
        else:
            mode_desc = f"ending with '{suffix_pattern}'"
    elif use_suffix:
        mode_desc = f"ending with '{args.prefix}'"
    else:
        mode_desc = f"starting with '{args.prefix}'"

    # Validate --workers before anything is printed or measured. Showing
    # "~-33,011 keys/s" or a bogus "ETA ~very long" and only then failing
    # after the user already confirmed is both wrong and wasteful. Previously a
    # non-positive value was silently coerced to 1, which hid typos; it is now
    # an explicit, up-front error.
    workers_n = _default_workers() if args.workers is None else args.workers
    if workers_n < 1:
        print(f"Error: --workers must be at least 1, got {args.workers}",
              file=sys.stderr)
        return 2
    if workers_n > 256:
        print(f"Error: --workers must be <= 256, got {workers_n}",
              file=sys.stderr)
        return 2

    # Budget estimator: search-space size + locally measured rate + ETA.
    # Requires confirmation on interactive terminals unless --force.
    # All user-facing text goes to stderr: stdout carries only the key.
    try:
        pat_lens = [len(args.prefix)]
        if args.both:
            pat_lens.append(len(args.prefix))
        elif suffix_pattern is not None:
            pat_lens.append(len(suffix_pattern))
        expected = _expected_attempts(args.encoding, *pat_lens)
        measured = _benchmark_rate()
        # Spawning the pool costs a few tenths of a second. If the search is
        # expected to finish sooner than that, staying serial is dramatically
        # faster (measured ~40x for short prefixes). Only apply this to the
        # automatic default: an explicit --workers is always honoured.
        if args.workers is None and measured > 0 and workers_n > 1:
            if expected / measured < _PARALLEL_MIN_SECONDS:
                workers_n = 1
        if measured > 0:
            # Scale through the measured curve rather than assuming linear, so
            # the quoted rate is one the user can plan around.
            scale = _worker_scale(workers_n)
            rate = measured * scale
            rate_str = (
                f"~{rate:,.0f} keys/s "
                f"(single-worker measurement x {scale:.1f} "
                f"for {workers_n} worker{'' if workers_n == 1 else 's'})"
            )
        else:
            rate = 0.0
            rate_str = "unknown rate"
        eta = _human_duration(expected / rate if rate > 0 else float("inf"))
        estimate_line = (
            f"Estimate: {expected:,} expected attempts "
            f"({rate_str}) | ETA ~{eta}"
        )
        if args.max_attempts is not None:
            estimate_line += f" | capped at {args.max_attempts:,} attempts by --max-attempts"
        print(estimate_line, file=sys.stderr)
        if not args.force and sys.stdin.isatty():
            try:
                # Prompt via stderr: input() would print to stdout and
                # contaminate piped output like `... > key.txt`.
                print("Continue? [y/N]: ", end="", file=sys.stderr)
                answer = input().strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("Aborted.", file=sys.stderr)
                return 1
            if answer not in ("y", "yes"):
                print("Aborted.", file=sys.stderr)
                return 1
    except BrokenPipeError:
        return 1

    # base64, base64url and base58 are case-SENSITIVE alphabets: a key that begins
    # "AB" does not match a request for "ab", and for a vanity search the whole
    # point is that the key literally matches the pattern asked for. Matching
    # them case-insensitively silently returned keys with the wrong case - ask
    # for `ab` and get `aB`. hex and bech32 are conventionally case-insensitive
    # (and their output is lowercase anyway), so they keep the friendly default.
    case_insensitive = _effective_case_insensitive(
        args.encoding, not args.case_sensitive
    )

    try:
        print(
            f"Searching for {args.encoding} public key {mode_desc} "
            f"({'case-insensitive' if case_insensitive else 'case-sensitive'})...",
            file=sys.stderr,
        )
    except BrokenPipeError:
        return 1

    try:
        result = generate_vanity_key(
            prefix=args.prefix,
            encoding=args.encoding,
            case_insensitive=case_insensitive,
            max_attempts=args.max_attempts,
            seed=seed_bytes,
            progress_interval=args.progress_interval,
            hrp=args.hrp,
            suffix=use_suffix,
            suffix_pattern=suffix_pattern,
            both=args.both,
            workers=workers_n,
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
    # Private keys are printed by DEFAULT.
    #
    # They used to require --output-private, and in practice people re-ran the
    # whole search to get them - minutes to days of wasted CPU, and two machines
    # mining the same wasted work. The printed key is the entire point of the
    # tool, so requiring a flag for it was backwards.
    #
    # Pass --no-output-private to suppress it where stdout/stderr is captured
    # somewhere you would not want a secret to land: a CI log, a shared terminal
    # scrollback, a piped dashboard. That is the one real cost of the default,
    # and it is why the opt-out exists.
    if not args.no_output_private:
        priv_b64 = base64.b64encode(serialize_private_key(result.private_key)).decode()
        expanded_hex = meshcore_expanded_private_key(result.private_seed).hex().upper()
        print(f"PRIVATE_KEY_BASE64={priv_b64}", file=sys.stderr)
        print(f"MESHCORE_PRIV_HEX={expanded_hex}", file=sys.stderr)
        print(f"set prv.key {expanded_hex}", file=sys.stderr)

    rate = result.attempts / result.elapsed if result.elapsed > 0 else 0
    try:
        print(
            f"Found in {result.attempts:,} attempts "
            f"({format_elapsed(result.elapsed)}, {rate:,.0f} keys/s)",
            file=sys.stderr,
        )
    except BrokenPipeError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
