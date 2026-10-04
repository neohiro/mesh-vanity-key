#!/usr/bin/env python3
"""MeshCore-compatible Ed25519 vanity public-key generator.

Generates keys until the encoded public key starts with a target prefix.
Only the encoded public key is printed to stdout; the private key is printed
to stderr, on three lines, by DEFAULT - re-running a search to recover it is
wasteful and people did exactly that. Pass --no-output-private to suppress it
where the output is captured somewhere a secret should not land (CI logs, a
shared terminal, a piped dashboard).

Optimizations:
- Scalar walk: candidates come from a 256-bit counter incremented in place,
  not from a fresh random draw, so a given --seed reproduces a search exactly.
  It does NOT skip work: libsodium derives each candidate with SHA-512 over
  that counter, so the hash is paid per attempt either way. Measured on this
  host, one candidate costs ~36.7us, of which SHA-512 is ~0.9us (2.5%) and the
  Ed25519 scalar multiplication ~32.4us (88%) - the wrapper arithmetic around
  it is ~1%. There is no meaningful overhead left to remove; the only lever on
  throughput is running more workers.
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


class ReservedPrefixWarning(UserWarning):
    """A pattern was accepted but may not be usable by standard clients."""


def _warn_reserved_once(message: str) -> None:
    """Emit ``message`` as a warning, at most once per process."""
    if message in _warned_reserved:
        return
    _warned_reserved.add(message)
    warnings.warn(message, ReservedPrefixWarning, stacklevel=3)


def _install_clean_warnings() -> warnings.catch_warnings:
    """Render warnings without the ``file:line:`` prefix, for the CLI.

    Python's default formatting leads with the source location, so a warning
    raised inside this file prints as ``meshcore_vanity.py:812: UserWarning: ...``.
    To someone running the tool that reads as an internal error pointing into the
    implementation, not as advice about their key. The library still emits a
    normal warning (so ``pytest.warns`` and any embedding application behave
    normally); only the CLI's own rendering is changed, and it is restored on the
    way out.
    """
    ctx = warnings.catch_warnings()

    def show(message, category, filename, lineno, file=None, line=None):
        print(f"Warning: {message}", file=sys.stderr)

    ctx.__enter__()
    warnings.showwarning = show
    return ctx


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
# method synchronized objects cannot be passed as pool task args â€” they must
# be inherited â€” so the pool initializer sets this global in each child.
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

        # Trim the batch to the worker's remaining share so the parent's total
        # budget is a real bound. One subtraction per batch, not per candidate.
        batch = BATCH_SIZE
        if max_attempts is not None:
            remaining = max_attempts - attempts
            if remaining < batch:
                batch = remaining
        batch_start_attempts = attempts

        for _ in range(batch):
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
        #
        # Add what this batch ACTUALLY processed, not BATCH_SIZE. The last batch
        # of a bounded search is trimmed to the worker's remaining share, so
        # adding a full batch there counted candidates that were never tried -
        # with a share of 2 and 8 workers, 16 real attempts were reported as
        # 128. The parent takes max(counter, sum of returned counts) as the
        # final total, so that inflation made the reported attempt count, and
        # the rate derived from it, exceed the --max-attempts the user set. One
        # subtraction per batch keeps the hot loop untouched.
        if _PROGRESS_COUNTER is not None:
            with _PROGRESS_COUNTER.get_lock():
                _PROGRESS_COUNTER.value += attempts - batch_start_attempts


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
    # Only meaningful when the pattern constrains the START of the key. 00 and FF
    # are reserved because MeshCore framework devices are addressed by keys
    # *beginning* with them; a key that merely ENDS in 00ff is unremarkable, and
    # warning that it "may not work with standard MeshCore clients" would be
    # simply wrong.
    if encoding == "hex" and label == "prefix" and len(prefix) >= 2:
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


def _alphabet_size(encoding: Encoding, at_key_end: bool = False) -> int:
    """Symbols available at one position of the encoded key.

    ``at_key_end`` marks the position of the key's LAST data character, which in
    base64 is not a full 6-bit character: the 32-byte key leaves 4 significant
    bits there, so only 16 of the 64 symbols can occur. That is the same fact
    _validate_base64_suffix_reachable() refuses impossible patterns with, kept in
    one place so the estimate and the validation cannot disagree.
    """
    if encoding == "hex":
        return 16
    if encoding in ("base64", "base64url"):
        return 16 if at_key_end else 64
    if encoding == "base58":
        return 58
    return 32


# Characters of the bech32 string either side of the final data character.
# The layout is hrp + '1' + data(52) + checksum(6), so the final data character
# sits exactly this far from the end, with the 6-character checksum outside it.
_BECH32_CHECKSUM_LEN = 6

# The 32-byte key is 256 bits, which does not fill 52 five-bit groups (260
# bits): 4 bits of padding land in the last data character, leaving it a single
# significant bit and so only 2 of the 32 symbols. Derived, then checked against
# 200,000 real encodings (see the reachability tests).
_BECH32_LAST_DATA_VALUES = frozenset(
    BECH32_CHARSET[v] for v in (0, 16)
)


def _bech32_last_data_offset(suffix_len: int) -> int:
    """Index, within a suffix pattern, of the character that is data[-1].

    The final data character is _BECH32_CHECKSUM_LEN + 1 characters from the end,
    so a suffix long enough to reach it contains it at this offset. Returns -1
    when the suffix is entirely within the checksum and cannot reach it.
    """
    if suffix_len <= _BECH32_CHECKSUM_LEN:
        return -1
    return suffix_len - (_BECH32_CHECKSUM_LEN + 1)


def _validate_bech32_suffix_reachable(suffix: str, label: str) -> None:
    """Refuse a bech32 suffix that provably cannot occur.

    Only the final DATA character is constrained (see
    _BECH32_LAST_DATA_VALUES); the 6-character checksum outside it is uniform, so
    a suffix of 6 or fewer characters is unconstrained and is always allowed.
    """
    offset = _bech32_last_data_offset(len(suffix))
    if offset < 0:
        return
    ch = suffix[offset]
    if ch in _BECH32_LAST_DATA_VALUES:
        return
    raise ValueError(
        f"this {label} can never match a bech32 key: a 32-byte key encodes to "
        f"52 data characters carrying 256 bits, so the last one holds only 4 "
        f"significant bits and can only be "
        f"{''.join(sorted(_BECH32_LAST_DATA_VALUES))} - but this pattern needs "
        f"{ch!r} there (position {offset} of {len(suffix)}, "
        f"{_BECH32_CHECKSUM_LEN + 1} characters from the end). A bech32 suffix "
        f"of {_BECH32_CHECKSUM_LEN} or fewer characters never reaches that "
        f"position and is unaffected."
    )


def _end_search_space(encoding: Encoding, suffix_len: int) -> int:
    """Search space of a pattern applied at the END of the key.

    The end is not the same as the start: the last data character of a key
    carries fewer bits than its alphabet implies (4 in base64, 1 in bech32), so
    a suffix is cheaper than a prefix of the same length. Charging a suffix the
    full alphabet overstated the estimate for every base64 and long bech32
    suffix.
    """
    if suffix_len <= 0:
        return 1
    if encoding in ("base64", "base64url"):
        return (
            _alphabet_size(encoding) ** (suffix_len - 1)
            * _alphabet_size(encoding, at_key_end=True)
        )
    if encoding == "bech32":
        # Characters inside the data part are ordinary; the one 6+1 from the end
        # is the constrained final data character, and the 6 outside it are the
        # checksum, which is uniform.
        offset = _bech32_last_data_offset(suffix_len)
        if offset < 0:
            return _alphabet_size(encoding) ** suffix_len
        constrained = offset          # ordinary data chars before it
        checksum = min(suffix_len, _BECH32_CHECKSUM_LEN)
        space = _alphabet_size(encoding) ** constrained
        space *= len(_BECH32_LAST_DATA_VALUES)
        space *= _alphabet_size(encoding) ** checksum
        return space
    return _alphabet_size(encoding) ** suffix_len


def _estimate_search_space(
    encoding: Encoding, prefix_len: int, suffix_len: int | None
) -> int:
    """Brute-force search space size for the stderr progress line.

    ``suffix_len`` is None when only the start of the key is constrained.
    Otherwise it is the length of the pattern applied at the END of the key, and
    two things follow:

    - constraining both ends multiplies the search space rather than adding to
      it, so the estimate is the product of the two ends;
    - the end of the key has a smaller alphabet than the start in base64, and
      the same is true of the final data character in bech32 (7 characters from
      the end, not 1). _end_search_space() owns that per encoding.

    Callers should go through _expected_attempts(), not this function directly.
    This is the arithmetic underneath a search space; _expected_attempts() knows
    WHICH pattern sits at which end of the key, and that is the part that is easy
    to get wrong. The live progress line once recomputed it here with a start
    alphabet while the pre-flight line used the end alphabet, and the two
    disagreed 4x for a bare --suffix.
    """
    space = _alphabet_size(encoding) ** prefix_len
    if suffix_len is None:
        return space
    return space * _end_search_space(encoding, suffix_len)


def _expected_attempts(
    encoding: Encoding,
    prefix_len: int,
    suffix_len: int,
    suffix: bool,
    two_ended: bool,
) -> int:
    """Expected attempts for one match mode, for every progress display.

    The one mode that is easy to get wrong is a bare ``--suffix``: the pattern
    sits at the END of the key, and the end's last data character carries fewer
    bits than the start's alphabet implies (4 in base64, 1 in bech32), so it must
    be costed with _end_search_space().

    Costing it against the START alphabet instead overstated the expectation 4x
    for base64 and up to 16x for a long bech32 suffix. Measured on
    `--suffix Ab4 --encoding base64`: the pre-flight line quoted 65,536 expected
    attempts and an ETA of ~2s, while the in-search progress line divided by
    262,144 - so it read 7.63% at 20,000 attempts and the ETA had drifted to
    10.4s and rising. The two disagreed by exactly the factor above.

    Both search paths and the CLI's pre-flight line go through here, which is
    what _estimate_search_space's own docstring promises; the duplication this
    replaces is what broke that promise.
    """
    if two_ended:
        return _estimate_search_space(encoding, prefix_len, suffix_len)
    if suffix:
        return _estimate_search_space(encoding, 0, prefix_len)
    return _estimate_search_space(encoding, prefix_len, None)


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


def _check_match_modes(
    suffix: bool, suffix_pattern: str | None, both: bool
) -> None:
    """Reject combinations of the matching-mode flags that contradict.

    Separate from the rest of generate_vanity_key() so main() can call it
    before it prints anything. The three modes are mutually exclusive, and
    announcing a search for the wrong pattern and *then* failing reads as if the
    search had started: `--suffix cd --both` used to print "starting AND ending
    with 'ab'" and only then explain that the flags contradict. main() already
    validates --workers up front for exactly this reason.
    """
    if both and suffix:
        raise ValueError("cannot use --both with --suffix")
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


def _base64_final_chars() -> frozenset[str]:
    """Characters that can actually end a base64/base64url encoded 32-byte key.

    32 bytes is 256 bits; base64 spends 6 bits per character, so 43 characters
    hold 258 bits and the last one carries only 4 significant bits - its low two
    bits are always zero. So the final character's alphabet index must be a
    multiple of 4, and 16 of the 64 symbols are unreachable there.

    This matters because a suffix is matched against the END of the key: a
    pattern whose last character is one of the other 48 can never match, and the
    search would otherwise run until it was killed rather than say so.
    Verified against 20,000 random keys - the derived set and the observed set
    are identical.
    """
    alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    )
    return frozenset(alphabet[i] for i in range(0, 64, 4))


def _validate_suffix_reachable(
    encoding: Encoding, suffix: str, label: str
) -> None:
    """Refuse a suffix that provably cannot occur, per encoding.

    Only encodings with a provable constraint are handled. hex and base58 have
    none: base58's leading-digit distribution makes some two- and three-character
    prefixes RARE but never impossible, which was checked exhaustively over all
    of them by interval arithmetic, so a validator there would only risk
    rejecting valid patterns. A wrong rejection is worse than a futile search,
    which at least ends in a visible "exceeded max_attempts".
    """
    if not suffix:
        return
    if encoding in ("base64", "base64url"):
        _validate_base64_suffix_reachable(suffix, label)
    elif encoding == "bech32":
        _validate_bech32_suffix_reachable(suffix, label)


def _validate_base64_suffix_reachable(suffix: str, label: str) -> None:
    """Refuse a base64 pattern that provably cannot end a key.

    Only the LAST character is constrained: earlier characters of the pattern sit
    at non-final positions where all 64 symbols are reachable.

    An empty pattern is not an error here. It legitimately reaches this function
    in --both mode, where the suffix side is the same pattern as the prefix and
    is supplied by the caller rather than by ``suffix_pattern``; and it
    constrains nothing, so there is nothing to reject. (It used to be indexed
    unconditionally, so `--both --encoding base64` died with an IndexError.)
    """
    if not suffix:
        return
    reachable = _base64_final_chars()
    last = suffix[-1]
    if last in reachable:
        return
    raise ValueError(
        f"this {label} can never match a base64 key: a 32-byte key's base64 "
        f"form is 43 data characters, and the last one carries only 4 "
        f"significant bits, so it can only be one of "
        f"{''.join(sorted(reachable))}. {last!r} is not among them "
        f"(the full pattern was {suffix!r})"
    )


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

    Uses the scalar walk for reproducibility, not for speed: see the module
    docstring for the measured breakdown of where a candidate's time actually
    goes.

    Matching modes, in precedence order:

    - ``suffix_pattern`` given: require ``prefix`` at the start **and**
      ``suffix_pattern`` at the end, as two independent patterns. This is what
      the browser does with its two input boxes, and it is the only mode that
      can ask for a prefix and a *different* suffix.
    - ``suffix=True``: require ``prefix`` at the end instead of the start.
    - ``both=True``: require ``prefix`` at both ends (the same pattern twice).
    - otherwise: require ``prefix`` at the start.
    """
    # Clamp case-insensitivity to what the encoding can actually support BEFORE
    # anything validates a pattern, so the validator sees the same setting the
    # matcher will use. Doing it afterwards meant a library caller hitting the
    # default (True) on a case-SENSITIVE encoding had its pattern lowercased for
    # validation: `--encoding base58 L...` was refused because "l" is not in the
    # base58 alphabet, even though "L" is and the match is case-sensitive anyway.
    case_insensitive = _effective_case_insensitive(encoding, case_insensitive)
    _check_match_modes(suffix, suffix_pattern, both)
    if suffix_pattern is not None:
        _validate_prefix(
            suffix_pattern, encoding, case_insensitive, label="suffix"
        )
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

    # Already clamped at the top of the function, before validation.
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
        # In --both mode the pattern is repeated at the end, so the same pattern
        # is what has to be reachable there, not an empty string.
        _validate_suffix_reachable(
            encoding, prefix if both else suffix_pattern, "suffix"
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
        _validate_suffix_reachable(encoding, prefix, "suffix")
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
    # Cost of the search, decided ONCE for every progress display: the live line
    # in the serial loop, the one the monitor thread prints in the parallel path,
    # and the CLI's pre-flight estimate. An empty pattern constrains nothing and
    # contributes a factor of 1, which _estimate_search_space gets right itself.
    expected_attempts = _expected_attempts(
        encoding, prefix_len, suffix_len, suffix, two_ended
    )

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

    # Single-threaded fallback (scalar walk)
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
    # Already computed above by _expected_attempts(); the CLI's pre-flight line
    # uses the same helper, so the figure quoted before the search and the one
    # measured against during it are the same number by construction.

    # Scalar walk: take the 256-bit counter from the seed once, then increment it
    # in place for each attempt. Note this counter is a SEED, not the private
    # scalar: libsodium still runs SHA-512 over it inside
    # crypto_sign_seed_keypair, so this avoids a fresh CSPRNG draw rather than a
    # hash. The walk also makes a given --seed reproduce a search exactly.
    scalar = int.from_bytes(hashlib.sha256(seed).digest(), "big")

    # Chunk the loop so max_attempts and the progress counter are only examined
    # every BATCH_SIZE candidates. It is NOT batch verification - each candidate
    # is still derived and matched on its own.
    BATCH_SIZE = 16
    next_report = progress_interval

    while True:
        if max_attempts is not None and attempts >= max_attempts:
            raise RuntimeError(f"exceeded max_attempts={max_attempts}")

        # Trim the last batch to what is left of the budget, so `max_attempts` is
        # a real upper bound rather than "N rounded up to a multiple of 16".
        # One subtraction per batch, not per candidate, so the hot loop is
        # unaffected. Without it, 8 workers could overshoot by ~127 attempts.
        batch = BATCH_SIZE
        if max_attempts is not None:
            remaining = max_attempts - attempts
            if remaining < batch:
                batch = remaining

        for _ in range(batch):
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


# How often the parent checks for a finished worker while waiting for a result.
#
# This is a liveness poll, not a timeout on the search: expiring it does nothing
# except hand control back so the worker check can run. It must stay well under
# the progress-report interval so a dead pool is noticed long before the user
# would wonder why the display stopped moving.
_POOL_POLL_SECONDS = 0.25


def _split_worker_budget(max_attempts: int | None, workers: int) -> list[int | None]:
    """Divide a TOTAL attempt budget into per-worker shares that sum exactly.

    Largest-remainder: the first ``max_attempts % workers`` workers take one
    extra attempt, so the shares add up to ``max_attempts`` for every input and
    no two workers differ by more than one.

    ``max_attempts=None`` means unbounded, and every share is None.

    This replaced ``max(1, max_attempts // workers)``, which was wrong in both
    directions at once: floor division discarded up to ``workers - 1`` attempts,
    while the ``max(1, ...)`` that stopped zero-share workers idling made
    ``--max-attempts 3 --workers 8`` run 8 attempts - more than twice the cap. A
    bound that is neither an upper nor an exact bound is the worst kind, because
    the caller cannot reason about cost and no test can pin it.
    """
    if max_attempts is None:
        return [None] * workers
    base, extra = divmod(max_attempts, workers)
    return [base + (1 if w < extra else 0) for w in range(workers)]


def _pool_lost_a_task(worker_pids: set, pool) -> bool:
    """True when no worker that could have been running a task is left.

    A multiprocessing.Pool replaces a dead worker with a fresh one, so the
    replacement is ALIVE and holds no task - asking "is any worker alive?" never
    trips. What cannot be faked is the disappearance of the processes that were
    actually given the tasks: once none of those PIDs remain in the pool, no
    further result can ever arrive, and the iterator would block forever.

    Fails open (returns False) when there is nothing to compare against: an
    empty PID set, or a Pool that does not expose ``_pool`` at all. Without that
    distinction a missing attribute would read as "no workers left" and report a
    failure that never happened - so only an EMPTY pool, which is real evidence,
    counts as a lost task.
    """
    if not worker_pids:
        return False
    procs = getattr(pool, "_pool", None)
    if procs is None:
        return False
    return not (worker_pids & {p.pid for p in procs})


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

    ``expected_attempts`` is computed by the caller through
    _expected_attempts() and used as given. It was previously recomputed here
    from a different expression, which silently disagreed with the caller's
    figure for a bare --suffix (4x in base64) - see that function's docstring.
    """
    ctx = mp.get_context("spawn")
    # Split the total attempt budget across workers so --max-attempts keeps its
    # documented meaning: the TOTAL, not a per-worker figure. See
    # _split_worker_budget for why the shares must sum exactly.
    per_worker_max = _split_worker_budget(max_attempts, workers)
    progress_counter = ctx.Value("Q", 0)
    with ctx.Pool(processes=workers, initializer=_init_worker_counter,
                   initargs=(progress_counter,)) as pool:
        worker_args = []
        for w in range(workers):
            worker_args.append((
                prefix, encoding, case_insensitive, per_worker_max[w], seed,
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

        # Consume results with an explicit poll instead of `for r in imap(...)`.
        #
        # A Pool hangs FOREVER if a worker dies while holding a task: the task is
        # gone, so its result is never produced and nothing completes the iterator.
        # The Pool quietly replaces the corpse with a fresh worker that never gets
        # the lost task, so `is_alive()` stays True and the search simply stops
        # progressing, silently, forever. concurrent.futures.ProcessPoolExecutor
        # detects this (BrokenProcessPool); multiprocessing.Pool does not.
        #
        # So detect it here: once every worker that could have been running a task
        # has left the pool, no further result can arrive. A worker that finishes
        # normally returns its result first, so this cannot fire on a healthy
        # search - including an unbounded one, where workers legitimately stay
        # alive for hours without returning anything.
        #
        # Original PIDs, not liveness: the auto-replacement workers ARE alive but
        # hold no tasks, so "is any worker alive?" would never trip.
        worker_pids = {p.pid for p in getattr(pool, "_pool", [])}
        results = pool.imap_unordered(_worker_search, worker_args)
        total_attempts = 0
        received = 0

        try:
            while received < workers:
                try:
                    priv_seed, worker_attempts, _ = results.next(
                        timeout=_POOL_POLL_SECONDS
                    )
                except mp.TimeoutError:
                    if _pool_lost_a_task(worker_pids, pool):
                        raise RuntimeError(
                            f"all {workers} search workers exited without "
                            f"returning a result ({received} of {workers} "
                            f"completed) - usually the OS killing a worker, "
                            f"e.g. the OOM killer. Retry with fewer workers "
                            f"(--workers 2) and check free memory."
                        ) from None
                    continue

                received += 1
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
    # Warnings are rendered without the "file:line:" prefix for the whole run.
    _warn_ctx = _install_clean_warnings()
    try:
        return _main()
    finally:
        _warn_ctx.__exit__(None, None, None)


def _main() -> int:
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

    # Reject contradictory flags before anything is printed or measured, for
    # the same reason --workers is validated up front: announcing a search for
    # the wrong pattern and then failing reads as though it had started.
    try:
        _check_match_modes(use_suffix, suffix_pattern, args.both)
        # An impossible base64 suffix would otherwise be reported only after the
        # search line and the estimate have already been printed. Reusing the
        # same helper keeps one source of truth for the reachable set.
        if suffix_pattern is not None:
            _validate_suffix_reachable(
                args.encoding, suffix_pattern, "suffix pattern"
            )
        elif use_suffix:
            _validate_suffix_reachable(args.encoding, args.prefix, "suffix")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

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
    # Same reasoning for the two remaining numeric options. generate_vanity_key
    # rejects both, but only once it is reached - which is AFTER the benchmark
    # burns CPU and, on a terminal, AFTER the user has already typed "y" to the
    # confirmation prompt. Answering the prompt and then being told the request
    # was invalid is the same wrong-then-fail sequence this block exists to
    # prevent, so reject them in the same place.
    if args.max_attempts is not None and args.max_attempts <= 0:
        print(f"Error: --max-attempts must be positive, got {args.max_attempts}",
              file=sys.stderr)
        return 2
    if args.progress_interval <= 0:
        print(f"Error: --progress-interval must be positive, "
              f"got {args.progress_interval}", file=sys.stderr)
        return 2

    # Budget estimator: search-space size + locally measured rate + ETA.
    # Requires confirmation on interactive terminals unless --force.
    # All user-facing text goes to stderr: stdout carries only the key.
    try:
        # Same model the search itself uses, so the figure quoted before the
        # search is the figure used during it. _expected_attempts() is the same
        # helper generate_vanity_key() uses for its live progress line, so the
        # two agree by construction rather than by two expressions happening to
        # match - which is how a bare --suffix came to disagree 4x.
        est = _expected_attempts(
            args.encoding,
            len(args.prefix),
            len(suffix_pattern) if suffix_pattern is not None else len(args.prefix),
            use_suffix,
            args.both or suffix_pattern is not None,
        )
        expected = est
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
