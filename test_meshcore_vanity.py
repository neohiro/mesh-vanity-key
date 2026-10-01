#!/usr/bin/env python3
"""Tests for meshcore_vanity.py"""

import base64
import io
import json
import re
import struct
from pathlib import Path

import pytest

from meshcore_vanity import (
    encode_public_key,
    generate_vanity_key,
    _base58_encode,
    _bech32_encode,
    _benchmark_rate,
    _expected_attempts,
    _format_progress,
    _human_duration,
    _validate_prefix,
    _validate_seed,
    _validate_hrp,
    meshcore_expanded_private_key,
    serialize_private_key,
    serialize_public_key,
    nacl,
)


def test_encode_base64():
    priv = nacl.signing.SigningKey.generate()
    pub = priv.verify_key
    encoded = encode_public_key(pub, "base64")
    assert isinstance(encoded, str)
    decoded = base64.b64decode(encoded)
    assert decoded == bytes(pub)


def test_encode_base64url():
    priv = nacl.signing.SigningKey.generate()
    pub = priv.verify_key
    encoded = encode_public_key(pub, "base64url")
    assert isinstance(encoded, str)
    assert "=" not in encoded
    assert "+" not in encoded
    assert "/" not in encoded
    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    assert decoded == bytes(pub)


def test_encode_hex():
    priv = nacl.signing.SigningKey.generate()
    pub = priv.verify_key
    encoded = encode_public_key(pub, "hex")
    assert isinstance(encoded, str)
    assert len(encoded) == 64
    assert all(c in "0123456789abcdef" for c in encoded)
    assert bytes.fromhex(encoded) == bytes(pub)


def test_encode_base58():
    priv = nacl.signing.SigningKey.generate()
    pub = priv.verify_key
    encoded = encode_public_key(pub, "base58")
    assert isinstance(encoded, str)
    assert len(encoded) > 0
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    assert all(c in alphabet for c in encoded)


def test_encode_bech32():
    priv = nacl.signing.SigningKey.generate()
    pub = priv.verify_key
    encoded = encode_public_key(pub, "bech32", hrp="mc")
    assert isinstance(encoded, str)
    assert encoded.startswith("mc1")
    assert len(encoded) > 10


def test_base58_encode_known():
    assert _base58_encode(b"") == ""
    assert _base58_encode(b"\x00") == "1"
    assert _base58_encode(b"\x00\x00") == "11"
    assert _base58_encode(b"\x61") == "2g"
    assert _base58_encode(b"\x62\x62\x62") == "a3gV"
    assert _base58_encode(b"\x63\x63\x63\x63") == "3YMA8z"


def test_bech32_encode_known():
    # BIP-0173 test vectors
    assert _bech32_encode("a", b"") == "a12uel5l"
    assert _bech32_encode("abcdef", b"") == "abcdef1hu3qdg"
    # 32 bytes of data with hrp='mc' should produce 61-char string
    data = bytes(range(32))
    result = _bech32_encode("mc", data)
    assert len(result) == 61
    assert result.startswith("mc1")


def test_generate_vanity_key_short_prefix():
    result = generate_vanity_key("ab", encoding="hex", max_attempts=100000)
    assert result.encoded.startswith("ab")
    assert result.attempts >= 0
    assert result.elapsed > 0
    assert isinstance(result.private_key, nacl.signing.SigningKey)
    assert isinstance(result.public_key, nacl.signing.VerifyKey)


def test_serialize_private_key():
    priv = nacl.signing.SigningKey.generate()
    serialized = serialize_private_key(priv)
    assert isinstance(serialized, bytes)
    assert len(serialized) == 32
    restored = nacl.signing.SigningKey(serialized)
    assert bytes(restored) == bytes(priv)


def test_serialize_public_key():
    priv = nacl.signing.SigningKey.generate()
    pub = priv.verify_key
    serialized = serialize_public_key(pub)
    assert isinstance(serialized, bytes)
    assert len(serialized) == 32
    restored = nacl.signing.VerifyKey(serialized)
    assert bytes(restored) == bytes(pub)


def test_validate_prefix_valid():
    _validate_prefix("abc", "hex")  # valid hex
    _validate_prefix("ABC", "base64")  # valid base64
    _validate_prefix("123", "base58")  # valid base58
    _validate_prefix("mc1q", "bech32")  # valid bech32 with '1'


def test_validate_prefix_case_insensitive_hex_bech32():
    # Uppercase is accepted when matching case-insensitively.
    _validate_prefix("AB", "hex", case_insensitive=True)
    _validate_prefix("NE", "bech32", case_insensitive=True)
    with pytest.raises(ValueError, match="invalid characters"):
        _validate_prefix("AB", "hex", case_insensitive=False)
    with pytest.raises(ValueError, match="invalid characters"):
        _validate_prefix("NEO", "bech32", case_insensitive=False)


def test_validate_prefix_invalid():
    with pytest.raises(ValueError, match="invalid characters"):
        _validate_prefix("xyz", "hex")  # invalid hex
    with pytest.raises(ValueError, match="invalid characters"):
        _validate_prefix("abc!", "base64")  # invalid base64
    with pytest.raises(ValueError, match="invalid characters"):
        _validate_prefix("0", "base58")  # '0' not in base58
    with pytest.raises(ValueError, match="cannot be empty"):
        _validate_prefix("", "hex")


def test_validate_seed():
    assert _validate_seed(None) is not None
    assert len(_validate_seed(None)) == 32
    seed = bytes(range(32))
    assert _validate_seed(seed) == seed
    with pytest.raises(ValueError, match="32 bytes"):
        _validate_seed(b"short")
    with pytest.raises(ValueError, match="32 bytes"):
        _validate_seed(b"x" * 33)


def test_validate_hrp():
    _validate_hrp("mc")
    _validate_hrp("meshcore")
    _validate_hrp("a" * 83)
    with pytest.raises(ValueError, match="length must be 1-83"):
        _validate_hrp("")
    with pytest.raises(ValueError, match="length must be 1-83"):
        _validate_hrp("a" * 84)
    with pytest.raises(ValueError, match="printable ASCII"):
        _validate_hrp("bad hrp")  # space not allowed
    with pytest.raises(ValueError, match="printable ASCII"):
        _validate_hrp("bad\thrp")  # tab not allowed


def test_generate_vanity_key_with_seed():
    """Test deterministic generation with seed."""
    result1 = generate_vanity_key("ab", encoding="hex", max_attempts=100000, seed=bytes(32))
    result2 = generate_vanity_key("ab", encoding="hex", max_attempts=100000, seed=bytes(32))
    assert result1.encoded == result2.encoded
    assert result1.attempts == result2.attempts


def test_generate_vanity_key_max_attempts():
    with pytest.raises(RuntimeError, match="exceeded max_attempts"):
        generate_vanity_key("deadbeefcafe", encoding="hex", max_attempts=10)


def test_generate_vanity_key_progress_interval():
    with pytest.raises(ValueError, match="positive"):
        generate_vanity_key("ab", encoding="hex", progress_interval=0)
    with pytest.raises(ValueError, match="positive"):
        generate_vanity_key("ab", encoding="hex", progress_interval=-1)


def test_generate_vanity_key_max_attempts_zero():
    with pytest.raises(ValueError, match="positive"):
        generate_vanity_key("ab", encoding="hex", max_attempts=0)
    with pytest.raises(ValueError, match="positive"):
        generate_vanity_key("ab", encoding="hex", max_attempts=-1)


def test_generate_vanity_key_bech32_impossible_prefix():
    with pytest.raises(ValueError, match="impossible with hrp"):
        generate_vanity_key("ne", encoding="bech32", hrp="mc", max_attempts=10)
    # Compatible prefixes pass validation (may or may not match in 1 attempt).
    try:
        generate_vanity_key("mc1qqqqqqqqqq", encoding="bech32", hrp="mc", max_attempts=1)
    except RuntimeError:
        pass


def test_meshcore_expanded_private_key():
    import hashlib

    seed = bytes(range(32))
    expanded = meshcore_expanded_private_key(seed)
    assert len(expanded) == 64
    h = hashlib.sha512(seed).digest()
    # Clamping bits per RFC 8032.
    assert expanded[0] == h[0] & 0xF8
    assert expanded[31] == ((h[31] & 0x7F) | 0x40)
    # Nonce half passes through untouched.
    assert expanded[32:] == h[32:]
    with pytest.raises(ValueError, match="32 bytes"):
        meshcore_expanded_private_key(b"short")


def test_generate_vanity_key_carries_private_seed():
    result = generate_vanity_key("ab", encoding="hex", max_attempts=100000, seed=bytes(32))
    assert len(result.private_seed) == 32
    assert serialize_private_key(result.private_key) == result.private_seed
    # Expanded form round-trips through the helper.
    assert len(meshcore_expanded_private_key(result.private_seed)) == 64


def test_main_smoke(monkeypatch, capsys):
    import sys
    import meshcore_vanity as mv

    monkeypatch.setattr(
        sys, "argv", ["meshcore_vanity.py", "ab", "--encoding", "hex", "--max-attempts", "100000"]
    )
    assert mv.main() == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("ab")

    # Impossible bech32 prefix exits 2, not an infinite search.
    monkeypatch.setattr(
        sys, "argv", ["meshcore_vanity.py", "ne", "--encoding", "bech32", "--max-attempts", "10"]
    )
    assert mv.main() == 2

    # Strict seed parsing rejects whitespace-embedded hex.
    monkeypatch.setattr(
        sys,
        "argv",
        ["meshcore_vanity.py", "ab", "--encoding", "hex", "--seed", "00 " * 32],
    )
    assert mv.main() == 2


def test_generate_vanity_key_empty_prefix():
    with pytest.raises(ValueError, match="cannot be empty"):
        generate_vanity_key("", encoding="hex")


def test_generate_vanity_key_long_prefix():
    # Prefixes longer than the encoding can ever produce fail fast.
    with pytest.raises(ValueError, match="too long"):
        generate_vanity_key("a" * 100, encoding="hex", max_attempts=10)
    with pytest.raises(ValueError, match="too long"):
        generate_vanity_key("a" * 45, encoding="base64", max_attempts=10)
    with pytest.raises(ValueError, match="too long"):
        generate_vanity_key("a" * 44, encoding="base64url", max_attempts=10)
    # Boundary lengths are still accepted (may just not match).
    try:
        generate_vanity_key("a" * 64, encoding="hex", max_attempts=1)
    except RuntimeError:
        pass


def test_generate_vanity_key_both_mode():
    # Both mode: pattern must match at both start and end
    # Use single char "a" for high probability (1/16^2 = 1/256)
    result = generate_vanity_key("a", encoding="hex", both=True, max_attempts=50000)
    assert result.encoded.startswith("a")
    assert result.encoded.endswith("a")
    assert result.attempts >= 0
    
    # Case sensitive
    result = generate_vanity_key("a", encoding="hex", both=True, max_attempts=50000, case_insensitive=False)
    assert result.encoded.startswith("a")
    assert result.encoded.endswith("a")


def test_generate_vanity_key_both_mutually_exclusive():
    with pytest.raises(ValueError, match="cannot use --both with --suffix"):
        generate_vanity_key("ab", encoding="hex", suffix=True, both=True, max_attempts=10)


def test_generate_vanity_key_parallel():
    result = generate_vanity_key("ab", encoding="hex", max_attempts=100000, workers=2)
    assert result.encoded.startswith("ab")
    assert result.attempts >= 0


def test_generate_vanity_key_parallel_max_attempts():
    # Impossible-in-budget search must fail fast, not hang workers.
    with pytest.raises(RuntimeError, match="exceeded max_attempts"):
        generate_vanity_key("deadbeefcafe", encoding="hex", max_attempts=20, workers=2)


def test_validate_prefix_reserved_hex():
    # 00/FF prefixes are reserved for MeshCore framework devices.
    with pytest.raises(ValueError, match="reserved"):
        _validate_prefix("00ab", "hex")
    with pytest.raises(ValueError, match="reserved"):
        _validate_prefix("FF12", "hex")
    _validate_prefix("ab", "hex")  # non-reserved passes


def test_validate_prefix_base64_padding():
    # '=' occurs only as the final char of a 44-char encoding of a 32-byte key.
    with pytest.raises(ValueError, match="can never match"):
        _validate_prefix("ab=", "base64")
    with pytest.raises(ValueError, match="can never match"):
        _validate_prefix("=abc", "base64")
    with pytest.raises(ValueError, match="can never match"):
        generate_vanity_key("ab=", encoding="base64", max_attempts=10)


def test_generate_vanity_key_base58():
    # Deterministic seed: scalar-walk finds 'A...' in 3 attempts.
    result = generate_vanity_key("A", encoding="base58", max_attempts=50000, seed=bytes(32))
    assert result.encoded.startswith("A")
    assert result.attempts == 3


def test_expected_attempts():
    assert _expected_attempts("hex", 2, False) == 16**2
    assert _expected_attempts("base64", 1, False) == 64
    assert _expected_attempts("base58", 1, False) == 58
    assert _expected_attempts("bech32", 1, False) == 32
    assert _expected_attempts("hex", 2, True) == 16**4


def test_format_progress():
    s = _format_progress(1000, 2.0, 10000)
    assert "attempts=1,000" in s
    assert "rate=500/s" in s
    assert "elapsed=2.0s" in s
    assert "progress=10.00%" in s
    # Pct caps at 100: overrunning the mean is statistically normal.
    assert "progress=100.00%" in _format_progress(200000, 1.0, 65536)
    # Zero elapsed never divides by zero.
    assert "rate=0/s" in _format_progress(0, 0.0, 100)


def test_parallel_live_progress_reports(capfd):
    # Deterministic ~2s search: the monitor thread must stream the shared
    # echo format to stderr mid-run (previously it printed nothing).
    result = generate_vanity_key(
        "abcd", encoding="hex", workers=2, progress_interval=5000, seed=bytes(32)
    )
    assert result.encoded.startswith("abcd")
    err = capfd.readouterr().err
    assert "attempts=" in err
    assert "rate=" in err


def _load_smoke_browser():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).parent / "tools" / "smoke_browser.py"
    spec = importlib.util.spec_from_file_location("smoke_browser", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_smoke_server_serves_page():
    # Browser-free half of the smoke test: the local server must serve the page.
    import urllib.request
    from pathlib import Path

    mod = _load_smoke_browser()
    server = mod.serve(Path(__file__).parent, 0)
    try:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/index.html", timeout=10) as r:
            body = r.read().decode("utf-8")
        assert "MeshCore Vanity Key Generator" in body
        assert "result-frame" in body or "results" in body
    finally:
        server.shutdown()
        server.server_close()


def _load_check_inline_js():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).parent / "tools" / "check_inline_js.py"
    spec = importlib.util.spec_from_file_location("check_inline_js", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_check_inline_js_extracts_current_page():
    from pathlib import Path

    mod = _load_check_inline_js()
    extracted = mod.extract(Path(__file__).parent)
    assert set(extracted) == {"worker.js", "main.js"}
    assert "await new Promise" in extracted["worker.js"]
    assert "startMining" in extracted["main.js"]


def test_page_js_behaviour():
    """Execute the extracted page/worker JS under node (skipped if absent).

    `node --check` only validates syntax. This runs tools/test_page_js.mjs,
    which asserts real behaviour: formatElapsed output, worker-count
    pluralisation, corrupt-history handling and - the shipped regression -
    that the worker waits for libsodium.ready before touching the crypto API.
    """
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    node = shutil.which("node") or shutil.which("bun")
    if node is None:
        pytest.skip("no node/bun runtime; CI runs tools/test_page_js.mjs directly")

    mod = _load_check_inline_js()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        extracted = mod.extract(Path(__file__).parent)
        for name, src in extracted.items():
            (root / name).write_text(src, encoding="utf-8")
        proc = subprocess.run(
            [node, str(Path(__file__).parent / "tools" / "test_page_js.mjs"),
             str(root / "main.js"), str(root / "worker.js")],
            capture_output=True, text=True, timeout=120,
        )
    assert proc.returncode == 0, (
        f"page JS behaviour tests failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    assert "behaviour checks passed" in proc.stdout, proc.stdout


def test_worker_awaits_libsodium_ready():
    """Regression: libsodium.js is an Emscripten build whose crypto_* wrappers
    only exist after libsodium.ready resolves. Without awaiting it, the worker
    throws "sodium.crypto_sign_seed_keypair is not a function"."""
    from pathlib import Path

    mod = _load_check_inline_js()
    worker = mod.extract(Path(__file__).parent)["worker.js"]
    assert "libsodium.ready" in worker, "worker must await libsodium.ready"
    assert "crypto_sign_seed_keypair" in worker
    # Readiness must be awaited before any crypto call, and guarded by a
    # typeof check so a missing API degrades to a message, not a TypeError.
    assert worker.index("await libsodium.ready") < worker.index("crypto_sign_seed_keypair(")


def test_page_estimates_and_formatting():
    """HTML helpers: singular/plural worker label and humanized elapsed time."""
    import re
    from pathlib import Path

    html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

    # Singular vs plural must be conditional, not a hardcoded "workers".
    assert "numWorkers === 1 ? 'worker' : 'workers'" in html
    assert "1 workers" not in html

    # formatElapsed() powers the "Found in ... attempts (...)" line.
    assert "function formatElapsed(seconds)" in html
    assert "formatElapsed(elapsed)" in html
    assert "'unknown'" in html
    # Guarded against NaN/Infinity/negative input.
    assert "isFinite(seconds)" in html

    # History buttons share one explicit height so labels can't misalign.
    assert ".remove-btn, .clear-all-btn" in html
    assert "height: 40px" in html
    assert "Clear All Keys" in html

    # Ready the page awaits libsodium before touching the crypto API.
    assert "await awaitSodium()" in html or "libsodium.ready" in html
    assert "sodiumIsUsable" in html

    # Sanity: the estimate line still names attempts and keys/s.
    assert re.search(r"Expected attempts: ", html)


def test_check_inline_js_rejects_banned_patterns(tmp_path):
    mod = _load_check_inline_js()
    (tmp_path / "index.html").write_text(
        "const workerCode = `await new Promise`; "
        "<style></style><script>var x = 1;</script>liveEtaStr",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="banned pattern"):
        mod.extract(tmp_path)


def test_benchmark_rate_positive():
    assert _benchmark_rate() > 0


def test_human_duration():
    assert _human_duration(45) == "45s"
    assert _human_duration(90) == "1.5m"
    assert _human_duration(7200) == "2.0h"
    assert _human_duration(172800) == "2.0d"
    assert _human_duration(float("inf")) == "very long"
    assert _human_duration(0) == "unknown"
    assert _human_duration(float("nan")) == "unknown"


class _TtyIn(io.StringIO):
    def isatty(self):
        return True


def test_main_estimator_abort_on_decline(monkeypatch, capsys):
    import sys
    import meshcore_vanity as mv

    monkeypatch.setattr(
        sys, "argv", ["meshcore_vanity.py", "ab", "--encoding", "hex", "--max-attempts", "100000"]
    )
    monkeypatch.setattr(sys, "stdin", _TtyIn("n\n"))
    assert mv.main() == 1
    assert "Aborted." in capsys.readouterr().err


def test_main_estimator_confirm_proceeds(monkeypatch, capsys):
    import sys
    import meshcore_vanity as mv

    monkeypatch.setattr(
        sys, "argv",
        ["meshcore_vanity.py", "ab", "--encoding", "hex", "--max-attempts", "100000",
         "--seed", "00" * 32],
    )
    monkeypatch.setattr(sys, "stdin", _TtyIn("y\n"))
    assert mv.main() == 0
    captured = capsys.readouterr()
    assert "Estimate:" in captured.err
    # Prompt must not leak to stdout: stdout carries only the key.
    assert "Continue?" not in captured.out
    assert captured.out.strip().startswith("ab")


def test_main_force_bypasses_prompt(monkeypatch, capsys):
    import sys
    import meshcore_vanity as mv

    # Impossible bech32 prefix exits 2; with -f no prompt is shown even on a tty.
    monkeypatch.setattr(
        sys, "argv", ["meshcore_vanity.py", "ne", "--encoding", "bech32", "-f"]
    )
    monkeypatch.setattr(sys, "stdin", _TtyIn("y\n"))
    assert mv.main() == 2
    err = capsys.readouterr().err
    assert "Continue?" not in err
    assert "Estimate:" in err


def test_generate_vanity_key_suffix():
    result = generate_vanity_key("ab", encoding="hex", suffix=True, max_attempts=100000)
    assert result.encoded.endswith("ab")


def test_generate_vanity_key_case_sensitive():
    result = generate_vanity_key("ab", encoding="hex", case_insensitive=False, max_attempts=100000)
    assert result.encoded.startswith("ab")


def test_encode_public_key_invalid_encoding():
    priv = nacl.signing.SigningKey.generate()
    pub = priv.verify_key
    with pytest.raises(ValueError, match="unknown encoding"):
        encode_public_key(pub, "invalid")


def test_generate_vanity_key_workers_validation():
    with pytest.raises(ValueError, match="workers must be positive"):
        generate_vanity_key("ab", encoding="hex", workers=0)
    with pytest.raises(ValueError, match="workers must be positive"):
        generate_vanity_key("ab", encoding="hex", workers=-1)
    with pytest.raises(ValueError, match="workers must be <= 256"):
        generate_vanity_key("ab", encoding="hex", workers=257)


def test_generate_vanity_key_batch_verification():
    result = generate_vanity_key("ab", encoding="hex", max_attempts=100000)
    assert result.encoded.startswith("ab")
    assert result.attempts >= 0


# --------------------------------------------------------------------------
# PWA integrity: manifest, icons and the service worker.
#
# These lock in three defects that shipped unnoticed:
#   1. manifest icons were data: URLs -> Chrome refused them, so the app was
#      never installable;
#   2. the service worker was cache-first on a never-bumped cache name, so
#      returning visitors stayed on stale (including buggy) code indefinitely;
#   3. the page advertised a SharedArrayBuffer/COEP speedup that the code never
#      used, backed by a dead _headers file.
# --------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent


def _manifest():
    return json.loads((_REPO_ROOT / "manifest.json").read_text(encoding="utf-8"))


def test_manifest_icons_are_real_same_origin_files():
    """data:/blob: manifest icons are rejected by Chrome -> PWA not installable."""
    manifest = _manifest()
    icons = manifest["icons"]
    assert icons, "manifest declares no icons"

    for icon in icons:
        src = icon["src"]
        assert not src.startswith(("data:", "blob:", "http://", "https://")), (
            f"icon {src!r} must be a same-origin file; data:/blob: URLs and "
            "absolute URLs break PWA installability"
        )
        assert ( _REPO_ROOT / src).is_file(), f"icon file missing: {src}"
        assert icon["type"] == "image/png"
        assert "sizes" in icon, f"icon {src!r} is missing the sizes field"


def _png_size(path: Path) -> tuple[int, int]:
    """Read width/height straight from the PNG IHDR chunk (stdlib only).

    Keeps the icon tests dependency-free so they run anywhere; Pillow is only
    used for the optional full-decode check below.
    """
    with path.open("rb") as fh:
        data = fh.read(33)
    if len(data) < 33:
        raise AssertionError(f"{path.name} is too short to be a PNG")
    assert data[:8] == b"\x89PNG\r\n\x1a\n", f"{path.name} is not a PNG"
    assert data[12:16] == b"IHDR", "first chunk is not IHDR"
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def test_manifest_icon_files_are_valid_pngs_of_declared_size():
    for icon in _manifest()["icons"]:
        path = _REPO_ROOT / icon["src"]
        declared = int(icon["sizes"].split("x")[0])
        assert _png_size(path) == (declared, declared), (
            f"{path.name} is {_png_size(path)} but manifest declares {icon['sizes']}"
        )
        # Truncated files (a classic commit accident) still carry a valid
        # header, so also require the terminating IEND chunk.
        assert path.read_bytes().rstrip()[-8:-4] == b"IEND", (
            f"{path.name} is truncated (no IEND chunk)"
        )


def test_manifest_icon_files_decode_fully():
    """Full decode: catches corruption the header check cannot see."""
    Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")
    for icon in _manifest()["icons"]:
        im = Image.open(_REPO_ROOT / icon["src"])
        im.load()
        assert im.format == "PNG"
        assert im.size == (int(icon["sizes"].split("x")[0]),) * 2


def test_manifest_provides_maskable_and_any_icons():
    """Android crops an 'any' icon badly; a maskable variant is required."""
    purposes = set()
    for icon in _manifest()["icons"]:
        purposes |= set(icon.get("purpose", "any").split())
    assert "any" in purposes
    assert "maskable" in purposes, "no maskable icon declared"


def test_manifest_start_url_is_relative():
    """An absolute '/' start_url breaks hosting under a subpath (GitHub Pages)."""
    assert _manifest()["start_url"] == "."
    assert _manifest()["scope"] == "."


def test_manifest_colors_match_page_theme():
    """A mismatched theme_color repaints the browser chrome on install."""
    manifest = _manifest()
    html = (_REPO_ROOT / "index.html").read_text(encoding="utf-8")
    assert manifest["background_color"] == "#0d1117"
    assert manifest["theme_color"] == "#161b22"
    assert f'<meta name="theme-color" content="{manifest["theme_color"]}">' in html


def test_index_html_declares_icon_links():
    html = (_REPO_ROOT / "index.html").read_text(encoding="utf-8")
    # iOS ignores manifest icons for the home screen; it needs the link tag.
    assert 'rel="apple-touch-icon"' in html
    assert 'rel="icon"' in html
    assert 'rel="manifest"' in html


def test_no_sharedarraybuffer_speedup_claim_without_support():
    """The page must not promise a SharedArrayBuffer speedup it does not use."""
    html = (_REPO_ROOT / "index.html").read_text(encoding="utf-8")
    assert "SharedArrayBuffer" not in html
    assert "COOP" not in html and "COEP" not in html
    # And there is no dead header config left behind.
    assert not (_REPO_ROOT / "_headers").exists()


def test_service_worker_precache_paths_all_exist():
    """A missing precache entry makes cache.addAll() reject -> SW never installs."""
    sw = (_REPO_ROOT / "sw.js").read_text(encoding="utf-8")
    block = sw.split("urlsToCache", 1)[1].split("]", 1)[0]
    urls = re.findall(r"'([^']+)'", block)
    assert urls, "could not parse urlsToCache from sw.js"

    for url in urls:
        assert url.startswith("/"), f"{url} should be root-relative"
        if url == "/":
            continue  # the app root
        assert (_REPO_ROOT / url.lstrip("/")).is_file(), (
            f"sw.js precaches {url!r} but no such file is in the repo"
        )


def test_service_worker_is_not_cache_first():
    """Regression guard: cache-first pinned users to stale code forever."""
    sw = (_REPO_ROOT / "sw.js").read_text(encoding="utf-8")
    assert "CACHE_VERSION" in sw, "cache version is not parameterised"
    # Must hand back the cached copy *and* refresh in the background.
    assert "event.waitUntil(network" in sw, (
        "service worker no longer revalidates in the background; users would "
        "be pinned to whatever was cached first"
    )


def test_service_worker_ignores_non_get_requests():
    sw = (_REPO_ROOT / "sw.js").read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", sw)
    assert "request.method !== 'GET'" in code


def test_service_worker_has_offline_navigation_fallback():
    sw = (_REPO_ROOT / "sw.js").read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", sw)
    assert "request.mode === 'navigate'" in code
    assert "index.html" in code


def test_service_worker_precache_tolerates_partial_failure():
    """cache.addAll() is all-or-nothing; individual adds degrade gracefully."""
    sw = (_REPO_ROOT / "sw.js").read_text(encoding="utf-8")
    # Strip line comments first: the file documents *why* addAll() is avoided,
    # and that prose must not trip the assertion below.
    code = re.sub(r"//[^\n]*", "", sw)
    assert "cache.addAll" not in code, (
        "addAll() rejects wholesale on a single failure, leaving the service "
        "worker permanently uninstalled"
    )
    assert ".catch(" in code


def test_committed_icons_match_generator():
    """The checked-in PNGs must be reproducible from tools/make_icons.py.

    Without this, editing the icon design and forgetting to re-run the script
    would silently ship stale assets.
    """
    make_icons = _load_make_icons()

    def render(draw_fn, size):
        buf = io.BytesIO()
        draw_fn(size).save(buf, format="PNG", optimize=True)
        return buf.getvalue()

    for size in make_icons.SIZES:
        name = f"icon-{size}.png"
        assert (_REPO_ROOT / name).read_bytes() == render(make_icons.draw_icon, size), (
            f"{name} is out of date; re-run `python tools/make_icons.py`"
        )

    name = f"icon-maskable-{make_icons.MASKABLE_SIZE}.png"
    assert (_REPO_ROOT / name).read_bytes() == render(
        make_icons.draw_maskable, make_icons.MASKABLE_SIZE
    ), f"{name} is out of date; re-run `python tools/make_icons.py`"


def _load_make_icons():
    import importlib.util

    pytest.importorskip("PIL.Image", reason="Pillow needed to render icons")
    path = _REPO_ROOT / "tools" / "make_icons.py"
    spec = importlib.util.spec_from_file_location("make_icons", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


if __name__ == "__main__":
    pytest.main([__file__, "-v"])