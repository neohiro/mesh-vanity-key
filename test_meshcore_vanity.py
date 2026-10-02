#!/usr/bin/env python3
"""Tests for meshcore_vanity.py"""

import base64
import io
import json
import multiprocessing
import os
import re
import struct
import sys
import warnings
from pathlib import Path

import pytest

import meshcore_vanity
from meshcore_vanity import (
    encode_public_key,
    generate_vanity_key,
    _base58_encode,
    _bech32_encode,
    _benchmark_rate,
    _expected_attempts,
    _format_progress,
    _human_duration,
    _allow_reserved,
    _default_workers,
    _PARALLEL_MIN_SECONDS,
    format_elapsed,
    format_eta,
    format_day_hint,
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


@pytest.mark.parametrize("bad", ["0", "-1", "257", "999"])
def test_main_rejects_invalid_workers_before_estimating(monkeypatch, capsys, bad):
    import meshcore_vanity as mv

    # A nonsensical --workers must fail immediately. Printing "~-33,011 keys/s"
    # or a bogus "ETA ~very long" and only erroring after the user confirmed
    # was both wrong and wasted their time.
    monkeypatch.setattr(
        sys,
        "argv",
        ["meshcore_vanity.py", "ab", "--encoding", "hex", "--workers", bad, "--force"],
    )
    assert mv.main() == 2
    err = capsys.readouterr().err
    assert "--workers" in err, err
    # No estimate may be printed for a value that cannot be used.
    assert "Estimate:" not in err, err
    assert "keys/s" not in err, err


def test_main_accepts_valid_workers(monkeypatch, capsys):
    import meshcore_vanity as mv

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meshcore_vanity.py", "ab", "--encoding", "hex",
            "--workers", "1", "--max-attempts", "100000", "--force",
        ],
    )
    assert mv.main() == 0
    assert capsys.readouterr().out.strip().startswith("ab")


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


def test_validate_prefix_reserved_hex_warns_but_allows():
    # 00/FF prefixes are reserved for MeshCore framework devices. They are
    # still mineable, so validation warns rather than rejecting (this matches
    # the browser's behaviour and the "allow" request).
    with pytest.warns(UserWarning, match="reserved"):
        _validate_prefix("00ab", "hex")
    with pytest.warns(UserWarning, match="reserved"):
        _validate_prefix("FF12", "hex")
    _validate_prefix("ab", "hex")  # non-reserved passes with no warning


def test_validate_prefix_reserved_hex_strict_env_rejects(monkeypatch):
    # Opt-in strict mode restores the hard rejection for CI/scripted use.
    monkeypatch.setenv("MESHCORE_VANITY_STRICT_RESERVED", "1")
    with pytest.raises(ValueError, match="reserved"):
        _validate_prefix("00ab", "hex")


def test_reserved_warning_is_emitted_once(monkeypatch):
    # Library use can validate the same pattern repeatedly (retries, or a
    # wrapper calling generate_vanity_key in a loop). The warning must fire
    # exactly once so output is not spammed.
    monkeypatch.setattr(meshcore_vanity, "_warned_reserved", set())
    counts = []
    for _ in range(5):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _validate_prefix("00ab", "hex")
        counts.append(len(caught))
    assert counts == [1, 0, 0, 0, 0], f"warned on every call: {counts}"
    assert len(meshcore_vanity._warned_reserved) == 1


def test_hot_loop_keygen_matches_pynacl_exactly():
    """The hot loop calls libsodium's seed_keypair; PyNaCl wraps it elsewhere.

    These must agree exactly, or the miner would report a public key that does
    not correspond to the private seed it hands back - a key that matches the
    pattern and cannot be used. This is the correctness invariant behind the
    hot loop bypassing the PyNaCl objects, so it is asserted directly rather
    than inferred from the surrounding tests.
    """
    from nacl import bindings

    seeds = [
        bytes(32),                          # all zero
        b"\xff" * 32,                      # all ones
        bytes([0xFF] * 31 + [0x80]),       # high bit set (clamping territory)
        bytes([0xFF] * 32),                # counter wrap case
        os.urandom(32),
    ]
    for seed in seeds:
        via_pynacl = bytes(nacl.signing.SigningKey(seed).verify_key)
        via_hot_loop = bindings.crypto_sign_seed_keypair(seed)[0]
        assert via_pynacl == via_hot_loop, f"seed {seed.hex()}: keys differ"
        assert len(via_hot_loop) == 32, "public key must be 32 bytes"


def test_hot_loop_keygen_matches_pynacl_over_random_seeds():
    from nacl import bindings

    for _ in range(50):
        seed = os.urandom(32)
        assert (
            bytes(nacl.signing.SigningKey(seed).verify_key)
            == bindings.crypto_sign_seed_keypair(seed)[0]
        ), f"seed {seed.hex()}: keys differ"


def test_third_party_imports_are_declared_in_requirements():
    """Every non-stdlib module imported by our code must be in requirements.txt.

    Regression: CI was switched to `pip install -r requirements.txt` while that
    file listed only PyNaCl/Pillow/PyYAML, so pytest - installed explicitly
    before - was missing and every run died with "No module named pytest". A
    dependency used by the suite but absent from the manifest is invisible until
    CI runs, and CI is not the place to discover it.
    """
    import ast
    import sys

    root = Path(__file__).resolve().parent
    sources = [root / "meshcore_vanity.py", root / "test_meshcore_vanity.py"]
    sources += sorted((root / "tools").glob("*.py"))

    stdlib = set(sys.stdlib_module_names)
    imported = set()
    for src in sources:
        if not src.exists():
            continue
        tree = ast.parse(src.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imported.add(a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    imported.add(node.module.split(".")[0])

    third_party = {
        m for m in imported
        if m not in stdlib
        # Local helper modules loaded by path, not installed packages.
        and m not in {"meshcore_vanity", "check_inline_js", "make_icons",
                      "smoke_browser", "bench_mining"}
    }

    declared = {
        line.split(">=")[0].split("==")[0].split("~=")[0].split("[")[0].strip()
        for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    # Distribution name -> import name. Several distributions are importable
    # under a different name, so normalise both sides before comparing.
    import_name = {"pillow": "PIL", "pynacl": "nacl", "pyyaml": "yaml"}
    provided = set(declared)
    provided.update(
        import_name[d.lower()] for d in declared if d.lower() in import_name
    )

    # Deliberately NOT in requirements.txt, each for a reason:
    #   cryptography - optional; only tools/bench_mining.py compares backends,
    #     inside a try/except that skips the comparison when it is absent.
    #   playwright   - optional; only tools/smoke_browser.py needs it, and the
    #     smoke CI job installs it in its own step.
    # Listed explicitly so a NEW undeclared import still fails this test.
    optional = {"cryptography", "playwright"}

    missing = sorted(m for m in third_party if m not in optional and m not in provided)
    assert not missing, (
        f"imported but not declared in requirements.txt: {missing}. "
        f"provided: {sorted(provided)}; explicitly-optional: {sorted(optional)}"
    )


def test_require_fails_loudly_for_missing_test_dependency():
    """_require must FAIL, never skip, when a declared dep is absent.

    This is the property that keeps the icon and workflow-integrity guards from
    silently going inert while the build stays green. A CI run on this repo was
    red with `1 failed, 89 passed, 3 skipped`, where the three skips were these
    guards themselves, because CI lacked PyYAML.
    """
    with pytest.raises(BaseException) as exc:
        _require("definitely_not_installed_xyz", "FakePackage")
    assert "FakePackage" in str(exc.value)
    assert "requirements.txt" in str(exc.value)


def test_declared_test_dependencies_are_importable():
    # Guards the environment itself: Pillow and PyYAML are declared in
    # requirements.txt, so a bare environment that lacks them is broken.
    import importlib

    for mod, pkg in (("PIL.Image", "Pillow"), ("yaml", "PyYAML")):
        try:
            importlib.import_module(mod)
        except ImportError as e:
            pytest.fail(f"{pkg} is declared in requirements.txt but missing: {e}")


def test_ci_workflow_only_uses_provisioned_runtimes():
    """A `run:` step must invoke a runtime the workflow actually installs.

    Regression: a step was added invoking `bun`, which is not present on GitHub
    runners, while the workflow only installs Node via setup-node. That step
    would have failed with "command not found" - and CI had never run, so
    nothing would have caught it locally.

    This asserts each interpreter named in a `run:` line is either the runner's
    built-in default (python) or is explicitly set up in the same workflow.
    """
    yaml = _require("yaml", "PyYAML")

    wf = Path(__file__).resolve().parent / ".github" / "workflows" / "ci.yml"
    assert wf.exists(), f"missing workflow: {wf}"
    doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
    assert doc.get("jobs"), "workflow defines no jobs"

    # Runtimes a bare ubuntu-latest runner provides without any setup step.
    builtin = {"python", "python3"}

    for job_name, job in doc["jobs"].items():
        steps = job.get("steps", [])
        # What this job provisions.
        provisioned = set(builtin)
        for s in steps:
            uses = s.get("uses", "")
            if "actions/setup-node" in uses:
                provisioned.add("node")
                provisioned.add("npx")
            if "actions/setup-python" in uses:
                provisioned.update({"python", "python3", "pip"})
            if "setup-bun" in uses or "oven-sh/setup-bun" in uses:
                provisioned.add("bun")

        for s in steps:
            run = s.get("run")
            if not run:
                continue
            first = run.strip().split()[0] if run.strip() else ""
            # Only judge invocations that look like a bare interpreter.
            if first in ("python", "python3", "node", "npx", "bun", "npm"):
                assert first in provisioned, (
                    f"job {job_name!r} step {s.get('name', run)!r} invokes "
                    f"{first!r}, which the job never installs. "
                    f"provisioned: {sorted(provisioned)}"
                )


def test_ci_smoke_job_is_a_required_gate():
    """The Playwright job must stay required, not advisory.

    Every other check runs the page inside a Node vm against mocks, so this is
    the only job that proves the app works in a real browser. A green `test`
    job on its own means nothing about that.
    """
    yaml = _require("yaml", "PyYAML")

    wf = Path(__file__).resolve().parent / ".github" / "workflows" / "ci.yml"
    doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
    jobs = doc["jobs"]

    assert "smoke" in jobs, "the browser smoke job was removed"
    smoke = jobs["smoke"]
    steps = " ".join(str(s.get("run", "")) for s in smoke.get("steps", []))
    assert "smoke_browser.py" in steps, "smoke job no longer runs the browser test"

    # `needs: test` is fine (faster), but the job must not be soft-failing.
    for s in smoke.get("steps", []):
        assert not s.get("continue-on-error"), (
            f"smoke step {s.get('name')!r} is marked continue-on-error; the "
            "browser gate must be able to fail the build"
        )
    assert not smoke.get("continue-on-error"), "smoke job must not be soft-failing"


def test_ci_referenced_repo_files_exist():
    """Every repo file a CI step names must actually exist.

    A renamed or deleted tool that CI still references is the classic way a
    pipeline rots: the step passes locally (where nobody runs it) and fails the
    moment CI executes. This checks the file paths in `run:` lines resolve.
    """
    yaml = _require("yaml", "PyYAML")

    root = Path(__file__).resolve().parent
    wf = root / ".github" / "workflows" / "ci.yml"
    doc = yaml.safe_load(wf.read_text(encoding="utf-8"))

    missing = []
    for job_name, job in doc["jobs"].items():
        for s in job.get("steps", []):
            run = s.get("run")
            if not run:
                continue
            for token in run.replace("|", " ").split():
                token = token.strip("'\"`;")
                if not token.startswith(("tools/", "meshcore_vanity.py",
                                         "test_meshcore_vanity.py", "index.html",
                                         "sw.js", "libsodium.js", "manifest.json")):
                    continue
                if not (root / token).exists():
                    missing.append(f"{job_name}/{s.get('name', '?')}: {token}")

    assert not missing, f"CI references files that do not exist: {missing}"


def test_hot_loops_have_no_dead_local_bindings():
    """The hot loops bind module-level functions to locals for speed.

    That optimisation is easy to leave behind: the refactor that replaced
    PyNaCl's SigningKey with libsodium's seed_keypair in _worker_search left
    an orphan `_SigningKey` binding which nothing referenced. This catches that
    class of leftover statically rather than by eye.
    """
    import ast

    src = Path(__file__).resolve().parent / "meshcore_vanity.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))

    targets = {"_worker_search", "generate_vanity_key"}
    seen = set()
    for fn in ast.walk(tree):
        if not (isinstance(fn, ast.FunctionDef) and fn.name in targets):
            continue
        seen.add(fn.name)
        bound = {}
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        bound[t.id] = node.lineno
        used = {
            n.id for n in ast.walk(fn)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
        }
        dead = {
            name: line for name, line in bound.items()
            if name.startswith("_") and name not in used
        }
        assert not dead, (
            f"{fn.name} has dead local bindings: {dead} "
            f"(remove them or use them)"
        )

    assert seen == targets, f"hot loops not found: {targets - seen}"


def test_version_flag_works_without_a_prefix(monkeypatch, capsys):
    # A stale copy of this script in a parent directory is easy to run by
    # accident and silently uses older behaviour, so --version reports the
    # version AND the resolved path. It must also work without a positional
    # prefix, which is why `prefix` is nargs="?".
    import meshcore_vanity as mv

    monkeypatch.setattr(sys, "argv", ["meshcore_vanity.py", "--version"])
    assert mv.main() == 0
    out = capsys.readouterr().out
    assert mv.__version__ in out, out
    assert "loaded from:" in out, out
    # The printed path must be this file, not some other copy.
    assert out.strip().endswith("meshcore_vanity.py"), out


def test_missing_prefix_is_reported(monkeypatch, capsys):
    import meshcore_vanity as mv

    monkeypatch.setattr(
        sys, "argv", ["meshcore_vanity.py", "--encoding", "hex"]
    )
    assert mv.main() == 2
    err = capsys.readouterr().err
    assert "prefix is required" in err, err
    # Must not print a traceback or a bare argparse usage dump.
    assert "Traceback" not in err, err
    assert "usage:" not in err, err


def test_default_workers_uses_all_cores():
    # --workers used to default to 1, leaving every other core idle. The search
    # is ~99% scalar multiplication with no shared state, so cores are free.
    n = _default_workers()
    assert n >= 1
    assert n <= 64, "must stay within the pool's own limit"
    assert n <= multiprocessing.cpu_count() or n == 1


def test_default_workers_never_exceeds_one():
    # Degrades safely where cpu_count() is unavailable.
    import meshcore_vanity as mv

    orig = mv.mp.cpu_count
    try:
        mv.mp.cpu_count = lambda: 0
        assert mv._default_workers() == 1
    finally:
        mv.mp.cpu_count = orig


def test_parallel_min_seconds_is_positive():
    # Guards the serial/parallel crossover constant: a non-positive value would
    # send every search through a multiprocessing pool, which is far slower for
    # short prefixes.
    assert _PARALLEL_MIN_SECONDS > 0.0


def test_allow_reserved_only_for_explicit_hex_request():
    # A reserved hex prefix opts in; anything else must not.
    assert _allow_reserved("00ab", "hex")
    assert _allow_reserved("ff12", "hex")
    assert not _allow_reserved("ab", "hex")
    assert not _allow_reserved("0", "hex")
    assert not _allow_reserved("", "hex")
    # Non-hex encodings can never target a 00/FF hex prefix.
    assert not _allow_reserved("00ab", "base64")
    assert not _allow_reserved("00ab", "bech32")


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


def test_format_day_hint_uses_half_day_steps():
    assert format_day_hint(30) == ""
    assert format_day_hint(86400 - 1) == ""          # just under a day
    assert format_day_hint(86400) == " (~1 day)"
    assert format_day_hint(86400 * 1.4) == " (~1.5 days)"
    assert format_day_hint(86400 * 2.5) == " (~2.5 days)"
    assert format_day_hint(86400 * 9.9) == " (~10 days)"
    # Beyond ~10 days the estimate is too uncertain to state; withhold it.
    assert format_day_hint(86400 * 10.5) == ""
    assert format_day_hint(0) == ""
    assert format_day_hint(-5) == ""
    assert format_day_hint(float("inf")) == ""
    assert format_day_hint(float("nan")) == ""


def test_format_eta_appends_day_hint():
    assert format_eta(30) == "30.0s"
    assert format_eta(86400) == "24h 0m 0s (~1 day)"
    assert format_eta(86400 * 2.5) == "60h 0m 0s (~2.5 days)"
    # Under a day nothing is appended.
    assert "(~" not in format_eta(3600)


def test_progress_line_uses_eta_with_day_hint():
    # A search expected to take a few days should show the day hint. 262,144
    # attempts at 1/s is ~2.9 days - inside the window where the hint applies.
    # (16**5 would be ~12 days, past the 10-day cutoff, where the hint is
    # deliberately withheld as false precision.)
    s = _format_progress(1, 1.0, 262_144)
    assert "eta=" in s, s
    assert "(~" in s, f"long ETA should carry a day hint: {s}"
    assert "days" in s, s
    # A sub-day ETA must NOT carry a hint.
    short = _format_progress(1, 1.0, 16**4)   # ~18h
    assert "(~" not in short, short
    # Nor may a hopeless (>10 day) one.
    absurd = _format_progress(1, 1.0, 16**6)
    assert "(~" not in absurd, absurd


def test_format_progress():
    s = _format_progress(1000, 2.0, 10000)
    assert "attempts=1,000" in s
    assert "rate=500/s" in s
    assert "elapsed=2.0s" in s
    assert "progress=10.00%" in s
    # Past the expected mean the overshoot is shown with a "+" prefix rather
    # than being clamped: ~37% of searches legitimately run past 100%.
    over = _format_progress(200000, 1.0, 65536)
    assert "progress=+305.18%" in over
    # Past the mean the naive remaining time is negative. It must never be
    # rendered as a negative ETA, and must not simply vanish: report the
    # overshoot share and duration instead.
    assert "eta=-" not in over
    assert "past expected" in over, over
    assert "over)" in over, over
    # Zero elapsed never divides by zero.
    assert "rate=0/s" in _format_progress(0, 0.0, 100)


def test_format_progress_unknown_expectation():
    # 16**n overflows to infinity for very long patterns. Reporting
    # progress=0.00% with a confident "no time remaining" would be misleading.
    s = _format_progress(500, 10.0, float("inf"))
    assert "eta=unknown" in s, s
    assert "NaN" not in s and "inf" not in s


def test_format_progress_zero_rate_is_explicit():
    s = _format_progress(0, 0.0, 1000)
    assert "rate=0/s" in s
    assert "eta=unknown" in s
    assert "NaN" not in s


def test_format_elapsed_units():
    assert format_elapsed(0.0) == "0.0s"
    assert format_elapsed(42.34) == "42.3s"
    assert format_elapsed(59.99) == "60.0s"
    assert format_elapsed(60.0) == "1m 0s"
    assert format_elapsed(130.0) == "2m 10s"
    assert format_elapsed(3600.0) == "1h 0m 0s"
    assert format_elapsed(3729.0) == "1h 2m 9s"
    assert format_elapsed(127453.4) == "35h 24m 13s"
    # Long searches must never render as raw seconds.
    assert "s" in format_elapsed(127453.4) and "h" in format_elapsed(127453.4)
    # Invalid input degrades gracefully.
    assert format_elapsed(-1) == "unknown"
    assert format_elapsed(float("nan")) == "unknown"
    assert format_elapsed(float("inf")) == "unknown"


def test_progress_elapsed_uses_human_units():
    s = _format_progress(1000, 3729.0, 1000000)
    assert "elapsed=1h 2m 9s" in s
    assert "3729.0s" not in s


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


def test_worker_wrapper_throughput_is_not_the_bottleneck():
    """Regression guard for the mining loop's own overhead.

    The shipped worker used to yield via setTimeout(0) every 16 candidates and
    rebuilt hex strings per candidate. Browsers clamp nested timers to >=4ms, so
    the wrapper capped a worker at a few thousand keys/s *regardless of
    libsodium* - measured at 9,182 keys/s with a stubbed (free) keygen.

    Here the keygen is stubbed too, so the number reflects wrapper cost alone.
    A regression to per-batch timers or per-candidate string building drops this
    by three orders of magnitude and fails the test.
    """
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    runtime = shutil.which("node") or shutil.which("bun")
    if runtime is None:
        pytest.skip("no node/bun runtime available")

    mod = _load_check_inline_js()
    with tempfile.TemporaryDirectory() as tmp:
        worker = Path(tmp) / "worker.js"
        worker.write_text(mod.extract(Path(__file__).parent)["worker.js"], encoding="utf-8")
        proc = subprocess.run(
            [runtime, str(Path(__file__).parent / "tools" / "bench_worker.mjs"), str(worker)],
            capture_output=True, text=True, timeout=180,
        )

    assert proc.returncode == 0, (
        f"worker benchmark failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    m = re.search(r"throughput: ([\d,]+) keys/s", proc.stdout)
    assert m, f"could not parse benchmark output: {proc.stdout!r}"
    rate = int(m.group(1).replace(",", ""))

    # Same floor as tools/bench_worker.mjs. A shared CI vCPU measured 2,733,763/s
    # against ~10-13M/s on a dev machine, so a threshold tuned locally does not
    # transfer - 3M kept turning CI red. 1M is ~2.7x below the slowest observed
    # runner and still 109x above the 9,182/s catastrophic regression, which is
    # the case that mattered: at that speed the wrapper costs about as much as
    # real key derivation (~13.5k/s) and mining becomes ~1000x slower.
    assert rate > 1_000_000, (
        f"worker wrapper overhead regressed: only {rate:,} keys/s with a stubbed "
        "keygen; the wrapper is the bottleneck again (expected >1,000,000)"
    )


def test_invalid_character_error_explains_allowed_and_why():
    """The rejection must teach, not just scold: what is allowed, and why."""
    with pytest.raises(ValueError) as exc:
        _validate_prefix("xyz", "hex")
    msg = str(exc.value)
    assert "invalid characters" in msg
    assert "'x'" in msg and "'y'" in msg
    # What is allowed...
    assert "0-9 and a-f" in msg
    # ...and why only those.
    assert "64 hexadecimal digits" in msg
    assert "can never occur" in msg

    with pytest.raises(ValueError) as exc2:
        _validate_prefix("ab!", "base64")
    msg2 = str(exc2.value)
    assert "Allowed for base64" in msg2
    assert "+ and /" in msg2


def test_suffix_mode_labels_the_argument_as_suffix():
    with pytest.raises(ValueError, match="suffix contains invalid characters"):
        generate_vanity_key("gg", encoding="hex", suffix=True, max_attempts=10)
    with pytest.raises(ValueError, match="prefix contains invalid characters"):
        generate_vanity_key("gg", encoding="hex", max_attempts=10)


def test_suffix_mode_too_long_reports_suffix():
    with pytest.raises(ValueError, match="suffix too long"):
        generate_vanity_key("a" * 70, encoding="hex", suffix=True, max_attempts=10)


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

    Compares DECODED PIXELS, not file bytes. An earlier version compared bytes
    and passed locally while failing in CI: PNG output is a lossy function of
    the encoder, so the zlib build, Pillow version and platform all change the
    bytes for identical artwork. That made the test report "icon is stale" when
    the artwork was in fact current. Pixel equality is the invariant that
    actually expresses the intent, and it is stable across environments.
    """
    from PIL import Image

    make_icons = _load_make_icons()

    def pixels(draw_fn, size):
        # Rendered through an in-memory buffer rather than a temp file: on
        # Windows a NamedTemporaryFile stays locked and PIL cannot reopen it.
        buf = io.BytesIO()
        draw_fn(size).save(buf, format="PNG")
        buf.seek(0)
        with Image.open(buf) as img:
            return img.size, img.convert("RGBA").tobytes()

    def assert_matches(name, draw_fn, size):
        path = _REPO_ROOT / name
        assert path.exists(), f"{name} is missing"
        with Image.open(path) as committed:
            actual = (committed.size, committed.convert("RGBA").tobytes())
        expected = pixels(draw_fn, size)
        assert actual == expected, (
            f"{name} artwork is out of date; re-run `python tools/make_icons.py`"
        )

    for size in make_icons.SIZES:
        assert_matches(f"icon-{size}.png", make_icons.draw_icon, size)

    assert_matches(
        f"icon-maskable-{make_icons.MASKABLE_SIZE}.png",
        make_icons.draw_maskable,
        make_icons.MASKABLE_SIZE,
    )


def test_index_html_has_history_obfuscation():
    html = (_REPO_ROOT / "index.html").read_text(encoding="utf-8")
    assert "encryptHistoryData" in html
    assert "decryptHistoryData" in html
    assert "OBFUSCATION_KEY_STORAGE" in html
    assert "0xef" in html  # obfuscation marker


def _require(module: str, package: str):
    """Import a declared test dependency, failing loudly if it is absent.

    Deliberately NOT pytest.importorskip. A skip is reported as a pass-ish
    green build, so a missing Pillow or PyYAML would leave the icon check and
    the workflow-integrity guards silently inert - exactly the failure they
    exist to catch. Both are declared in requirements.txt, so their absence is
    a broken environment and should say so.
    """
    import importlib

    try:
        return importlib.import_module(module)
    except ImportError as e:
        pytest.fail(
            f"{package} is a declared test dependency (see requirements.txt). "
            f"Run `pip install -r requirements.txt`. Original error: {e}"
        )


def _load_make_icons():
    """Load the icon generator, failing loudly when Pillow is missing."""
    import importlib.util

    _require("PIL.Image", "Pillow")
    path = _REPO_ROOT / "tools" / "make_icons.py"
    spec = importlib.util.spec_from_file_location("make_icons", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


if __name__ == "__main__":
    pytest.main([__file__, "-v"])