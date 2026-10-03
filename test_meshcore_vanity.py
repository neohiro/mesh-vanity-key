#!/usr/bin/env python3
"""Tests for meshcore_vanity.py"""

import base64
import hashlib
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
    _BECH32_CHECKSUM_LEN,
    _BECH32_LAST_DATA_VALUES,
    _base58_encode,
    _bech32_encode,
    _bech32_last_data_offset,
    _benchmark_rate,
    _end_search_space,
    _estimate_search_space,
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
    _validate_suffix_reachable,
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


def test_required_status_check_contexts_match_real_job_names():
    """Branch protection must not require a check that can never be reported.

    This bit, and it is invisible to every other test in this file. Branch
    protection on `main` requires a status check context named `ci`, but
    GitHub reports check runs named after each JOB's `name:`, not after the
    workflow's `name:`. ci.yml declares `name: ci` while its jobs report as
    `test` and `Browser smoke (required)`, so no check run is ever called `ci`
    and the required context can never be satisfied. Every PR to this repo is
    therefore permanently unmergeable, review or not - it reads as "awaiting
    review" when the real blocker is unsatisfiable.

    The fix belongs in the repo, not in a test-only workaround, so this asserts
    the invariant: every required context must equal some job's reported name
    (its `name:` if set, otherwise the YAML key).

    Reads live branch protection when a token is available, since that is the
    authoritative source. Skips otherwise - it is a network-dependent check and
    must never be the reason a local run fails.
    """
    import os
    import urllib.error
    import urllib.request

    yaml = _require("yaml", "PyYAML")

    root = Path(__file__).resolve().parent
    doc = yaml.safe_load(
        (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    jobs = doc.get("jobs") or {}
    # A check run is named after the job's `name:`, falling back to the YAML key.
    reported = {job.get("name") or key for key, job in jobs.items()}

    protection = None
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        req = urllib.request.Request(
            "https://api.github.com/repos/neohiro/meshcore-vanity-key"
            "/branches/main/protection",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                protection = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError):
            protection = None
    else:
        # Fall back to the gh CLI, which handles its own auth.
        import shutil
        import subprocess

        if shutil.which("gh"):
            try:
                proc = subprocess.run(
                    ["gh", "api",
                     "repos/neohiro/meshcore-vanity-key/branches/main/protection"],
                    capture_output=True, text=True, timeout=60,
                )
            except (OSError, subprocess.SubprocessError):
                proc = None
            if proc is not None and proc.returncode == 0:
                try:
                    protection = json.loads(proc.stdout)
                except ValueError:
                    protection = None

    if protection is None:
        pytest.skip(
            "no GitHub API access (no GH_TOKEN/GITHUB_TOKEN and no working "
            "`gh api`); cannot read branch protection"
        )

    required = ((protection.get("required_status_checks") or {}).get("contexts")) or []
    if not required:
        pytest.skip("no required status checks configured")

    unsatisfiable = [c for c in required if c not in reported]
    assert not unsatisfiable, (
        f"branch protection requires status check(s) {unsatisfiable}, but ci.yml "
        f"only ever reports {sorted(reported)}. A required context that no check "
        "run can ever satisfy makes EVERY pull request permanently unmergeable. "
        "Fix by setting the required contexts to the real job names (or renaming "
        "a job), via: gh api --method PUT "
        "repos/neohiro/meshcore-vanity-key/branches/main/protection"
    )


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
    assert "pattern is required" in err, err
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


def test_pyproject_version_matches_the_reported_version() -> None:
    """pyproject and --version must not drift apart.

    pyproject.toml carries the version the package is built and installed as,
    which is what the one-line online install resolves. meshcore_vanity.__version__
    is what `--version` prints. A release that bumped one and not the other would
    install one version and advertise another.
    """
    from pathlib import Path

    import tomllib

    root = Path(__file__).parent
    pyproject = root / "pyproject.toml"
    assert pyproject.exists(), "pyproject.toml is needed for the online install"
    with pyproject.open("rb") as fh:
        data = tomllib.load(fh)
    assert data["project"]["version"] == meshcore_vanity.__version__, (
        f"pyproject {data['project']['version']} != "
        f"__version__ {meshcore_vanity.__version__}"
    )
    # The console script is the whole point of the online install; if it is
    # renamed there, the documented one-liner breaks.
    scripts = data["project"]["scripts"]
    assert "meshcore-vanity" in scripts, scripts
    assert scripts["meshcore-vanity"] == "meshcore_vanity:main", scripts


def test_the_online_install_needs_only_pynacl() -> None:
    """Installing must not drag in the test tooling."""
    from pathlib import Path

    import tomllib

    with (Path(__file__).parent / "pyproject.toml").open("rb") as fh:
        deps = tomllib.load(fh)["project"]["dependencies"]
    names = " ".join(deps).lower()
    for test_only in ("pytest", "ruff", "pillow"):
        assert test_only not in names, f"{test_only} must stay in requirements.txt"
    assert "pynacl" in names, deps


def test_parallel_workers_honour_a_separate_suffix_pattern() -> None:
    """The spawn path must carry the suffix pattern to the child processes.

    The worker receives its arguments as a positional tuple that is unpacked in
    the child. Adding the suffix arguments shifted that tuple, and a mismatch
    between the order it is built in and the order it is unpacked would only
    surface at run time as a spawn error - the single-threaded tests all pass
    either way, because they never build the tuple.
    """
    result = generate_vanity_key(
        "a", encoding="hex", suffix_pattern="b", max_attempts=400_000, workers=4
    )
    assert result.encoded.startswith("a"), result.encoded
    assert result.encoded.endswith("b"), result.encoded


def test_parallel_workers_honour_both_ends_modes() -> None:
    """--both and bare --suffix must survive the trip through spawn too."""
    both = generate_vanity_key(
        "a", encoding="hex", both=True, max_attempts=400_000, workers=4
    )
    assert both.encoded.startswith("a") and both.encoded.endswith("a"), both.encoded
    tail = generate_vanity_key(
        "b", encoding="hex", suffix=True, max_attempts=400_000, workers=4
    )
    assert tail.encoded.endswith("b"), tail.encoded


def test_conflicting_modes_are_rejected_before_anything_is_printed() -> None:
    """The tool must not announce a search it is about to refuse.

    `--suffix cd --both` used to print "starting AND ending with 'ab'" and only
    then report that the flags contradict, which reads as though the search had
    begun. main() already validates --workers up front for the same reason.
    """
    for argv in (
        ["ab", "--suffix", "cd", "--both"],
        ["ab", "--suffix", "--both"],
    ):
        proc = _run_cli(*argv, "--force", "--max-attempts", "3000")
        assert proc.returncode == 2, (argv, proc.stderr)
        assert "Searching for" not in proc.stderr, (
            f"{argv} announced a search before rejecting itself:\n{proc.stderr}"
        )
        assert "Estimate:" not in proc.stderr, (
            f"{argv} quoted an estimate before rejecting itself:\n{proc.stderr}"
        )
        assert proc.stdout.strip() == "", (
            f"{argv} printed a key it never searched for:\n{proc.stdout}"
        )


def test_the_suffix_flag_does_not_swallow_a_following_option() -> None:
    """`--suffix` takes an optional value, so it must not eat the next flag.

    argparse will happily use a following token as the value; a bare `--suffix`
    followed by another option has to stay a bare `--suffix`.
    """
    proc = _run_cli(
        "ab", "--suffix", "--encoding", "hex",
        "--max-attempts", "400000", "--force",
    )
    assert proc.returncode == 0, proc.stderr
    assert "ending with 'ab'" in proc.stderr, proc.stderr
    data = proc.stdout.strip()
    assert data.endswith("ab"), data

    # And with a value it must consume exactly that value. hex is used because
    # every hex digit is reachable at every position, whereas a base64 suffix
    # ending in an unreachable final character can never match at all.
    proc2 = _run_cli(
        "a", "--suffix", "c", "--encoding", "hex",
        "--max-attempts", "400000", "--force",
    )
    assert proc2.returncode == 0, proc2.stderr
    assert "starting with 'a' AND ending with 'c'" in proc2.stderr, proc2.stderr
    assert proc2.stdout.strip().startswith("a"), proc2.stdout
    assert proc2.stdout.strip().endswith("c"), proc2.stdout


def test_the_derived_reachable_set_matches_reality() -> None:
    """The reachable-final-character set is derived, so check the derivation.

    32 bytes is 256 bits and base64 spends 6 per character, so the 43rd data
    character carries 4 significant bits and its low two bits are always zero:
    its alphabet index must be a multiple of 4. That derivation is cheap but it
    is the whole basis for rejecting a suffix as impossible, so it is checked
    against real encodings rather than trusted.
    """
    import base64 as _b64
    import os as _os

    from meshcore_vanity import _base64_final_chars

    reachable = _base64_final_chars()
    assert len(reachable) == 16, sorted(reachable)
    observed = {_b64.b64encode(_os.urandom(32)).decode()[42] for _ in range(3000)}
    # A sample can miss a character that is merely rare, but it must never
    # produce one the derivation says is impossible.
    assert observed <= reachable, sorted(observed - reachable)
    assert len(observed) == 16, (
        f"expected all 16 reachable characters in 3000 keys, saw {sorted(observed)}"
    )


def test_an_unreachable_base64_suffix_is_refused_rather_than_searched() -> None:
    """An impossible suffix must fail immediately, not run until killed.

    'b' is alphabet index 27, and 27 is not a multiple of 4, so no 32-byte key
    can end with it. Searching for one would loop forever.
    """
    for kwargs in (
        {"suffix_pattern": "b"},
        {"suffix_pattern": "7f"},
        {"suffix": True},  # bare --suffix uses the prefix as the pattern
    ):
        pattern = "b" if kwargs.get("suffix") else next(iter(kwargs.values()))
        with pytest.raises(ValueError, match="can never match a base64 key"):
            generate_vanity_key(
                pattern, encoding="base64", max_attempts=1, **kwargs
            )

    # Reachable final characters must NOT be refused. A single attempt will
    # usually be exhausted (a 1-char base64 suffix carries only 4 bits), and
    # that RuntimeError is the correct outcome - what must not happen is the
    # ValueError above.
    from meshcore_vanity import _base64_final_chars
    for ch in sorted(_base64_final_chars()):
        try:
            generate_vanity_key(
                "a", encoding="base64", suffix_pattern=ch, max_attempts=1
            )
        except RuntimeError:
            pass


def test_the_unreachable_suffix_is_reported_before_the_search_starts() -> None:
    """It must not print the search line and estimate first."""
    proc = _run_cli("ab", "--suffix", "b", "--force", "--max-attempts", "100")
    assert proc.returncode == 2, proc.stderr
    assert "Searching for" not in proc.stderr, proc.stderr
    assert "Estimate:" not in proc.stderr, proc.stderr
    assert "can never match a base64 key" in proc.stderr, proc.stderr


def test_hex_suffixes_are_never_refused_for_reachability() -> None:
    """Every hex digit is reachable at every position, so none may be rejected."""
    for ch in "0123456789abcdefABCDEF":
        result = generate_vanity_key(
            "a", encoding="hex", suffix_pattern=ch, max_attempts=200_000
        )
        assert result.encoded.startswith("a"), result.encoded
        assert result.encoded.endswith(ch.lower()), result.encoded


def test_expected_attempts():
    # Only the start is constrained.
    assert _estimate_search_space("hex", 2, None) == 16**2
    assert _estimate_search_space("base64", 1, None) == 64
    assert _estimate_search_space("base58", 1, None) == 58
    assert _estimate_search_space("bech32", 1, None) == 32
    # Both ends multiply, they do not add. For hex and base58 the end alphabet
    # is the same as the start, so this is simply the product.
    assert _estimate_search_space("hex", 2, 2) == 16**4
    assert _estimate_search_space("hex", 2, 3) == 16**5
    assert _estimate_search_space("base58", 2, 2) == 58**4
    # A base64 suffix is cheaper than a base64 prefix of the same length,
    # because the key's final character only carries 4 significant bits. The
    # reduction applies to the LAST character of the pattern only.
    assert _estimate_search_space("base64", 2, 2) == 64**2 * 64 * 16
    assert _estimate_search_space("base64", 0, 1) == 16
    assert _estimate_search_space("base64", 1, 1) == 64 * 16
    assert _estimate_search_space("base64url", 1, 1) == 64 * 16
    # An empty pattern constrains nothing.
    assert _estimate_search_space("hex", 2, 0) == 16**2
    assert _estimate_search_space("hex", 0, 2) == 16**2


def test_the_base64_suffix_estimate_matches_the_reachable_alphabet() -> None:
    """The estimate must agree with what the validator will accept.

    These two used to be derived separately, and disagreed: the estimate charged
    a base64 suffix a full 6 bits per character while the validator rejected
    patterns whose final character only has 4. A pattern the estimate priced as
    reachable could be refused outright.
    """
    from meshcore_vanity import _base64_final_chars

    reach = _base64_final_chars()
    # A 1-character suffix costs exactly the number of reachable characters,
    # because that character is the final one.
    assert _estimate_search_space("base64", 0, 1) == len(reach)
    # And a 2-character suffix costs (any of 64) x (the reachable subset).
    assert _estimate_search_space("base64", 0, 2) == 64 * len(reach)


def test_the_preflight_estimate_matches_the_in_search_estimate() -> None:
    """The figure quoted before the search is the one used during it.

    Both go through _estimate_search_space(); this pins the CLI's pre-flight
    line to the same number the progress reporting will use, so they cannot
    drift apart again.
    """
    import re

    for argv in (
        ["abcd"],
        ["abcd", "--both", "--encoding", "hex"],
        ["ab", "--suffix", "Yc"],
        ["ab", "--suffix", "b", "--encoding", "hex"],
    ):
        proc = _run_cli(*argv, "--force", "--max-attempts", "1")
        m = re.search(r"Estimate: ([\d,]+) expected", proc.stderr)
        assert m, proc.stderr
        quoted = int(m.group(1).replace(",", ""))
        encoding = "hex" if "hex" in argv else "base64"
        both = "--both" in argv
        if both:
            n = len(argv[0])
            expected = _estimate_search_space(encoding, n, n)
        elif "--suffix" in argv:
            expected = _estimate_search_space(
                encoding, len(argv[0]), len(argv[argv.index("--suffix") + 1])
            )
        else:
            expected = _estimate_search_space(encoding, len(argv[0]), None)
        assert quoted == expected, (argv, quoted, expected)


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
    assert "elapsed=2.00s" in s
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


def test_format_elapsed_precision_follows_magnitude():
    # Two decimals below 10s, one below a minute, whole inside compound.
    assert format_elapsed(0.0) == "0.00s"
    assert format_elapsed(0.04) == "0.04s"   # was a useless "0.0s"
    assert format_elapsed(9.99) == "9.99s"
    assert format_elapsed(10.0) == "10.0s"
    assert format_elapsed(59.9) == "59.9s"
    assert format_elapsed(60.0) == "1m 0s"


def test_format_elapsed_units():
    assert format_elapsed(0.0) == "0.00s"
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


def test_smoke_eval_snippets_parse():
    """The smoke test's page.evaluate() snippets must be valid JS.

    They are built from adjacent Python string literals, so a stray bracket is
    invisible until Playwright evaluates it -- which only happens in the CI
    browser job, where it fails a required check. That is exactly how a stray
    closing paren got pushed once, so the parse is checked here instead.
    """
    import shutil
    import subprocess
    from pathlib import Path

    node = shutil.which("node") or shutil.which("bun")
    if node is None:
        pytest.skip("no node/bun runtime available to parse the snippets")

    proc = subprocess.run(
        [node, str(Path(__file__).parent / "tools" / "check_eval_snippets.mjs")],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, (
        f"smoke test page.evaluate() snippets do not parse:\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    # The extractor is regex-based, so assert it actually found something to
    # check: silently matching zero snippets would make this test vacuous.
    match = re.search(r"(\d+) parsed", proc.stdout)
    assert match and int(match.group(1)) > 0, (
        f"no page.evaluate() snippets were found to parse: {proc.stdout!r}"
    )
    assert "0 invalid" in proc.stdout, proc.stdout


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
    #
    # The count it conditions on is `shownWorkers`, not `numWorkers`: once the
    # rate is measured the line describes the workers actually running, so a
    # search that lost some to an init failure must not still claim the planned
    # count beside a figure derived from fewer.
    assert "shownWorkers === 1 ? 'worker' : 'workers'" in html
    assert "const shownWorkers = usingLive ? (workers.length || numWorkers) : numWorkers;" in html
    # The facts are newline-separated so the line can break between them; the
    # `|` separators were a desktop affordance that stranded at wrapped line
    # ends and could widen the page on a phone.
    assert "\\nEstimated time: ~" in html
    assert "+ '\\n(' + shownWorkers + ' ' + workerLabel" in html
    assert "white-space: pre-line" in html
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


def test_worker_bench_takes_several_trials_and_reports_the_best():
    """The throughput gate must not depend on one lucky sample.

    A CI run failed `test_worker_wrapper_throughput_is_not_the_bottleneck` at
    921,735 keys/s against the 1,000,000 floor on a commit whose extracted
    worker source was byte-identical to main (sha256 03a8ce1c02faec71). The
    bench took a single short sample with no warm-up, so module parsing, JIT
    warm-up, or a descheduled shared vCPU could each drag it under on their
    own.

    This pins the two properties that make the gate trustworthy:

      1. it samples more than once, and reports the BEST trial, because
         warm-up and contention can only ever make a trial slower;
      2. the floor is NOT lowered to paper over noise. 1,000,000 sits ~109x
         above the 9,182/s functional cliff, and a real regression is orders of
         magnitude below it, so the fix belongs in the measurement rather than
         in eroding that margin.

    It also guards the contract the pytest parser above depends on: the
    reported figure must remain parseable as `throughput: N keys/s`.
    """
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    runtime = shutil.which("node") or shutil.which("bun")
    if runtime is None:
        pytest.skip("no node/bun runtime available")

    bench_src = (Path(__file__).parent / "tools" / "bench_worker.mjs").read_text(
        encoding="utf-8"
    )

    m = re.search(r"const TRIALS\s*=\s*(\d+)", bench_src)
    assert m, "bench_worker.mjs must declare a TRIALS count"
    trials = int(m.group(1))
    assert trials >= 3, (
        f"the throughput gate samples {trials} time(s); a single sample is not "
        "robust to JIT warm-up or a descheduled shared vCPU (this exact "
        "failure turned CI red at 921,735 keys/s on unchanged code)"
    )

    # The reported figure must be the maximum across trials, not the last one
    # and not the mean: a slow final trial must not fail an otherwise healthy
    # run, but a slow *first* trial must not either.
    assert re.search(r"rate:\s*Math\.max\(\.\.\.rates\)", bench_src), (
        "bench_worker.mjs must report the best trial (Math.max), so that "
        "warm-up or contention in any one trial cannot fail the gate"
    )
    assert re.search(r"const r\s*=\s*\{\s*\.\.\.last,\s*rate:\s*Math\.max", bench_src) or \
        re.search(r"Math\.max\(\.\.\.rates\)", bench_src), (
        "the reported rate must be derived from the collected trial rates"
    )

    # The floor must stay where the threat model puts it, not be lowered to
    # make a noisy run pass.
    fm = re.search(r"const MIN_KEYS_PER_SEC\s*=\s*([\d_]+)", bench_src)
    assert fm, "bench_worker.mjs must declare MIN_KEYS_PER_SEC"
    floor = int(fm.group(1).replace("_", ""))
    assert floor >= 1_000_000, (
        f"the throughput floor is {floor:,} keys/s; it must stay at or above "
        "1,000,000, which is ~109x the 9,182/s functional cliff. Lowering it to "
        "absorb runner noise would remove the margin that makes this gate "
        "worth having."
    )

    # And the output contract the pytest assertion parses must be preserved.
    assert re.search(r"throughput:.*keys/s", bench_src), (
        "bench_worker.mjs must keep printing 'throughput: N keys/s'; "
        "test_worker_wrapper_throughput_is_not_the_bottleneck parses that line"
    )

    # Prove the whole pipeline still runs end to end and reports a parseable
    # number, rather than only asserting on the file's text.
    mod = _load_check_inline_js()
    with tempfile.TemporaryDirectory() as tmp:
        worker = Path(tmp) / "worker.js"
        worker.write_text(
            mod.extract(Path(__file__).parent)["worker.js"], encoding="utf-8"
        )
        proc = subprocess.run(
            [runtime, str(Path(__file__).parent / "tools" / "bench_worker.mjs"), str(worker)],
            capture_output=True, text=True, timeout=180,
        )
    assert proc.returncode == 0, f"benchmark failed:\n{proc.stdout}\n{proc.stderr}"
    parsed = re.search(r"throughput: ([\d,]+) keys/s", proc.stdout)
    assert parsed, f"could not parse 'throughput: N keys/s' from:\n{proc.stdout}"
    # Multiple trials must actually be reported, so a reader can see the
    # spread rather than a single number that hides it.
    assert len(re.findall(r"trial \d+/", proc.stdout)) >= 3, (
        f"expected per-trial output, got:\n{proc.stdout}"
    )
    assert int(parsed.group(1).replace(",", "")) > floor, (
        f"reported {parsed.group(1)} keys/s, expected above the {floor:,} floor"
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
    """Regression guard: a cached document must not pin users to stale code.

    Originally this asserted stale-while-revalidate for every request. That is
    not good enough for an app whose whole UI, validation and estimation logic
    lives in one HTML file: serving the cached document first means every deploy
    is invisible until the *second* reload, so users run old code while the page
    appears current.

    The document is now NETWORK-FIRST (cache only as the offline fallback), and
    only the rarely-changing static assets stay cache-first. Both properties are
    asserted so neither half can silently regress.
    """
    sw = (_REPO_ROOT / "sw.js").read_text(encoding="utf-8")
    assert "CACHE_VERSION" in sw, "cache version is not parameterised"

    code = re.sub(r"//[^\n]*", "", sw)

    # Navigation requests must fetch before consulting the cache.
    assert "request.mode === 'navigate'" in code, (
        "navigation requests are no longer special-cased; the cached document "
        "will be served first and users will stay on stale code"
    )
    nav = code[code.index("request.mode === 'navigate'"):]
    assert "await fromNetwork()" in nav, (
        "navigation must try the network before falling back to the cache"
    )

    # Static assets stay cache-first, and still revalidate in the background so
    # a redeploy of an asset is picked up on the following load.
    assert "event.waitUntil(fromNetwork()" in code, (
        "cached assets no longer revalidate in the background; a redeployed "
        "asset would be pinned to whatever was cached first"
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
def _run_cli(*args: str, timeout: int = 120):
    """Run the CLI in a child process and return the completed process.

    The environment is inherited rather than replaced. Handing subprocess a
    bare ``{"PATH": ...}`` looks hermetic but drops SystemRoot on Windows,
    which breaks interpreter startup in ways that are miserable to debug, and
    it silently changes behaviour on any platform whose CLI reads the
    environment. MESHCORE_VANITY_STRICT_RESERVED is the one variable that
    alters CLI behaviour, so it is cleared explicitly and the rest is left
    alone.
    """
    import subprocess
    import sys
    from pathlib import Path

    env = dict(os.environ)
    env.pop("MESHCORE_VANITY_STRICT_RESERVED", None)
    return subprocess.run(
        [sys.executable, str(Path(__file__).parent / "meshcore_vanity.py"), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def test_private_key_is_printed_by_default() -> None:
    """The key must print without a flag.

    Re-running a search to recover the private key costs minutes to days of
    CPU. That is why it used to be behind --output-private and no longer is.
    """
    proc = _run_cli("ab", "--force")
    assert proc.returncode == 0, proc.stderr
    err = proc.stderr
    assert "PRIVATE_KEY_BASE64=" in err, (
        "the private key must be printed to stderr WITHOUT a flag:\n" + err
    )
    assert "MESHCORE_PRIV_HEX=" in err, "the expanded hex form must also print"
    assert "set prv.key " in err, "and the copy-pasteable CLI command"

    # The stdout/stderr split is the whole security story of this feature:
    # stdout is what gets piped into a file or another program, so the secret
    # must never appear there. Asserted rather than assumed.
    for secret in ("PRIVATE_KEY_BASE64", "MESHCORE_PRIV_HEX", "set prv.key"):
        assert secret not in proc.stdout, (
            f"{secret} leaked to stdout, which is the piped/redirected stream:\n"
            + proc.stdout
        )

    # The two forms must agree: base64 is the 32-byte seed, and the expanded
    # hex is the 64-byte clamped-scalar||nonce form MeshCore's `set prv.key`
    # expects (NOT a seed with a suffix - see meshcore_expanded_private_key).
    b64 = base64.b64decode(
        next(
            line.split("=", 1)[1]
            for line in err.splitlines()
            if line.startswith("PRIVATE_KEY_BASE64=")
        )
    )
    expanded = next(
        line.split("=", 1)[1]
        for line in err.splitlines()
        if line.startswith("MESHCORE_PRIV_HEX=")
    )
    assert len(b64) == 32, f"the seed must be 32 bytes, got {len(b64)}"
    assert len(expanded) == 128, (
        f"the expanded key must be 64 bytes of hex (128 chars), got {len(expanded)}"
    )

    # The first 32 bytes must be SHA-512(seed) with Ed25519 clamping applied -
    # which means the low bits are cleared, so compare against a clamped copy
    # rather than the raw digest.
    digest = hashlib.sha512(b64).digest()
    want = bytearray(digest[:32])
    want[0] &= 0xF8
    want[31] &= 0x7F
    want[31] |= 0x40
    got = bytes.fromhex(expanded)
    assert got[:32] == bytes(want), (
        "the first half of the expanded key must be the clamped SHA-512 scalar"
    )
    # And the second half is the untouched nonce half of the same digest.
    assert got[32:] == digest[32:], (
        "the second half must be the SHA-512 nonce, unmodified"
    )
    # The Ed25519 invariants themselves, independent of the digest.
    assert got[0] & 0x07 == 0, "scalar must have its low 3 bits cleared"
    assert got[31] & 0x80 == 0, "scalar must have its high bit cleared"
    assert got[31] & 0x40 == 0x40, "scalar must have bit 254 set"


def test_no_output_private_suppresses_the_key() -> None:
    """The opt-out must work, and must not touch the public key."""
    proc = _run_cli("ab", "--force", "--no-output-private")
    assert proc.returncode == 0, proc.stderr
    assert "PRIVATE_KEY_BASE64" not in proc.stderr, (
        "--no-output-private must suppress the key:\n" + proc.stderr
    )
    assert "MESHCORE_PRIV_HEX" not in proc.stderr
    assert "set prv.key" not in proc.stderr
    # The public key - the actual product - must still be there.
    assert proc.stdout.strip(), "the public key must still be printed"
    assert "Found in" in proc.stderr, "and the summary line must still print"


def test_the_removed_output_private_flag_is_rejected() -> None:
    """--output-private is gone; it must not silently become a no-op.

    Silently accepting it would let a script keep passing it and believe it
    were suppressing output, when it would now be *enabling* it.
    """
    proc = _run_cli("ab", "--force", "--output-private")
    assert proc.returncode != 0, "the removed flag must be rejected"
    assert "unrecognized arguments" in proc.stderr, proc.stderr
    # A rejected flag must not have leaked the key on its way out.
    assert "PRIVATE_KEY_BASE64" not in proc.stderr, proc.stderr


def test_the_launcher_documents_itself_without_installing() -> None:
    """`run.sh --help` must answer before it tries to create a venv."""
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).parent
    # Assert the launcher had no *side effect*, not that .venv is absent. Anyone
    # who has actually used the tool has a .venv, and asserting non-existence
    # would fail for them while proving nothing. Comparing before/after is the
    # only version of this that tests the launcher's behaviour.
    venv = root / ".venv"
    existed_before = venv.exists()
    proc = subprocess.run(
        [sys.executable, str(root / "run.py"), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "run.sh" in proc.stdout, "the help must show the short command"
    assert "run.bat" in proc.stdout, "and the Windows one"
    assert venv.exists() == existed_before, (
        "--help must not create a virtual environment as a side effect"
    )


def test_the_launcher_exists_for_both_platforms() -> None:
    """Both wrappers must be present, or the documented command is wrong."""
    from pathlib import Path

    root = Path(__file__).parent
    assert (root / "run.py").exists(), "run.py is the actual implementation"
    assert (root / "run.sh").exists(), "run.sh is documented in the README"
    assert (root / "run.bat").exists(), "run.bat is documented in the README"
    for name in ("run.sh", "run.py"):
        assert (root / name).read_text(encoding="utf-8").startswith(
            "#!/usr/bin/env"
        ), f"{name} needs a shebang to be directly executable"

def test_separate_prefix_and_suffix_are_both_required() -> None:
    """--suffix PATTERN adds a second, independent pattern.

    The browser has always allowed a prefix and a *different* suffix in one
    search; the CLI could only do one end, or the same pattern at both ends.
    """
    result = generate_vanity_key(
        "a", encoding="hex", suffix_pattern="b", max_attempts=200_000
    )
    data = result.encoded.rstrip("=")
    assert data.startswith("a"), result.encoded
    assert data.endswith("b"), result.encoded


def test_suffix_matches_key_data_not_base64_padding() -> None:
    """Regression: a base64 key is 44 chars and the last is always '='.

    Suffix matching used to compare `encoded[-n:]`, which for base64 is the
    padding. A short suffix therefore could never match and the search ran
    until it was killed rather than reporting that the target was impossible.
    """
    result = generate_vanity_key(
        "Yc", encoding="base64", suffix=True, max_attempts=200_000
    )
    # 44 chars, last is the pad; the suffix must land inside the 43 data chars.
    assert len(result.encoded) == 44, result.encoded
    assert result.encoded.endswith("="), result.encoded
    assert result.encoded[:-1].endswith("Yc"), result.encoded
    assert not result.encoded.endswith("Yc"), (
        "the suffix must not be matched against the padding"
    )


def test_separate_prefix_and_suffix_on_base64_use_the_data_region() -> None:
    """Both ends must match inside the key data, ignoring the pad."""
    result = generate_vanity_key(
        "a", encoding="base64", suffix_pattern="c", max_attempts=200_000
    )
    data = result.encoded[:-1]
    assert data.startswith("a"), result.encoded
    assert data.endswith("c"), result.encoded


def test_overlapping_prefix_and_suffix_are_rejected() -> None:
    """Overlapping patterns can never both match, so refuse them up front."""
    with pytest.raises(ValueError, match="overlap"):
        generate_vanity_key(
            "a" * 40, encoding="hex", suffix_pattern="b" * 30, max_attempts=1
        )
    # Exactly filling the key is the boundary and must stay allowed.
    with pytest.raises(RuntimeError):
        generate_vanity_key(
            "a" * 32, encoding="hex", suffix_pattern="b" * 32, max_attempts=1
        )


def test_suffix_longer_than_the_key_is_rejected() -> None:
    """base64 has 43 data characters, so a 50-char suffix is impossible."""
    with pytest.raises(ValueError, match="too long"):
        generate_vanity_key(
            "ab", encoding="base64", suffix_pattern="b" * 50, max_attempts=1
        )


def test_conflicting_match_modes_are_rejected() -> None:
    """The two-ended modes contradict each other and must say so."""
    with pytest.raises(ValueError, match="--both with a separate suffix"):
        generate_vanity_key(
            "ab", encoding="hex", suffix_pattern="cd", both=True, max_attempts=1
        )
    with pytest.raises(ValueError, match="match at the end"):
        generate_vanity_key(
            "ab", encoding="hex", suffix=True, suffix_pattern="cd", max_attempts=1
        )
    with pytest.raises(ValueError, match="must not be empty"):
        generate_vanity_key("ab", encoding="hex", suffix_pattern="", max_attempts=1)


def test_suffix_pattern_validates_its_alphabet() -> None:
    """The second pattern gets the same charset check as the first."""
    with pytest.raises(ValueError, match="invalid characters"):
        generate_vanity_key(
            "ab", encoding="hex", suffix_pattern="zz", max_attempts=1
        )


def test_the_suffix_flag_without_a_value_still_means_match_at_the_end() -> None:
    """Back-compat: bare --suffix must not change meaning.

    argparse cannot tell "flag absent" from "flag present with no value" when
    both default to None, so a sentinel carries the difference. If that ever
    collapses, this test catches it.
    """
    proc = _run_cli("Yc", "--suffix", "--force", "--max-attempts", "200000")
    assert proc.returncode == 0, proc.stderr
    assert "ending with 'Yc'" in proc.stderr, proc.stderr
    key = proc.stdout.strip()
    assert key[:-1].endswith("Yc"), key


def test_the_suffix_flag_with_a_value_adds_a_second_pattern() -> None:
    """`--suffix PATTERN` is the separate-prefix-and-suffix mode."""
    proc = _run_cli("a", "--suffix", "c", "--force", "--max-attempts", "200000")
    assert proc.returncode == 0, proc.stderr
    assert "starting with 'a' AND ending with 'c'" in proc.stderr, proc.stderr
    key = proc.stdout.strip()
    assert key[:-1].startswith("a"), key
    assert key[:-1].endswith("c"), key


def test_suffix_pattern_alone_needs_no_prefix() -> None:
    """`--suffix cd` with no positional constrains only the end."""
    proc = _run_cli("--suffix", "Yc", "--force", "--max-attempts", "200000")
    assert proc.returncode == 0, proc.stderr
    assert "ending with 'Yc'" in proc.stderr, proc.stderr
    assert proc.stdout.strip()[:-1].endswith("Yc")


# --- per-encoding suffix reachability, and the estimate that shares it ---
#
# The rule these encode: refuse a suffix that provably CANNOT occur, and never
# refuse one that merely does not occur. A wrong rejection costs the user a valid
# target; a futile search at least ends in a visible "exceeded max_attempts".

VALID_BASE58 = set(meshcore_vanity.BASE58_ALPHABET.decode())
BECH32_PREFIX = "mc1q"


def bech32_suffix(length, at_offset=None, ch="c"):
    """Build a valid-charset bech32 suffix, optionally forcing one position."""
    out = ["c"] * length
    if at_offset is not None:
        out[at_offset] = ch
    return "".join(out)


# --- bech32: the constrained character is the 7th from the end ---------------

@pytest.mark.parametrize("length", [7, 8, 9, 10, 12])
def test_bech32_suffix_allows_the_reachable_character_at_its_offset(length):
    """The constrained slot is 7 from the end, whatever the suffix length."""
    offset = length - (_BECH32_CHECKSUM_LEN + 1)
    for good in sorted(_BECH32_LAST_DATA_VALUES):
        # Must not raise a reachability error; exhausting the attempt budget is
        # the expected outcome.
        with pytest.raises(RuntimeError):
            generate_vanity_key(
                BECH32_PREFIX, encoding="bech32",
                suffix_pattern=bech32_suffix(length, offset, good),
                max_attempts=1,
            )


@pytest.mark.parametrize("length", [7, 8, 9, 10, 12])
def test_bech32_suffix_refuses_an_impossible_character_at_its_offset(length):
    offset = length - (_BECH32_CHECKSUM_LEN + 1)
    for bad in "xz0":
        with pytest.raises(ValueError, match="can never match a bech32 key"):
            generate_vanity_key(
                BECH32_PREFIX, encoding="bech32",
                suffix_pattern=bech32_suffix(length, offset, bad),
                max_attempts=1,
            )


@pytest.mark.parametrize("length", [7, 8, 9, 12])
def test_bech32_reachable_character_in_the_wrong_place_is_still_refused(length):
    """'q' is only allowed in the one constrained slot."""
    offset = length - (_BECH32_CHECKSUM_LEN + 1)
    positions = [offset + 1] if offset + 1 < length else [offset - 1]
    for pos in positions:
        with pytest.raises(ValueError, match="can never match a bech32 key"):
            generate_vanity_key(
                BECH32_PREFIX, encoding="bech32",
                suffix_pattern=bech32_suffix(length, pos, "q"),
                max_attempts=1,
            )


@pytest.mark.parametrize("pattern", ["c", "cc", "ccc", "cccccc", "zzzzzz"])
def test_bech32_short_suffixes_are_never_refused(pattern):
    """6 or fewer characters land in the checksum, which is uniform."""
    assert len(pattern) <= _BECH32_CHECKSUM_LEN
    with pytest.raises(RuntimeError):
        generate_vanity_key(
            BECH32_PREFIX, encoding="bech32", suffix_pattern=pattern,
            max_attempts=1,
        )


def test_bech32_offset_helper():
    assert _bech32_last_data_offset(1) == -1
    assert _bech32_last_data_offset(_BECH32_CHECKSUM_LEN) == -1
    assert _bech32_last_data_offset(7) == 0
    assert _bech32_last_data_offset(8) == 1
    assert _bech32_last_data_offset(20) == 13


def test_the_derived_bech32_character_set_matches_real_encodings():
    """The {0, 16} derivation is checked against 3,000 real encodings.

    256 bits do not fill 52 five-bit groups (260 bits), so 4 padding bits land in
    the last data character and only 2 of the 32 symbols can occur. That
    derivation is the entire basis for refusing a suffix, so it is verified
    rather than trusted - exactly as the base64 equivalent already is.
    """
    seen = set()
    for _ in range(3000):
        five = meshcore_vanity._bech32_convertbits(os.urandom(32), 8, 5, True)
        seen.add(five[-1])
    assert seen == {0, 16}, sorted(seen)
    assert _BECH32_LAST_DATA_VALUES == frozenset(
        meshcore_vanity.BECH32_CHARSET[v] for v in seen
    )


def test_bech32_suffix_space_accounts_for_the_constrained_character():
    """A bech32 suffix of 7+ is 16x cheaper than 32**n, not 32**n."""
    assert _end_search_space("bech32", 6) == 32 ** 6
    assert _end_search_space("bech32", 7) == 2 * 32 ** 6
    assert _end_search_space("bech32", 8) == 32 * 2 * 32 ** 6
    assert _end_search_space("bech32", 10) == 32 ** 3 * 2 * 32 ** 6


# --- base58 and hex: nothing may be refused ----------------------------------

@pytest.mark.parametrize("pattern", [
    "1", "1Z", "1z", "LZ", "abc", "1abc", "zzzz", "111", "L1Z", "1111",
    "zzzzzzzz", "1zzzzzzz",
])
def test_base58_prefixes_are_never_refused(pattern):
    """Exhaustively checked offline: all 1-3 character prefixes are reachable.

    base58's leading-digit distribution makes some two- and three-character
    prefixes RARE - a leading '1' comes from the encoder's zero-pad path, which
    narrows the next digit - but none impossible. Refusing any would reject a
    valid target, which is the worse failure.
    """
    assert set(pattern) <= VALID_BASE58, f"{pattern!r} is not valid base58"
    _validate_suffix_reachable("base58", pattern, "suffix")
    with pytest.raises(RuntimeError):
        generate_vanity_key(pattern, encoding="base58", max_attempts=1)


def test_base58_uppercase_L_is_accepted_despite_lowercase_l_being_excluded():
    """Regression: validation used to lowercase a case-SENSITIVE pattern.

    base58 excludes 'l' but includes 'L'. The validator folded the pattern to
    lowercase, so a library caller on the default case_insensitive=True had a
    valid 'L' prefix refused for containing an invalid 'l'.
    """
    assert "l" not in VALID_BASE58 and "L" in VALID_BASE58
    with pytest.raises(RuntimeError):
        generate_vanity_key("LZ", encoding="base58", max_attempts=1)


@pytest.mark.parametrize("pattern", ["f", "0f", "abc", "0123456789abcdef"])
def test_hex_suffixes_are_never_refused(pattern):
    _validate_suffix_reachable("hex", pattern, "suffix")
    with pytest.raises(RuntimeError):
        generate_vanity_key(
            "a", encoding="hex", suffix_pattern=pattern, max_attempts=1
        )


def test_the_dispatcher_accepts_every_encoding_and_an_empty_pattern():
    """A new encoding must not be silently skipped, and '' must be harmless."""
    for enc in ("hex", "base64", "base64url", "base58", "bech32"):
        _validate_suffix_reachable(enc, "", "suffix")


# --- the CLI surfaces it before announcing a search --------------------------

def test_cli_reports_the_bech32_refusal_before_printing_anything():
    proc = _run_cli(BECH32_PREFIX, "--encoding", "bech32", "--suffix",
                    "ccccccc", "--force", "--max-attempts", "100")
    assert proc.returncode == 2, proc.stderr
    assert "can never match a bech32 key" in proc.stderr, proc.stderr
    assert "Searching for" not in proc.stderr, proc.stderr
    assert "Estimate:" not in proc.stderr, proc.stderr


def test_both_mode_uses_the_prefix_for_the_bech32_check():
    """--both puts the pattern at the end too, so it faces the same constraint.

    Regression: the two-ended call sat under a base64/base64url guard, so bech32
    --both skipped the reachability check entirely.

    An 8-character pattern has its constrained slot at offset 1, which 'c' fails.
    A SHORTER pattern cannot be tested this way, because a suffix below 7
    characters does not reach the constrained slot at all - which is the whole
    reason the check is length-dependent.
    """
    for pattern in ("mc1qcccc", "mc1qqccc"):
        with pytest.raises(ValueError, match="can never match a bech32 key"):
            generate_vanity_key(
                pattern, encoding="bech32", both=True, max_attempts=1,
            )


def test_a_short_bech32_prefix_in_both_mode_is_not_refused():
    """The complement: a pattern that cannot reach the slot must be allowed."""
    with pytest.raises(RuntimeError):
        generate_vanity_key(
            "mc1qc", encoding="bech32", both=True, max_attempts=1,
        )


def test_reserved_warning_is_not_emitted_for_a_hex_suffix() -> None:
    """00/FF are reserved because framework keys *begin* with them.

    Warning that a key merely ENDING in 00ff "may not work with standard
    MeshCore clients" is simply wrong, and alarming. The check is on the
    pattern that constrains the start of the key, nothing else.
    """
    import warnings as _w

    with _w.catch_warnings(record=True) as caught:
        _w.simplefilter("always")
        _validate_prefix("00ff", "hex", label="suffix")
    assert not [x for x in caught if "reserved" in str(x.message)], [
        str(x.message) for x in caught
    ]

    # ...while a genuine prefix still warns.
    meshcore_vanity._warned_reserved.clear()
    with _w.catch_warnings(record=True) as caught2:
        _w.simplefilter("always")
        _validate_prefix("00ff", "hex", label="prefix")
    assert [x for x in caught2 if "reserved" in str(x.message)], [
        str(x.message) for x in caught2
    ]


def test_a_hex_suffix_starting_00_is_still_mined() -> None:
    """End-to-end: the false warning is gone AND the search still runs.

    The suffix is "00" rather than something longer on purpose. A 1-char prefix
    plus a 2-char suffix is 3 nibbles, so it resolves in thousands of attempts;
    "a" + "00ff" is 20 bits, roughly a million, which passes on an idle machine
    and times out on a loaded CI runner. A test that only sometimes passes is
    worse than no test.
    """
    import warnings as _w

    meshcore_vanity._warned_reserved.clear()
    with _w.catch_warnings(record=True) as caught:
        _w.simplefilter("always")
        result = generate_vanity_key(
            "a", encoding="hex", suffix_pattern="00", max_attempts=200_000
        )
    assert result.encoded.startswith("a"), result.encoded
    assert result.encoded.endswith("00"), result.encoded
    assert not [x for x in caught if "reserved" in str(x.message)]


def test_bare_suffix_starting_00_is_not_warned_either() -> None:
    """`--suffix` with a reserved-looking pattern is a tail, not a head."""
    import warnings as _w

    meshcore_vanity._warned_reserved.clear()
    with _w.catch_warnings(record=True) as caught:
        _w.simplefilter("always")
        with pytest.raises(RuntimeError):
            generate_vanity_key(
                "00ff", encoding="hex", suffix=True, max_attempts=1
            )
    assert not [x for x in caught if "reserved" in str(x.message)]


def test_the_cli_renders_warnings_without_a_source_location() -> None:
    """A warning must not read as an internal error pointing into the source.

    Python's default format leads with "meshcore_vanity.py:NNN:", which to
    someone running the tool looks like a bug report rather than advice.
    """
    # "00" not "00ff": 8 bits rather than 16, so the search completes inside the
    # budget on a loaded machine too. The warning is emitted before any search.
    proc = _run_cli("00", "--encoding", "hex", "--force", "--max-attempts", "20000")
    err = proc.stderr
    assert proc.returncode == 0, err
    assert "reserved" in err, err
    assert "Warning:" in err, err
    assert "meshcore_vanity.py:" not in err, (
        "the warning must not carry a file:line prefix:\n" + err
    )
    assert "UserWarning" not in err, err


def test_the_cli_still_exits_correctly_with_the_clean_warning_renderer() -> None:
    """The catch_warnings context must not disturb exits or --version."""
    assert _run_cli("--version").returncode == 0
    missing = _run_cli("--force")
    assert missing.returncode == 2, missing.stderr
    assert "pattern is required" in missing.stderr, missing.stderr


def test_reserved_prefix_strict_env_still_rejects_a_real_prefix(monkeypatch) -> None:
    """Opting into hard rejection must still work through the new renderer."""
    monkeypatch.setenv("MESHCORE_VANITY_STRICT_RESERVED", "1")
    meshcore_vanity._warned_reserved.clear()
    with pytest.raises(ValueError, match="reserved"):
        _validate_prefix("00ff", "hex", label="prefix")
    # ...and must NOT reject a suffix that merely looks reserved.
    _validate_prefix("00ff", "hex", label="suffix")


def test_readme_documented_constants_match_the_code() -> None:
    """The README quotes real numbers; a stale one is a small lie.

    Every constant asserted here was changed at some point and the prose around
    it did not always follow: a removed "forced first report", a worker yield
    quoted at 30 ms after it moved to 250 ms, and an ETA slot documented at 20ch
    after it shrank to 2ch. Cheap to pin, and it fails loudly instead of
    misleading.
    """
    import re
    from pathlib import Path

    root = Path(__file__).parent
    readme = (root / "README.md").read_text(encoding="utf-8")
    page = (root / "index.html").read_text(encoding="utf-8")

    # Browser constants the README states in prose.
    yield_ms = re.search(r"const YIELD_EVERY_MS = (\d+)", page)
    report_ms = re.search(r"const REPORT_EVERY_MS = (\d+)", page)
    assert yield_ms and report_ms, "constants must be literals to be quotable"
    report_s = int(report_ms.group(1)) // 1000
    assert f"every {report_s} s" in readme, (
        "the README's report interval must match REPORT_EVERY_MS"
    )
    assert f"every {yield_ms.group(1)} ms" in readme, (
        "the README's worker-yield interval must match YIELD_EVERY_MS"
    )

    # The removed forced first report must not be documented as present.
    assert "firstReportSent" not in readme, (
        "the forced first report was removed as redundant; the README still "
        "describes it"
    )
    assert "firstReportSent" not in page, (
        "the redundant forced first report must not come back"
    )

    # ETA slot widths.
    hours_ch = re.search(r"\.eta-num \{[^}]*min-width: (\d+)ch", page)
    days_ch = re.search(r"\.eta-days \{[^}]*min-width: (\d+)ch", page)
    assert hours_ch and days_ch, "the ETA slot reservations must be literal"
    assert f"| hours | `{hours_ch.group(1)}ch` |" in readme, (
        "the README's ETA hours reservation must match the CSS"
    )
    assert f"| days | `{days_ch.group(1)}ch` |" in readme, (
        "the README's ETA days reservation must match the CSS"
    )


def test_the_readme_reserved_prefix_claim_matches_behaviour() -> None:
    """The README says 00/FF warn rather than reject; verify that is true."""
    # "00" rather than "00ff": 8 bits instead of 16, so the search still finishes
    # inside the attempt budget and the test stays quick.
    proc = _run_cli("00", "--encoding", "hex", "--force",
                    "--max-attempts", "20000")
    assert proc.returncode == 0, proc.stderr
    assert "Warning:" in proc.stderr and "reserved" in proc.stderr, proc.stderr
    assert proc.stdout.strip().startswith("00"), proc.stdout
    # The warning must not claim the tool refused.
    assert "Error:" not in proc.stderr, proc.stderr
    # ...and it must not carry a source location, which reads as an internal
    # error rather than advice about the key.
    assert "meshcore_vanity.py:" not in proc.stderr, proc.stderr


def test_max_attempts_is_an_upper_bound_not_a_rounding() -> None:
    """The budget must be respected exactly, not rounded up to a batch.

    Both loops checked `attempts >= max_attempts` only at the top of a 16-wide
    batch, so a budget of 17 could do 32 candidates, and the parent split the
    budget with ceiling division, adding up to workers-1 more. With 8 workers
    that is a ~127-attempt overshoot on a documented "Stop after N attempts".

    Exercised at the level the property holds: each worker respects its own
    share, and the parent's split is floor division so the shares cannot sum to
    more than the request.
    """
    def worker_attempts(n):
        args = ("abcdef0123456789", "hex", False, n, bytes(32), 16,
                "abcdef0123456789", "", slice(None), False, slice(0, 16),
                "mc", 0, 0, 1, True, None)
        priv, attempts, _counter = meshcore_vanity._worker_search(args)
        assert priv is None, "an impossible pattern must not match"
        return attempts

    # The interesting values straddle the 16-candidate batch boundary.
    for n in (1, 5, 15, 16, 17, 31, 32, 33, 100, 1000):
        got = worker_attempts(n)
        assert got <= n, f"budget {n} did {got} candidates"


def test_the_worker_budget_split_cannot_exceed_the_request() -> None:
    """Floor division, so the shares sum to at most --max-attempts.

    The max(1, ...) floor keeps every worker useful when the budget is smaller
    than the worker count, which is the one case where an exact bound is not
    achievable.
    """
    for total, workers in ((100, 8), (500, 8), (1000, 4), (64, 8), (5000, 8)):
        per_worker = max(1, total // workers)
        assert per_worker * workers <= total, (
            f"total={total} workers={workers}: shares sum to "
            f"{per_worker * workers}"
        )


def test_a_parallel_search_reports_the_requested_budget_not_a_workers() -> None:
    """The user passed 500; the message must say 500, not one worker's share."""
    proc = _run_cli("abcdef0123456789", "--encoding", "hex", "--force",
                    "--max-attempts", "500", "--workers", "4")
    assert proc.returncode != 0, proc.stdout
    assert "exceeded max_attempts=500" in proc.stderr, proc.stderr


if __name__ == "__main__":
    pytest.main([__file__, "-v"])