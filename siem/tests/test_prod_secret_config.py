"""Fail-closed production secret configuration (prodconfig + signing + create_app startup).

Covers: missing secret, invalid/placeholder secret, key consistency, production startup failure,
and backward-compatible historical signature verification (rotation preserves verify_only/retired
trust and the canonical signing format is unchanged). Pure in-process + one subprocess startup
demonstration; no database, no network.
"""
import base64
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import prodconfig  # noqa: E402
import signing  # noqa: E402

_MANAGED = ("SECRET_KEY", "RANGER_SIGNING_KEY", "RANGER_SIGNING_KEYS", "RANGER_SIGNING_VERIFY_KIDS",
            "RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV", "RANGER_REQUIRE_SECURE_SECRETS")


@pytest.fixture()
def clean_env():
    """Save/clear the managed secret + environment-marker vars; restore and reset the signing
    registry afterward so no test leaks key material into another."""
    saved = {k: os.environ.get(k) for k in _MANAGED}
    for k in _MANAGED:
        os.environ.pop(k, None)
    signing._reset_registry()
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        signing._reset_registry()


def _seed_b64():
    k = Ed25519PrivateKey.generate()
    raw = k.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption())
    return base64.b64encode(raw).decode()


# ---- SECRET_KEY contract --------------------------------------------------------------------

def test_require_secret_key_missing_in_production_raises(clean_env):
    os.environ["RANGER_ENV"] = "production"
    with pytest.raises(prodconfig.InsecureConfigError) as ei:
        prodconfig.require_secret_key()
    assert "SECRET_KEY" in str(ei.value)
    # the error must not echo any value (there is none here, but assert the shape)
    assert "required in production" in str(ei.value)


def test_require_secret_key_too_short_in_production_raises(clean_env):
    os.environ["RANGER_ENV"] = "production"
    os.environ["SECRET_KEY"] = "short"
    with pytest.raises(prodconfig.InsecureConfigError):
        prodconfig.require_secret_key()


def test_require_secret_key_placeholder_in_production_raises(clean_env):
    os.environ["RANGER_ENV"] = "production"
    os.environ["SECRET_KEY"] = "qwalora-ranger-dev"  # a known dev placeholder (len>=min, still rejected)
    with pytest.raises(prodconfig.InsecureConfigError):
        prodconfig.require_secret_key()


def test_require_secret_key_valid_in_production_returns(clean_env):
    os.environ["RANGER_ENV"] = "production"
    val = os.urandom(32).hex()  # 64 chars, strong
    os.environ["SECRET_KEY"] = val
    assert prodconfig.require_secret_key() == val


def test_secret_key_lenient_outside_production(clean_env):
    # no production marker, no SECRET_KEY -> returns None so the caller keeps its dev fallback
    assert prodconfig.require_secret_key() is None
    assert prodconfig.is_production() is False


@pytest.mark.parametrize("marker", ["RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"])
def test_each_production_marker_is_honored(clean_env, marker):
    os.environ[marker] = "production"
    assert prodconfig.is_production() is True
    with pytest.raises(prodconfig.InsecureConfigError):
        prodconfig.require_secret_key()


# ---- signing key contract -------------------------------------------------------------------

def test_signing_no_key_in_production_fails_closed(clean_env):
    os.environ["RANGER_ENV"] = "production"
    # no RANGER_SIGNING_KEY / RANGER_SIGNING_KEYS -> must not derive from SECRET_KEY/dev literal
    os.environ["SECRET_KEY"] = os.urandom(32).hex()
    with pytest.raises(prodconfig.InsecureConfigError) as ei:
        signing.assert_signing_ready()
    assert "signing key" in str(ei.value).lower()


def test_signing_valid_explicit_key_in_production_ready(clean_env):
    os.environ["RANGER_ENV"] = "production"
    os.environ["SECRET_KEY"] = os.urandom(32).hex()
    os.environ["RANGER_SIGNING_KEY"] = _seed_b64()
    kid = signing.assert_signing_ready()
    assert kid  # an active kid exists
    rec = {"a": 1, "b": [2, 3], "nested": {"z": 9}}
    sig = signing.sign(rec)
    assert signing.verify(rec, sig) is True


def test_signing_malformed_key_raises(clean_env):
    os.environ["RANGER_SIGNING_KEY"] = "!!!not-base64!!!"
    with pytest.raises(prodconfig.InsecureConfigError):
        signing.assert_signing_ready()


def test_signing_too_short_seed_raises(clean_env):
    os.environ["RANGER_SIGNING_KEY"] = base64.b64encode(b"tooshort").decode()
    with pytest.raises(prodconfig.InsecureConfigError):
        signing.assert_signing_ready()


def test_active_kid_is_deterministic_for_a_seed(clean_env):
    seed = _seed_b64()
    os.environ["RANGER_SIGNING_KEY"] = seed
    k1 = signing.assert_signing_ready()
    pub1 = signing.public_key_b64()
    signing._reset_registry()
    k2 = signing.assert_signing_ready()
    pub2 = signing.public_key_b64()
    assert k1 == k2 and pub1 == pub2  # same seed -> same kid + public key


# ---- backward-compatible historical verification (rotation) ---------------------------------

def test_canonical_format_is_unchanged(clean_env):
    # lock the canonical bytes so the fix cannot silently alter the signing format
    assert signing.canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_historical_signatures_verify_after_rotation(clean_env):
    os.environ["RANGER_ENV"] = "production"
    os.environ["SECRET_KEY"] = os.urandom(32).hex()
    seed_a, seed_b = _seed_b64(), _seed_b64()
    # Phase 1: key A is the sole active key; sign a record under it.
    os.environ["RANGER_SIGNING_KEYS"] = json.dumps(
        [{"kid": "kA", "alg": "ed25519", "state": "active", "seed_b64": seed_a}])
    signing.assert_signing_ready()
    assert signing.active_kid() == "kA"
    rec = {"run_id": "run-x", "researcher_id": "r1", "metrics": {"kind": "investigation"}}
    sig_a = signing.sign(rec)
    assert signing.verify(rec, sig_a, kid="kA") is True

    # Phase 2: rotate - A demoted to verify_only, B becomes active. Historical A record must still verify.
    os.environ["RANGER_SIGNING_KEYS"] = json.dumps([
        {"kid": "kA", "alg": "ed25519", "state": "verify_only", "seed_b64": seed_a},
        {"kid": "kB", "alg": "ed25519", "state": "active", "seed_b64": seed_b}])
    signing._reset_registry()
    signing.assert_signing_ready()
    assert signing.active_kid() == "kB"
    assert signing.verify(rec, sig_a, kid="kA") is True   # historical signature still trusted
    sig_b = signing.sign(rec)
    assert signing.verify(rec, sig_b, kid="kB") is True   # new signing uses B

    # Phase 3: revoke A - its historical signatures must now fail closed.
    os.environ["RANGER_SIGNING_KEYS"] = json.dumps([
        {"kid": "kA", "alg": "ed25519", "state": "revoked", "seed_b64": seed_a},
        {"kid": "kB", "alg": "ed25519", "state": "active", "seed_b64": seed_b}])
    signing._reset_registry()
    signing.assert_signing_ready()
    assert signing.verify(rec, sig_a, kid="kA") is False  # revoked key no longer trusted
    assert signing.verify(rec, sig_b, kid="kB") is True


def test_unknown_kid_fails_closed(clean_env):
    os.environ["RANGER_SIGNING_KEY"] = _seed_b64()
    signing.assert_signing_ready()
    rec = {"x": 1}
    sig = signing.sign(rec)
    assert signing.verify(rec, sig, kid="no-such-kid") is False


# ---- hardening: marker ambiguity, force flag, var conflicts, leakage, entropy, kid pinning ----

def test_ambiguous_ranger_env_fails_closed(clean_env):
    os.environ["RANGER_ENV"] = "produciton"  # misspelled production
    with pytest.raises(prodconfig.InsecureConfigError):
        prodconfig.is_production()
    with pytest.raises(prodconfig.InsecureConfigError):
        prodconfig.require_secret_key()


def test_recognized_dev_marker_is_lenient(clean_env):
    os.environ["RANGER_ENV"] = "development"
    assert prodconfig.is_production() is False
    assert prodconfig.require_secret_key() is None


def test_force_flag_enables_secure_mode_without_marker(clean_env):
    os.environ["RANGER_REQUIRE_SECURE_SECRETS"] = "1"
    assert prodconfig.is_production() is True
    with pytest.raises(prodconfig.InsecureConfigError):
        prodconfig.require_secret_key()  # no SECRET_KEY -> fail closed


def test_low_entropy_secret_in_production_raises(clean_env):
    os.environ["RANGER_ENV"] = "production"
    os.environ["SECRET_KEY"] = "a" * 48  # long but near-zero entropy
    with pytest.raises(prodconfig.InsecureConfigError):
        prodconfig.require_secret_key()
    os.environ["SECRET_KEY"] = "0123" * 12  # 48 chars, only 4 distinct -> weak
    with pytest.raises(prodconfig.InsecureConfigError):
        prodconfig.require_secret_key()


def test_both_signing_vars_set_fails_closed(clean_env):
    os.environ["RANGER_SIGNING_KEY"] = _seed_b64()
    os.environ["RANGER_SIGNING_KEYS"] = json.dumps(
        [{"kid": "kA", "alg": "ed25519", "state": "active", "seed_b64": _seed_b64()}])
    with pytest.raises(prodconfig.InsecureConfigError) as ei:
        signing.assert_signing_ready()
    assert "exactly one" in str(ei.value)


def test_malformed_registry_does_not_leak_key_material(clean_env):
    secret_seed = _seed_b64()
    # invalid JSON that nonetheless embeds the seed; the error must not echo it
    os.environ["RANGER_SIGNING_KEYS"] = '[{"kid":"kA","state":"active","seed_b64":"%s"' % secret_seed
    with pytest.raises(prodconfig.InsecureConfigError) as ei:
        signing.assert_signing_ready()
    assert secret_seed not in str(ei.value)
    assert "malformed or invalid" in str(ei.value)


def test_verify_kids_pin_missing_fails_closed(clean_env):
    os.environ["RANGER_SIGNING_KEY"] = _seed_b64()
    os.environ["RANGER_SIGNING_VERIFY_KIDS"] = "legacy:deadbeefdeadbeef"  # not present in registry
    with pytest.raises(prodconfig.InsecureConfigError):
        signing.assert_signing_ready()


def test_verify_kids_pin_present_ok(clean_env):
    seed_a, seed_b = _seed_b64(), _seed_b64()
    os.environ["RANGER_SIGNING_KEYS"] = json.dumps([
        {"kid": "kA", "alg": "ed25519", "state": "verify_only", "seed_b64": seed_a},
        {"kid": "kB", "alg": "ed25519", "state": "active", "seed_b64": seed_b}])
    os.environ["RANGER_SIGNING_VERIFY_KIDS"] = "kA,kB"
    assert signing.assert_signing_ready() == "kB"


def test_verify_kids_pin_revoked_fails_closed(clean_env):
    seed_a, seed_b = _seed_b64(), _seed_b64()
    os.environ["RANGER_SIGNING_KEYS"] = json.dumps([
        {"kid": "kA", "alg": "ed25519", "state": "revoked", "seed_b64": seed_a},
        {"kid": "kB", "alg": "ed25519", "state": "active", "seed_b64": seed_b}])
    os.environ["RANGER_SIGNING_VERIFY_KIDS"] = "kA"  # revoked is not a trusted state
    with pytest.raises(prodconfig.InsecureConfigError):
        signing.assert_signing_ready()


# ---- create_app startup demonstration (subprocess) ------------------------------------------

def test_create_app_fails_closed_in_production_without_secret():
    env = {k: v for k, v in os.environ.items() if k not in _MANAGED}
    env["RANGER_ENV"] = "production"
    env["PYTHONPATH"] = ROOT
    code = (
        "import sys\n"
        "try:\n"
        "    import app\n"  # app.py runs app = create_app() at import
        "except Exception as e:\n"
        "    sys.stderr.write(type(e).__name__)\n"
        "    sys.exit(7)\n"
        "sys.exit(0)\n")
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 7, "create_app should fail closed in production without SECRET_KEY: %r / %r" % (
        r.returncode, r.stderr[-400:])
    assert "InsecureConfigError" in r.stderr


def test_create_app_boots_in_production_with_valid_secrets():
    env = {k: v for k, v in os.environ.items() if k not in _MANAGED}
    env["RANGER_ENV"] = "production"
    env["SECRET_KEY"] = os.urandom(32).hex()
    env["RANGER_SIGNING_KEY"] = _seed_b64()
    env["DATABASE_URL"] = "sqlite:///:memory:"
    env["PYTHONPATH"] = ROOT
    code = (
        "import sys\n"
        "try:\n"
        "    import app\n"
        "    assert app.app is not None\n"
        "except Exception as e:\n"
        "    sys.stderr.write(repr(e))\n"
        "    sys.exit(7)\n"
        "sys.exit(0)\n")
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, "create_app should boot in production with valid secrets: %r / %r" % (
        r.returncode, r.stderr[-400:])
