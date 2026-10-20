"""RC database-identity guard + RC signing-key strategy.

Proves the release-candidate isolation controls fail CLOSED and, critically, that rejection happens
BEFORE any write-capable startup step (create_all / ensure_schema / cohort+resource bootstrap). Also
proves the RC signing configuration (public-only verify_only historical key + a disposable active
key + a mandatory historical pin) verifies historical records without exposing historical private
material and without changing the Ed25519 signature format.

Pure unit/integration tests: SQLite marker databases and in-memory signing registries; no Railway,
no live database, no real signing key.
"""
import base64
import json
import os
import sqlite3
import sys

import pytest
from sqlalchemy import create_engine, text

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

import rc_guard  # noqa: E402
import signing  # noqa: E402
import prodconfig  # noqa: E402
import app as app_module  # noqa: E402  (import once, at clean env, before any RC env is set)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402


def _marker_db(path, token):
    """A disposable-fork SQLite db stamped with one rc_fork_marker row."""
    e = create_engine("sqlite:///" + path)
    with e.begin() as c:
        c.execute(text("CREATE TABLE rc_fork_marker (token text primary key)"))
        c.execute(text("INSERT INTO rc_fork_marker VALUES (:t)"), {"t": token})
    return e


def _accepted_like_db(path):
    """A db that looks like the accepted operational database: app tables, NO rc_fork_marker."""
    e = create_engine("sqlite:///" + path)
    with e.begin() as c:
        c.execute(text("CREATE TABLE candidates (id integer primary key)"))
    return e


# --------------------------------------------------------------------------- guard: unit behavior
def test_not_rc_mode_is_noop(monkeypatch, tmp_path):
    monkeypatch.delenv(rc_guard.ALLOW_ENV, raising=False)
    monkeypatch.delenv(rc_guard.EXPECT_ENV, raising=False)
    e = create_engine("sqlite:///" + str(tmp_path / "plain.db"))  # unmarked, but RC not declared
    assert rc_guard.assert_rc_identity(e) is None


def test_happy_path_returns_token(monkeypatch, tmp_path):
    tok = "rc-abc123-disposable"
    e = _marker_db(str(tmp_path / "fork.db"), tok)
    monkeypatch.setenv(rc_guard.ALLOW_ENV, "1")
    monkeypatch.setenv(rc_guard.EXPECT_ENV, tok)
    assert rc_guard.assert_rc_identity(e) == tok


def test_allow_missing_fails(monkeypatch, tmp_path):
    tok = "rc-abc123-disposable"
    e = _marker_db(str(tmp_path / "fork.db"), tok)
    monkeypatch.delenv(rc_guard.ALLOW_ENV, raising=False)   # RC intent declared via EXPECT, no ALLOW
    monkeypatch.setenv(rc_guard.EXPECT_ENV, tok)
    with pytest.raises(rc_guard.RCGuardError):
        rc_guard.assert_rc_identity(e)


def test_expect_missing_fails(monkeypatch, tmp_path):
    e = _marker_db(str(tmp_path / "fork.db"), "rc-abc123-disposable")
    monkeypatch.setenv(rc_guard.ALLOW_ENV, "1")
    monkeypatch.delenv(rc_guard.EXPECT_ENV, raising=False)
    with pytest.raises(rc_guard.RCGuardError):
        rc_guard.assert_rc_identity(e)


def test_malformed_token_fails(monkeypatch, tmp_path):
    e = _marker_db(str(tmp_path / "fork.db"), "rc-abc123-disposable")
    monkeypatch.setenv(rc_guard.ALLOW_ENV, "1")
    monkeypatch.setenv(rc_guard.EXPECT_ENV, "short")        # < 8 chars / malformed
    with pytest.raises(rc_guard.RCGuardError):
        rc_guard.assert_rc_identity(e)


def test_unmarked_db_rejected(monkeypatch, tmp_path):
    e = create_engine("sqlite:///" + str(tmp_path / "unmarked.db"))  # no marker table at all
    monkeypatch.setenv(rc_guard.ALLOW_ENV, "1")
    monkeypatch.setenv(rc_guard.EXPECT_ENV, "rc-abc123-disposable")
    with pytest.raises(rc_guard.RCGuardError):
        rc_guard.assert_rc_identity(e)


def test_marker_mismatch_fails(monkeypatch, tmp_path):
    e = _marker_db(str(tmp_path / "fork.db"), "rc-REAL-token-9999")
    monkeypatch.setenv(rc_guard.ALLOW_ENV, "1")
    monkeypatch.setenv(rc_guard.EXPECT_ENV, "rc-WRONG-token-0000")
    with pytest.raises(rc_guard.RCGuardError):
        rc_guard.assert_rc_identity(e)


def test_accepted_database_identity_rejected(monkeypatch, tmp_path):
    e = _accepted_like_db(str(tmp_path / "accepted.db"))   # app tables, no RC marker
    monkeypatch.setenv(rc_guard.ALLOW_ENV, "1")
    monkeypatch.setenv(rc_guard.EXPECT_ENV, "rc-abc123-disposable")
    with pytest.raises(rc_guard.RCGuardError):
        rc_guard.assert_rc_identity(e)


def test_identity_unverifiable_fails(monkeypatch):
    # Engine whose connection fails: identity cannot be verified -> fail closed.
    e = create_engine("postgresql+psycopg2://nouser:nopass@127.0.0.1:1/none",
                      connect_args={"connect_timeout": 2})
    monkeypatch.setenv(rc_guard.ALLOW_ENV, "1")
    monkeypatch.setenv(rc_guard.EXPECT_ENV, "rc-abc123-disposable")
    with pytest.raises(rc_guard.RCGuardError):
        rc_guard.assert_rc_identity(e)


# ------------------------------------------------------ enforcement happens BEFORE any startup write
def test_create_app_rejects_unmarked_db_before_writes(monkeypatch, tmp_path):
    dbf = str(tmp_path / "rc_nomarker.db")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + dbf)
    monkeypatch.setenv(rc_guard.ALLOW_ENV, "1")
    monkeypatch.setenv(rc_guard.EXPECT_ENV, "rc-nomarker-token-1")
    monkeypatch.setenv("SECRET_KEY", "x" * 48)
    monkeypatch.setenv("RANGER_ENV", "test")
    monkeypatch.delenv("RANGER_REQUIRE_SECURE_SECRETS", raising=False)
    with pytest.raises(rc_guard.RCGuardError):
        app_module.create_app()
    # The guard runs before db.create_all()/ensure_schema()/bootstrap: no application tables exist.
    con = sqlite3.connect(dbf)
    names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    assert "candidates" not in names and "cohorts" not in names and "resources" not in names


def test_create_app_boots_on_marked_fork(monkeypatch, tmp_path):
    dbf = str(tmp_path / "rc_fork.db")
    _marker_db(dbf, "rc-ok-token-12345")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + dbf)
    monkeypatch.setenv(rc_guard.ALLOW_ENV, "1")
    monkeypatch.setenv(rc_guard.EXPECT_ENV, "rc-ok-token-12345")
    monkeypatch.setenv("SECRET_KEY", "y" * 48)
    monkeypatch.setenv("RANGER_ENV", "test")
    monkeypatch.delenv("RANGER_REQUIRE_SECURE_SECRETS", raising=False)
    a = app_module.create_app()         # must NOT raise: guard passed, startup proceeds
    assert a is not None
    con = sqlite3.connect(dbf)
    names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    assert "candidates" in names        # create_all ran only AFTER the guard passed


# --------------------------------------------------------- RC signing-key strategy (no private seed)
def _kp():
    k = Ed25519PrivateKey.generate()
    pub = base64.b64encode(k.public_key().public_bytes(
        _ser.Encoding.Raw, _ser.PublicFormat.Raw)).decode()
    seed = base64.b64encode(k.private_bytes(
        _ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption())).decode()
    return k, pub, seed


def _rc_signing_env(monkeypatch, keys, verify_kids=None):
    monkeypatch.delenv("RANGER_SIGNING_KEY", raising=False)
    monkeypatch.setenv("RANGER_SIGNING_KEYS", json.dumps(keys))
    if verify_kids is not None:
        monkeypatch.setenv("RANGER_SIGNING_VERIFY_KIDS", verify_kids)
    else:
        monkeypatch.delenv("RANGER_SIGNING_VERIFY_KIDS", raising=False)
    signing._reset_registry()


def test_rc_verify_only_historical_plus_disposable_active(monkeypatch):
    hist, hist_pub, _hist_seed = _kp()          # historical key: ONLY its public half goes to the RC
    kid_hist = signing._kid_for_pub(hist_pub)
    disp, disp_pub, disp_seed = _kp()           # disposable active key generated "on the RC"
    kid_disp = signing._kid_for_pub(disp_pub)
    keys = [
        {"kid": kid_hist, "alg": "ed25519", "state": "verify_only", "public_b64": hist_pub},
        {"kid": kid_disp, "alg": "ed25519", "state": "active", "seed_b64": disp_seed},
    ]
    _rc_signing_env(monkeypatch, keys, verify_kids=kid_hist)
    try:
        assert signing.assert_signing_ready() == kid_disp      # active is the disposable key
        # A record "signed historically" by the real private key (which the RC does NOT hold):
        payload = {"run_id": "run-historical", "n": 1}
        sig_hist = base64.b64encode(hist.sign(signing.canonical(payload))).decode()
        assert signing.verify(payload, sig_hist, kid=kid_hist) is True   # verifies via PUBLIC only
        # The RC registry holds no private material for the historical kid.
        with pytest.raises(Exception):
            signing._registry()[kid_hist].private()
        # New records sign under the disposable active key and verify.
        sig_new = signing.sign(payload)
        assert signing.verify(payload, sig_new, kid=kid_disp) is True
        # Ed25519 signature format preserved: 64 raw bytes, base64-encoded.
        assert len(base64.b64decode(sig_hist)) == 64 and len(base64.b64decode(sig_new)) == 64
    finally:
        signing._reset_registry()


def test_rc_missing_historical_pin_fails_closed(monkeypatch):
    hist, hist_pub, _ = _kp()
    kid_hist = signing._kid_for_pub(hist_pub)        # pinned but intentionally absent from registry
    disp, disp_pub, disp_seed = _kp()
    kid_disp = signing._kid_for_pub(disp_pub)
    keys = [{"kid": kid_disp, "alg": "ed25519", "state": "active", "seed_b64": disp_seed}]
    _rc_signing_env(monkeypatch, keys, verify_kids=kid_hist)
    try:
        with pytest.raises(prodconfig.InsecureConfigError):
            signing.assert_signing_ready()           # historical pin not satisfied -> fail closed
    finally:
        signing._reset_registry()
