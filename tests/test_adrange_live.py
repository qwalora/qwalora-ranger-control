"""Live-execution AD range (Samba AD DC on Railway) portal adapter: NT-hash proof correctness,
submission parsing, fail-closed creditability, and signed proof-of-compromise attestations."""
import importlib
import os

import pytest

import adrange_live as AL


class _Cand:
    handle = "rtest"
    github_id = "gh-123"
    cohort = "2026-A"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("ADRANGE_ENABLED", "ADRANGE_HOST", "ADRANGE_PORTS", "ADRANGE_ADMIN_PASSWORD",
              "ADRANGE_FOOTHOLD_USER", "ADRANGE_FOOTHOLD_PASSWORD", "ADRANGE_ADAPTER_VERIFIED",
              "ADRANGE_INTERNAL_URL", "ADRANGE_PROOF_TOKEN", "ADRANGE_REALM"):
        monkeypatch.delenv(k, raising=False)
    yield


def test_nt_hash_known_vectors():
    assert AL.nt_hash("password") == "8846f7eaee8fb117ad06bdd830b7586c"
    assert AL.nt_hash("") == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_parse_submitted_hash_formats():
    nt = "8846f7eaee8fb117ad06bdd830b7586c"
    assert AL.parse_submitted_hash(nt) == nt
    assert AL.parse_submitted_hash(nt.upper()) == nt
    assert AL.parse_submitted_hash("aad3b435b51404eeaad3b435b51404ee:" + nt) == nt
    assert AL.parse_submitted_hash("Administrator:500:aad3b435b51404eeaad3b435b51404ee:%s:::" % nt) == nt
    assert AL.parse_submitted_hash("not a hash") is None
    assert AL.parse_submitted_hash("") is None


def test_enabled_requires_flag_and_host(monkeypatch):
    assert AL.enabled() is False
    monkeypatch.setenv("ADRANGE_ENABLED", "1")
    assert AL.enabled() is False  # no host yet
    monkeypatch.setenv("ADRANGE_HOST", "proxy.rlwy.net")
    assert AL.enabled() is True


def test_connection_details_never_leaks_admin(monkeypatch):
    monkeypatch.setenv("ADRANGE_ENABLED", "1")
    monkeypatch.setenv("ADRANGE_HOST", "proxy.rlwy.net")
    monkeypatch.setenv("ADRANGE_SOCKS_PORT", "23456")
    monkeypatch.setenv("ADRANGE_SOCKS_USER", "ranger")
    monkeypatch.setenv("ADRANGE_SOCKS_PASSWORD", "SocksPw1!")
    monkeypatch.setenv("ADRANGE_ADMIN_PASSWORD", "SuperSecretAdmin1!")
    monkeypatch.setenv("ADRANGE_FOOTHOLD_USER", "ranger")
    monkeypatch.setenv("ADRANGE_FOOTHOLD_PASSWORD", "FootPw1!")
    d = AL.connection_details(_Cand())
    blob = repr(d)
    assert "SuperSecretAdmin1!" not in blob  # admin password/hash never surfaced to the candidate
    assert d["socks"]["host"] == "proxy.rlwy.net" and d["socks"]["port"] == 23456
    assert d["socks"]["password"] == "SocksPw1!"
    assert d["foothold"]["username"] == "ranger"
    assert d["foothold"]["password"] == "FootPw1!"
    assert "socks5 proxy.rlwy.net 23456" in d["proxychains_conf"]


def test_verify_compromise(monkeypatch):
    monkeypatch.setenv("ADRANGE_ADMIN_PASSWORD", "SuperSecretAdmin1!")
    exp = AL.expected_admin_nt_hash()
    assert AL.verify_compromise(exp)["ok"] is True
    assert AL.verify_compromise("Administrator:500:%s:%s:::" % ("0" * 32, exp))["ok"] is True
    assert AL.verify_compromise("deadbeef" * 4)["ok"] is False
    assert AL.verify_compromise("")["ok"] is False


def test_validate_live_fail_closed_when_unconfigured():
    r = AL.validate_live()
    assert r["ok"] is False and r["reachable"] is False


def test_attest_requires_adapter_validation_and_proof(monkeypatch):
    monkeypatch.setenv("ADRANGE_ADMIN_PASSWORD", "SuperSecretAdmin1!")
    monkeypatch.setenv("ADRANGE_REALM", "QWALORA.RANGE")
    good = AL.verify_compromise(AL.expected_admin_nt_hash())
    passval = {"ok": True, "reachable": True, "checks": {"provisioned": True}, "reason": "ok"}
    failval = {"ok": False, "reachable": True, "checks": {}, "reason": "path not planted"}

    # No adapter confirmation -> not creditable even with good proof + validation.
    cred, rec = AL.attest(_Cand(), 5, validation=passval, proof=good)
    assert cred is False and rec["mode"] == "unavailable"

    monkeypatch.setenv("ADRANGE_ADAPTER_VERIFIED", "1")
    # Good proof + failing validation -> not creditable.
    cred, _ = AL.attest(_Cand(), 5, validation=failval, proof=good)
    assert cred is False
    # Failing proof + good validation -> not creditable.
    cred, _ = AL.attest(_Cand(), 5, validation=passval, proof={"ok": False, "reason": "no"})
    assert cred is False
    # All three -> creditable, signed, verifiable.
    cred, rec = AL.attest(_Cand(), 5, cohort="2026-A", attempt=1, validation=passval, proof=good)
    assert cred is True and rec["mode"] == "real" and rec["real"] is True
    ok, _ = AL.verify_attestation(rec, handle="rtest", board=5, cohort="2026-A", attempt=1)
    assert ok is True


def test_attestation_identity_binding(monkeypatch):
    monkeypatch.setenv("ADRANGE_ADMIN_PASSWORD", "SuperSecretAdmin1!")
    monkeypatch.setenv("ADRANGE_ADAPTER_VERIFIED", "1")
    good = AL.verify_compromise(AL.expected_admin_nt_hash())
    passval = {"ok": True, "reachable": True, "checks": {"provisioned": True}, "reason": "ok"}
    cred, rec = AL.attest(_Cand(), 5, cohort="2026-A", attempt=1, validation=passval, proof=good)
    assert cred
    # foreign handle / board / cohort fail closed
    assert AL.verify_attestation(rec, handle="someone-else", board=5, cohort="2026-A")[0] is False
    assert AL.verify_attestation(rec, handle="rtest", board=6, cohort="2026-A")[0] is False
    assert AL.verify_attestation(rec, handle="rtest", board=5, cohort="2026-B")[0] is False
    # tampered signature fails
    bad = dict(rec)
    bad["proof_of_compromise"] = {"verified": True, "target": "Administrator"}
    assert AL.verify_attestation(bad, handle="rtest", board=5, cohort="2026-A")[0] is False


def test_attestation_does_not_embed_full_hash(monkeypatch):
    monkeypatch.setenv("ADRANGE_ADMIN_PASSWORD", "SuperSecretAdmin1!")
    monkeypatch.setenv("ADRANGE_ADAPTER_VERIFIED", "1")
    exp = AL.expected_admin_nt_hash()
    good = AL.verify_compromise(exp)
    passval = {"ok": True, "reachable": True, "checks": {"provisioned": True}, "reason": "ok"}
    _, rec = AL.attest(_Cand(), 5, validation=passval, proof=good)
    import json
    blob = json.dumps(rec)
    assert exp not in blob  # only a short fingerprint is stored, never the full secret hash
