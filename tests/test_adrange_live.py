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
              "ADRANGE_INTERNAL_URL", "ADRANGE_PROOF_TOKEN", "ADRANGE_REALM",
              "ADRANGE_SOCKS_PORT", "ADRANGE_SOCKS_USER", "ADRANGE_SOCKS_PASSWORD",
              "ADRANGE_VALIDATOR_USER", "ADRANGE_VALIDATOR_PASSWORD"):
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


def test_validate_live_no_token_fails_closed(monkeypatch):
    # Even with a private URL, a missing proof token is fail-closed (never a fabricated pass).
    monkeypatch.setenv("ADRANGE_INTERNAL_URL", "http://adrange.railway.internal:9443")
    r = AL.validate_live()
    assert r["ok"] is False and r["reachable"] is False


def test_validate_live_pivot_not_configured_is_fail_closed(monkeypatch):
    # Token set but no internal URL and no validator pivot credential -> fail-closed, not a crash.
    monkeypatch.setenv("ADRANGE_PROOF_TOKEN", "tok")
    r = AL.validate_live()
    assert r["ok"] is False and r["reachable"] is False
    assert "not configured" in r["reason"]


def test_shape_validation_requires_all_checks_true():
    assert AL._shape_validation({"ok": True, "checks": {"a": True, "b": True}})["ok"] is True
    assert AL._shape_validation({"ok": True, "checks": {"a": True, "b": False}})["ok"] is False
    # A top-level ok:false never passes, and an error key is ignored for the all-true test but
    # the top-level ok gate still fails it.
    assert AL._shape_validation({"ok": False, "checks": {"a": True}})["ok"] is False
    shaped = AL._shape_validation({"ok": True, "checks": {"a": True}})
    assert shaped["reachable"] is True


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


def test_trophy_flag_deterministic_and_scoped(monkeypatch):
    monkeypatch.setenv("ADRANGE_PROOF_TOKEN", "proof-secret-key")
    a = AL.trophy_flag("alice", 5, 1)
    assert a == AL.trophy_flag("alice", 5, 1)           # deterministic
    assert a.startswith("pwn-") and len(a) == 20        # CN-safe shape
    assert a != AL.trophy_flag("bob", 5, 1)             # per-candidate
    assert a != AL.trophy_flag("alice", 6, 1)           # per-board
    assert a != AL.trophy_flag("alice", 5, 2)           # per-attempt


def test_trophy_flag_unforgeable_without_key(monkeypatch):
    monkeypatch.setenv("ADRANGE_PROOF_TOKEN", "key-one")
    one = AL.trophy_flag("alice", 5, 1)
    monkeypatch.setenv("ADRANGE_PROOF_TOKEN", "key-two")
    assert one != AL.trophy_flag("alice", 5, 1)  # a different portal key yields a different flag


def test_verify_trophy_reads_dc(monkeypatch):
    monkeypatch.setenv("ADRANGE_PROOF_TOKEN", "proof-secret-key")
    seen = {}

    def fake_get(path, timeout):
        seen["path"] = path
        return {"present": True, "realm": "QWALORA.RANGE"}, True, "ok"

    monkeypatch.setattr(AL, "_proof_http_get", fake_get)
    r = AL.verify_trophy(_Cand(), 5, attempt=1)
    assert r["ok"] is True and r["present"] is True
    assert r["flag"] == AL.trophy_flag("rtest", 5, 1)
    assert r["flag"] in seen["path"] and seen["path"].startswith("/trophy?flag=")


def test_verify_trophy_absent_and_unreachable(monkeypatch):
    monkeypatch.setenv("ADRANGE_PROOF_TOKEN", "proof-secret-key")
    monkeypatch.setattr(AL, "_proof_http_get",
                        lambda p, t: ({"present": False}, True, "ok"))
    assert AL.verify_trophy(_Cand(), 5)["ok"] is False
    # fail-closed when the proof channel is unreachable
    monkeypatch.setattr(AL, "_proof_http_get", lambda p, t: (None, False, "pivot unreachable"))
    r = AL.verify_trophy(_Cand(), 5)
    assert r["ok"] is False and r["reachable"] is False


def test_attest_with_trophy_proof(monkeypatch):
    monkeypatch.setenv("ADRANGE_ADAPTER_VERIFIED", "1")
    monkeypatch.setenv("ADRANGE_PROOF_TOKEN", "proof-secret-key")
    passval = {"ok": True, "reachable": True, "checks": {"provisioned": True}, "reason": "ok"}
    proof = {"ok": True, "present": True, "reason": "trophy present", "flag": "pwn-abc123"}
    cred, rec = AL.attest(_Cand(), 5, cohort="2026-A", attempt=1, validation=passval, proof=proof)
    assert cred is True
    assert rec["proof_of_compromise"]["method"] == "trophy-write"
    assert rec["proof_of_compromise"]["trophy"] == "pwn-abc123"
    ok, _ = AL.verify_attestation(rec, handle="rtest", board=5, cohort="2026-A", attempt=1)
    assert ok is True
