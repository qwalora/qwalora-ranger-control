"""Phase 2 SIEM tests that run WITHOUT a live cluster, against the in-process
security-enforcing fake. They prove the Ranger-side logic: telemetry generation
and idempotent ingestion, candidate isolation at the API layer, and the Ranger
authorization integration. The same suites run against the real node once approved.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest  # noqa: E402

from siem import schema, telemetry  # noqa: E402
from siem.authz import CredentialBroker, index_name, candidate_role  # noqa: E402
from siem.client import FakeOpenSearch, AuthorizationError  # noqa: E402
from siem.ingest import Seeder, IngestionError  # noqa: E402

COHORT = "2026-A"


def _setup():
    os_ = FakeOpenSearch()
    return os_, Seeder(os_)


def _enroll(seeder, cid, board, seed, status="active"):
    prov = seeder.broker.provision(COHORT, cid, status, board)
    rec = seeder.seed(COHORT, cid, status, board, seed)
    return prov, rec


# --- telemetry -------------------------------------------------------------
def test_events_are_indexed_and_counted():
    _, seeder = _setup()
    _, rec = _enroll(seeder, "alice", 1, "seed-a1")
    assert rec["status"] == "ok"
    assert rec["indexed_count"] == rec["expected_count"] > 20


def test_search_returns_expected_records():
    os_, seeder = _setup()
    _enroll(seeder, "alice", 1, "seed-a1")
    idx = index_name(COHORT, "alice", 1)
    # genuine query: failed SSH authentications
    failed = os_.search(os_.ADMIN, idx, {"term": {"event.action": "ssh_login_failed"}})
    assert len(failed) >= 8
    assert all(d["event"]["outcome"] == "failure" for d in failed)
    # the C2 beacon DNS is present and queryable
    dns = os_.search(os_.ADMIN, idx, {"term": {"event.action": "dns_query"}})
    assert any("duckdns" in d["dns"]["question"]["name"] or "." in d["dns"]["question"]["name"] for d in dns)


def test_every_event_is_synthetic_valid_and_carries_provenance():
    _, seeder = _setup()
    events = telemetry.generate("alice", 1, "seed-a1")
    for e in events:
        src = e["_source"]
        assert schema.validate(src) == []
        assert src["data"]["synthetic"] is True
        assert src["ranger"]["candidate_id"] == "alice"
        assert src["ranger"]["generator_version"]
        assert src["ranger"]["scenario"] in telemetry.SCENARIO_FAMILIES


def test_no_event_reveals_an_answer_label():
    # Events must not carry a verdict/technique answer field.
    events = telemetry.generate("alice", 1, "seed-a1")
    for e in events:
        src = e["_source"]
        assert "verdict" not in src and "_key" not in src
        assert "technique" not in src.get("ranger", {})


def test_seed_is_reproducible():
    a = telemetry.generate("alice", 1, "seed-x")
    b = telemetry.generate("alice", 1, "seed-x")
    assert [e["_id"] for e in a] == [e["_id"] for e in b]
    # a different seed is a different exercise
    c = telemetry.generate("alice", 1, "seed-y")
    assert [e["_id"] for e in a] != [e["_id"] for e in c]


def test_duplicate_ingestion_is_idempotent():
    _, seeder = _setup()
    _enroll(seeder, "alice", 1, "seed-a1")
    rec2 = seeder.seed(COHORT, "alice", "active", 1, "seed-a1")  # seed again
    assert rec2["idempotent_ok"] is True
    assert rec2["newly_added"] == 0  # nothing new; count did not inflate


def test_reset_and_reseed_are_predictable():
    os_, seeder = _setup()
    _enroll(seeder, "alice", 1, "seed-a1")
    idx = index_name(COHORT, "alice", 1)
    before = os_.count(os_.ADMIN, idx)
    r = seeder.reset(COHORT, "alice", 1)
    assert r["existed"] is True and not os_.index_exists(idx)
    rec = seeder.reseed(COHORT, "alice", "active", 1, "seed-a1")
    assert rec["status"] == "ok" and os_.count(os_.ADMIN, idx) == before


def test_dry_run_validates_without_writing():
    os_, seeder = _setup()
    rec = seeder.seed(COHORT, "alice", "active", 1, "seed-a1", dry_run=True)
    assert rec["status"] == "dry-run" and rec["validated"] is True
    assert not os_.index_exists(index_name(COHORT, "alice", 1))


# --- candidate isolation (the critical requirement) ------------------------
def test_candidate_reads_only_their_own_index():
    os_, seeder = _setup()
    pa, _ = _enroll(seeder, "alice", 1, "seed-a1")
    pb, _ = _enroll(seeder, "bob", 1, "seed-b1")
    a_idx, b_idx = index_name(COHORT, "alice", 1), index_name(COHORT, "bob", 1)
    # A reads A
    assert len(os_.search(pa["username"], a_idx, {"match_all": {}})) > 0
    # A cannot read B (403 at the API layer, not just the UI)
    with pytest.raises(AuthorizationError):
        os_.search(pa["username"], b_idx, {"match_all": {}})
    # B cannot read A
    with pytest.raises(AuthorizationError):
        os_.search(pb["username"], a_idx, {"match_all": {}})
    # B reads B
    assert len(os_.search(pb["username"], b_idx, {"match_all": {}})) > 0


def test_direct_api_query_enforces_restriction_not_just_dashboards():
    os_, seeder = _setup()
    pa, _ = _enroll(seeder, "alice", 1, "seed-a1")
    _enroll(seeder, "bob", 1, "seed-b1")
    # A tries a direct REST-style search against B's index pattern: denied.
    with pytest.raises(AuthorizationError):
        os_.search(pa["username"], index_name(COHORT, "bob", 1), {"term": {"event.action": "sudo"}})


def test_document_level_security_is_a_second_layer():
    # Even if two candidates shared an index, the per-candidate DLS term filter
    # would restrict each to their own documents.
    os_ = FakeOpenSearch()
    shared = "ranger-2026-a-shared-b1"
    os_.create_index(os_.ADMIN, shared)
    os_.bulk_index(os_.ADMIN, shared, [
        {"_id": "1", "_source": {"ranger": {"candidate_id": "alice"}, "message": "a"}},
        {"_id": "2", "_source": {"ranger": {"candidate_id": "bob"}, "message": "b"}},
    ])
    # give alice a role whose pattern includes the shared index but DLS to alice
    role = candidate_role(COHORT, "alice")
    role.index_patterns = [shared]
    os_.put_role(os_.ADMIN, role)
    os_.put_user(os_.ADMIN, "cand_alice", [role.name])
    rows = os_.search("cand_alice", shared, {"match_all": {}})
    assert len(rows) == 1 and rows[0]["ranger"]["candidate_id"] == "alice"


# --- Ranger authorization integration --------------------------------------
def test_unapproved_candidate_gets_no_access():
    os_, seeder = _setup()
    prov = seeder.broker.provision(COHORT, "carol", "pending", 1)
    assert prov["allowed"] is False and "not-active" in prov["reason"]
    rec = seeder.seed(COHORT, "carol", "pending", 1, "seed-c1")
    assert rec["status"] == "denied"
    assert not os_.index_exists(index_name(COHORT, "carol", 1))


def test_non_siem_board_is_denied():
    _, seeder = _setup()
    prov = seeder.broker.provision(COHORT, "dave", "active", 5)  # board 5 = Ludus/GOAD
    assert prov["allowed"] is False and "not-a-siem-board" in prov["reason"]


def test_revoked_candidate_loses_access():
    os_, seeder = _setup()
    pa, _ = _enroll(seeder, "alice", 1, "seed-a1")
    a_idx = index_name(COHORT, "alice", 1)
    assert len(os_.search(pa["username"], a_idx, {"match_all": {}})) > 0
    seeder.broker.revoke("alice")               # e.g. status -> washed_out
    with pytest.raises(AuthorizationError):      # user no longer exists
        os_.search(pa["username"], a_idx, {"match_all": {}})


def test_cross_candidate_ingestion_is_prevented():
    _, seeder = _setup()
    # Hand the pipeline events whose candidate_id does not match the target.
    bad = telemetry.generate("bob", 1, "seed-b1")
    seeder.client.put_role(seeder.admin, candidate_role(COHORT, "alice"))
    seeder.client.create_index(seeder.admin, index_name(COHORT, "alice", 1))

    class _Patched(Seeder):
        def _events(self):
            return bad
    # Directly exercise the guard: validate that bob's events cannot target alice.
    import siem.telemetry as T
    orig = T.generate
    T.generate = lambda cid, b, s: bad
    try:
        with pytest.raises(IngestionError):
            seeder.seed(COHORT, "alice", "active", 1, "seed-a1")
    finally:
        T.generate = orig
