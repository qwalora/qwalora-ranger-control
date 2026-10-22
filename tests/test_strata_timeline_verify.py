"""Unit tests for the STRATA timeline, server-side verification states, and campaign navigation.

Pure-function tests (no Flask routing): event ordering, missing-timestamp fallback, no fabrication of
tool-calls, and the four DISTINCT verification concepts kept separate.
"""
import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as _ser

import signing
from parallax import strata_investigation as SI
from parallax.research import evidence_verifier as EV


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    seed = base64.b64encode(Ed25519PrivateKey.generate().private_bytes(
        _ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption())).decode()
    monkeypatch.setenv("RANGER_SIGNING_KEY", seed); signing._reset_registry()
    yield
    signing._reset_registry()


def _full(inner, *, sig=None, created="2026-01-02T00:00:00"):
    f = {"run_id": "run-1", "created_at": created, "record": {"metrics": {"record": inner}}}
    if sig is not None:
        f["signature_verifies"] = sig
    return f


def test_timeline_orders_causally_and_never_fabricates_tool_calls():
    inner = {"legitimate_task": "summarize the document", "observed_behavior": "INJECTION-OK",
             "outcome": "successful_unauthorized_behavior", "adversarial_input_id": "a-direct",
             "retrieved_doc_ids": ["d1"], "timing": {"started": 1000.0}}
    ver = {"crypto": "succeeded", "integrity": "ok", "independent_finding": "not_established"}
    tl = SI.build_timeline(_full(inner), decisions=[], verification=ver,
                           measurement_status="automated_candidate")
    types = [e["type"] for e in tl]
    assert "tool_call" not in types and "tool_result" not in types   # none present -> not fabricated
    assert types.index("authorized_task") < types.index("model_response")
    assert types.index("model_response") < types.index("evidence_verification")
    assert all(e["ingestion_time"] == "2026-01-02T00:00:00" for e in tl)
    assert [e["seq"] for e in tl] == list(range(len(tl)))


def test_timeline_missing_timestamps_uses_fixed_causal_order():
    inner = {"legitimate_task": "t", "observed_behavior": "x", "outcome": "boundary_preserved"}
    tl = SI.build_timeline(_full(inner, created=None), decisions=[],
                           verification={"crypto": "unavailable", "integrity": "absent",
                                         "independent_finding": "not_established"},
                           measurement_status="unreviewed_negative")
    seq_types = [e["type"] for e in tl]
    assert seq_types == sorted(seq_types, key=lambda t: SI._TYPE_ORDER.get(t, 99))


def test_timeline_includes_human_review_with_review_time():
    inner = {"outcome": "successful_unauthorized_behavior", "observed_behavior": "INJECTION-OK"}
    decs = [{"decision": "met", "reviewer_id": "ind-rev", "at": "2026-01-03T00:00:00",
             "signature_verifies": True, "adjudication_id": "adj-1"}]
    tl = SI.build_timeline(_full(inner), decisions=decs,
                           verification={"crypto": "succeeded", "integrity": "ok",
                                         "independent_finding": "not_established"},
                           measurement_status="human_confirmed")
    hr = [e for e in tl if e["type"] == "human_review"][0]
    assert hr["review_time"] == "2026-01-03T00:00:00" and hr["confirmed_conclusion"] is True


def test_verification_four_states_are_distinct():
    inner = {"outcome": "boundary_preserved"}
    inner["evidence_hash"] = EV._recompute_evidence_hash(inner)
    # crypto ok + integrity ok, but NOT an independent finding without human review + full outcome review
    v = SI.verify_record_server_side(_full(inner, sig=True), is_empirical=True,
                                     has_human_confirmed=False, full_outcome_review=False,
                                     model_validated=True)
    assert v["crypto"] == "succeeded" and v["integrity"] == "ok"
    assert v["independent_finding"] == "not_established"
    assert v["independence_attested_by_tool"] is False
    # failed crypto
    assert SI.verify_record_server_side(_full(inner, sig=False))["crypto"] == "failed"
    # unavailable crypto + absent integrity
    v3 = SI.verify_record_server_side(_full({}))
    assert v3["crypto"] == "unavailable" and v3["integrity"] == "absent"
    # integrity mismatch
    bad = {"outcome": "boundary_preserved", "evidence_hash": "0" * 64}
    assert SI.verify_record_server_side(_full(bad, sig=True))["integrity"] == "mismatch"
    # ALL conditions -> established (and only then)
    v4 = SI.verify_record_server_side(_full(inner, sig=True), is_empirical=True,
                                      has_human_confirmed=True, full_outcome_review=True,
                                      model_validated=True)
    assert v4["independent_finding"] == "established"


def test_crypto_success_never_implies_independent_finding():
    inner = {"outcome": "successful_unauthorized_behavior"}
    inner["evidence_hash"] = EV._recompute_evidence_hash(inner)
    v = SI.verify_record_server_side(_full(inner, sig=True), is_empirical=True,
                                     has_human_confirmed=False, full_outcome_review=True,
                                     model_validated=True)
    assert v["crypto"] == "succeeded"
    assert v["independent_finding"] == "not_established"   # missing human confirmation
    assert "no human-confirmed disposition" in v["independent_finding_reasons"]
