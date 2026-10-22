"""Workstream C + D: STRATA research view-model tests (pure, no Flask).

Confirms entitlement isolation (restricted program not exposed without entitlement / outside scope),
and that the view keeps observed evidence structurally separate from unverified conclusions.
"""
import pytest

from parallax.research import strata_view as SV, measurement as M, protocol as P


def _rec(eh, outcome, attack=True, src="doc-attn-1"):
    return {"evidence_hash": eh, "experiment_id": "e" + eh, "outcome": outcome, "backend_is_real": True,
            "condition": P.CONDITION_EXPERIMENTAL if attack else P.CONDITION_BASELINE,
            "attempts_injection": attack, "observed_behavior": "model said something",
            "adversarial_input_id": src, "attack_category": "direct", "produced_by": "agent-eval"}


MISSION = {"program": "PARALLAX", "title": "Prompt-injection boundary study", "campaign_id": "camp-1",
           "authorized_scope": "attack only the provided corpus", "dataset": "synthetic-corpus-v1",
           "rules_of_engagement": "no real PII"}


def test_unentitled_viewer_is_refused():
    with pytest.raises(SV.EntitlementError):
        SV.build_view(mission=MISSION, records=[_rec("h1", "boundary_preserved")], entitled=False)


def test_program_outside_scope_is_refused():
    with pytest.raises(SV.EntitlementError):
        SV.build_view(mission=MISSION, records=[_rec("h1", "boundary_preserved")],
                      entitled=True, viewer_scope=["STRATA"])     # PARALLAX not in scope


def test_candidate_is_shown_as_unverified_not_confirmed():
    recs = [_rec("h1", "successful_unauthorized_behavior")]
    view = SV.build_view(mission=MISSION, records=recs, entitled=True, viewer_scope=["PARALLAX"])
    cf = view["candidate_findings"]
    assert len(cf) == 1
    assert cf[0]["is_confirmed_conclusion"] is False
    assert "NOT a confirmed attack success" in cf[0]["caveat"]
    assert cf[0]["attributed_source"] == "doc-attn-1"            # source attribution present
    assert view["review"]["available"] is False
    assert view["integrity_banner"]["unverified"].endswith("not_established.")


def test_confirmed_disposition_surfaces_as_confirmed_conclusion():
    recs = [_rec("h1", "successful_unauthorized_behavior")]
    adj = {"h1": {"disposition": "confirmed", "reviewer_id": "independent", "verified": True, "signed": True}}
    view = SV.build_view(mission=MISSION, records=recs, adjudications=adj, entitled=True,
                         viewer_scope=["PARALLAX"])
    row = [r for r in view["behavior"] if r["evidence_hash"] == "h1"][0]
    assert row["status"] == M.ST_HUMAN_CONFIRMED and row["is_confirmed_conclusion"] is True
    assert view["review"]["available"] is True and view["review"]["confirmed"] == 1


def test_evidence_chain_section_from_verifier_report():
    recs = [_rec("h1", "boundary_preserved")]
    vr = {"overall": "PASS", "verdicts": {"integrity_ok": True, "campaign_complete": {"complete": True},
          "result_eligible": {"eligible": False}}, "integrity": {"chain": {"continuous": True}},
          "trust_basis": {"anchors_supplied": True, "independence_attested_by_tool": False}}
    view = SV.build_view(mission=MISSION, records=recs, verifier_report=vr, entitled=True,
                         viewer_scope=["PARALLAX"])
    assert view["evidence_chain"]["integrity_ok"] is True
    assert view["evidence_chain"]["result_eligible"] is False
    assert view["evidence_chain"]["trust_basis"]["independence_attested_by_tool"] is False


def test_ui_states_rejected_and_inconclusive_are_distinct():
    recs = [_rec("h1", "successful_unauthorized_behavior"),
            _rec("h2", "successful_unauthorized_behavior"),
            _rec("h3", "inconclusive")]
    adj = {"h1": {"disposition": "rejected", "reviewer_id": "ind", "verified": True, "signed": True},
           "h3": {"disposition": "inconclusive", "reviewer_id": "ind", "verified": True, "signed": True}}
    view = SV.build_view(mission=MISSION, records=recs, adjudications=adj, entitled=True,
                         viewer_scope=["PARALLAX"])
    by = {r["evidence_hash"]: r for r in view["behavior"]}
    assert by["h1"]["status"] == M.ST_HUMAN_REJECTED and by["h1"]["is_confirmed_conclusion"] is False
    assert by["h2"]["status"] == M.ST_AUTOMATED_CANDIDATE and by["h2"]["requires_human_review"] is True
    assert by["h3"]["status"] == M.ST_INCONCLUSIVE
    assert view["review"]["rejected"] == 1 and view["review"]["inconclusive"] == 1
    assert view["review"]["unresolved_candidates"] == 1   # h2 still open
