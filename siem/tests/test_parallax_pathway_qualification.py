"""PARALLAX pathway-qualification separation + hardening (findings 1, 2, 3).

Proves a single passing assessment is never a pathway qualification; the portfolio policy must be a
SIGNED, authorized approval binding the exact competency inventory (not a caller boolean); transplanted
signatures are rejected; and both activation flags behave correctly independently and together.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "parallax-pathway-test")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

from parallax import laba_assessment as A, governance, review  # noqa: E402
from parallax import laba_blueprint as BP, laba_sim as sim  # noqa: E402
from parallax import pathway_qualification as PQ  # noqa: E402

COHORT = "2026-PX-A"
ADMINS = {"admin-1"}
COMP = BP.LABA_SPEC.competency
AID = BP.LABA_SPEC.assessment_id
AVER = BP.LABA_SPEC.version
_FLAGS = ("RANGER_PARALLAX_QUALIFICATION_ACTIVE", "RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE")


@pytest.fixture(autouse=True)
def _gates_off():
    for k in _FLAGS:
        os.environ.pop(k, None)
    yield
    for k in _FLAGS:
        os.environ.pop(k, None)


def _passing_record(cand):
    approval = governance.approve_spec(BP.LABA_SPEC, BP.blueprint(), approver_id="admin-1",
                                       authorized_admins=ADMINS)
    binding = {"candidate_key": cand, "cohort": COHORT, "assessment_id": AID, "attempt": 1}
    directory = review.ReviewerDirectory(authorized={"rev-1"})
    directory.assign("rev-1", binding)
    reviewer = {"reviewer_id": "rev-1", "directory": directory, "decision": "pass", "note": "ok",
                "rubric_scores": {"rootcause_analysis_quality": 85}}
    spec, contract, inst = A.bind_instance(cohort=COHORT, candidate_key=cand, approval=approval,
                                           authorized_admins=ADMINS)
    t = sim.truth(inst)
    findings = {"findings": [{"event_id": b, "classification": "unauthorized_access", "evidence": [b]}
                            for b in sorted(t["breaches"])], "analysis": "root cause"}
    r = A.run_assessment(findings, cohort=COHORT, candidate_key=cand, approval=approval,
                         authorized_admins=ADMINS, reviewer=reviewer)
    assert r["assessment_passed"] is True and r["pathway_qualified"] is False
    return r, directory


def _records(r):
    return {COMP: {"signed_decision": r["signed"], "adjudication": r["adjudication"]}}


def _portfolio(required=None):
    required = required or [{"competency": COMP, "assessment_id": AID, "assessment_version": AVER}]
    return PQ.PortfolioPolicy(version="2026.1", required=required)


def _portfolio_approval(policy):
    return governance.approve_portfolio(policy, approver_id="admin-1", authorized_admins=ADMINS)


def test_single_assessment_is_not_pathway_qualification():
    r, _ = _passing_record("gh-alice")
    assert r["pathway_qualified"] is False


def test_unapproved_portfolio_rejected():
    r, directory = _passing_record("gh-alice")
    policy = _portfolio()
    d = PQ.decide_pathway(candidate_key="gh-alice", cohort=COHORT, portfolio=policy,
                          portfolio_approval={"record": {}, "signature": "x"}, authorized_admins=ADMINS,
                          competency_records=_records(r), directory=directory)
    assert d["qualified"] is False and d["reason"] == "no_approved_portfolio_policy"


def test_portfolio_approval_bound_to_exact_inventory():
    """An approval signed for one inventory does not authorize a different (e.g. padded) inventory."""
    r, directory = _passing_record("gh-alice")
    approved_policy = _portfolio()
    approval = _portfolio_approval(approved_policy)
    tampered = _portfolio(required=[{"competency": COMP, "assessment_id": AID, "assessment_version": AVER},
                                    {"competency": "extra", "assessment_id": "X", "assessment_version": "1"}])
    d = PQ.decide_pathway(candidate_key="gh-alice", cohort=COHORT, portfolio=tampered,
                          portfolio_approval=approval, authorized_admins=ADMINS,
                          competency_records=_records(r), directory=directory)
    assert d["qualified"] is False and d["reason"] == "no_approved_portfolio_policy"


def test_all_met_but_pathway_activation_off_withholds():
    r, directory = _passing_record("gh-alice")
    policy = _portfolio()
    d = PQ.decide_pathway(candidate_key="gh-alice", cohort=COHORT, portfolio=policy,
                          portfolio_approval=_portfolio_approval(policy), authorized_admins=ADMINS,
                          competency_records=_records(r), directory=directory)
    assert d["assessment_complete"] is True
    assert d["qualified"] is False and d["reason"] == "pathway_qualification_inactive"


def test_pathway_activation_on_qualifies():
    r, directory = _passing_record("gh-alice")
    policy = _portfolio()
    os.environ["RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"] = "1"
    d = PQ.decide_pathway(candidate_key="gh-alice", cohort=COHORT, portfolio=policy,
                          portfolio_approval=_portfolio_approval(policy), authorized_admins=ADMINS,
                          competency_records=_records(r), directory=directory)
    assert d["qualified"] is True and d["reason"] == "qualified"


def test_missing_required_competency_incomplete():
    r, directory = _passing_record("gh-alice")
    policy = _portfolio(required=[{"competency": COMP, "assessment_id": AID, "assessment_version": AVER},
                                  {"competency": "ai_incident_response_and_forensics",
                                   "assessment_id": "LAB-F", "assessment_version": "1.0.0"}])
    os.environ["RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"] = "1"
    d = PQ.decide_pathway(candidate_key="gh-alice", cohort=COHORT, portfolio=policy,
                          portfolio_approval=_portfolio_approval(policy), authorized_admins=ADMINS,
                          competency_records=_records(r), directory=directory)
    assert d["qualified"] is False and d["reason"] == "required_competencies_incomplete"


def test_transplanted_assessment_from_another_candidate_rejected():
    r_a, dir_a = _passing_record("gh-alice")
    r_b, dir_b = _passing_record("gh-bob")
    policy = _portfolio()
    os.environ["RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"] = "1"
    # use ALICE's signed assessment + adjudication to try to qualify BOB
    d = PQ.decide_pathway(candidate_key="gh-bob", cohort=COHORT, portfolio=policy,
                          portfolio_approval=_portfolio_approval(policy), authorized_admins=ADMINS,
                          competency_records=_records(r_a), directory=dir_a)
    assert d["qualified"] is False
    assert d["breakdown"][COMP]["assessment_ok"] is False


def test_transplanted_adjudication_rejected():
    r_a, dir_a = _passing_record("gh-alice")
    r_b, dir_b = _passing_record("gh-bob")
    policy = _portfolio()
    os.environ["RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"] = "1"
    # alice's valid assessment, but bob's adjudication (bound to bob's provenance) -> review fails
    recs = {COMP: {"signed_decision": r_a["signed"], "adjudication": r_b["adjudication"]}}
    d = PQ.decide_pathway(candidate_key="gh-alice", cohort=COHORT, portfolio=policy,
                          portfolio_approval=_portfolio_approval(policy), authorized_admins=ADMINS,
                          competency_records=recs, directory=dir_a)
    assert d["qualified"] is False and d["breakdown"][COMP]["review_ok"] is False


@pytest.mark.parametrize("per_assess,pathway", [("0", "0"), ("1", "0"), ("0", "1"), ("1", "1")])
def test_flag_matrix_single_assessment_never_pathway(per_assess, pathway):
    """Across all four flag combinations, a single assessment is assessment-only (never pathway)."""
    os.environ["RANGER_PARALLAX_QUALIFICATION_ACTIVE"] = per_assess
    os.environ["RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"] = pathway
    r, _ = _passing_record("gh-alice")
    assert r["assessment_passed"] is True
    assert r["pathway_qualified"] is False
    assert r["assessment_decision"]["qualified"] is False


@pytest.mark.parametrize("per_assess,pathway,expect", [("0", "0", False), ("1", "0", False),
                                                       ("0", "1", True), ("1", "1", True)])
def test_flag_matrix_pathway_only_gated_by_pathway_flag(per_assess, pathway, expect):
    """Pathway qualification depends ONLY on the pathway flag (+ all met + approved portfolio); the
    per-assessment flag has no effect either way."""
    os.environ["RANGER_PARALLAX_QUALIFICATION_ACTIVE"] = per_assess
    os.environ["RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"] = pathway
    r, directory = _passing_record("gh-alice")
    policy = _portfolio()
    d = PQ.decide_pathway(candidate_key="gh-alice", cohort=COHORT, portfolio=policy,
                          portfolio_approval=_portfolio_approval(policy), authorized_admins=ADMINS,
                          competency_records=_records(r), directory=directory)
    assert d["qualified"] is expect
