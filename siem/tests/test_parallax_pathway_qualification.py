"""PARALLAX pathway-qualification separation.

Proves a single passing assessment is NOT a pathway qualification, and that pathway qualification
requires an approved portfolio of all required competencies, independent verified adjudications, AND a
separate activation - which is off by default.
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


@pytest.fixture(autouse=True)
def _gates_off():
    for k in ("RANGER_PARALLAX_QUALIFICATION_ACTIVE", "RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"):
        os.environ.pop(k, None)
    yield
    for k in ("RANGER_PARALLAX_QUALIFICATION_ACTIVE", "RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"):
        os.environ.pop(k, None)


def _passing_record(cand):
    approval = governance.approve_spec(BP.LABA_SPEC, approver_id="admin-1", authorized_admins=ADMINS)
    binding = {"candidate_key": cand, "cohort": COHORT, "assessment_id": BP.LABA_SPEC.assessment_id,
               "attempt": 1}
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
    assert r["assessment_passed"] is True
    return r, directory


def _records_map(r):
    return {COMP: {"signed_decision": r["signed"], "adjudication": r["adjudication"],
                   "binding": r["binding"]}}


def test_single_assessment_is_not_pathway_qualification():
    r, _ = _passing_record("gh-alice")
    assert r["pathway_qualified"] is False


def test_no_approved_portfolio_means_no_qualification():
    r, directory = _passing_record("gh-alice")
    portfolio = PQ.PortfolioPolicy(version="draft", required_competencies=[COMP], approved=False)
    d = PQ.decide_pathway(candidate_key="gh-alice", cohort=COHORT, portfolio=portfolio,
                          competency_records=_records_map(r), directory=directory)
    assert d["qualified"] is False and d["reason"] == "no_approved_portfolio_policy"


def test_all_competencies_met_but_activation_off_withholds_qualification():
    r, directory = _passing_record("gh-alice")
    portfolio = PQ.PortfolioPolicy(version="2026.1", required_competencies=[COMP], approved=True)
    d = PQ.decide_pathway(candidate_key="gh-alice", cohort=COHORT, portfolio=portfolio,
                          competency_records=_records_map(r), directory=directory)
    assert d["assessment_complete"] is True
    assert d["qualified"] is False and d["reason"] == "pathway_qualification_inactive"


def test_activation_on_with_all_competencies_qualifies():
    r, directory = _passing_record("gh-alice")
    portfolio = PQ.PortfolioPolicy(version="2026.1", required_competencies=[COMP], approved=True)
    os.environ["RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"] = "1"
    d = PQ.decide_pathway(candidate_key="gh-alice", cohort=COHORT, portfolio=portfolio,
                          competency_records=_records_map(r), directory=directory)
    assert d["qualified"] is True and d["reason"] == "qualified"


def test_missing_a_required_competency_is_incomplete():
    r, directory = _passing_record("gh-alice")
    portfolio = PQ.PortfolioPolicy(version="2026.1",
                                   required_competencies=[COMP, "ai_incident_response_and_forensics"],
                                   approved=True)
    os.environ["RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"] = "1"
    d = PQ.decide_pathway(candidate_key="gh-alice", cohort=COHORT, portfolio=portfolio,
                          competency_records=_records_map(r), directory=directory)
    assert d["qualified"] is False and d["reason"] == "required_competencies_incomplete"
