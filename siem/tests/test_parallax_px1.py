"""PARALLAX PX-1 (EXPERIMENTAL component) - leakage-safe model evaluation.

PX-1 is retained as a reusable, clearly-labeled experimental assessment, not a mandatory PARALLAX
qualification. These tests exercise its objective evaluator and the HARDENED boundary it shares with
Lab A: governance-approved binding, a verified authorized/assigned reviewer adjudication (never
candidate-supplied), assessment-only outcomes (never a pathway qualification), and tamper-evidence.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "parallax-px1-test")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ.pop("RANGER_PARALLAX_QUALIFICATION_ACTIVE", None)

import pytest  # noqa: E402

from parallax import px1_assessment as A, governance, review  # noqa: E402
from parallax import px1_blueprint as BP, contracts  # noqa: E402

COHORT = "2026-PX-A"
ADMINS = {"px-admin"}


def _approval():
    return governance.approve_spec(BP.PX1_SPEC, BP.blueprint(), approver_id="px-admin",
                                   authorized_admins=ADMINS)


def _reviewer(cand, attempt=1, decision="pass"):
    binding = {"candidate_key": cand, "cohort": COHORT, "assessment_id": BP.PX1_SPEC.assessment_id,
               "attempt": attempt}
    directory = review.ReviewerDirectory(authorized={"rev-1"})
    directory.assign("rev-1", binding)
    return {"reviewer_id": "rev-1", "directory": directory, "decision": decision, "note": "ok",
            "rubric_scores": {"leakage_analysis_quality": 85}}


def _instance(cand):
    spec, contract, inst = A.bind_instance(cohort=COHORT, candidate_key=cand,
                                           approval=_approval(), authorized_admins=ADMINS)
    honest = [c for c in inst.feature_names if c != inst.leak_feature]
    return spec, contract, inst, honest


def _run(cand, submission, decision="pass"):
    return A.run_assessment(submission, cohort=COHORT, candidate_key=cand, approval=_approval(),
                            authorized_admins=ADMINS, reviewer=_reviewer(cand, decision=decision))


def _safe(honest, leak):
    return {"feature_set": honest, "model_config": {"family": "logistic_regression", "C": 1.0},
            "leakage_analysis": "column %s is a target leak; excluded" % leak}


@pytest.fixture(autouse=True)
def _gate_off():
    for k in ("RANGER_PARALLAX_QUALIFICATION_ACTIVE", "RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"):
        os.environ.pop(k, None)
    yield
    for k in ("RANGER_PARALLAX_QUALIFICATION_ACTIVE", "RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"):
        os.environ.pop(k, None)


def test_leakage_safe_meets_assessment_never_pathway_qualifies():
    spec, contract, inst, honest = _instance("gh-alice")
    r = _run("gh-alice", _safe(honest, inst.leak_feature))
    assert r["assessment_passed"] is True
    assert r["pathway_qualified"] is False          # a single lab is never a pathway qualification
    assert r["candidate_feedback"]["verdict"] == "pass"


def test_single_assessment_not_pathway_even_with_per_assessment_gate_on():
    spec, contract, inst, honest = _instance("gh-alice")
    os.environ["RANGER_PARALLAX_QUALIFICATION_ACTIVE"] = "1"
    r = _run("gh-alice", _safe(honest, inst.leak_feature))
    assert r["pathway_qualified"] is False, "one lab must never award pathway qualification"


def test_leakage_dependence_is_critical_veto():
    spec, contract, inst, honest = _instance("gh-bob")
    leaky = {"feature_set": [inst.leak_feature] + honest[:2], "model_config": {"family": "random_forest"},
             "leakage_analysis": "x"}
    r = _run("gh-bob", leaky)
    assert r["assessment_passed"] is False
    assert r["objective_result"]["critical"] is True
    assert r["candidate_feedback"]["verdict"] == "critical_failure"


def test_below_threshold_fails():
    spec, contract, inst, honest = _instance("gh-carol")
    # deterministically pick the single weakest (lowest |correlation|) non-leak feature so the holdout
    # metric is reliably below threshold regardless of per-instance feature placement
    corr = inst.train[honest].corrwith(inst.train[inst.label_col]).abs().sort_values()
    weakest = [corr.index[0]]
    weak = {"feature_set": weakest, "model_config": {"family": "logistic_regression"},
            "leakage_analysis": "x"}
    r = _run("gh-carol", weak)
    assert r["assessment_passed"] is False and r["candidate_feedback"]["verdict"] == "fail"


def test_governance_required_no_hardcoded_approval():
    with pytest.raises(contracts.ContractError):
        A.bind_instance(cohort=COHORT, candidate_key="gh-x",
                        approval={"record": {}, "signature": "x"}, authorized_admins=ADMINS)


def test_candidate_supplied_reviewer_fields_ignored():
    spec, contract, inst, honest = _instance("gh-dan")
    sub = dict(_safe(honest, inst.leak_feature))
    sub["reviewer_decision"] = {"decision": "pass", "reviewer_id": "self"}  # candidate tries to self-review
    sub["rubric_scores"] = {"leakage_analysis_quality": 100}
    # no server-side reviewer supplied -> human review absent -> assessment not met despite the injected fields
    r = A.run_assessment(sub, cohort=COHORT, candidate_key="gh-dan", approval=_approval(),
                         authorized_admins=ADMINS, reviewer=None)
    assert r["assessment_passed"] is False


def test_per_candidate_instances_differ():
    _, ca, _, _ = _instance("gh-alice")
    _, cb, _, _ = _instance("gh-bob")
    assert ca.seed() != cb.seed()


def test_signed_decision_roundtrip_and_tamper():
    from siem import assessment_contract as ac
    spec, contract, inst, honest = _instance("gh-alice")
    r = _run("gh-alice", _safe(honest, inst.leak_feature))
    assert ac.verify_decision(r["signed"]) is True
    bad = json.loads(json.dumps(r["signed"]))
    bad["record"]["qualified"] = True
    assert ac.verify_decision(bad) is False


def test_protected_metadata_absent():
    spec, contract, inst, honest = _instance("gh-bob")
    r = _run("gh-bob", _safe(honest, inst.leak_feature))
    blob = json.dumps({"d": r["assessment_decision"], "fb": r["candidate_feedback"], "s": r["signed"]})
    assert inst.leak_feature not in blob and str(contract.seed()) not in blob
