"""PARALLAX Phase 1 - PX-1 "Leakage-Safe Model Evaluation" vertical slice.

Positive, negative, isolation, gate, and integrity tests for the first PARALLAX assessment, driven
through the shared platform qualification contract (`siem.assessment_contract.decide`). These prove:

  * a competent leakage-safe solution MEETS the assessment but is NOT finally qualified while the
    platform gate is off (assessment vs qualification are distinct);
  * depending on the planted leakage feature is a critical-failure veto;
  * a below-threshold solution fails on unseen data;
  * the platform gate, when activated, is what turns a met assessment into a qualification;
  * PARALLAX cannot award STRATA credit (authorization/blueprint isolation) and vice versa;
  * per-candidate instances differ (non-transfer);
  * the instance contract and the signed decision are tamper-evident;
  * protected metadata (the leak's identity, the seed) never appears in the decision or feedback;
  * the STRATA baseline is unaffected.
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
os.environ.pop("RANGER_PARALLAX_QUALIFICATION_ACTIVE", None)  # gate OFF by default

import pytest  # noqa: E402

import pathways  # noqa: E402
from siem import assessment_contract as ac  # noqa: E402
import siem.evaluator as ev  # noqa: E402
from parallax import px1_assessment as A  # noqa: E402  (import also registers the evaluator)
from parallax import px1_blueprint as BP, contracts  # noqa: E402

COHORT = "2026-PX-A"
REVIEWER = {"decision": "pass", "reviewer_id": "rev-1"}
RUBRIC = {"leakage_analysis_quality": 85}


@pytest.fixture(autouse=True)
def _gate_off():
    saved = os.environ.get("RANGER_PARALLAX_QUALIFICATION_ACTIVE")
    os.environ.pop("RANGER_PARALLAX_QUALIFICATION_ACTIVE", None)
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop("RANGER_PARALLAX_QUALIFICATION_ACTIVE", None)
        else:
            os.environ["RANGER_PARALLAX_QUALIFICATION_ACTIVE"] = saved


def _instance(cand):
    spec, contract, inst = A.bind_instance(cohort=COHORT, candidate_key=cand)
    honest = [c for c in inst.feature_names if c != inst.leak_feature]
    return spec, contract, inst, honest


def _safe_submission(honest, leak):
    return {"feature_set": honest, "model_config": {"family": "logistic_regression", "C": 1.0},
            "leakage_analysis": "column %s is a target leak (near-perfect on train/val); excluded" % leak}


# --- positive -------------------------------------------------------------------------------------
def test_leakage_safe_meets_assessment_but_not_qualified_while_gate_off():
    spec, contract, inst, honest = _instance("gh-alice")
    r = A.run_assessment(_safe_submission(honest, inst.leak_feature), cohort=COHORT,
                         candidate_key="gh-alice", reviewer_decision=REVIEWER, rubric_scores=RUBRIC)
    d = r["decision"]
    assert d["assessment_passed"] is True, d
    assert d["qualified"] is False, "final qualification must be withheld while the platform gate is off"
    assert d["reason"] == "qualification_inactive"
    assert r["candidate_feedback"]["verdict"] == "pass"
    assert r["candidate_feedback"]["holdout_metric"] >= spec.pass_threshold


def test_platform_gate_activates_qualification():
    spec, contract, inst, honest = _instance("gh-alice")
    os.environ["RANGER_PARALLAX_QUALIFICATION_ACTIVE"] = "1"
    r = A.run_assessment(_safe_submission(honest, inst.leak_feature), cohort=COHORT,
                         candidate_key="gh-alice", reviewer_decision=REVIEWER, rubric_scores=RUBRIC)
    assert r["decision"]["qualified"] is True and r["decision"]["reason"] == "qualified"


# --- negative -------------------------------------------------------------------------------------
def test_leakage_dependence_is_critical_veto():
    spec, contract, inst, honest = _instance("gh-bob")
    leaky = {"feature_set": [inst.leak_feature] + honest[:2],
             "model_config": {"family": "random_forest"}, "leakage_analysis": "used all"}
    r = A.run_assessment(leaky, cohort=COHORT, candidate_key="gh-bob",
                         reviewer_decision=REVIEWER, rubric_scores=RUBRIC)
    assert r["decision"]["qualified"] is False
    assert r["decision"]["breakdown"]["critical_failures"]["veto"] is True
    assert BP.CRITICAL_LEAKAGE in r["decision"]["breakdown"]["critical_failures"]["present"]
    assert r["candidate_feedback"]["verdict"] == "critical_failure"


def test_below_threshold_fails_on_unseen_data():
    spec, contract, inst, honest = _instance("gh-carol")
    weak = {"feature_set": honest[:1], "model_config": {"family": "logistic_regression"},
            "leakage_analysis": "minimal"}
    r = A.run_assessment(weak, cohort=COHORT, candidate_key="gh-carol",
                         reviewer_decision=REVIEWER, rubric_scores=RUBRIC)
    assert r["decision"]["assessment_passed"] is False
    assert r["candidate_feedback"]["verdict"] == "fail"
    assert r["candidate_feedback"]["holdout_metric"] < spec.pass_threshold


def test_missing_human_review_blocks_assessment():
    """Even a strong objective result does not meet the PARALLAX assessment without the human-review
    pass and rubric threshold (the platform's mandatory human-review gate)."""
    spec, contract, inst, honest = _instance("gh-dan")
    r = A.run_assessment(_safe_submission(honest, inst.leak_feature), cohort=COHORT,
                         candidate_key="gh-dan", reviewer_decision=None, rubric_scores=None)
    assert r["decision"]["assessment_passed"] is False
    assert r["decision"]["qualified"] is False


def test_candidate_self_certification_rejected():
    spec, contract, inst, honest = _instance("gh-eve")
    cheat = {"feature_set": honest, "passed": True, "ground_truth": {"label": 1},
             "model_config": {"family": "logistic_regression"}, "leakage_analysis": "x"}
    r = A.run_assessment(cheat, cohort=COHORT, candidate_key="gh-eve",
                         reviewer_decision=REVIEWER, rubric_scores=RUBRIC)
    assert r["objective_result"]["passed"] is False
    assert r["objective_result"]["detail"].get("error") == "candidate_supplied_truth"
    assert r["decision"]["qualified"] is False


# --- isolation (no cross-track credit) ------------------------------------------------------------
def test_cross_pathway_authorization_refused():
    """A PARALLAX blueprint graded under a STRATA-scoped authorization is refused: PARALLAX credit
    cannot be produced from a STRATA authorization (and vice versa)."""
    spec, contract, inst, honest = _instance("gh-frank")
    scope = ev.EvaluatorScope(allowed_index="parallax-px1",
                              truth_handle=A.make_truth_handle(inst, contract.seed(), spec.pass_threshold))
    result = ev.get_evaluator(BP.OBJECTIVE_CHECK).verify(_safe_submission(honest, inst.leak_feature),
                                                         scope, reader=None)
    bp = BP.blueprint()
    strata_auth = {"candidate_id": "gh-frank", "pathway": pathways.PATHWAY_STRATA}
    d = ac.decide(bp, authorization=strata_auth, objective_results=[result],
                  rubric_scores=RUBRIC, reviewer_decision=REVIEWER,
                  scenario_version=bp["environment_version"])
    assert d["qualified"] is False
    assert d["breakdown"]["authorization"]["ok"] is False


def test_parallax_result_cannot_satisfy_a_strata_blueprint():
    """A STRATA-bar blueprint is not satisfied by a PARALLAX objective result: its required objective
    check id is absent, so no STRATA credit is produced from PARALLAX evidence."""
    spec, contract, inst, honest = _instance("gh-grace")
    scope = ev.EvaluatorScope(allowed_index="parallax-px1",
                              truth_handle=A.make_truth_handle(inst, contract.seed(), spec.pass_threshold))
    px_result = ev.get_evaluator(BP.OBJECTIVE_CHECK).verify(_safe_submission(honest, inst.leak_feature),
                                                           scope, reader=None)
    strata_bp = {
        "pathway": pathways.PATHWAY_STRATA, "blueprint_version": 1, "environment_version": "s-1",
        "objective_checks": [{"check_id": "event_reference", "evaluator": "event_reference",
                              "required": True}],
        "decision_policy": {"type": ac.POLICY_STRATA_BAR},
    }
    d = ac.decide(strata_bp, authorization={"candidate_id": "gh-grace", "pathway": pathways.PATHWAY_STRATA},
                  objective_results=[px_result], scenario_version="s-1")
    assert d["qualified"] is False  # PX-1 result's check_id != required STRATA check


def test_per_candidate_instances_differ():
    _, c_a, inst_a, _ = _instance("gh-alice")
    _, c_b, inst_b, _ = _instance("gh-bob")
    assert c_a.seed() != c_b.seed(), "each candidate must get a distinct instance (non-transfer)"


# --- integrity / protected metadata ---------------------------------------------------------------
def test_contract_integrity_tamper_detected():
    spec = BP.PX1_SPEC
    good = contracts.bind(spec, cohort=COHORT, candidate_key="gh-alice")
    good.verify()  # ok
    tampered = contracts.GenerationContract(**{**good.__dict__, "candidate_key": "gh-mallory"})
    with pytest.raises(contracts.ContractError):
        tampered.verify()


def test_signed_decision_roundtrip_and_tamper():
    spec, contract, inst, honest = _instance("gh-alice")
    r = A.run_assessment(_safe_submission(honest, inst.leak_feature), cohort=COHORT,
                         candidate_key="gh-alice", reviewer_decision=REVIEWER, rubric_scores=RUBRIC)
    assert ac.verify_decision(r["signed"]) is True
    bad = json.loads(json.dumps(r["signed"]))
    bad["record"]["qualified"] = True
    assert ac.verify_decision(bad) is False


def test_protected_metadata_absent_from_decision_and_feedback():
    spec, contract, inst, honest = _instance("gh-bob")
    r = A.run_assessment(_safe_submission(honest, inst.leak_feature), cohort=COHORT,
                         candidate_key="gh-bob", reviewer_decision=REVIEWER, rubric_scores=RUBRIC)
    blob = json.dumps({"decision": r["decision"], "feedback": r["candidate_feedback"],
                       "signed": r["signed"]})
    assert inst.leak_feature not in blob, "the planted leak's identity must never reach the candidate"
    assert str(contract.seed()) not in blob, "the instance seed must never reach the candidate"


# --- STRATA baseline unaffected -------------------------------------------------------------------
def test_strata_baseline_unaffected():
    import program
    assert program.PASS_BAR == 95.0
    # the implemented STRATA evaluator remains; PARALLAX added its own without displacing it
    assert "event_reference" in ev.EVALUATORS
    assert BP.OBJECTIVE_CHECK in ev.EVALUATORS
    assert pathways.PATHWAY_STRATA in ac.SUPPORTED_BLUEPRINT_VERSIONS
