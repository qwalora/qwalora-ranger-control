"""PX-1 end-to-end orchestration: bind -> instance -> objective evaluation -> platform decision.

Ties the PARALLAX-specific pieces to the shared platform qualification engine:

  bind(spec)                      -> integrity-verified per-candidate instance contract
  generate(contract)              -> the instance (sealed holdout server-side)
  evaluator.verify(...)           -> signed ObjectiveCheckResult (holdout generalization + leak veto)
  assessment_contract.decide(...) -> deterministic ten-concern decision (PARALLAX policy + platform gate)
  sign_decision(...)              -> immutable signed qualification/assessment record

Phase 1 awards NO real credit: the platform gate `RANGER_PARALLAX_QUALIFICATION_ACTIVE` is off by
default, so `decision["qualified"]` stays False even when the assessment is fully met
(`assessment_passed=True`). The isolation invariant is enforced by `decide`: the authorization is
PARALLAX-scoped, so this can never award STRATA credit.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import pathways
from siem import assessment_contract as ac
import siem.evaluator as ev
from siem.evaluator import EvaluatorScope

from . import contracts, px1_blueprint, brief as brief_mod
from .px1_dataset import generate
from .px1_evaluator import make_truth_handle  # ensures the evaluator is registered on import

PX1_INDEX = "parallax-px1"      # least-privilege scope label for this assessment family


def bind_instance(*, cohort: str, candidate_key: str, attempt: int = 1):
    """Mint and verify a PX-1 instance contract and generate its instance (with the sealed holdout)."""
    spec = px1_blueprint.PX1_SPEC
    contract = contracts.resolve(spec, contracts.bind(
        spec, cohort=cohort, candidate_key=candidate_key, attempt=attempt))
    instance = generate(contract)
    return spec, contract, instance


def candidate_brief(*, cohort: str, candidate_key: str, attempt: int = 1) -> Dict[str, Any]:
    """Build the candidate-safe brief for a bound instance (no sealed data, no leak identity)."""
    spec, contract, instance = bind_instance(cohort=cohort, candidate_key=candidate_key, attempt=attempt)
    return brief_mod.build_brief(spec, contract, instance)


def _safe_feedback(result: Dict[str, Any], spec) -> Dict[str, Any]:
    """Candidate-safe feedback derived from the signed objective result: the verdict, the candidate's
    own holdout score and the threshold, never the leak identity or another instance's data."""
    d = result.get("detail") or {}
    if d.get("outcome") == "critical_failure":
        return {"verdict": "critical_failure", "reason": d.get("reason"),
                "pass_threshold": spec.pass_threshold}
    return {"verdict": "pass" if result.get("passed") else "fail",
            "holdout_metric": d.get("holdout_auc"), "metric_name": spec.metric,
            "pass_threshold": d.get("pass_threshold"), "auc_ci95": d.get("auc_ci95")}


def run_assessment(submission: Dict[str, Any], *, cohort: str, candidate_key: str, attempt: int = 1,
                   reviewer_decision: Optional[Dict[str, Any]] = None,
                   rubric_scores: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Grade one PX-1 submission through the platform contract and return a signed decision envelope.

    `reviewer_decision` and `rubric_scores` come from the human review of the written leakage analysis
    (the platform's mandatory human-review gate); without a reviewer pass the assessment is not met."""
    spec, contract, instance = bind_instance(cohort=cohort, candidate_key=candidate_key, attempt=attempt)

    scope = EvaluatorScope(
        allowed_index=PX1_INDEX,
        truth_handle=make_truth_handle(instance, contract.seed(), spec.pass_threshold))
    result = ev.get_evaluator(px1_blueprint.OBJECTIVE_CHECK).verify(submission, scope, reader=None)

    critical_findings = ([{"id": px1_blueprint.CRITICAL_LEAKAGE, "present": True, "remediated": False}]
                         if result.get("critical") else [])
    bp = px1_blueprint.blueprint()
    authorization = {"candidate_id": candidate_key, "pathway": pathways.PATHWAY_PARALLAX}

    decision = ac.decide(
        bp, authorization=authorization, objective_results=[result],
        critical_findings=critical_findings, rubric_scores=rubric_scores or {},
        reviewer_decision=reviewer_decision or {}, scenario_version=bp["environment_version"])

    signed = ac.sign_decision(decision, candidate_id=candidate_key,
                              unit_ref="%s@%s" % (spec.assessment_id, spec.version))
    return {"decision": decision, "signed": signed, "objective_result": result,
            "candidate_feedback": _safe_feedback(result, spec),
            "contract_mac": contract.mac}
