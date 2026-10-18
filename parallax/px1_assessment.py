"""PX-1 orchestration (EXPERIMENTAL component - not a mandatory PARALLAX qualification).

PX-1 (leakage-safe model evaluation) is retained as a reusable, clearly-labeled experimental assessment
component; it is not the first PARALLAX assessment and does not drive the approved progression (see
docs/PARALLAX_ARCHITECTURE.md). It uses the SAME hardened boundary as Lab A: governance-approved bind,
a verified authorized/assigned reviewer adjudication (never candidate-supplied), and an
assessment-only outcome that is never a pathway qualification.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

import pathways
import signing
from siem import assessment_contract as ac
import siem.evaluator as ev
from siem.evaluator import EvaluatorScope

from . import contracts, review, px1_blueprint
from .px1_dataset import generate
from .px1_evaluator import make_truth_handle   # importing also registers the evaluator
from . import brief as brief_mod

PX1_INDEX = "parallax-px1"
_REVIEWER_KEYS = ("reviewer_decision", "rubric_scores", "adjudication", "reviewer_id", "reviewer")


def _sha(obj: Any) -> str:
    return hashlib.sha256(signing.canonical(obj)).hexdigest()


def bind_instance(*, cohort: str, candidate_key: str, attempt: int = 1,
                  approval: Dict[str, Any], authorized_admins):
    spec = px1_blueprint.PX1_SPEC
    contract = contracts.resolve(spec, contracts.bind(
        spec, px1_blueprint.blueprint(), cohort=cohort, candidate_key=candidate_key, attempt=attempt,
        approval=approval, authorized_admins=authorized_admins))
    return spec, contract, generate(contract)


def candidate_brief(*, cohort: str, candidate_key: str, attempt: int = 1,
                    approval: Dict[str, Any], authorized_admins) -> Dict[str, Any]:
    spec, contract, instance = bind_instance(cohort=cohort, candidate_key=candidate_key, attempt=attempt,
                                             approval=approval, authorized_admins=authorized_admins)
    return brief_mod.build_brief(spec, contract, instance)


def _candidate_submission_only(submission: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in (submission or {}).items() if k not in _REVIEWER_KEYS}


def _safe_feedback(result: Dict[str, Any], spec) -> Dict[str, Any]:
    d = result.get("detail") or {}
    if d.get("outcome") == "critical_failure":
        return {"verdict": "critical_failure", "reason": d.get("reason"),
                "pass_threshold": spec.pass_threshold}
    return {"verdict": "pass" if result.get("passed") else "fail",
            "holdout_metric": d.get("holdout_auc"), "metric_name": spec.metric,
            "pass_threshold": d.get("pass_threshold"), "auc_ci95": d.get("auc_ci95")}


def run_assessment(submission: Dict[str, Any], *, cohort: str, candidate_key: str, attempt: int = 1,
                   approval: Dict[str, Any], authorized_admins,
                   reviewer: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Grade one PX-1 submission (experimental). Same hardened boundary as Lab A; assessment-only."""
    spec, contract, instance = bind_instance(cohort=cohort, candidate_key=candidate_key, attempt=attempt,
                                             approval=approval, authorized_admins=authorized_admins)
    sub = _candidate_submission_only(submission)

    scope = EvaluatorScope(allowed_index=PX1_INDEX,
                           truth_handle=make_truth_handle(instance, contract.seed(), spec.pass_threshold))
    result = ev.get_evaluator(px1_blueprint.OBJECTIVE_CHECK).verify(sub, scope, reader=None)

    bp = px1_blueprint.blueprint()
    binding = {"candidate_key": candidate_key, "cohort": cohort,
               "assessment_id": spec.assessment_id, "attempt": int(attempt)}
    provenance = {"submission_sha": _sha(sub), "objective_result_sig": result.get("evidence_sig"),
                  "contract_mac": contract.mac, "blueprint_hash": ac.blueprint_hash(bp),
                  "binding": binding}
    provenance_hash = _sha(provenance)

    reviewer_decision: Dict[str, Any] = {}
    rubric_scores: Dict[str, Any] = {}
    adjudication = None
    if reviewer:
        adjudication = review.make_adjudication(
            reviewer_id=reviewer["reviewer_id"], directory=reviewer["directory"], binding=binding,
            assessment_record_hash=provenance_hash, decision=reviewer.get("decision", "fail"),
            note=reviewer.get("note", ""), rubric_scores=reviewer.get("rubric_scores"))
        verified = review.verify_adjudication(adjudication, directory=reviewer["directory"],
                                              binding=binding, assessment_record_hash=provenance_hash)
        reviewer_decision = review.reviewer_decision_for_contract(verified)
        rubric_scores = verified.get("rubric_scores") or {}

    critical_findings = ([{"id": px1_blueprint.CRITICAL_LEAKAGE, "present": True, "remediated": False}]
                         if result.get("critical") else [])
    authorization = {"candidate_id": candidate_key, "pathway": pathways.PATHWAY_PARALLAX}

    decision = ac.decide(bp, authorization=authorization, objective_results=[result],
                         critical_findings=critical_findings, rubric_scores=rubric_scores,
                         reviewer_decision=reviewer_decision, scenario_version=bp["environment_version"])
    decision["provenance"] = {**provenance, "provenance_hash": provenance_hash,
                              "adjudication_hash": (_sha(adjudication["record"]) if adjudication else None)}
    signed = ac.sign_decision(decision, candidate_id=candidate_key,
                              unit_ref="%s@%s" % (spec.assessment_id, spec.version))
    return {"assessment_decision": decision, "assessment_passed": bool(decision.get("assessment_passed")),
            "pathway_qualified": False, "signed": signed, "objective_result": result,
            "adjudication": adjudication, "binding": binding,
            "candidate_feedback": _safe_feedback(result, spec)}
