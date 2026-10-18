"""Lab A end-to-end orchestration.

  governance-approved bind -> sealed instance -> candidate findings -> independent evaluator ->
  verified reviewer adjudication -> assessment_contract.decide -> cryptographically-bound signed record.

This produces an ASSESSMENT record only. It never asserts pathway qualification (that is
`parallax.pathway_qualification.decide_pathway`, which requires an approved portfolio of all required
competencies and a separate activation). Reviewer decisions and rubric scores are taken ONLY from a
verified, authorized, assigned reviewer adjudication - never from the candidate submission. The final
record binds the submission content, the evaluator's signed result, the reviewer adjudication, the
instance contract, the blueprint, and the candidate/cohort/assessment/attempt identity.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

import pathways
import signing
from siem import assessment_contract as ac
import siem.evaluator as ev
from siem.evaluator import EvaluatorScope

from . import contracts, governance, review, laba_blueprint as BP
from .laba_sim import generate, Instance
from .laba_evaluator import make_truth_handle  # importing also registers the evaluator
from . import laba_brief

LABA_INDEX = "parallax-laba"
_REVIEWER_KEYS = ("reviewer_decision", "rubric_scores", "adjudication", "reviewer_id", "reviewer")


def _sha(obj: Any) -> str:
    return hashlib.sha256(signing.canonical(obj)).hexdigest()


def bind_instance(*, cohort: str, candidate_key: str, attempt: int = 1,
                  approval: Dict[str, Any], authorized_admins):
    spec = BP.LABA_SPEC
    contract = contracts.resolve(spec, contracts.bind(
        spec, cohort=cohort, candidate_key=candidate_key, attempt=attempt,
        approval=approval, authorized_admins=authorized_admins))
    return spec, contract, generate(contract)


def candidate_brief(*, cohort: str, candidate_key: str, attempt: int = 1,
                    approval: Dict[str, Any], authorized_admins) -> Dict[str, Any]:
    spec, contract, instance = bind_instance(cohort=cohort, candidate_key=candidate_key, attempt=attempt,
                                             approval=approval, authorized_admins=authorized_admins)
    return laba_brief.build_brief(spec, contract, instance)


def _candidate_submission_only(submission: Dict[str, Any]) -> Dict[str, Any]:
    """Strip any reviewer/rubric fields a candidate might try to supply at the candidate boundary."""
    return {k: v for k, v in (submission or {}).items() if k not in _REVIEWER_KEYS}


def _safe_feedback(result: Dict[str, Any], spec) -> Dict[str, Any]:
    d = result.get("detail") or {}
    if d.get("outcome") == "critical_failure":
        return {"verdict": "critical_failure", "reason": d.get("reason"),
                "metric_name": spec.metric, "pass_threshold": spec.pass_threshold}
    return {"verdict": "pass" if result.get("passed") else "fail",
            "metric_name": spec.metric, "breach_f1": d.get("f1"),
            "precision": d.get("precision"), "recall": d.get("recall"),
            "pass_threshold": spec.pass_threshold}


def run_assessment(submission: Dict[str, Any], *, cohort: str, candidate_key: str, attempt: int = 1,
                   approval: Dict[str, Any], authorized_admins,
                   reviewer: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Grade one Lab A submission. `reviewer`, when given, is a SERVER-SIDE dict
    {reviewer_id, directory, decision, note, rubric_scores}; it is turned into a verified, bound,
    signed adjudication. Candidate-supplied reviewer/rubric fields are ignored."""
    spec, contract, instance = bind_instance(cohort=cohort, candidate_key=candidate_key, attempt=attempt,
                                             approval=approval, authorized_admins=authorized_admins)
    sub = _candidate_submission_only(submission)

    scope = EvaluatorScope(allowed_index=LABA_INDEX, truth_handle=make_truth_handle(instance))
    result = ev.get_evaluator(BP.OBJECTIVE_CHECK).verify(sub, scope, reader=None)

    bp = BP.blueprint()
    binding = {"candidate_key": candidate_key, "cohort": cohort,
               "assessment_id": spec.assessment_id, "attempt": int(attempt)}
    # stable pre-decision provenance the reviewer adjudication binds to (no circular dependency)
    provenance = {"submission_sha": _sha(sub), "objective_result_sig": result.get("evidence_sig"),
                  "contract_mac": contract.mac, "blueprint_hash": ac.blueprint_hash(bp),
                  "binding": binding}
    provenance_hash = _sha(provenance)

    # reviewer adjudication: authoritative only via a verified, authorized, assigned, signed record
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

    critical_findings = ([{"id": BP.CRITICAL_BREACH, "present": True, "remediated": False}]
                         if result.get("critical") else [])
    authorization = {"candidate_id": candidate_key, "pathway": pathways.PATHWAY_PARALLAX}

    decision = ac.decide(bp, authorization=authorization, objective_results=[result],
                         critical_findings=critical_findings, rubric_scores=rubric_scores,
                         reviewer_decision=reviewer_decision, scenario_version=bp["environment_version"])
    # bind all provenance into the decision before signing (covered by the signature)
    decision["provenance"] = {**provenance, "provenance_hash": provenance_hash,
                              "adjudication_hash": (_sha(adjudication["record"]) if adjudication else None)}
    signed = ac.sign_decision(decision, candidate_id=candidate_key,
                              unit_ref="%s@%s" % (spec.assessment_id, spec.version))
    return {
        "assessment_decision": decision,
        "assessment_passed": bool(decision.get("assessment_passed")),
        "pathway_qualified": False,     # a single assessment is NEVER a pathway qualification
        "pathway_note": "pathway qualification requires parallax.pathway_qualification.decide_pathway "
                        "(approved portfolio of all required competencies + separate activation)",
        "signed": signed,
        "objective_result": result,
        "adjudication": adjudication,
        "binding": binding,
        "candidate_feedback": _safe_feedback(result, spec),
    }
