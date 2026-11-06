"""PX-DE1 end-to-end assessment orchestration (portal side).

  governance-approved bind -> server-side detection measurement (from the grader) -> deterministic
  objective evaluator (reproducible gate + critical veto) -> assessment_contract.decide
  (POLICY_PARALLAX_AUTO, objective-only -> ai_involved=False) -> signed record + automatic feedback.

No model in any scoring path; the score is a fully deterministic measurement of the candidate's
detection rules, bound to the exact code (SHA-256) that was measured.
"""
from __future__ import annotations

from typing import Any, Dict

import pathways
from siem import assessment_contract as ac
import siem.evaluator as ev
from siem.evaluator import EvaluatorScope

from . import contracts, detection_blueprint as BP
from .detection_evaluator import make_truth_handle, KIND as DETECTION_CHECK  # importing registers it

PXDE1_INDEX = "parallax-pxde1"


def bind_instance(*, cohort: str, candidate_key: str, attempt: int = 1,
                  approval: Dict[str, Any], authorized_admins):
    spec = BP.DETECTION_SPEC
    contract = contracts.resolve(spec, contracts.bind(
        spec, BP.blueprint(), cohort=cohort, candidate_key=candidate_key, attempt=attempt,
        approval=approval, authorized_admins=authorized_admins))
    return spec, contract


def _feedback(decision: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    d = result.get("detail") or {}
    pol = decision.get("policy") or {}
    if result.get("critical"):
        verdict = "critical_failure"
    elif decision.get("assessment_passed"):
        verdict = "pass"
    else:
        verdict = "fail"
    if d.get("outcome") == "detection_miss":
        text = ("Your rules miss attacks (low recall). Cover the brute-force, account-takeover, "
                "exfiltration, and malicious-process scenarios in the policy.")
    elif d.get("outcome") == "detection_overblock":
        text = ("Your rules alert on benign activity (low specificity). Tighten thresholds so "
                "look-alikes (sub-threshold failures, internal transfers, normal processes) are not "
                "flagged.")
    elif verdict == "pass":
        text = "Detections enforced: attacks are caught and benign activity is not alerted."
    else:
        text = "The measured detection behavior did not clear the objective bar; see recall/specificity."
    return {"verdict": verdict, "final_score": pol.get("final_score"),
            "objective_composite": d.get("composite"),
            "measured_recall": d.get("security_rate"), "measured_specificity": d.get("task_rate"),
            "false_positives": d.get("false_positives"), "objective_pass": d.get("objective_pass"),
            "reason": decision.get("reason"), "feedback": text, "ai_involved": False}


def run_assessment(*, measurement: Dict[str, Any], cohort: str, candidate_key: str, attempt: int = 1,
                   approval: Dict[str, Any], authorized_admins, code_sha: str) -> Dict[str, Any]:
    spec, contract = bind_instance(cohort=cohort, candidate_key=candidate_key, attempt=attempt,
                                   approval=approval, authorized_admins=authorized_admins)
    bp = BP.blueprint()
    objective_pass = float(spec.params.get("objective_pass", BP.OBJECTIVE_PASS))
    security_floor = float(spec.params.get("security_floor", BP.SECURITY_FLOOR))
    task_floor = float(spec.params.get("task_floor", BP.TASK_FLOOR))

    scope = EvaluatorScope(allowed_index=PXDE1_INDEX,
                           truth_handle=make_truth_handle(measurement, objective_pass=objective_pass,
                                                          security_floor=security_floor, task_floor=task_floor))
    eval_submission = {"code": True, "defense_hash": code_sha}
    result = ev.get_evaluator(DETECTION_CHECK).verify(eval_submission, scope, reader=None)

    critical_findings = ([{"id": BP.CRITICAL_BREACH, "present": True, "remediated": False}]
                         if result.get("critical") else [])
    authorization = {"candidate_id": candidate_key, "pathway": pathways.PATHWAY_PARALLAX}

    decision = ac.decide(bp, authorization=authorization, objective_results=[result],
                         critical_findings=critical_findings, rubric_scores={},
                         model_scoring=None, scenario_version=bp["environment_version"])

    binding = {"candidate_key": candidate_key, "cohort": cohort,
               "assessment_id": spec.assessment_id, "attempt": int(attempt)}
    decision["provenance"] = {
        "submission_code_sha256": measurement.get("defense_hash"),
        "objective_result_sig": result.get("evidence_sig"),
        "contract_mac": contract.mac, "blueprint_hash": ac.blueprint_hash(bp),
        "binding": binding}
    signed = ac.sign_decision(decision, candidate_id=candidate_key,
                              unit_ref="%s@%s" % (spec.assessment_id, spec.version))
    return {
        "assessment_decision": decision,
        "assessment_passed": bool(decision.get("assessment_passed")),
        "pathway_qualified": False,
        "signed": signed,
        "objective_result": result,
        "binding": binding,
        "candidate_feedback": _feedback(decision, result),
    }
