"""PX-AR1 end-to-end assessment orchestration (portal side). Governance-approved bind -> server-side
architecture-review measurement -> deterministic objective evaluator (gate + critical veto) ->
assessment_contract.decide (POLICY_PARALLAX_AUTO, objective-only -> ai_involved=False) -> signed record
+ automatic feedback. No model in any scoring path; bound to the exact code (SHA-256) measured.
"""
from __future__ import annotations

from typing import Any, Dict

import pathways
from siem import assessment_contract as ac
import siem.evaluator as ev
from siem.evaluator import EvaluatorScope

from . import contracts, architecture_blueprint as BP
from .architecture_evaluator import make_truth_handle, KIND as ARCH_CHECK  # importing registers it

PXAR1_INDEX = "parallax-pxar1"


def bind_instance(*, cohort: str, candidate_key: str, attempt: int = 1,
                  approval: Dict[str, Any], authorized_admins):
    spec = BP.ARCHITECTURE_SPEC
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
    if d.get("outcome") == "architecture_gap":
        text = ("Your review misses design flaws (low recall). Cover exposed datastores, unencrypted "
                "PII, plaintext PII links, unauthenticated public services, and single points of failure.")
    elif d.get("outcome") == "architecture_overblock":
        text = ("Your review reports violations on a sound design (false findings). Flag a control only "
                "when it is actually violated.")
    elif verdict == "pass":
        text = "Architecture review enforced: real violations are found and a sound design passes clean."
    else:
        text = "The measured review did not clear the objective bar; see recall/specificity."
    return {"verdict": verdict, "final_score": pol.get("final_score"),
            "objective_composite": d.get("composite"),
            "measured_recall": d.get("security_rate"), "measured_specificity": d.get("task_rate"),
            "false_findings": d.get("false_findings"), "objective_pass": d.get("objective_pass"),
            "reason": decision.get("reason"), "feedback": text, "ai_involved": False}


def run_assessment(*, measurement: Dict[str, Any], cohort: str, candidate_key: str, attempt: int = 1,
                   approval: Dict[str, Any], authorized_admins, code_sha: str) -> Dict[str, Any]:
    spec, contract = bind_instance(cohort=cohort, candidate_key=candidate_key, attempt=attempt,
                                   approval=approval, authorized_admins=authorized_admins)
    bp = BP.blueprint()
    objective_pass = float(spec.params.get("objective_pass", BP.OBJECTIVE_PASS))
    security_floor = float(spec.params.get("security_floor", BP.SECURITY_FLOOR))
    task_floor = float(spec.params.get("task_floor", BP.TASK_FLOOR))

    scope = EvaluatorScope(allowed_index=PXAR1_INDEX,
                           truth_handle=make_truth_handle(measurement, objective_pass=objective_pass,
                                                          security_floor=security_floor, task_floor=task_floor))
    result = ev.get_evaluator(ARCH_CHECK).verify({"code": True, "defense_hash": code_sha}, scope, reader=None)

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
        "contract_mac": contract.mac, "blueprint_hash": ac.blueprint_hash(bp), "binding": binding}
    signed = ac.sign_decision(decision, candidate_id=candidate_key,
                              unit_ref="%s@%s" % (spec.assessment_id, spec.version))
    return {"assessment_decision": decision,
            "assessment_passed": bool(decision.get("assessment_passed")),
            "pathway_qualified": False, "signed": signed, "objective_result": result,
            "binding": binding, "candidate_feedback": _feedback(decision, result)}
