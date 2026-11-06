"""PX-CAP end-to-end assessment orchestration (portal side). Governance-approved bind -> server-side
composite measurement (per-component results from the grader) -> deterministic objective evaluator
(all-must-pass + critical veto) -> assessment_contract.decide (POLICY_PARALLAX_AUTO, objective-only ->
ai_involved=False) -> signed record + automatic feedback. No model in any scoring path.
"""
from __future__ import annotations

from typing import Any, Dict

import pathways
from siem import assessment_contract as ac
import siem.evaluator as ev
from siem.evaluator import EvaluatorScope

from . import contracts, capstone_blueprint as BP
from .capstone_evaluator import make_truth_handle, KIND as CAP_CHECK  # importing registers it

PXCAP_INDEX = "parallax-pxcap"


def bind_instance(*, cohort: str, candidate_key: str, attempt: int = 1,
                  approval: Dict[str, Any], authorized_admins):
    spec = BP.CAPSTONE_SPEC
    contract = contracts.resolve(spec, contracts.bind(
        spec, BP.blueprint(), cohort=cohort, candidate_key=candidate_key, attempt=attempt,
        approval=approval, authorized_admins=authorized_admins))
    return spec, contract


def _feedback(decision: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    d = result.get("detail") or {}
    pol = decision.get("policy") or {}
    if decision.get("assessment_passed"):
        verdict = "pass"
        text = "Capstone cleared: every component board passed (authz, detection, gates, architecture)."
    elif result.get("critical"):
        verdict = "critical_failure"
        text = ("Capstone not cleared: these components failed their board bar: %s. Every component "
                "must pass." % ", ".join(d.get("failed") or []))
    else:
        verdict = "fail"
        text = "Capstone not cleared; see the per-component results."
    comp_scores = {k: v.get("composite") for k, v in (d.get("components") or {}).items()}
    return {"verdict": verdict, "final_score": pol.get("final_score"),
            "mean_composite": d.get("mean_composite"), "components": comp_scores,
            "failed_components": d.get("failed"), "reason": decision.get("reason"),
            "feedback": text, "ai_involved": False}


def run_assessment(*, measurement: Dict[str, Any], cohort: str, candidate_key: str, attempt: int = 1,
                   approval: Dict[str, Any], authorized_admins, code_sha: str) -> Dict[str, Any]:
    spec, contract = bind_instance(cohort=cohort, candidate_key=candidate_key, attempt=attempt,
                                   approval=approval, authorized_admins=authorized_admins)
    bp = BP.blueprint()
    objective_pass = float(spec.params.get("objective_pass", BP.OBJECTIVE_PASS))
    scope = EvaluatorScope(allowed_index=PXCAP_INDEX,
                           truth_handle=make_truth_handle(measurement, objective_pass=objective_pass))
    result = ev.get_evaluator(CAP_CHECK).verify({"code": True, "defense_hash": code_sha}, scope, reader=None)

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
