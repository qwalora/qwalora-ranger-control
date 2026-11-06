"""PX-A1 end-to-end assessment orchestration (portal side).

  governance-approved bind -> server-side authorization measurement (from the grader) -> deterministic
  objective evaluator (reproducible gate + critical veto) -> assessment_contract.decide
  (POLICY_PARALLAX_AUTO, objective-only -> ai_involved=False) -> signed record + automatic feedback.

No model is used in any scoring path; the score is a fully deterministic measurement of the candidate's
authorization handler, bound to the exact code (SHA-256) that was measured.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import pathways
import signing
from siem import assessment_contract as ac
import siem.evaluator as ev
from siem.evaluator import EvaluatorScope

from . import contracts, apisec_blueprint as BP
from .apisec_evaluator import make_truth_handle, KIND as APISEC_CHECK  # importing registers the evaluator

PXA1_INDEX = "parallax-pxa1"


def bind_instance(*, cohort: str, candidate_key: str, attempt: int = 1,
                  approval: Dict[str, Any], authorized_admins):
    spec = BP.APISEC_SPEC
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
    if d.get("outcome") == "authz_bypass":
        text = ("Object-level authorization is bypassed: non-owner requests are served (BOLA). Add an "
                "ownership check so a subject can only read records it owns.")
    elif d.get("outcome") == "authz_overblock":
        text = ("The handler denies legitimate owner access. Owners must still receive their own "
                "records (200); deny only non-owners (403).")
    elif verdict == "pass":
        text = "Authorization enforced: owners are served and non-owners (including spoofed requests) are denied."
    else:
        text = "The measured authorization behavior did not clear the objective bar; see the rates."
    return {"verdict": verdict, "final_score": pol.get("final_score"),
            "objective_composite": d.get("composite"),
            "measured_allow_rate": d.get("allow_rate"), "measured_deny_rate": d.get("deny_rate"),
            "measured_leak_rate": d.get("leak_rate"), "objective_pass": d.get("objective_pass"),
            "reason": decision.get("reason"), "feedback": text, "ai_involved": False}


def run_assessment(*, measurement: Dict[str, Any], cohort: str, candidate_key: str, attempt: int = 1,
                   approval: Dict[str, Any], authorized_admins,
                   code_sha: str) -> Dict[str, Any]:
    """Grade one PX-A1 submission from a server-side authorization measurement. `measurement` is
    {metrics, defense_hash, ...} from the grader. Returns the signed decision + automatic feedback."""
    spec, contract = bind_instance(cohort=cohort, candidate_key=candidate_key, attempt=attempt,
                                   approval=approval, authorized_admins=authorized_admins)
    bp = BP.blueprint()
    objective_pass = float(spec.params.get("objective_pass", BP.OBJECTIVE_PASS))
    leak_ceiling = float(spec.params.get("leak_ceiling", BP.LEAK_CEILING))
    allow_floor = float(spec.params.get("allow_floor", BP.ALLOW_FLOOR))

    scope = EvaluatorScope(allowed_index=PXA1_INDEX,
                           truth_handle=make_truth_handle(measurement, objective_pass=objective_pass,
                                                          leak_ceiling=leak_ceiling, allow_floor=allow_floor))
    eval_submission = {"code": True, "defense_hash": code_sha}
    result = ev.get_evaluator(APISEC_CHECK).verify(eval_submission, scope, reader=None)

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
