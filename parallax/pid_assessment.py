"""PX-D1 end-to-end assessment orchestration (portal side).

  governance-approved bind -> server-side measurement (from the grader) -> deterministic objective
  evaluator (reproducible gate + critical veto) -> model-judge rubric -> assessment_contract.decide
  (POLICY_PARALLAX_AUTO, ai_involved=True) -> signed record + automatic candidate feedback.

Split of responsibility (keeps the grader low-privilege, the portal the only key-holder):
  * The GRADER (private network, holds no signing key) runs pid_evaluator.measure_defense against the
    platform model with the candidate defense, and pid_judge.judge, then posts {measurement, rubric}.
  * The PORTAL (holds the signing key) calls run_assessment: it re-scores the measurement with the
    signed objective evaluator, folds in the model rubric, decides, and signs. No human reviewer is
    required to produce a score; a reviewer override remains available (parallax.review).
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

import pathways
import signing
from siem import assessment_contract as ac
import siem.evaluator as ev
from siem.evaluator import EvaluatorScope

from . import contracts, pid_blueprint as BP
from .research import defense as D
from .pid_evaluator import make_truth_handle, KIND as PID_CHECK  # importing registers the evaluator

PID_INDEX = "parallax-pxd1"


def _sha(obj: Any) -> str:
    return hashlib.sha256(signing.canonical(obj)).hexdigest()


def bind_instance(*, cohort: str, candidate_key: str, attempt: int = 1,
                  approval: Dict[str, Any], authorized_admins):
    """Mint the governance-bound per-candidate contract against the APPROVED spec (unchanged). The
    contract's keyed seed already includes (assessment, cohort, candidate, attempt), so two cohorts and
    two candidates get distinct instances - the campaign selection is derived from contract.seed() (see
    pid_instance) - while ONE signed approval of the single blueprint grades them all."""
    spec = BP.PID_SPEC
    contract = contracts.resolve(spec, contracts.bind(
        spec, BP.blueprint(), cohort=cohort, candidate_key=candidate_key, attempt=attempt,
        approval=approval, authorized_admins=authorized_admins))
    return spec, contract


def _feedback(decision: Dict[str, Any], result: Dict[str, Any],
              rubric: Dict[str, Any]) -> Dict[str, Any]:
    d = result.get("detail") or {}
    pol = decision.get("policy") or {}
    if result.get("critical"):
        verdict = "critical_failure"
    elif decision.get("assessment_passed"):
        verdict = "pass"
    else:
        verdict = "fail"
    text = rubric.get("feedback")
    if not text:
        # deterministic fallback when the judge is unavailable (honest, metric-grounded)
        text = ("Automated score from the measured defense behavior. "
                "A model-written rubric was not available for this attempt.")
    return {"verdict": verdict, "final_score": pol.get("final_score"),
            "objective_composite": d.get("composite"), "measured_asr": d.get("measured_asr"),
            "measured_tcr": d.get("measured_tcr"), "measured_fpr": d.get("measured_fpr"),
            "objective_pass": d.get("objective_pass"), "reason": decision.get("reason"),
            "rubric_scores": rubric.get("rubric_scores"), "rubric_feedback": text,
            "ai_involved": True}


def run_assessment(*, measurement: Dict[str, Any], defense: Optional[Dict[str, Any]],
                   rubric: Dict[str, Any], cohort: str, candidate_key: str, attempt: int = 1,
                   approval: Dict[str, Any], authorized_admins,
                   code_sha: Optional[str] = None,
                   blueprint_kwargs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Grade one PX-D1 submission from a server-side measurement + model-judge rubric. `measurement` is
    {metrics, defense_hash, ...} from the grader; `rubric` is {rubric_scores|None, feedback, provenance,
    available} from the judge; `defense` is the normalized candidate defense (hash-bound to the
    measurement). Returns the signed decision + automatic candidate feedback."""
    spec, contract = bind_instance(cohort=cohort, candidate_key=candidate_key, attempt=attempt,
                                   approval=approval, authorized_admins=authorized_admins)
    bp = BP.blueprint(**(blueprint_kwargs or {}))
    objective_pass = float(spec.params.get("objective_pass", BP.OBJECTIVE_PASS))
    asr_ceiling = float(spec.params.get("asr_ceiling", BP.ASR_CEILING))
    min_tcr = float(spec.params.get("min_tcr", BP.MIN_TCR))

    scope = EvaluatorScope(allowed_index=PID_INDEX,
                           truth_handle=make_truth_handle(measurement, objective_pass=objective_pass,
                                                          asr_ceiling=asr_ceiling, min_tcr=min_tcr))
    eval_submission = {"defense": defense, "code": bool(code_sha),
                       "defense_hash": code_sha or D.defense_hash(defense)}
    result = ev.get_evaluator(PID_CHECK).verify(eval_submission, scope, reader=None)

    critical_findings = ([{"id": BP.CRITICAL_BREACH, "present": True, "remediated": False}]
                         if result.get("critical") else [])
    rubric_scores = (rubric or {}).get("rubric_scores") or {}
    model_scoring = {**((rubric or {}).get("provenance") or {}), "scoring_mode": "model_primary"}
    authorization = {"candidate_id": candidate_key, "pathway": pathways.PATHWAY_PARALLAX}

    decision = ac.decide(bp, authorization=authorization, objective_results=[result],
                         critical_findings=critical_findings, rubric_scores=rubric_scores,
                         model_scoring=model_scoring, scenario_version=bp["environment_version"])

    binding = {"candidate_key": candidate_key, "cohort": cohort,
               "assessment_id": spec.assessment_id, "attempt": int(attempt)}
    decision["provenance"] = {
        "submission_defense_hash": measurement.get("defense_hash"),
        "objective_result_sig": result.get("evidence_sig"),
        "contract_mac": contract.mac, "blueprint_hash": ac.blueprint_hash(bp),
        "rubric_available": bool((rubric or {}).get("available")),
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
        "candidate_feedback": _feedback(decision, result, rubric or {}),
    }
