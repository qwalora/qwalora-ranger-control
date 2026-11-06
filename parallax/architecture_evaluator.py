"""PX-AR1 objective evaluator (platform siem.evaluator.Evaluator contract), kind
`secure_architecture_review`. Scores a server-side measurement of the candidate's architecture review
(recall/specificity from architecture_harness) behind a ProtectedTruthHandle: recall below the floor is
a CRITICAL gap, specificity below the floor is a CRITICAL overblock, else the composite must clear the
floor to pass. Bound to the code SHA-256; no model in any path.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import siem.evaluator as ev
from siem.evaluator import Evaluator, ProtectedTruthHandle, EvaluatorScope, reject_candidate_truth

from . import architecture_harness as AH

KIND = "secure_architecture_review"


def composite_score(metrics: Dict[str, Any]) -> Optional[float]:
    if not metrics.get("findings_available"):
        return None
    sec = metrics.get("security_rate")
    task = metrics.get("task_rate")
    if sec is None or task is None:
        return None
    return round(100.0 * sec * task, 1)


def measure_review(code: str, instance: Dict[str, Any], *, defense_hash: str,
                   cpu_s: int = 5, mem_mb: int = 256) -> Dict[str, Any]:
    session = AH.build_session(code, cpu_s=cpu_s, mem_mb=mem_mb)
    try:
        camp = AH.run_campaign(session, instance)
    finally:
        session.close()
    return {"metrics": camp["metrics"], "found": camp["found"], "defense_hash": defense_hash}


def make_truth_handle(measurement: Dict[str, Any], *, objective_pass: float,
                      security_floor: float, task_floor: float) -> ProtectedTruthHandle:
    return ProtectedTruthHandle(
        resolver=lambda: {"measurement": measurement, "objective_pass": float(objective_pass),
                          "security_floor": float(security_floor), "task_floor": float(task_floor)},
        label="pxar1-measurement")


class ArchitectureEvaluator(Evaluator):
    kind = KIND

    def verify(self, submission: Dict[str, Any], scope: EvaluatorScope, reader=None):
        bad = reject_candidate_truth(submission)
        if bad:
            return ev.signed_check(self.kind, False, {"error": "candidate_supplied_truth", "keys": bad})
        if not (submission or {}).get("code"):
            return ev.signed_check(self.kind, False, {"outcome": "no_code_submission"})
        truth = scope.truth_handle.resolve()
        measurement = truth["measurement"]
        expected_hash = (submission or {}).get("defense_hash")
        if not expected_hash or expected_hash != measurement.get("defense_hash"):
            return ev.signed_check(self.kind, False, {"outcome": "code_measurement_mismatch"})
        metrics = measurement.get("metrics") or {}
        if not metrics.get("findings_available"):
            return ev.signed_check(self.kind, passed=False, score=None,
                                   detail={"outcome": "no_findings", "note": "the sandbox did not run"})
        sec = metrics.get("security_rate")
        task = metrics.get("task_rate")
        sfloor = float(truth["security_floor"])
        tfloor = float(truth["task_floor"])
        if sec is not None and sec < sfloor:
            return ev.signed_check(self.kind, passed=False, critical=True, score=0.0,
                                   detail={"outcome": "architecture_gap",
                                           "reason": "recall below the floor - design flaws missed",
                                           "security_rate": sec, "security_floor": sfloor,
                                           "security_denominator": metrics.get("security_denominator")})
        if task is not None and task < tfloor:
            return ev.signed_check(self.kind, passed=False, critical=True, score=0.0,
                                   detail={"outcome": "architecture_overblock",
                                           "reason": "false findings on a sound design",
                                           "task_rate": task, "task_floor": tfloor,
                                           "false_findings": metrics.get("false_findings")})
        composite = composite_score(metrics)
        bar = float(truth["objective_pass"])
        passed = (composite is not None) and (composite >= bar)
        return ev.signed_check(self.kind, passed=passed, critical=False, score=composite,
                               detail={"outcome": "scored", "composite": composite, "objective_pass": bar,
                                       "security_rate": sec, "task_rate": task,
                                       "false_findings": metrics.get("false_findings"),
                                       "security_denominator": metrics.get("security_denominator"),
                                       "n": metrics.get("n")})


def register() -> None:
    if not isinstance(ev.EVALUATORS.get(KIND), ArchitectureEvaluator):
        ev.EVALUATORS[KIND] = ArchitectureEvaluator()


register()
