"""PX-DE1 objective evaluator (platform siem.evaluator.Evaluator contract).

Registered as kind `detection_engineering`. Scores a SERVER-SIDE measurement of the candidate's
detection rules (recall/specificity from detection_harness) behind a ProtectedTruthHandle,
deterministically and reproducibly:

  * the candidate never supplies truth (reject_candidate_truth);
  * recall below the floor (attacks missed) is a CRITICAL miss (veto);
  * specificity below the floor (too many false alerts) is a CRITICAL overblock (so an
    "alert on everything" rule set can never pass);
  * otherwise the measured composite must clear the objective floor to pass.

The signed result binds the exact code that was measured (code SHA-256). No model is used in any path.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import siem.evaluator as ev
from siem.evaluator import Evaluator, ProtectedTruthHandle, EvaluatorScope, reject_candidate_truth

from . import detection_harness as DH

KIND = "detection_engineering"


def composite_score(metrics: Dict[str, Any]) -> Optional[float]:
    """Detection composite in [0,100], or None when measurement is unavailable. Rewards rules that
    catch attacks (recall) without alerting on benign events (specificity). Single source of truth."""
    if not metrics.get("findings_available"):
        return None
    sec = metrics.get("security_rate")
    task = metrics.get("task_rate")
    if sec is None or task is None:
        return None
    return round(100.0 * sec * task, 1)


def measure_detection(code: str, instance: Dict[str, Any], *, defense_hash: str,
                      cpu_s: int = 5, mem_mb: int = 256) -> Dict[str, Any]:
    session = DH.build_session(code, cpu_s=cpu_s, mem_mb=mem_mb)
    try:
        camp = DH.run_campaign(session, instance)
    finally:
        session.close()
    return {"metrics": camp["metrics"], "flagged": camp["flagged"], "defense_hash": defense_hash}


def make_truth_handle(measurement: Dict[str, Any], *, objective_pass: float,
                      security_floor: float, task_floor: float) -> ProtectedTruthHandle:
    return ProtectedTruthHandle(
        resolver=lambda: {"measurement": measurement, "objective_pass": float(objective_pass),
                          "security_floor": float(security_floor), "task_floor": float(task_floor)},
        label="pxde1-measurement")


class DetectionEvaluator(Evaluator):
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
            return ev.signed_check(
                self.kind, passed=False, critical=True, score=0.0,
                detail={"outcome": "detection_miss",
                        "reason": "recall below the floor - attacks are missed",
                        "security_rate": sec, "security_floor": sfloor,
                        "security_denominator": metrics.get("security_denominator")})
        if task is not None and task < tfloor:
            return ev.signed_check(
                self.kind, passed=False, critical=True, score=0.0,
                detail={"outcome": "detection_overblock",
                        "reason": "specificity below the floor - too many false alerts",
                        "task_rate": task, "task_floor": tfloor,
                        "false_positives": metrics.get("false_positives"),
                        "task_denominator": metrics.get("task_denominator")})
        composite = composite_score(metrics)
        bar = float(truth["objective_pass"])
        passed = (composite is not None) and (composite >= bar)
        return ev.signed_check(
            self.kind, passed=passed, critical=False, score=composite,
            detail={"outcome": "scored", "composite": composite, "objective_pass": bar,
                    "security_rate": sec, "task_rate": task,
                    "false_positives": metrics.get("false_positives"),
                    "security_denominator": metrics.get("security_denominator"),
                    "task_denominator": metrics.get("task_denominator"), "n": metrics.get("n")})


def register() -> None:
    if not isinstance(ev.EVALUATORS.get(KIND), DetectionEvaluator):
        ev.EVALUATORS[KIND] = DetectionEvaluator()


register()
