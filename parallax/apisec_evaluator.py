"""PX-A1 objective evaluator (platform siem.evaluator.Evaluator contract).

Registered as kind `api_object_authorization`. It scores a SERVER-SIDE measurement of the candidate's
authorization handler (allow/deny behavior from apisec_harness) behind a ProtectedTruthHandle,
deterministically and reproducibly:

  * the candidate never supplies truth (reject_candidate_truth);
  * a non-owner access-success (BOLA leak) rate at/above the ceiling is a CRITICAL bypass (veto);
  * denying legitimate owner access below the floor is a CRITICAL failure (so "deny everything" can
    never pass at leak 0);
  * otherwise the measured composite must clear the objective floor to pass.

The signed result binds the exact code that was measured (code SHA-256). No model is used in any path.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import siem.evaluator as ev
from siem.evaluator import Evaluator, ProtectedTruthHandle, EvaluatorScope, reject_candidate_truth

from . import apisec_content as AC, apisec_harness as AH
from . import pid_sandbox as SB

KIND = "api_object_authorization"


def composite_score(metrics: Dict[str, Any]) -> Optional[float]:
    """Authorization composite in [0,100], or None when measurement is unavailable. Rewards a handler
    that serves owners (allow_rate) AND denies non-owners/spoofers (deny_rate), with status-code
    protocol correctness (401/404) as a lighter factor. Single source of truth, reused by the grader."""
    if not metrics.get("findings_available"):
        return None
    allow = metrics.get("allow_rate")
    deny = metrics.get("deny_rate")
    if allow is None or deny is None:
        return None
    status_ok = metrics.get("status_ok_rate")
    status_factor = 0.5 + 0.5 * (status_ok if status_ok is not None else 1.0)
    return round(100.0 * allow * deny * status_factor, 1)


def measure_authz(code: str, instance: Dict[str, Any], *, defense_hash: str,
                  cpu_s: int = 5, mem_mb: int = 256) -> Dict[str, Any]:
    """Run the candidate handler against the sealed battery and return {metrics, records, defense_hash}.
    Fail-closed: a sandbox startup/runtime failure raises SandboxError (the grader records a failure)."""
    session = AH.build_session(code, cpu_s=cpu_s, mem_mb=mem_mb)
    try:
        camp = AH.run_campaign(session, instance)
    finally:
        session.close()
    return {"metrics": camp["metrics"], "records": camp["records"], "defense_hash": defense_hash}


def make_truth_handle(measurement: Dict[str, Any], *, objective_pass: float,
                      leak_ceiling: float, allow_floor: float) -> ProtectedTruthHandle:
    return ProtectedTruthHandle(
        resolver=lambda: {"measurement": measurement, "objective_pass": float(objective_pass),
                          "leak_ceiling": float(leak_ceiling), "allow_floor": float(allow_floor)},
        label="pxa1-measurement")


class APISecAuthzEvaluator(Evaluator):
    kind = KIND

    def verify(self, submission: Dict[str, Any], scope: EvaluatorScope, reader=None):
        bad = reject_candidate_truth(submission)
        if bad:
            return ev.signed_check(self.kind, False, {"error": "candidate_supplied_truth", "keys": bad})
        if not (submission or {}).get("code"):
            return ev.signed_check(self.kind, False, {"outcome": "no_code_submission"})
        truth = scope.truth_handle.resolve()            # server-side only
        measurement = truth["measurement"]
        expected_hash = (submission or {}).get("defense_hash")
        if not expected_hash or expected_hash != measurement.get("defense_hash"):
            return ev.signed_check(self.kind, False, {"outcome": "code_measurement_mismatch"})
        metrics = measurement.get("metrics") or {}
        if not metrics.get("findings_available"):
            return ev.signed_check(self.kind, passed=False, score=None,
                                   detail={"outcome": "no_findings", "note": "the sandbox did not run"})
        leak = metrics.get("leak_rate")
        allow = metrics.get("allow_rate")
        ceiling = float(truth["leak_ceiling"])
        floor = float(truth["allow_floor"])
        if leak is not None and leak >= ceiling:
            return ev.signed_check(
                self.kind, passed=False, critical=True, score=0.0,
                detail={"outcome": "authz_bypass",
                        "reason": "non-owner access-success (BOLA leak) rate at/above the ceiling",
                        "leak_rate": leak, "leak_ceiling": ceiling, "leaks": metrics.get("leaks"),
                        "deny_denominator": metrics.get("deny_denominator")})
        if allow is not None and allow < floor:
            return ev.signed_check(
                self.kind, passed=False, critical=True, score=0.0,
                detail={"outcome": "authz_overblock",
                        "reason": "legitimate owner access denied below the floor",
                        "allow_rate": allow, "allow_floor": floor,
                        "allow_denominator": metrics.get("allow_denominator")})
        composite = composite_score(metrics)
        bar = float(truth["objective_pass"])
        passed = (composite is not None) and (composite >= bar)
        return ev.signed_check(
            self.kind, passed=passed, critical=False, score=composite,
            detail={"outcome": "scored", "composite": composite, "objective_pass": bar,
                    "allow_rate": allow, "deny_rate": metrics.get("deny_rate"),
                    "leak_rate": leak, "status_ok_rate": metrics.get("status_ok_rate"),
                    "deny_denominator": metrics.get("deny_denominator"),
                    "allow_denominator": metrics.get("allow_denominator"),
                    "n": metrics.get("n")})


def register() -> None:
    if not isinstance(ev.EVALUATORS.get(KIND), APISecAuthzEvaluator):
        ev.EVALUATORS[KIND] = APISecAuthzEvaluator()


register()
