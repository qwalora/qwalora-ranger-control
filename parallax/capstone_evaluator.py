"""PX-CAP objective evaluator (platform siem.evaluator.Evaluator contract), kind `parallax_capstone`.
Scores a server-side composite measurement (per-component results from capstone_harness) behind a
ProtectedTruthHandle: any component critical-failing (or not passing its bar) critical-fails the
capstone; it passes only when EVERY component passed. Bound to the combined code SHA-256; no model.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import siem.evaluator as ev
from siem.evaluator import Evaluator, ProtectedTruthHandle, EvaluatorScope, reject_candidate_truth

KIND = "parallax_capstone"


def make_truth_handle(measurement: Dict[str, Any], *, objective_pass: float) -> ProtectedTruthHandle:
    return ProtectedTruthHandle(
        resolver=lambda: {"measurement": measurement, "objective_pass": float(objective_pass)},
        label="pxcap-measurement")


class CapstoneEvaluator(Evaluator):
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
        comps = measurement.get("components") or {}
        if not metrics.get("findings_available"):
            return ev.signed_check(self.kind, passed=False, score=None,
                                   detail={"outcome": "no_findings", "note": "the sandbox did not run"})
        mean_c = metrics.get("mean_composite")
        if metrics.get("any_critical") or not metrics.get("all_passed"):
            return ev.signed_check(
                self.kind, passed=False, critical=bool(metrics.get("any_critical")),
                score=mean_c,
                detail={"outcome": "capstone_component_failure",
                        "reason": "not every component passed its board's bar",
                        "failed": metrics.get("failed_names"), "passed": metrics.get("passed_names"),
                        "components": comps, "mean_composite": mean_c})
        return ev.signed_check(
            self.kind, passed=True, critical=False, score=mean_c,
            detail={"outcome": "scored", "mean_composite": mean_c,
                    "passed_components": metrics.get("passed_components"),
                    "total_components": metrics.get("total_components"), "components": comps})


def register() -> None:
    if not isinstance(ev.EVALUATORS.get(KIND), CapstoneEvaluator):
        ev.EVALUATORS[KIND] = CapstoneEvaluator()


register()
