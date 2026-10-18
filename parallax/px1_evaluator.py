"""PX-1 objective evaluator, implementing the platform `siem.evaluator.Evaluator` contract.

Registered into the shared evaluator registry as kind `generalization_holdout`, so the pathway-neutral
`siem.assessment_contract.decide` can reference it from a PARALLAX blueprint exactly as it references
STRATA's `event_reference`. By construction it honors both platform invariants:

  1. The candidate never supplies truth: `reject_candidate_truth` refuses any self-certifying field,
     and the holdout + leak identity are recomputed server-side behind a ProtectedTruthHandle.
  2. Least privilege: the evaluator reads only its own instance via the scope's truth handle.

Verdict: PASS iff the declared leakage-safe solution meets the holdout threshold (with a bootstrap CI
clear of baseline) AND does not use the planted leak. Using the leak is a CRITICAL failure (the
`critical` flag), which the assessment contract turns into a non-overridable veto. The result is
evaluator-signed so a downstream decision detects tampering. The leak's identity is never placed in
the result, so it cannot reach a candidate-facing surface through the decision record.
"""
from __future__ import annotations

from typing import Any, Dict

import siem.evaluator as ev
from siem.evaluator import Evaluator, ProtectedTruthHandle, EvaluatorScope, reject_candidate_truth

KIND = "generalization_holdout"


def make_truth_handle(instance, seed: int, pass_threshold: float) -> ProtectedTruthHandle:
    """Build the server-side truth handle for one PX-1 instance. The sealed holdout and the planted
    leak identity live only inside this handle; they are never returned to a candidate context."""
    return ProtectedTruthHandle(
        resolver=lambda: {"instance": instance, "seed": seed, "pass_threshold": pass_threshold},
        label="px1-holdout")


class PX1GeneralizationEvaluator(Evaluator):
    kind = KIND

    def verify(self, submission: Dict[str, Any], scope: EvaluatorScope, reader=None):
        from .px1_score import score, SubmissionError, CI_MARGIN  # lazy: keep registration sklearn-free
        bad = reject_candidate_truth(submission)
        if bad:
            return ev.signed_check(self.kind, False,
                                   {"error": "candidate_supplied_truth", "keys": bad})
        truth = scope.truth_handle.resolve()            # server-side only
        inst = truth["instance"]
        seed = int(truth["seed"])
        threshold = float(truth["pass_threshold"])
        try:
            res = score(inst, submission, seed)
        except SubmissionError as e:
            return ev.signed_check(self.kind, False, {"error": "malformed_submission", "message": str(e)})

        if res.used_leak:
            # depending on the planted leakage feature is a critical engineering failure
            return ev.signed_check(
                self.kind, passed=False, critical=True, score=0.0,
                detail={"outcome": "critical_failure",
                        "reason": "solution depends on a non-generalizing (data-leakage) feature",
                        "declared_feature_count": res.declared_feature_count})

        ci_low = res.auc_ci95[0]
        passed = (res.holdout_auc >= threshold) and (ci_low >= 0.5 + CI_MARGIN)
        return ev.signed_check(
            self.kind, passed=passed, critical=False, score=round(res.holdout_auc, 6),
            detail={"outcome": "scored", "holdout_auc": round(res.holdout_auc, 6),
                    "holdout_accuracy": round(res.holdout_accuracy, 6),
                    "auc_ci95": [round(ci_low, 6), round(res.auc_ci95[1], 6)],
                    "pass_threshold": threshold, "model_family": res.model_family,
                    "declared_feature_count": res.declared_feature_count,
                    # reference evidence (not candidate-identifying): proves the trap is real & solvable
                    "reference_honest_holdout_auc": res.reference_honest_holdout_auc,
                    "reference_leak_only_holdout_auc": res.reference_leak_only_holdout_auc})


def register() -> None:
    """Idempotently register the PX-1 evaluator into the shared platform registry. Called at import so
    `assessment_contract.validate_blueprint` recognizes the `generalization_holdout` check kind."""
    if not isinstance(ev.EVALUATORS.get(KIND), PX1GeneralizationEvaluator):
        ev.EVALUATORS[KIND] = PX1GeneralizationEvaluator()


register()
