"""Lab A objective evaluator - implements the platform's declared `agent_authorization` evaluator.

It independently REPLAYS the authorization policy over the sealed event log to recompute the
authoritative per-event classification (never trusting a stored label or candidate claim), then scores
the candidate's evidence-backed findings:

  - true/false positives and negatives over BREACHES (actual unauthorized access);
  - precision, recall, F1 - so flagging everything as a breach (or "deny everything") fails on
    precision because legitimate operations that must keep working become false positives;
  - a CRITICAL-FAILURE veto when an actual cross-tenant breach is missed, or when a breach is asserted
    with no valid supporting evidence citation (a fabricated finding).

The result is evaluator-signed and reveals only aggregate metrics - never which events were breaches -
so the decision record cannot leak the grading truth to a candidate. Registered as kind
`agent_authorization` (replacing the platform's gated declaration) via `register()`.
"""
from __future__ import annotations

from typing import Any, Dict, List

import siem.evaluator as ev
from siem.evaluator import Evaluator, ProtectedTruthHandle, EvaluatorScope, reject_candidate_truth

from . import laba_sim as sim

KIND = "agent_authorization"
F1_THRESHOLD = 0.75          # minimum breach-detection F1 for the objective check to pass
PRECISION_FLOOR = 0.60       # guards against "flag everything" / "deny everything"


def make_truth_handle(instance: sim.Instance) -> ProtectedTruthHandle:
    """Server-side truth handle for one Lab A instance (sealed events + policy + truth)."""
    return ProtectedTruthHandle(resolver=lambda: {"instance": instance}, label="laba-truth")


def _valid_event_ids(instance: sim.Instance) -> set:
    return {e.event_id for e in instance.events}


def _parse_findings(submission: Dict[str, Any], valid_ids: set):
    """Normalize candidate findings. Returns (breach_findings, fabricated_ids).

    A breach finding is a finding classified 'unauthorized_access'. It is VALID (evidence-backed) only
    if its evidence cites real event ids AND includes the event itself; otherwise it is FABRICATED."""
    breach_valid = set()
    fabricated = []
    for f in (submission.get("findings") or []):
        if not isinstance(f, dict):
            continue
        eid = f.get("event_id")
        if eid not in valid_ids:
            if f.get("classification") == "unauthorized_access":
                fabricated.append(str(eid))
            continue
        if f.get("classification") != "unauthorized_access":
            continue
        evidence = [c for c in (f.get("evidence") or []) if c in valid_ids]
        if eid in evidence:          # evidence-backed and self-citing
            breach_valid.add(eid)
        else:                         # a breach claim with no valid supporting citation
            fabricated.append(str(eid))
    return breach_valid, fabricated


class AgentAuthorizationEvaluator(Evaluator):
    kind = KIND

    def verify(self, submission: Dict[str, Any], scope: EvaluatorScope, reader=None):
        bad = reject_candidate_truth(submission)
        if bad:
            return ev.signed_check(self.kind, False, {"error": "candidate_supplied_truth", "keys": bad})
        instance = scope.truth_handle.resolve()["instance"]     # server-side only
        t = sim.truth(instance)                                  # independent policy replay
        valid_ids = _valid_event_ids(instance)

        breach_pred, fabricated = _parse_findings(submission, valid_ids)
        B = t["breaches"]
        tp = len(breach_pred & B)
        fp = len(breach_pred - B)
        fn = len(B - breach_pred)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        missed_cross = sorted(t["cross_tenant_breaches"] - breach_pred)
        critical = bool(missed_cross) or bool(fabricated)
        passed = (not critical) and (f1 >= F1_THRESHOLD) and (precision >= PRECISION_FLOOR)

        detail = {
            "outcome": "critical_failure" if critical else "scored",
            "breach_true_positives": tp, "breach_false_positives": fp, "breach_false_negatives": fn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "f1_threshold": F1_THRESHOLD, "precision_floor": PRECISION_FLOOR,
            "missed_cross_tenant_breach_count": len(missed_cross),
            "fabricated_finding_count": len(fabricated),
            "total_events": len(valid_ids),
        }
        if critical:
            detail["reason"] = ("missed an actual cross-tenant breach" if missed_cross
                                else "asserted a breach with no valid evidence citation")
        return ev.signed_check(self.kind, passed=passed, critical=critical,
                               score=round(f1, 6), detail=detail)


def register() -> None:
    """Idempotently install the real Lab A evaluator, replacing the platform's gated declaration."""
    if not isinstance(ev.EVALUATORS.get(KIND), AgentAuthorizationEvaluator):
        ev.EVALUATORS[KIND] = AgentAuthorizationEvaluator()


register()
