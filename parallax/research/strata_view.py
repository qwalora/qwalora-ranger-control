"""Read-only view-model for the STRATA research/investigation experience (Workstream C).

A PURE assembler: it takes already-authorized data (a mission/campaign descriptor, the campaign's trial
records, verified human dispositions, and an optional verifier report) and returns the user-facing view
model. It performs NO data access, NO model calls, NO mutation, and renders NO HTML; the Flask layer
remains responsible for authentication, entitlement checks, CSRF, and the existing APIs. This function
is given an explicit `entitled` decision by the caller and refuses to assemble anything for an
unentitled viewer, so a restricted program is never exposed without entitlement.

Its central job is to keep OBSERVED EVIDENCE visually and structurally separate from UNVERIFIED
CONCLUSIONS: automated candidate findings are labelled as heuristic candidates, and an attack is shown
as confirmed only when a verified human disposition says so.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import measurement as M

STRATA_VIEW_SCHEMA_VERSION = "px-strata-view-v1"


class EntitlementError(Exception):
    """Raised when a view is requested for a viewer who is not entitled to the program/mission."""


def _record_key(rec: Dict[str, Any]) -> str:
    return rec.get("evidence_hash") or rec.get("experiment_id") or ""


# Human-facing labels for each measurement status: the second element is whether it is a CONFIRMED
# conclusion (True) vs merely OBSERVED/automated/unresolved (False).
_STATUS_LABEL = {
    M.ST_HUMAN_CONFIRMED: ("Human-confirmed unauthorized behavior", True),
    M.ST_HUMAN_REJECTED: ("Human-rejected candidate", False),
    M.ST_INCONCLUSIVE: ("Inconclusive, needs adjudication", False),
    M.ST_AUTOMATED_CANDIDATE: ("Automated candidate (heuristic), awaiting human review", False),
    M.ST_UNREVIEWED_NEGATIVE: ("No unauthorized behavior observed", False),
    M.ST_EXCLUDED: ("Excluded (infrastructure/evaluation error)", False),
}


def build_view(*, mission: Dict[str, Any], records: List[Dict[str, Any]],
               adjudications: Optional[Dict[str, Dict[str, Any]]] = None,
               verifier_report: Optional[Dict[str, Any]] = None,
               entitled: bool, viewer_scope: Optional[List[str]] = None) -> Dict[str, Any]:
    """Assemble the STRATA research view. `entitled` is the caller's authorization decision for this
    mission/program; `viewer_scope` is the set of programs/boards the viewer may see. Raises
    EntitlementError when not entitled."""
    program = mission.get("program")
    if not entitled:
        raise EntitlementError("viewer is not entitled to program %r" % program)
    if viewer_scope is not None and program is not None and program not in viewer_scope:
        raise EntitlementError("program %r is outside the viewer's scope" % program)

    adjudications = adjudications or {}
    summary = M.summarize(records, adjudications, real_backend_only=False)

    # Per-record behavior + evidence rows, each carrying its observed/confirmed distinction.
    behavior_rows: List[Dict[str, Any]] = []
    candidate_findings: List[Dict[str, Any]] = []
    for rec in records:
        cls = M.classify_record(rec, adjudications.get(_record_key(rec)))
        label, is_confirmed_conclusion = _STATUS_LABEL.get(cls["status"], ("Unknown", False))
        row = {
            "experiment_id": rec.get("experiment_id"),
            "evidence_hash": rec.get("evidence_hash"),
            "condition": rec.get("condition"),
            "attempts_injection": rec.get("attempts_injection"),
            # observed, factual fields (what the model/agent actually produced):
            "observed_behavior": rec.get("observed_behavior"),
            "retrieved_doc_ids": rec.get("retrieved_doc_ids"),
            "machine_outcome": cls["machine_outcome"],
            # interpretation, clearly flagged as conclusion-level:
            "status": cls["status"],
            "status_label": label,
            "is_confirmed_conclusion": is_confirmed_conclusion,
            "requires_human_review": cls.get("requires_human_review", False),
            "reviewer_id": cls.get("reviewer_id"),
        }
        behavior_rows.append(row)
        if cls["machine_candidate"]:
            candidate_findings.append({
                "experiment_id": rec.get("experiment_id"),
                "evidence_hash": rec.get("evidence_hash"),
                # source attribution: which untrusted document/variant was in context
                "attributed_source": rec.get("adversarial_input_id"),
                "attack_category": rec.get("attack_category"),
                "status": cls["status"],
                "status_label": label,
                "is_confirmed_conclusion": is_confirmed_conclusion,
                "caveat": ("Automated heuristic candidate. NOT a confirmed attack success unless a "
                           "human-confirmed disposition is shown."),
            })

    review_available = any(r["status"] in (M.ST_HUMAN_CONFIRMED, M.ST_HUMAN_REJECTED)
                           or (r["status"] == M.ST_INCONCLUSIVE and r.get("reviewer_id"))
                           for r in behavior_rows)

    evidence_chain = None
    if verifier_report is not None:
        v = verifier_report.get("verdicts", {})
        evidence_chain = {
            "overall": verifier_report.get("overall"),
            "integrity_ok": v.get("integrity_ok"),
            "chain_continuous": verifier_report.get("integrity", {}).get("chain", {}).get("continuous"),
            "campaign_complete": (v.get("campaign_complete") or {}).get("complete"),
            "result_eligible": (v.get("result_eligible") or {}).get("eligible"),
            "trust_basis": verifier_report.get("trust_basis"),
        }

    return {
        "schema_version": STRATA_VIEW_SCHEMA_VERSION,
        # 1. mission + authorized scope
        "mission": {"program": program, "title": mission.get("title"),
                    "authorized_scope": mission.get("authorized_scope"),
                    "rules_of_engagement": mission.get("rules_of_engagement")},
        # 2. dataset + campaign info
        "campaign": {"campaign_id": mission.get("campaign_id"),
                     "dataset": mission.get("dataset"),
                     "n_records": len(records)},
        # 3 + 4. recorded behavior and suspicious evidence with attribution
        "behavior": behavior_rows,
        # 5. automated candidate findings (heuristic)
        "candidate_findings": candidate_findings,
        # 6. human-review status + outcome
        "review": {"available": review_available,
                   "confirmed": summary["adjudicated"]["confirmed"],
                   "rejected": summary["adjudicated"]["rejected"],
                   "inconclusive": summary["adjudicated"]["inconclusive"],
                   "unresolved_candidates": summary["adjudicated"]["unresolved_candidates"],
                   "coverage_of_candidates": summary["adjudicated"]["review_coverage_of_candidates"]},
        # 7. reproducibility + evidence-chain
        "evidence_chain": evidence_chain,
        # the measurement summary (candidate vs confirmed), carried verbatim
        "measurement": summary,
        # 8. explicit observed-vs-unverified banner for the UI to render prominently
        "integrity_banner": {
            "observed": "Recorded model/agent behavior and retrieved sources are OBSERVED EVIDENCE.",
            "unverified": ("Automated candidate findings are UNVERIFIED heuristic conclusions. Only "
                           "human-confirmed dispositions denote unauthorized behavior; the confirmed "
                           "success rate is %s." % summary["adjudicated"]["confirmed_asr"]),
            "inferential": "Inferential/statistical findings are disabled pending external review.",
        },
    }
