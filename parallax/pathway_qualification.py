"""PARALLAX pathway-level qualification - separate from, and strictly above, single-assessment results.

A single lab's assessment record (even a passing one) is NEVER a pathway qualification. Pathway
qualification is a distinct decision that fails closed unless ALL hold:

  1. an APPROVED, versioned portfolio policy enumerates the required competencies;
  2. every required competency has a verified, signed, PASSING assessment record bound to
     (candidate, cohort, assessment, attempt);
  3. every such record has an independent, verified AUTHORIZED-reviewer adjudication (pass);
  4. the platform pathway-qualification activation is separately authorized
     (`RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE`, OFF by default).

No approved portfolio policy exists in Phase 1, and the activation flag is off, so pathway
qualification is impossible by construction. This module assigns no board count, duration, or overall
passing threshold - those are set only in an approved portfolio policy, which requires separate
approval.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

from siem import assessment_contract as ac
from .review import ReviewerDirectory, verify_adjudication


def pathway_qualification_active() -> bool:
    """Platform gate for FINAL pathway qualification. OFF by default and distinct from the
    per-assessment gate. A blueprint, score, reviewer, or single-assessment pass cannot turn it on."""
    return str(os.environ.get("RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE", "")).strip().lower() \
        in ("1", "true", "yes")


@dataclass(frozen=True)
class PortfolioPolicy:
    """An approved, versioned enumeration of the competencies a PARALLAX qualification requires.
    `approved` is set only through separate governance; an unapproved policy qualifies no one."""
    version: str
    required_competencies: List[str] = field(default_factory=list)
    approved: bool = False


def decide_pathway(*, candidate_key: str, cohort: str, portfolio: PortfolioPolicy,
                   competency_records: Dict[str, Dict[str, Any]],
                   directory: ReviewerDirectory) -> Dict[str, Any]:
    """Decide pathway qualification. `competency_records` maps competency -> {assessment_record,
    signed_decision, adjudication, binding}. Fails closed on any gap. Deterministic, no AI."""
    breakdown: Dict[str, Any] = {}
    if not portfolio.approved or not portfolio.required_competencies:
        return {"qualified": False, "reason": "no_approved_portfolio_policy", "breakdown": breakdown}

    all_ok = True
    for comp in portfolio.required_competencies:
        entry = (competency_records or {}).get(comp)
        detail = {"present": bool(entry)}
        ok = False
        if entry:
            signed = entry.get("signed_decision") or {}
            adjud = entry.get("adjudication")
            binding = entry.get("binding") or {}
            rec = signed.get("record") or {}
            # (2) verified, signed, passing assessment record, bound to this candidate/cohort
            assessment_ok = (ac.verify_decision(signed)
                             and rec.get("pathway") == "parallax"
                             and bool((rec.get("decision") or {}).get("assessment_passed"))
                             and binding.get("candidate_key") == candidate_key
                             and binding.get("cohort") == cohort)
            # (3) independent, verified authorized-reviewer adjudication (pass)
            review_ok = False
            # the adjudication is bound to the pre-decision provenance hash (stable; no circular
            # dependency on the final record hash), which the signed decision carries in provenance.
            expected_adj_hash = ((rec.get("decision") or {}).get("provenance") or {}).get("provenance_hash")
            if assessment_ok and adjud_is_dict(adjud):
                try:
                    vr = verify_adjudication(adjud, directory=directory, binding=binding,
                                             assessment_record_hash=expected_adj_hash)
                    review_ok = (vr.get("decision") == "pass")
                except Exception:  # noqa: BLE001 - any verification failure is a hard fail
                    review_ok = False
            detail.update({"assessment_ok": assessment_ok, "review_ok": review_ok})
            ok = bool(assessment_ok and review_ok)
        breakdown[comp] = detail
        all_ok = all_ok and ok

    platform_active = pathway_qualification_active()
    qualified = bool(all_ok and platform_active)
    if not all_ok:
        reason = "required_competencies_incomplete"
    elif not platform_active:
        reason = "pathway_qualification_inactive"   # all competencies met; final qualification withheld
    else:
        reason = "qualified"
    return {"qualified": qualified, "assessment_complete": all_ok,
            "platform_pathway_qualification_active": platform_active,
            "reason": reason, "breakdown": breakdown}


def adjud_is_dict(x) -> bool:
    return isinstance(x, dict)
