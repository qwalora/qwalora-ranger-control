"""PARALLAX pathway-level qualification - separate from, and strictly above, single-assessment results.

A single lab's assessment record (even a passing, signed one) is NEVER a pathway qualification. Pathway
qualification fails closed unless ALL hold:

  1. a SIGNED, authorized PORTFOLIO approval binds the exact required-competency inventory (finding 2);
  2. for every required competency, a verified SIGNED assessment record whose OWN signed identity
     (candidate, cohort, assessment_id, attempt, provenance) matches the slot - so a valid signature
     transplanted from another candidate or another assessment is rejected (finding 3);
  3. a verified, authorized, assigned reviewer adjudication bound to that same identity + provenance;
  4. the separate platform pathway-qualification activation
     (`RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE`, OFF by default).

No approved portfolio exists in Phase 1 and the activation flag is off, so pathway qualification is
impossible by construction. This module declares no board count, duration, or overall threshold; those
live only in an approved portfolio policy, which requires separate authorization.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

import pathways
from siem import assessment_contract as ac
from . import governance
from .review import ReviewerDirectory, verify_adjudication


def pathway_qualification_active() -> bool:
    """Platform gate for FINAL pathway qualification. OFF by default and distinct from the
    (now informational) per-assessment flag. A blueprint, score, reviewer, or single-assessment pass
    cannot turn it on."""
    return str(os.environ.get("RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE", "")).strip().lower() \
        in ("1", "true", "yes")


@dataclass(frozen=True)
class PortfolioPolicy:
    """A versioned enumeration of the competencies a PARALLAX qualification requires. Each entry binds
    a competency to a specific assessment (`assessment_id` + `assessment_version`). There is NO
    caller-controlled `approved` flag: authority comes only from a signed `governance.approve_portfolio`
    record verified in `decide_pathway`."""
    version: str
    required: List[Dict[str, str]] = field(default_factory=list)  # [{competency, assessment_id, assessment_version}]

    def competencies(self) -> List[str]:
        return [r["competency"] for r in self.required]


def _verified_assessment_identity(signed: Dict[str, Any], *, candidate_key: str, cohort: str,
                                  assessment_id: str) -> Dict[str, Any]:
    """Return the signed decision's own bound identity iff the record verifies, is a PARALLAX
    assessment that passed, and its provenance binding matches the expected candidate/cohort/assessment.
    Raises ValueError otherwise. This is the transplant guard: identity is read from INSIDE the signed
    record, not from any caller-supplied sidecar."""
    if not ac.verify_decision(signed):
        raise ValueError("assessment decision signature/record invalid")
    rec = signed.get("record") or {}
    decision = rec.get("decision") or {}
    if rec.get("pathway") != pathways.PATHWAY_PARALLAX:
        raise ValueError("not a PARALLAX assessment record")
    if not bool(decision.get("assessment_passed")):
        raise ValueError("assessment not passed")
    prov = decision.get("provenance") or {}
    binding = prov.get("binding") or {}
    if binding.get("candidate_key") != candidate_key or binding.get("cohort") != cohort:
        raise ValueError("assessment record is bound to a different candidate/cohort (transplant)")
    if binding.get("assessment_id") != assessment_id:
        raise ValueError("assessment record is for a different assessment than this competency slot")
    if not str(rec.get("unit_ref", "")).startswith(assessment_id + "@"):
        raise ValueError("assessment record unit_ref does not match the required assessment")
    if not prov.get("provenance_hash"):
        raise ValueError("assessment record carries no provenance binding")
    return {"binding": binding, "provenance_hash": prov["provenance_hash"]}


def decide_pathway(*, candidate_key: str, cohort: str, portfolio: PortfolioPolicy,
                   portfolio_approval: Dict[str, Any], authorized_admins,
                   competency_records: Dict[str, Dict[str, Any]],
                   directory: ReviewerDirectory) -> Dict[str, Any]:
    """Decide pathway qualification. Fails closed on any gap. Deterministic, no AI.

    `competency_records` maps competency -> {signed_decision, adjudication}. Identity is read from the
    signed records themselves; a transplanted signature (valid but bound to another candidate/assessment)
    is rejected because its internal binding will not match the slot."""
    breakdown: Dict[str, Any] = {}

    # (1) the portfolio itself must be independently approved (signed), binding the exact inventory
    try:
        governance.verify_portfolio_approval(portfolio_approval, portfolio,
                                              authorized_admins=authorized_admins or ())
    except governance.ApprovalError as e:
        return {"qualified": False, "reason": "no_approved_portfolio_policy",
                "detail": str(e), "breakdown": breakdown}
    if not portfolio.required:
        return {"qualified": False, "reason": "no_approved_portfolio_policy", "breakdown": breakdown}

    all_ok = True
    for req in portfolio.required:
        comp, assessment_id = req["competency"], req["assessment_id"]
        entry = (competency_records or {}).get(comp) or {}
        detail: Dict[str, Any] = {"present": bool(entry), "assessment_id": assessment_id}
        ok = False
        try:
            ident = _verified_assessment_identity(entry.get("signed_decision") or {},
                                                  candidate_key=candidate_key, cohort=cohort,
                                                  assessment_id=assessment_id)
            # (3) the adjudication must be authorized/assigned AND bound to the SAME identity+provenance
            vr = verify_adjudication(entry.get("adjudication") or {}, directory=directory,
                                     binding=ident["binding"],
                                     assessment_record_hash=ident["provenance_hash"])
            ok = (vr.get("decision") == "pass")
            detail.update({"assessment_ok": True, "review_ok": ok})
        except Exception as e:  # noqa: BLE001 - any verification failure is a hard, closed fail
            detail.update({"assessment_ok": False, "review_ok": False, "error": str(e)})
        breakdown[comp] = detail
        all_ok = all_ok and ok

    platform_active = pathway_qualification_active()
    qualified = bool(all_ok and platform_active)
    if not all_ok:
        reason = "required_competencies_incomplete"
    elif not platform_active:
        reason = "pathway_qualification_inactive"
    else:
        reason = "qualified"
    return {"qualified": qualified, "assessment_complete": all_ok,
            "platform_pathway_qualification_active": platform_active,
            "reason": reason, "breakdown": breakdown}
