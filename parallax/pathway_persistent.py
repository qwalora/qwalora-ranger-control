"""PARALLAX Phase 1B - pathway decision over AUTHORITATIVE persisted records (Workstream D).

Feeds `pathway_qualification.decide_pathway` entirely from durable, verified inputs: the approved
portfolio policy from the governance registry, the signed assessment records from the assessment store,
and reviewer assignments from the reviewer store. It fails closed when any required record or the
infrastructure is unavailable, and it preserves the pathway activation control.

This does NOT activate qualification and does NOT create a portfolio. There is no approved PARALLAX
portfolio, so `active_portfolio` returns None and a final pathway qualification is impossible by
construction - regardless of how a candidate performed in any single assessment.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple

from . import registry, reviewer_store, assessment_store
from . import pathway_qualification as PQ


def active_portfolio(db) -> Optional[Tuple[PQ.PortfolioPolicy, Dict[str, Any]]]:
    """Return (policy, signed_approval) for the single active portfolio policy, or None.

    The policy is reconstructed from the signed approval record and then re-verified, so the returned
    policy is exactly the one that was authorized. More than one active portfolio is ambiguous and
    fails closed (None)."""
    from models import ParallaxApproval
    rows = ParallaxApproval.query.filter_by(kind="portfolio", status="active").all()
    if len(rows) != 1:
        return None   # zero (the Phase 1B reality) or ambiguous -> fail closed
    rec = json.loads(rows[0].approval_record)
    required = [{"competency": c, "assessment_id": a, "assessment_version": v}
                for (c, a, v) in rec.get("required", [])]
    policy = PQ.PortfolioPolicy(version=rec.get("version"), required=required)
    approval = registry.active_portfolio_approval(db, policy)   # re-verifies signature + authority
    if approval is None:
        return None
    return policy, approval


def decide_pathway_persistent(db, *, candidate_key: str, cohort: Optional[str]) -> Dict[str, Any]:
    """Decide PARALLAX pathway qualification from persisted, verified records. Fails closed."""
    try:
        got = active_portfolio(db)
        if got is None:
            return {"qualified": False, "reason": "no_approved_portfolio_policy", "breakdown": {}}
        policy, portfolio_approval = got

        directory = reviewer_store.directory_for_candidate(db, candidate_key=candidate_key, cohort=cohort)
        competency_records: Dict[str, Any] = {}
        for req in policy.required:
            rec = assessment_store.assessment_record_for(db, candidate_key=candidate_key,
                                                         assessment_id=req["assessment_id"])
            if rec is not None:
                competency_records[req["competency"]] = rec

        return PQ.decide_pathway(
            candidate_key=candidate_key, cohort=cohort, portfolio=policy,
            portfolio_approval=portfolio_approval, authorized_admins=registry.authorized_admins(db),
            competency_records=competency_records, directory=directory)
    except Exception as e:  # noqa: BLE001 - consequential verification fails closed on any infra error
        db.session.rollback()
        return {"qualified": False, "reason": "infrastructure_unavailable", "detail": str(e),
                "breakdown": {}}
