"""PARALLAX Phase 1B - durable governance registry (the persistent authority for approvals).

Wraps the pure, signed approval logic in `parallax.governance` and stores approvals in the
`parallax_approvals` table. Authority is bound to Ranger's server-side administrative identity
(`strata_catalog._is_authorized_admin` + the reviewer allowlist), never to a caller-supplied string.
An approval is valid only for the exact content it fingerprints AND only while its approver's
governing authorization remains effective AND while its status is active. Content columns are
immutable; lifecycle is expressed through status/revoked_*/superseded_by. Every issuance, revocation
and supersession writes a signed audit event atomically with the change.

This module stores and enforces the mechanism; it does NOT create or approve a real PARALLAX
qualification portfolio.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Optional, Tuple

import strata_catalog as _cat
import githuboauth
from . import governance, auditlog


class RegistryAuthError(Exception):
    """The caller is not an authenticated, authorized administrator."""


class RegistryError(Exception):
    """A registry operation is refused (e.g. re-approving revoked content)."""


def authorized_admins(db) -> set:
    """The set of ids that may approve PARALLAX governance: the reviewer allowlist
    (REVIEWER_GITHUB_IDS) UNION persisted AdminUser rows holding an approver role. Read server-side."""
    from models import AdminUser
    ids = set(githuboauth.reviewer_ids())
    try:
        ids |= {a.github_id for a in AdminUser.query.filter(
            AdminUser.role.in_(_cat.APPROVER_ROLES)).all()}
    except Exception:  # noqa: BLE001
        db.session.rollback()
    return ids


def _authorize(db, principal) -> str:
    """Return the authenticated authorized admin id, or raise. Uses the production authority primitive;
    inside an HTTP request this trusts only the session, not the passed principal."""
    ok, who = _cat._is_authorized_admin(principal)
    if not ok or not who:
        raise RegistryAuthError("a governance change requires an authenticated authorized administrator")
    return who


def _commit_recover(db, find_winner):
    try:
        db.session.commit()
    except Exception:  # noqa: BLE001 - a concurrent writer won the unique row
        db.session.rollback()
        won = find_winner()
        if won is not None:
            return won
        raise
    return None


# --- scoring-spec approvals ----------------------------------------------------------------------
def store_spec_approval(db, spec, blueprint: Dict[str, Any], *, principal) -> Tuple[Dict[str, Any], Any]:
    """Issue and persist a signed scoring-spec approval. Idempotent on content; refuses to re-approve
    content that was revoked. Returns (approval_dict, row)."""
    from models import ParallaxApproval
    who = _authorize(db, principal)
    content_hash = governance.scoring_spec_hash(spec, blueprint)

    # serialize the whole get-or-create on this exact content so a concurrent approver blocks here and
    # then observes the committed row (idempotent), rather than racing to a duplicate INSERT.
    auditlog.lock(db, "parallax-approval:scoring_spec:" + content_hash)
    existing = ParallaxApproval.query.filter_by(kind="scoring_spec", content_hash=content_hash).first()
    if existing is not None:
        if existing.status == "active":
            return {"record": json.loads(existing.approval_record), "signature": existing.signature}, existing
        raise RegistryError("this exact scoring spec was previously %s; it cannot be silently "
                            "re-approved (issue a new/ superseding spec)" % existing.status)

    approval = governance.approve_spec(spec, blueprint, approver_id=who, authorized_admins={who})
    row = ParallaxApproval(
        pathway="parallax", kind="scoring_spec", assessment_id=spec.assessment_id,
        assessment_version=spec.version, competency=spec.competency, content_hash=content_hash,
        approval_record=json.dumps(approval["record"], sort_keys=True, separators=(",", ":")),
        signature=approval["signature"], approver_id=who, status="active")
    db.session.add(row)
    auditlog.append(db, action="approve_scoring_spec", actor_id=who, subject_kind="scoring_spec",
                    subject_ref=content_hash,
                    detail={"assessment_id": spec.assessment_id, "version": spec.version})
    won = _commit_recover(db, lambda: ParallaxApproval.query.filter_by(
        kind="scoring_spec", content_hash=content_hash).first())
    row = won or row
    return {"record": json.loads(row.approval_record), "signature": row.signature}, row


def active_spec_approval(db, spec, blueprint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the active, signature-valid approval for this exact spec+blueprint, or None. Fails closed
    if the stored signature does not verify or the approver's governing authority is no longer in
    effect (approval valid only while its governing authorization is effective)."""
    from models import ParallaxApproval
    content_hash = governance.scoring_spec_hash(spec, blueprint)
    row = ParallaxApproval.query.filter_by(kind="scoring_spec", content_hash=content_hash,
                                           status="active").first()
    if row is None:
        return None
    approval = {"record": json.loads(row.approval_record), "signature": row.signature}
    try:
        governance.verify_approval(approval, spec, blueprint, authorized_admins={row.approver_id})
    except governance.ApprovalError:
        return None
    if row.approver_id not in authorized_admins(db):
        return None   # the approver's governing authorization has lapsed
    return approval


def revoke_spec_approval(db, *, principal, content_hash: str, reason: str = "") -> bool:
    """Revoke an active scoring-spec approval (content immutable; only status transitions). Audited."""
    from models import ParallaxApproval
    from models import _now
    who = _authorize(db, principal)
    row = ParallaxApproval.query.filter_by(kind="scoring_spec", content_hash=content_hash,
                                           status="active").first()
    if row is None:
        return False
    row.status = "revoked"
    row.revoked_at = _now()
    row.revoked_by = who
    row.revoke_reason = (reason or "")[:200]
    auditlog.append(db, action="revoke_scoring_spec", actor_id=who, subject_kind="scoring_spec",
                    subject_ref=content_hash, detail={"reason": (reason or "")[:120]})
    db.session.commit()
    return True


# --- portfolio approvals -------------------------------------------------------------------------
def store_portfolio_approval(db, policy, *, principal) -> Tuple[Dict[str, Any], Any]:
    """Issue and persist a signed portfolio approval binding the exact required-competency inventory."""
    from models import ParallaxApproval
    who = _authorize(db, principal)
    content_hash = governance.portfolio_content_hash(policy)
    auditlog.lock(db, "parallax-approval:portfolio:" + content_hash)
    existing = ParallaxApproval.query.filter_by(kind="portfolio", content_hash=content_hash).first()
    if existing is not None:
        if existing.status == "active":
            return {"record": json.loads(existing.approval_record), "signature": existing.signature}, existing
        raise RegistryError("this exact portfolio was previously %s; reauthorization required" % existing.status)
    approval = governance.approve_portfolio(policy, approver_id=who, authorized_admins={who})
    row = ParallaxApproval(
        pathway="parallax", kind="portfolio", policy_version=policy.version, content_hash=content_hash,
        approval_record=json.dumps(approval["record"], sort_keys=True, separators=(",", ":")),
        signature=approval["signature"], approver_id=who, status="active")
    db.session.add(row)
    auditlog.append(db, action="approve_portfolio", actor_id=who, subject_kind="portfolio",
                    subject_ref=content_hash, detail={"version": policy.version,
                                                      "competencies": len(policy.required)})
    won = _commit_recover(db, lambda: ParallaxApproval.query.filter_by(
        kind="portfolio", content_hash=content_hash).first())
    row = won or row
    return {"record": json.loads(row.approval_record), "signature": row.signature}, row


def active_portfolio_approval(db, policy) -> Optional[Dict[str, Any]]:
    """Return the active, signature-valid approval for this exact portfolio inventory, or None."""
    from models import ParallaxApproval
    content_hash = governance.portfolio_content_hash(policy)
    row = ParallaxApproval.query.filter_by(kind="portfolio", content_hash=content_hash,
                                           status="active").first()
    if row is None:
        return None
    approval = {"record": json.loads(row.approval_record), "signature": row.signature}
    try:
        governance.verify_portfolio_approval(approval, policy, authorized_admins={row.approver_id})
    except governance.ApprovalError:
        return None
    if row.approver_id not in authorized_admins(db):
        return None
    return approval


def revoke_portfolio_approval(db, *, principal, content_hash: str, reason: str = "") -> bool:
    from models import ParallaxApproval, _now
    who = _authorize(db, principal)
    row = ParallaxApproval.query.filter_by(kind="portfolio", content_hash=content_hash,
                                           status="active").first()
    if row is None:
        return False
    row.status = "revoked"
    row.revoked_at = _now()
    row.revoked_by = who
    row.revoke_reason = (reason or "")[:200]
    auditlog.append(db, action="revoke_portfolio", actor_id=who, subject_kind="portfolio",
                    subject_ref=content_hash, detail={"reason": (reason or "")[:120]})
    db.session.commit()
    return True
