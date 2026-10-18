"""PARALLAX assessment-spec approval governance.

Replaces any hardcoded `approved=True` on a spec. An assessment spec may bind a candidate instance only
when an AUTHORIZED admin has issued a signed approval record for that spec's exact content hash. The
approval is bound to (assessment_id, version, content_hash, approver) and signed with the platform key,
so it cannot be forged and does not transfer to an edited (drifted) spec.

Authorized approvers are supplied server-side (an injected directory, backed in production by the
platform's reviewer/admin roles - `AdminUser` with a reviewer role or `REVIEWER_GITHUB_IDS`). They are
never read from candidate input.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable

import signing


class ApprovalError(Exception):
    """Raised when an approval is missing, unauthorized, or does not match the spec."""


def _body(assessment_id: str, version: str, content_hash: str, approver_id: str) -> Dict[str, Any]:
    return {"kind": "parallax_spec_approval", "assessment_id": assessment_id, "version": version,
            "content_hash": content_hash, "approver_id": approver_id}


def approve_spec(spec, *, approver_id: str, authorized_admins: Iterable[str]) -> Dict[str, Any]:
    """Issue a signed approval for `spec`. `approver_id` must be in the server-side authorized set.
    Returns a signed approval record bound to the spec's content hash."""
    admins = set(authorized_admins or ())
    if not approver_id or approver_id not in admins:
        raise ApprovalError("approver %r is not an authorized PARALLAX spec approver" % approver_id)
    body = _body(spec.assessment_id, spec.version, spec.content_hash(), approver_id)
    return {"record": body, "signature": signing.sign(body)}


def verify_approval(approval: Dict[str, Any], spec, *, authorized_admins: Iterable[str]) -> None:
    """Fail closed unless `approval` is a valid, authorized, signed approval for exactly this spec."""
    if not isinstance(approval, dict):
        raise ApprovalError("approval record is required (versioned governance, not a hardcoded flag)")
    rec = approval.get("record") or {}
    sig = approval.get("signature")
    admins = set(authorized_admins or ())
    if rec.get("approver_id") not in admins:
        raise ApprovalError("approval was not issued by an authorized approver")
    if rec.get("assessment_id") != spec.assessment_id or rec.get("version") != spec.version:
        raise ApprovalError("approval does not match this assessment/version")
    if rec.get("content_hash") != spec.content_hash():
        raise ApprovalError("approval does not match the current spec content (spec drifted since approval)")
    expect = _body(spec.assessment_id, spec.version, spec.content_hash(), rec.get("approver_id"))
    if rec != expect or not signing.verify(rec, sig):
        raise ApprovalError("approval signature/content invalid")


def is_approved(approval: Dict[str, Any], spec, *, authorized_admins: Iterable[str]) -> bool:
    try:
        verify_approval(approval, spec, authorized_admins=authorized_admins)
        return True
    except ApprovalError:
        return False
