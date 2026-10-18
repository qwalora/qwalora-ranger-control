"""PARALLAX Phase 1B - durable reviewer identity and assignment (authoritative, server-side).

Replaces the in-memory reviewer directory with persisted `parallax_reviewer_assignments` rows bound to
Ranger's administrative identity. Eligibility to adjudicate requires BOTH (a) being an eligible
reviewer identity (the reviewer allowlist / AdminUser reviewer role) AND (b) an ACTIVE, unexpired
assignment to the exact (candidate, cohort, assessment, attempt). Being an administrator does not by
itself make one an assigned reviewer. Assignments are created and revoked only by an authorized
administrator, and every lifecycle action is audited.

`directory_for*` builds a `review.ReviewerDirectory` from live DB rows, so the existing, unchanged
`review.verify_adjudication` enforces the same binding against authoritative data.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from . import registry, auditlog
from .review import ReviewerDirectory, binding_key


class AssignmentError(Exception):
    """A reviewer assignment is refused (unauthorized admin, ineligible reviewer, conflict, …)."""


def authorized_reviewers(db) -> set:
    """Reviewer identities eligible to adjudicate: the reviewer allowlist UNION AdminUser reviewers."""
    return registry.authorized_admins(db)


def _is_active(row) -> bool:
    from models import _now
    if row.status != "active":
        return False
    if row.expires_at is not None and row.expires_at <= _now():
        return False
    return True


def assign_reviewer(db, *, principal, reviewer_id: str, candidate_key: str, cohort: Optional[str],
                    assessment_id: str, attempt: int = 1, expires_at=None):
    """Create an active assignment. Authorized-admin only; the reviewer must be an eligible reviewer
    identity and not the candidate; only one active reviewer per attempt."""
    from models import ParallaxReviewerAssignment
    who = registry._authorize(db, principal)
    if reviewer_id not in authorized_reviewers(db):
        raise AssignmentError("%r is not an eligible reviewer identity" % reviewer_id)
    if reviewer_id == candidate_key:
        raise AssignmentError("a candidate may not be assigned to review their own assessment")

    # "one active reviewer per attempt" is a code invariant with no unique-constraint backstop (two
    # DIFFERENT reviewers are two distinct rows), so serialize the check-then-insert on the attempt
    # key; a concurrent assigner blocks and then sees the first active row and is refused.
    auditlog.lock(db, "parallax-assignment:%s:%s:%s:%s" % (candidate_key, cohort, assessment_id, attempt))
    rows = ParallaxReviewerAssignment.query.filter_by(
        candidate_key=candidate_key, cohort=cohort, assessment_id=assessment_id, attempt=attempt).all()
    for r in rows:
        if _is_active(r) and r.reviewer_id == reviewer_id:
            return r   # idempotent
        if _is_active(r) and r.reviewer_id != reviewer_id:
            raise AssignmentError("another reviewer is already actively assigned to this attempt; "
                                  "revoke it before assigning a different reviewer")
    row = ParallaxReviewerAssignment(candidate_key=candidate_key, cohort=cohort,
                                     assessment_id=assessment_id, attempt=attempt,
                                     reviewer_id=reviewer_id, assigned_by=who, status="active",
                                     expires_at=expires_at)
    db.session.add(row)
    auditlog.append(db, action="assign_reviewer", actor_id=who, subject_kind="reviewer_assignment",
                    subject_ref="%s:%s:%s" % (candidate_key, assessment_id, attempt),
                    detail={"reviewer_id": reviewer_id})
    registry._commit_recover(db, lambda: None)
    return row


def revoke_assignment(db, *, principal, reviewer_id: str, candidate_key: str, cohort: Optional[str],
                      assessment_id: str, attempt: int = 1, reason: str = "") -> bool:
    from models import ParallaxReviewerAssignment, _now
    who = registry._authorize(db, principal)
    row = ParallaxReviewerAssignment.query.filter_by(
        candidate_key=candidate_key, cohort=cohort, assessment_id=assessment_id, attempt=attempt,
        reviewer_id=reviewer_id, status="active").first()
    if row is None:
        return False
    row.status = "revoked"
    row.revoked_at = _now()
    row.revoked_by = who
    auditlog.append(db, action="revoke_reviewer_assignment", actor_id=who,
                    subject_kind="reviewer_assignment",
                    subject_ref="%s:%s:%s" % (candidate_key, assessment_id, attempt),
                    detail={"reviewer_id": reviewer_id, "reason": (reason or "")[:120]})
    db.session.commit()
    return True


def _assignments_map(db, *, candidate_key: str, cohort: Optional[str],
                     assessment_id: Optional[str] = None) -> Dict:
    """Return {binding_key: reviewer_id} for every ACTIVE, unexpired assignment of this candidate
    (optionally scoped to one assessment)."""
    from models import ParallaxReviewerAssignment
    q = ParallaxReviewerAssignment.query.filter_by(candidate_key=candidate_key, cohort=cohort,
                                                   status="active")
    if assessment_id is not None:
        q = q.filter_by(assessment_id=assessment_id)
    out = {}
    for r in q.all():
        if _is_active(r):
            out[binding_key(r.candidate_key, r.cohort, r.assessment_id, r.attempt)] = r.reviewer_id
    return out


def directory_for(db, binding: Dict[str, Any]) -> ReviewerDirectory:
    """Build a ReviewerDirectory covering exactly one assessment attempt, from live DB rows."""
    return ReviewerDirectory(
        authorized=authorized_reviewers(db),
        assignments=_assignments_map(db, candidate_key=binding["candidate_key"],
                                     cohort=binding.get("cohort"),
                                     assessment_id=binding["assessment_id"]))


def directory_for_candidate(db, *, candidate_key: str, cohort: Optional[str]) -> ReviewerDirectory:
    """Build a ReviewerDirectory covering all of a candidate's active assignments (for decide_pathway)."""
    return ReviewerDirectory(authorized=authorized_reviewers(db),
                             assignments=_assignments_map(db, candidate_key=candidate_key, cohort=cohort))
