"""Authenticated, assigned reviewer authority for PARALLAX adjudications.

A reviewer adjudication is authoritative only when ALL hold:
  - the reviewer is an AUTHORIZED reviewer (server-side directory, backed in production by the
    platform's reviewer role / REVIEWER_GITHUB_IDS - never candidate input);
  - the reviewer was ASSIGNED to this exact (candidate, cohort, assessment, attempt);
  - the adjudication is a SIGNED record bound to that identity AND to the assessment record's hash.

A mere non-empty reviewer id is insufficient. Candidate-supplied `reviewer_decision`/`rubric_scores`
are never accepted; the only authoritative reviewer input comes through `make_adjudication` on the
server side and is re-checked with `verify_adjudication`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

import signing


class ReviewAuthorityError(Exception):
    """Raised when a reviewer is unauthorized, unassigned, or an adjudication fails verification."""


def binding_key(candidate_key: str, cohort: str, assessment_id: str, attempt: int) -> Tuple:
    return (candidate_key, cohort, assessment_id, int(attempt))


@dataclass
class ReviewerDirectory:
    """Server-side reviewer authority. `authorized` is the set of reviewer ids with review authority;
    `assignments` maps a binding_key to the reviewer id approved to adjudicate it."""
    authorized: set = field(default_factory=set)
    assignments: Dict[Tuple, str] = field(default_factory=dict)

    def is_authorized(self, reviewer_id: str) -> bool:
        return bool(reviewer_id) and reviewer_id in self.authorized

    def assigned_reviewer(self, binding: Dict[str, Any]) -> Optional[str]:
        return self.assignments.get(binding_key(binding["candidate_key"], binding["cohort"],
                                                 binding["assessment_id"], binding["attempt"]))

    def assign(self, reviewer_id: str, binding: Dict[str, Any]) -> None:
        if not self.is_authorized(reviewer_id):
            raise ReviewAuthorityError("cannot assign an unauthorized reviewer %r" % reviewer_id)
        self.assignments[binding_key(binding["candidate_key"], binding["cohort"],
                                     binding["assessment_id"], binding["attempt"])] = reviewer_id


def _adj_body(binding, assessment_record_hash, reviewer_id, decision, note, rubric_scores):
    return {"kind": "parallax_reviewer_adjudication",
            "candidate_key": binding["candidate_key"], "cohort": binding["cohort"],
            "assessment_id": binding["assessment_id"], "attempt": int(binding["attempt"]),
            "assessment_record_hash": assessment_record_hash, "reviewer_id": reviewer_id,
            "decision": decision, "note": note, "rubric_scores": rubric_scores or {}}


def make_adjudication(*, reviewer_id: str, directory: ReviewerDirectory, binding: Dict[str, Any],
                      assessment_record_hash: str, decision: str, note: str = "",
                      rubric_scores: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Create a signed, bound adjudication. Fails closed unless the reviewer is authorized AND is the
    reviewer assigned to this binding. Called only server-side (never from a candidate boundary)."""
    if not directory.is_authorized(reviewer_id):
        raise ReviewAuthorityError("reviewer %r is not an authorized reviewer" % reviewer_id)
    if directory.assigned_reviewer(binding) != reviewer_id:
        raise ReviewAuthorityError("reviewer %r is not assigned to this assessment attempt" % reviewer_id)
    if decision not in ("pass", "fail"):
        raise ReviewAuthorityError("reviewer decision must be 'pass' or 'fail'")
    body = _adj_body(binding, assessment_record_hash, reviewer_id, decision, note, rubric_scores)
    return {"record": body, "signature": signing.sign(body)}


def verify_adjudication(adjudication: Dict[str, Any], *, directory: ReviewerDirectory,
                        binding: Dict[str, Any], assessment_record_hash: str) -> Dict[str, Any]:
    """Return the verified adjudication record, or raise. Checks signature, authority, assignment, and
    that the adjudication is bound to exactly this binding + assessment record hash."""
    if not isinstance(adjudication, dict):
        raise ReviewAuthorityError("an adjudication record is required (not a raw reviewer dict)")
    rec = adjudication.get("record") or {}
    sig = adjudication.get("signature")
    rid = rec.get("reviewer_id")
    if not directory.is_authorized(rid):
        raise ReviewAuthorityError("adjudication reviewer is not authorized")
    if directory.assigned_reviewer(binding) != rid:
        raise ReviewAuthorityError("adjudication reviewer is not the assigned reviewer")
    expect = _adj_body(binding, assessment_record_hash, rid, rec.get("decision"), rec.get("note"),
                       rec.get("rubric_scores"))
    if rec != expect:
        raise ReviewAuthorityError("adjudication is not bound to this assessment record/identity")
    if not signing.verify(rec, sig):
        raise ReviewAuthorityError("adjudication signature invalid")
    return rec


def reviewer_decision_for_contract(verified_record: Dict[str, Any]) -> Dict[str, Any]:
    """Map a VERIFIED adjudication into the reviewer_decision shape `assessment_contract.decide` reads.
    Only ever built from a verified record, never from candidate input."""
    return {"decision": verified_record.get("decision"), "reviewer_id": verified_record.get("reviewer_id")}
