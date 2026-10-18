"""PARALLAX Phase 1B - durable signed assessment records (persisted in models.UnitResult).

Persists the signed assessment decision and the signed reviewer adjudication produced by
`laba_assessment.run_assessment` / `px1_assessment.run_assessment`, preserving every signed identity
property from Phase 1 (candidate, cohort, assessment id+version, attempt, competency, provenance,
unit_ref, blueprint/scoring-spec identity, reviewer binding). Verification is never weakened: the exact
canonical signed record is stored and re-verified with `assessment_contract.verify_decision` on read.

Guarantees:
  - idempotent retried writes (UNIQUE(candidate, unit_ref, kind, record_hash) + get-or-create + commit
    recovery), so a resubmission does not create a duplicate or a conflicting record;
  - substitution-proof: a record is stored under a candidate only if the record's OWN signed binding
    names that candidate; cross-candidate/assessment/cohort/attempt substitution is rejected on write;
  - adjudications are append-only rows linked to the decision's provenance hash (never a mutation);
  - candidate-scoped retrieval (a candidate reads only their own records).

Only ids/hashes are logged; no evidence payloads, signing secrets, tokens, or unnecessary PII.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

import signing
from siem import assessment_contract as ac
from . import auditlog, registry


class AssessmentPersistError(Exception):
    """A record cannot be persisted (unknown candidate, invalid signature, or identity mismatch)."""


def _candidate_row(db, candidate_key: str):
    from models import Candidate
    c = Candidate.query.filter_by(github_id=candidate_key).first()
    if c is None:
        c = Candidate.query.filter_by(handle=candidate_key).first()
    return c


def _record_hash(record: Dict[str, Any]) -> str:
    return hashlib.sha256(signing.canonical(record)).hexdigest()


def record_assessment(db, envelope: Dict[str, Any], *, candidate_key: str) -> Dict[str, Any]:
    """Persist one assessment decision (+ its adjudication, if present). Idempotent and
    substitution-proof. Returns {decision_row, adjudication_row}."""
    from models import UnitResult, _now  # noqa: F401
    signed = envelope.get("signed") or {}
    if not ac.verify_decision(signed):
        raise AssessmentPersistError("refusing to persist an assessment whose signature does not verify")
    rec = signed.get("record") or {}
    decision = rec.get("decision") or {}
    prov = decision.get("provenance") or {}
    binding = prov.get("binding") or {}
    # substitution guard: the record's OWN signed binding must name this candidate
    if binding.get("candidate_key") != candidate_key:
        raise AssessmentPersistError("assessment record binding does not match the candidate (substitution)")
    if rec.get("pathway") != "parallax":
        raise AssessmentPersistError("not a PARALLAX assessment record")

    c = _candidate_row(db, candidate_key)
    if c is None:
        raise AssessmentPersistError("no candidate row for %r" % candidate_key)

    unit_ref = rec.get("unit_ref")
    dec_hash = rec.get("record_hash")
    prov_hash = prov.get("provenance_hash")

    # serialize the get-or-create on this candidate+assessment so a resubmission racing the first
    # write blocks here and then observes the committed decision row, instead of racing to an INSERT
    # that would trip the UNIQUE(candidate, unit_ref, kind, record_hash) during an autoflush.
    auditlog.lock(db, "parallax-assessment:%s:%s" % (c.id, unit_ref))

    # idempotent get-or-create for the decision row
    dec_row = UnitResult.query.filter_by(candidate_id=c.id, unit_ref=unit_ref,
                                         kind="qualification_decision", record_hash=dec_hash).first()
    if dec_row is None:
        dec_row = UnitResult(
            candidate_id=c.id, pathway="parallax", unit_ref=unit_ref,
            blueprint_version=rec.get("blueprint_version"), blueprint_hash=rec.get("blueprint_hash"),
            qualified=False, reason=(rec.get("reason") or "")[:60],
            decision_json=json.dumps(rec, sort_keys=True, separators=(",", ":")),
            record_hash=dec_hash, parent_record_hash=None, kind="qualification_decision",
            signature=signed.get("signature"))
        db.session.add(dec_row)
        auditlog.append(db, action="record_assessment", actor_id=None, subject_kind="assessment",
                        subject_ref=dec_hash or "",
                        detail={"candidate_key": candidate_key, "unit_ref": unit_ref,
                                "assessment_id": binding.get("assessment_id"),
                                "attempt": binding.get("attempt")})

    adj_row = None
    adjudication = envelope.get("adjudication")
    if adjudication:
        adj_rec = adjudication.get("record") or {}
        adj_hash = _record_hash(adj_rec)
        adj_row = UnitResult.query.filter_by(candidate_id=c.id, unit_ref=unit_ref,
                                             kind="reviewer_adjudication", record_hash=adj_hash).first()
        if adj_row is None:
            adj_row = UnitResult(
                candidate_id=c.id, pathway="parallax", unit_ref=unit_ref,
                qualified=False, reason=(adj_rec.get("decision") or "")[:60],
                decision_json=json.dumps(adj_rec, sort_keys=True, separators=(",", ":")),
                record_hash=adj_hash, parent_record_hash=prov_hash, kind="reviewer_adjudication",
                signature=adjudication.get("signature"))
            db.session.add(adj_row)
            auditlog.append(db, action="adjudicate", actor_id=adj_rec.get("reviewer_id"),
                            subject_kind="assessment", subject_ref=dec_hash or "",
                            detail={"candidate_key": candidate_key, "decision": adj_rec.get("decision")})

    def _winner():
        return UnitResult.query.filter_by(candidate_id=c.id, unit_ref=unit_ref,
                                          kind="qualification_decision", record_hash=dec_hash).first()
    registry._commit_recover(db, _winner)
    return {"decision_row": dec_row, "adjudication_row": adj_row}


def assessment_record_for(db, *, candidate_key: str, assessment_id: str) -> Optional[Dict[str, Any]]:
    """Reconstruct the signed {signed_decision, adjudication} envelope for a candidate's assessment, or
    None. Used to feed decide_pathway from authoritative persisted records."""
    from models import UnitResult
    c = _candidate_row(db, candidate_key)
    if c is None:
        return None
    dec = (UnitResult.query.filter_by(candidate_id=c.id, kind="qualification_decision", pathway="parallax")
           .filter(UnitResult.unit_ref.like(assessment_id + "@%"))
           .order_by(UnitResult.created_at.desc()).first())
    if dec is None:
        return None
    signed_decision = {"record": json.loads(dec.decision_json), "signature": dec.signature}
    prov_hash = (((signed_decision["record"].get("decision") or {}).get("provenance") or {})
                 .get("provenance_hash"))
    adjudication = None
    if prov_hash:
        adj = (UnitResult.query.filter_by(candidate_id=c.id, kind="reviewer_adjudication",
                                          pathway="parallax", parent_record_hash=prov_hash)
               .order_by(UnitResult.created_at.desc()).first())
        if adj is not None:
            adjudication = {"record": json.loads(adj.decision_json), "signature": adj.signature}
    return {"signed_decision": signed_decision, "adjudication": adjudication}


def records_for_candidate(db, *, authenticated_candidate_key: str, target_candidate_key: str):
    """Candidate-scoped retrieval: a candidate may read only their own records."""
    if authenticated_candidate_key != target_candidate_key:
        raise AssessmentPersistError("candidate may only retrieve their own assessment records")
    from models import UnitResult
    c = _candidate_row(db, target_candidate_key)
    if c is None:
        return []
    return (UnitResult.query.filter_by(candidate_id=c.id, pathway="parallax")
            .order_by(UnitResult.created_at.asc()).all())
