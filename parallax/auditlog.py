"""PARALLAX Phase 1B - append-only, signed, hash-chained governance/reviewer audit trail.

Modeled on Ranger's custody chain: each event carries its own record_hash, links to the prior event's
hash, and is Ed25519-signed. Events are added to the caller's transaction so the audit entry commits
atomically with the action it records (or not at all). Details are redacted by callers (ids/hashes
only - never secrets, tokens, evidence payloads, or unnecessary PII)."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from sqlalchemy import text

import signing

_STREAM = "parallax-governance"


def lock(db, key: str) -> None:
    """Acquire a transaction-scoped advisory lock on `key` (auto-released at commit/rollback); a no-op
    on SQLite (single writer). Serializes a critical section across PostgreSQL connections.

    Callers MUST take the subject lock for a mutation at the very start of the operation - before the
    idempotency/conflict read - so a concurrent writer blocks there and then observes the committed
    row, instead of racing to an INSERT that fails (possibly during an autoflush, where it would
    escape the commit-time recovery). pg advisory locks are stackable and re-entrant within a
    transaction, so taking the per-subject lock and then the audit-stream lock below is safe; every
    operation takes its subject lock first and the shared stream lock last, a consistent order that
    cannot deadlock."""
    if db.engine.dialect.name == "postgresql":
        db.session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": key})


def _lock(db) -> None:
    """Serialize global audit seq allocation on PostgreSQL; a no-op on SQLite (single writer)."""
    lock(db, "parallax-audit:" + _STREAM)


def append(db, *, action: str, actor_id: Optional[str], subject_kind: str, subject_ref: str,
           detail: Optional[Dict[str, Any]] = None):
    """Append one signed audit event to the caller's open transaction (does NOT commit). Returns the
    ORM row. The caller commits it together with the consequential change it describes."""
    from models import ParallaxAuditEvent
    _lock(db)
    prior = (ParallaxAuditEvent.query.filter_by(stream=_STREAM)
             .order_by(ParallaxAuditEvent.seq.desc()).first())
    seq = (prior.seq + 1) if prior else 0
    parent_hash = prior.record_hash if prior else None
    record = {"stream": _STREAM, "seq": seq, "action": action, "actor_id": actor_id,
              "subject_kind": subject_kind, "subject_ref": subject_ref, "detail": detail or {},
              "parent_hash": parent_hash}
    record_hash = hashlib.sha256(signing.canonical(record)).hexdigest()
    row = ParallaxAuditEvent(stream=_STREAM, seq=seq, action=action, actor_id=actor_id,
                             subject_kind=subject_kind, subject_ref=subject_ref,
                             detail_json=signing.canonical(record).decode("utf-8"),
                             record_hash=record_hash, parent_hash=parent_hash,
                             signature=signing.sign(record))
    db.session.add(row)
    return row


def verify_chain(db) -> bool:
    """True if every audit event's signature is intact and the parent-hash chain is unbroken."""
    from models import ParallaxAuditEvent
    rows = (ParallaxAuditEvent.query.filter_by(stream=_STREAM)
            .order_by(ParallaxAuditEvent.seq.asc()).all())
    prev_hash = None
    for r in rows:
        import json
        try:
            record = json.loads(r.detail_json)
        except Exception:  # noqa: BLE001
            return False
        if record.get("parent_hash") != prev_hash:
            return False
        if hashlib.sha256(signing.canonical(record)).hexdigest() != r.record_hash:
            return False
        if not signing.verify(record, r.signature):
            return False
        prev_hash = r.record_hash
    return True
