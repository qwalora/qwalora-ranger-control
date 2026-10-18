"""PARALLAX Phase 1C Workstream B - safe migration of the UnitResult uniqueness constraint.

Phase 1B added UNIQUE(candidate_id, unit_ref, kind, record_hash) on `unit_results`, but create_all only
applies it to FRESH databases. A database that predates it needs a controlled schema migration. This
module performs that migration safely:

  * preflight inspects the live schema and detects rows that would VIOLATE the constraint, using the
    same NULL-distinct semantics as a SQL UNIQUE (record_hash IS NULL rows never conflict);
  * it NEVER deletes or merges duplicates automatically - if conflicting rows exist it ABORTS with a
    diagnostic so an operator (not this code) decides the authoritative survivor;
  * it is idempotent (constraint already present -> no-op) and serialized by a PostgreSQL advisory
    lock so two concurrent operators cannot both run it;
  * it preserves every existing signed row unchanged (value-add only: it adds a constraint, it does
    not rewrite evidence or custody history);
  * it runs in a transaction and rolls back on error (forward-recovery: re-run after resolving the
    reported duplicates).

SQLite cannot ALTER TABLE ADD CONSTRAINT; on SQLite a fresh table already carries the constraint via
create_all, so this migration targets PostgreSQL production. On SQLite it reports `noop` when the
constraint is present and `unsupported` when it is absent (rather than rebuilding the table).
"""
from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy import inspect as _inspect, text

TABLE = "unit_results"
CONSTRAINT_NAME = "uq_unit_result_record"
IDENTITY = ("candidate_id", "unit_ref", "kind", "record_hash")
_LOCK_KEY = "parallax-migrate:uq_unit_result_record"


def _dialect(db) -> str:
    return db.engine.dialect.name


def constraint_present(db) -> bool:
    """True if a unique constraint OR unique index over exactly IDENTITY (or named CONSTRAINT_NAME)
    exists on unit_results."""
    insp = _inspect(db.engine)
    if TABLE not in insp.get_table_names():
        return False
    want = set(IDENTITY)
    for uc in insp.get_unique_constraints(TABLE):
        if uc.get("name") == CONSTRAINT_NAME or set(uc.get("column_names") or []) == want:
            return True
    # a unique index created by ADD CONSTRAINT also satisfies the guarantee
    for ix in insp.get_indexes(TABLE):
        if ix.get("unique") and set(ix.get("column_names") or []) == want:
            return True
    return False


def find_duplicates(db) -> List[Dict[str, Any]]:
    """Rows that would violate the constraint: identical IDENTITY with record_hash NOT NULL and a
    count > 1. NULL record_hash rows are excluded because a SQL UNIQUE treats NULLs as distinct."""
    insp = _inspect(db.engine)
    if TABLE not in insp.get_table_names():
        return []
    sql = text(
        "SELECT candidate_id, unit_ref, kind, record_hash, COUNT(*) AS c "
        "FROM unit_results "
        "WHERE record_hash IS NOT NULL AND candidate_id IS NOT NULL "
        "  AND unit_ref IS NOT NULL AND kind IS NOT NULL "
        "GROUP BY candidate_id, unit_ref, kind, record_hash "
        "HAVING COUNT(*) > 1")
    rows = db.session.execute(sql).fetchall()
    return [{"candidate_id": r[0], "unit_ref": r[1], "kind": r[2], "record_hash": r[3], "count": r[4]}
            for r in rows]


def preflight(db) -> Dict[str, Any]:
    """Inspect-only. Returns the dialect, whether the constraint is present, the conflicting groups,
    and a decision: noop | ready | blocked | unsupported."""
    dialect = _dialect(db)
    present = constraint_present(db)
    dups = find_duplicates(db)
    if present:
        decision = "noop"
    elif dups:
        decision = "blocked"
    elif dialect == "postgresql":
        decision = "ready"
    else:
        decision = "unsupported"   # SQLite/other: cannot ALTER ADD CONSTRAINT after the fact
    return {"dialect": dialect, "constraint_present": present,
            "duplicate_groups": dups, "duplicate_rows": sum(d["count"] for d in dups),
            "decision": decision}


def _advisory_lock(db) -> None:
    if _dialect(db) == "postgresql":
        db.session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": _LOCK_KEY})


def apply_migration(db) -> Dict[str, Any]:
    """Apply the migration if safe. Idempotent and serialized. Returns {status, ...} where status is
    noop | applied | blocked | unsupported. NEVER removes duplicates; blocks instead. The ADD
    CONSTRAINT holds a brief ACCESS EXCLUSIVE lock on unit_results, so concurrent writers wait for the
    (fast, small-table) index build; on error the transaction rolls back and the migration can be
    re-run after resolving the reported conflicts."""
    # Serialize concurrent migrators and re-read state under the lock.
    _advisory_lock(db)
    if constraint_present(db):
        db.session.rollback()
        return {"status": "noop", "reason": "constraint already present"}
    dups = find_duplicates(db)
    if dups:
        db.session.rollback()
        return {"status": "blocked", "reason": "conflicting duplicate rows present; resolve manually",
                "duplicate_groups": dups, "duplicate_rows": sum(d["count"] for d in dups)}
    if _dialect(db) != "postgresql":
        db.session.rollback()
        return {"status": "unsupported",
                "reason": "%s cannot ALTER TABLE ADD CONSTRAINT; fresh tables get it via create_all"
                          % _dialect(db)}
    try:
        db.session.execute(text(
            'ALTER TABLE unit_results ADD CONSTRAINT %s UNIQUE (candidate_id, unit_ref, kind, record_hash)'
            % CONSTRAINT_NAME))
        db.session.commit()
    except Exception as e:  # noqa: BLE001 - roll back and report; migration is re-runnable
        db.session.rollback()
        return {"status": "blocked", "reason": "ALTER failed: %s" % e}
    if not constraint_present(db):   # postflight verification
        return {"status": "blocked", "reason": "postflight check did not find the constraint"}
    return {"status": "applied", "constraint": CONSTRAINT_NAME}
