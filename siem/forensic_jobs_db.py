"""F4.1 - PostgreSQL/SQLAlchemy adapters for the forensic job lifecycle, evidence sink, trusted
fixture registry, and reference-counted blob lifecycle.

These are the durable, concurrency-safe implementations of the storage-agnostic interfaces the
JobCoordinator drives (the in-memory versions in forensic_jobs.py remain for unit tests/demos).
They use the existing models.ForensicJob / EvidenceArtifact / CustodyEvent / BlobReference rows and
the Flask-SQLAlchemy session (per-thread scoped, so independent threads/connections are isolated).

Concurrency primitives (PostgreSQL):
  * idempotent create  - UNIQUE(idempotency_key); INSERT, and on conflict return the existing row.
  * atomic claim        - a transaction-scoped advisory lock serialises the slot decision, then a
                          conditional UPDATE ... WHERE state='queued' AND worker_token IS NULL takes
                          the job; the cap is counted inside the same lock so it is never exceeded.
  * cancellation-safe   - finalize_success is a conditional UPDATE ... WHERE state='running' AND
    finalize             worker_token=:tok; if it matches 0 rows (job was canceled) the whole
                          transaction (including the pending derived rows) is rolled back, so a
                          canceled job never becomes succeeded and commits no result.
  * blob lifecycle      - every create/release/hold/delete on a given object takes the same
                          per-object advisory lock, so bytes are never physically deleted from a
                          stale snapshot while another reference is being created.

On SQLite (unit tests) the advisory-lock calls are skipped; these adapters are intended for the
PostgreSQL deployment and are exercised by siem/tests/test_f41_persistence_pg.py against a real DB.
"""
from __future__ import annotations

import datetime as _dt
import json

from sqlalchemy import text

from . import evidence_persistence as ep
from . import evidence_validation as ev
from . import custody_integrity as ci

CLAIM_LOCK_KEY = 991877   # constant advisory-lock key serialising claim/slot decisions


def _iso(ts=None):
    return (ts or _dt.datetime.now(_dt.timezone.utc)).isoformat()


def _is_pg(db):
    return db.engine.dialect.name == "postgresql"


def _xact_lock_int(db, n):
    if _is_pg(db):
        db.session.execute(text("SELECT pg_advisory_xact_lock(:n)"), {"n": int(n)})


def _xact_lock_text(db, s):
    if _is_pg(db):
        db.session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:s))"), {"s": str(s)})


# ============================== Job store ===================================
class SqlJobStore:
    def __init__(self, db, model=None):
        self.db = db
        if model is None:
            from models import ForensicJob as model
        self.M = model

    def _row_to_dict(self, r):
        if r is None:
            return None
        return {"job_id": r.job_id, "operation": r.operation,
                "source_evidence_id": r.source_evidence_id, "case_id": r.case_id,
                "candidate_id": r.candidate_id, "cohort": r.cohort, "pathway": r.pathway,
                "params": json.loads(r.params) if r.params else {},
                "idempotency_key": r.idempotency_key, "state": r.state,
                "requested_by": r.requested_by, "attempts": r.attempts,
                "max_attempts": r.max_attempts, "worker_token": r.worker_token,
                "claimed_at": r.claimed_at, "started_at": r.started_at,
                "finished_at": r.finished_at, "wall_ms": r.wall_ms,
                "error_code": r.error_code, "error_detail": r.error_detail,
                "result_manifest": r.result_manifest,
                "derived_evidence_ids": json.loads(r.derived_evidence_ids)
                if r.derived_evidence_ids else []}

    def create(self, job):
        db, M = self.db, self.M
        idem = job.get("idempotency_key")
        if idem:
            existing = M.query.filter_by(idempotency_key=idem).first()
            if existing:
                return self._row_to_dict(existing), False
        row = M(job_id=job["job_id"], operation=job["operation"],
                source_evidence_id=job["source_evidence_id"], case_id=job.get("case_id"),
                candidate_id=job.get("candidate_id"), cohort=job.get("cohort"),
                pathway=job.get("pathway"), params=json.dumps(job.get("params") or {}),
                idempotency_key=idem, state="queued", requested_by=job.get("requested_by"),
                attempts=0, max_attempts=job.get("max_attempts", 1))
        db.session.add(row)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            if idem:
                existing = M.query.filter_by(idempotency_key=idem).first()
                if existing:
                    return self._row_to_dict(existing), False
            raise
        return self._row_to_dict(row), True

    def get(self, job_id):
        return self._row_to_dict(self.M.query.filter_by(job_id=job_id).first())

    def list_running(self):
        return [self._row_to_dict(r) for r in self.M.query.filter_by(state="running").all()]

    def list_stale(self, older_than_iso):
        rows = self.M.query.filter_by(state="running").all()
        return [self._row_to_dict(r) for r in rows if (r.claimed_at or "") < older_than_iso]

    def claim(self, job_id, worker_token, *, max_concurrent=None):
        db, M = self.db, self.M
        _xact_lock_int(db, CLAIM_LOCK_KEY)   # serialise slot decisions (released on commit)
        if max_concurrent is not None:
            running = db.session.query(M).filter_by(state="running").count()
            if running >= max_concurrent:
                db.session.rollback()
                return None
        res = db.session.execute(text(
            "UPDATE forensic_jobs SET state='running', worker_token=:tok, attempts=attempts+1, "
            "claimed_at=:ts, started_at=:ts WHERE job_id=:id AND state='queued' "
            "AND worker_token IS NULL"), {"tok": worker_token, "ts": _iso(), "id": job_id})
        if res.rowcount != 1:
            db.session.rollback()
            return None
        db.session.commit()
        return self.get(job_id)

    def finalize_success(self, job_id, token, fields):
        db = self.db
        res = db.session.execute(text(
            "UPDATE forensic_jobs SET state='succeeded', finished_at=:fa, wall_ms=:wm, "
            "result_manifest=:rm, derived_evidence_ids=:de, error_code=NULL, error_detail=NULL "
            "WHERE job_id=:id AND state='running' AND worker_token=:tok"),
            {"fa": fields.get("finished_at"), "wm": fields.get("wall_ms"),
             "rm": fields.get("result_manifest"),
             "de": json.dumps(fields.get("derived_evidence_ids") or []),
             "id": job_id, "tok": token})
        if res.rowcount == 1:
            db.session.commit()      # commits the job AND the pending derived rows together
            return True
        db.session.rollback()        # canceled/lost: drop pending derived rows, commit nothing
        return False

    def fail(self, job_id, token, *, requeue, error_code, error_detail, wall_ms=None):
        db = self.db
        if requeue:
            sql = ("UPDATE forensic_jobs SET state='queued', worker_token=NULL, claimed_at=NULL, "
                   "started_at=NULL, attempts=GREATEST(0, attempts-1), error_code=:ec, "
                   "error_detail=:ed WHERE job_id=:id AND state='running' AND worker_token=:tok")
            params = {"ec": error_code, "ed": error_detail, "id": job_id, "tok": token}
        else:
            sql = ("UPDATE forensic_jobs SET state='failed', finished_at=:fa, wall_ms=:wm, "
                   "error_code=:ec, error_detail=:ed WHERE job_id=:id AND state='running' "
                   "AND worker_token=:tok")
            params = {"fa": _iso(), "wm": wall_ms, "ec": error_code, "ed": error_detail,
                      "id": job_id, "tok": token}
        res = db.session.execute(text(sql), params)
        db.session.commit()
        return res.rowcount == 1

    def cancel(self, job_id):
        db = self.db
        db.session.execute(text(
            "UPDATE forensic_jobs SET state='canceled', finished_at=:fa, worker_token=NULL "
            "WHERE job_id=:id AND state IN ('queued','running')"), {"fa": _iso(), "id": job_id})
        db.session.commit()
        return self.get(job_id)

    def update(self, job_id, **changes):
        row = self.M.query.filter_by(job_id=job_id).first()
        if not row:
            return None
        for k, v in changes.items():
            if k == "derived_evidence_ids":
                v = json.dumps(v)
            setattr(row, k, v)
        self.db.session.commit()
        return self.get(job_id)


# ============================== Evidence sink ===============================
class SqlEvidenceSink:
    def __init__(self, db, store, *, ea_model=None, ce_model=None, br_model=None):
        self.db = db
        self.store = store
        from models import EvidenceArtifact, CustodyEvent, BlobReference
        self.EA = ea_model or EvidenceArtifact
        self.CE = ce_model or CustodyEvent
        self.BR = br_model or BlobReference
        self._seq = {}
        self._head = {}

    def add_source(self, artifact):
        # the source is already persisted (by acquisition); nothing to insert. ensure a ref exists.
        self._ensure_ref(artifact)

    def get_source(self, evidence_id):
        r = self.EA.query.filter_by(evidence_id=evidence_id).first()
        if not r:
            return None
        return {"evidence_id": r.evidence_id, "evidence_type": r.evidence_type,
                "case_id": r.case_id, "candidate_id": r.candidate_id, "cohort": r.cohort,
                "pathway": r.pathway, "content_hash": r.content_hash,
                "validation_state": r.validation_state, "scan_state": r.scan_state,
                "object_key": r.object_key, "revoked": r.revoked,
                "retention_class": r.retention_class, "retention_until": r.retention_until}

    def _seed(self, evidence_id):
        if evidence_id in self._seq:
            return
        rows = self.CE.query.filter_by(evidence_id=evidence_id).order_by(self.CE.seq).all()
        self._seq[evidence_id] = len(rows)
        self._head[evidence_id] = rows[-1].record_hash if rows else None

    def record_custody(self, signed):
        rec = signed["record"]
        eid = rec["evidence_id"]
        self._seed(eid)
        seq = self._seq[eid]
        linked = ep.custody_event(rec["kind"], evidence_id=eid, actor=rec.get("actor"),
                                  candidate_id=rec.get("candidate_id"), cohort=rec.get("cohort"),
                                  pathway=rec.get("pathway"), detail=rec.get("detail"),
                                  parent_hash=self._head.get(eid), seq=seq)
        self.db.session.add(self.CE(**ep.custody_row(linked)))   # pending; committed at finalize
        self._head[eid] = linked["record"]["record_hash"]
        self._seq[eid] = seq + 1
        return linked

    def save_derived(self, artifact):
        a = artifact
        self.db.session.add(self.EA(
            evidence_id=a["evidence_id"], evidence_type=a["evidence_type"], case_id=a.get("case_id"),
            candidate_id=a.get("candidate_id"), cohort=a.get("cohort"), pathway=a.get("pathway"),
            content_hash=a["content_hash"], validation_state=a.get("validation_state", "unvalidated"),
            object_key=a.get("object_key"), storage_backend="filesystem",
            scan_state=a.get("scan_state", "unscanned"), transform=a.get("transform"),
            tool_version=a.get("tool_version"),
            derived_from=json.dumps(a.get("derived_from") or []), supersedes=a.get("supersedes"),
            blob_sha256=a.get("content_hash"),
            blob_media_type=(a.get("blob_ref") or {}).get("media_type"),
            blob_bytes=(a.get("blob_ref") or {}).get("bytes")))
        if a.get("object_key"):
            self.db.session.add(self.BR(object_key=a["object_key"], evidence_id=a["evidence_id"],
                                        candidate_id=a.get("candidate_id"), cohort=a.get("cohort"),
                                        pathway=a.get("pathway"), active=True))

    def chain(self, evidence_id):
        rows = self.CE.query.filter_by(evidence_id=evidence_id).order_by(self.CE.seq).all()
        return [ci.signed_from_row(r) for r in rows]

    def discard_pending(self, created, *, store=None):
        # the pending derived rows live in this uncommitted session: a rollback drops them all.
        self.db.session.rollback()
        self._seq.clear(); self._head.clear()
        st = store or self.store
        for key in created.get("object_keys") or []:
            try:
                st.delete(key, authorized_reason="canceled_job_result_discard")
            except Exception:
                pass

    def _ensure_ref(self, artifact):
        key = artifact.get("object_key")
        if not key:
            return
        exists = self.BR.query.filter_by(object_key=key, evidence_id=artifact["evidence_id"]).first()
        if exists:
            return
        self.db.session.add(self.BR(object_key=key, evidence_id=artifact["evidence_id"],
                                    candidate_id=artifact.get("candidate_id"),
                                    cohort=artifact.get("cohort"), pathway=artifact.get("pathway"),
                                    active=True))
        self.db.session.commit()


# ============================== Trusted fixture registry ====================
class SqlTrustedFixtureRegistry:
    """Durable, administrator-approved fixture registry (models.TrustedFixture)."""
    def __init__(self, db, model=None):
        self.db = db
        from models import TrustedFixture
        self.M = model or TrustedFixture

    def register(self, sha256, *, note, approver):
        if (approver or {}).get("role") != "admin":
            raise ev.ValidationError("NOT_ADMIN", "only an administrator may register a fixture")
        if not self.M.query.filter_by(sha256=sha256).first():
            self.db.session.add(self.M(sha256=sha256, note=note,
                                       approved_by=approver.get("id") or "admin"))
            self.db.session.commit()
        return sha256

    def is_trusted(self, sha256):
        return bool(sha256) and self.M.query.filter_by(sha256=sha256).first() is not None


# ============================== Blob lifecycle (DB) =========================
class SqlBlobLifecycle:
    """Transactionally-safe reference-counted lifecycle. Every mutation on a given object takes the
    same per-object advisory lock, so a physical delete can never race a concurrent reference
    creation or observe a stale snapshot."""
    def __init__(self, db, store, model=None):
        self.db = db
        self.store = store
        from models import BlobReference
        self.BR = model or BlobReference

    def add_reference(self, object_key, evidence_id, *, candidate_id=None, cohort=None, pathway=None):
        db = self.db
        _xact_lock_text(db, object_key)
        if not self.BR.query.filter_by(object_key=object_key, evidence_id=evidence_id).first():
            db.session.add(self.BR(object_key=object_key, evidence_id=evidence_id,
                                   candidate_id=candidate_id, cohort=cohort, pathway=pathway,
                                   active=True))
        db.session.commit()

    def place_hold(self, object_key, *, on=True, evidence_id=None):
        db = self.db
        _xact_lock_text(db, object_key)
        q = self.BR.query.filter_by(object_key=object_key)
        if evidence_id:
            q = q.filter_by(evidence_id=evidence_id)
        n = 0
        for r in q.all():
            r.hold = bool(on); n += 1
        db.session.commit()
        return n

    def revoke(self, object_key, *, evidence_id=None, candidate_id=None, cohort=None, reason):
        db = self.db
        _xact_lock_text(db, object_key)
        q = self.BR.query.filter_by(object_key=object_key, active=True)
        if evidence_id:
            q = q.filter_by(evidence_id=evidence_id)
        if candidate_id is not None:
            q = q.filter_by(candidate_id=candidate_id)
        if cohort is not None:
            q = q.filter_by(cohort=cohort)
        released = []
        for r in q.all():
            r.active = False; r.released_at = _iso(); r.release_reason = reason
            released.append(r.evidence_id)
        db.session.commit()
        return released

    def sweep_object(self, object_key, *, reason="retention_sweep"):
        """Under the per-object lock, physically delete the bytes iff no active reference and no
        hold remain. Used to reclaim an object whose references were all released separately."""
        db = self.db
        _xact_lock_text(db, object_key)
        active = self.BR.query.filter_by(object_key=object_key, active=True).count()
        held = self.BR.query.filter_by(object_key=object_key, hold=True).count()
        physical, storage_error = False, None
        if active == 0 and held == 0:
            try:
                self.store.delete(object_key, authorized_reason=reason)
                physical = True
            except Exception as e:  # noqa
                storage_error = f"{type(e).__name__}: {e}"
        db.session.commit()
        return {"physical": physical, "storage_error": storage_error,
                "preserved": not physical and (active or held)}

    def managed_delete(self, artifact, *, reason, now=None):
        db = self.db
        ok, why = ep.can_delete(artifact, reason=reason, now=now)
        if not ok:
            return {"ok": False, "physical": False, "reason": why}
        key = artifact["object_key"]
        _xact_lock_text(db, key)   # serialise all lifecycle ops on this object
        # release THIS reference
        r = self.BR.query.filter_by(object_key=key, evidence_id=artifact["evidence_id"],
                                    active=True).first()
        if r:
            r.active = False; r.released_at = _iso(); r.release_reason = reason
        db.session.flush()
        active = self.BR.query.filter_by(object_key=key, active=True).count()
        held = self.BR.query.filter_by(object_key=key, hold=True).count()
        physical, storage_error = False, None
        if active == 0 and held == 0:
            try:
                self.store.delete(key, authorized_reason=reason)
                physical = True
            except Exception as e:  # noqa
                storage_error = f"{type(e).__name__}: {e}"
        db.session.commit()   # releases the advisory lock
        return {"ok": True, "physical": physical, "storage_error": storage_error,
                "reason": ("physically_deleted" if physical
                           else "storage_delete_failed_orphan_pending_sweep" if storage_error
                           else "logically_released_object_preserved")}


def install_db_backends(db, store, coordinator_cls, *, max_concurrent=2, scratch_dir=None):
    """Convenience: build a JobCoordinator wired to the DB-backed job store + evidence sink, and
    install the DB-backed trusted-fixture registry as the active one."""
    from . import forensic_jobs as fj
    ev.set_fixture_registry(SqlTrustedFixtureRegistry(db))
    return fj.JobCoordinator(store, SqlJobStore(db), SqlEvidenceSink(db, store),
                             max_concurrent=max_concurrent, scratch_dir=scratch_dir)
