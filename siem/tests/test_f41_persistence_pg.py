"""F4.1 - real PostgreSQL transactional + concurrency tests for the forensic job lifecycle, the
reference-counted blob lifecycle, and cancellation/terminal-state integrity.

Gated on a PostgreSQL DATABASE_URL (SKIPs on SQLite). Uses independent threads, each with its own
app context and SQLAlchemy session (so real, separate connections), to exercise the advisory-lock
and conditional-UPDATE guarantees against a live database. Forensic correctness itself is covered by
the real-sandbox suite; here a deterministic FakeProcessor isolates the persistence behaviour.
"""
import hashlib
import io
import os
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECRET_KEY", "f41-pg")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pgtest  # noqa: E402

from siem import artifact_store as stmod          # noqa: E402
from siem import evidence_types as et             # noqa: E402
from siem import evidence_persistence as ep       # noqa: E402
from siem import evidence_validation as valn      # noqa: E402
from siem import forensic_ops as fo               # noqa: E402
from siem import forensic_jobs as fj              # noqa: E402
from siem import forensic_jobs_db as fjdb         # noqa: E402
from siem import custody_integrity as ci          # noqa: E402

ADMIN = {"role": "admin", "id": "admin-pg"}


def _pg_or_skip():
    if not _pgtest.resolve_test_url():
        pytest.skip("RANGER_TEST_DATABASE_URL not set; F4.1 real-DB tests skipped (fail-closed)")


class FakeProcessor:
    """Deterministic, sandbox-free processor. Optionally runs a hook BEFORE returning (used to
    inject a cancellation during processing), and can emit fixed bytes (to force a dedup hit)."""
    def __init__(self, n_derived=1, hook=None, fixed_bytes=None):
        self.n = n_derived
        self.hook = hook
        self.fixed_bytes = fixed_bytes

    def run(self, op_id, source_path, *, params=None, trusted_fixture=False):
        if self.hook:
            self.hook()
        r = fo.OpResult(op_id, fo.OPS[op_id]["category"])
        r.ok = True
        r.tool = "fake-processor/1"
        r.sandbox = {"runtime_version": "fake", "wall_ms": 1, "out_bytes": 0}
        r.observed_facts = {"fake": True}
        for i in range(self.n):
            b = self.fixed_bytes if self.fixed_bytes is not None else \
                b"\x89PNG\r\n\x1a\n" + bytes([i]) * 200 + os.urandom(16)
            r.derived.append({"name": f"f{i}.png", "bytes": b, "media_type": "image/png",
                              "kind": "frame", "sha256": hashlib.sha256(b).hexdigest()})
        return r


class FailingProcessor:
    """Always fails with a retriable operation error and no usable output."""
    def run(self, op_id, source_path, *, params=None, trusted_fixture=False):
        r = fo.OpResult(op_id, fo.OPS[op_id]["category"])
        r.ok = False
        r.tool = "failing-processor/1"
        r.sandbox = {"runtime_version": "fake", "wall_ms": 1, "out_bytes": 0}
        r.errors = [{"code": "FAKE_FAIL", "message": "deterministic failure"}]
        return r


def _app():
    import app as appmod
    application = appmod.create_app()
    return application


def _fresh_schema(application):
    from models import db, Candidate
    with application.app_context():
        db.create_all()
        from models import ensure_schema
        ensure_schema(db)
        # disposable database: no destructive cleanup of shared tables is needed
        # candidates satisfy the evidence_artifacts.candidate_id FK on PostgreSQL
        for cid, handle in ((1, "pg-c1"), (2, "pg-c2")):
            if not Candidate.query.get(cid):
                db.session.add(Candidate(id=cid, handle=handle, name=handle, email=f"{handle}@e",
                                         cohort="2026-A", github_id=f"{handle}-gid", status="active",
                                         current_board=2))
        db.session.commit()


def _acquire_source(application, store, raw, *, evidence_type=et.EV_MEDIA_IMAGE, cand=1,
                    cohort="2026-A", pathway="parallax", trust=True):
    from models import db, EvidenceArtifact, CustodyEvent
    with application.app_context():
        acq = ep.acquire(store, io.BytesIO(raw), evidence_type=evidence_type, case_id=None,
                         candidate_id=cand, cohort=cohort, pathway=pathway,
                         source_identity="pg-f41", retention_class="default")
        a = acq["artifact"]
        db.session.add(EvidenceArtifact(
            evidence_id=a["evidence_id"], evidence_type=a["evidence_type"], case_id=None,
            candidate_id=cand, cohort=cohort, pathway=pathway, content_hash=a["content_hash"],
            validation_state=a["validation_state"], object_key=a["object_key"],
            storage_backend="filesystem", scan_state=a["scan_state"], retention_class="default",
            blob_sha256=a["content_hash"], blob_media_type=a["blob_ref"]["media_type"],
            blob_bytes=a["blob_ref"]["bytes"]))
        # sequence the acquire event at seq=0 so the source chain is well-ordered from the start
        cev0 = ep.custody_event("acquire", evidence_id=a["evidence_id"], actor="ranger-server",
                                candidate_id=cand, cohort=cohort, pathway=pathway,
                                detail={"acquired": True}, seq=0)
        db.session.add(CustodyEvent(**ep.custody_row(cev0)))
        db.session.commit()
        if trust:
            fjdb.SqlTrustedFixtureRegistry(db).register(a["content_hash"], note="pg fixture",
                                                        approver=ADMIN)
        return a["evidence_id"], a["content_hash"]


def _run_f41():
    application = _app()
    _fresh_schema(application)
    from models import db, ForensicJob, EvidenceArtifact, BlobReference
    store = stmod.FilesystemArtifactStore(tempfile.mkdtemp(prefix="f41pg-"))
    scratch = tempfile.mkdtemp(prefix="f41scratch-")
    P = {"pass": 0, "fail": 0}

    def check(name, ok):
        print(("PASS " if ok else "FAIL ") + name); P["pass" if ok else "fail"] += 1

    # --- 1. idempotent create under concurrency -----------------------------
    src_eid, _ = _acquire_source(application, store, b"\x89PNG\r\n\x1a\n" + b"src" * 400)
    results = {}

    def creator(i):
        with application.app_context():
            js = fjdb.SqlJobStore(db)
            job = {"job_id": f"fj-idem-{i}", "operation": "image.inspect",
                   "source_evidence_id": src_eid, "params": {}, "idempotency_key": "IDEM-1",
                   "requested_by": "admin", "max_attempts": 1}
            row, created = js.create(job)
            results[i] = (row["job_id"], created)
            db.session.remove()

    threads = [threading.Thread(target=creator, args=(i,)) for i in range(6)]
    [t.start() for t in threads]; [t.join() for t in threads]
    with application.app_context():
        n = ForensicJob.query.filter_by(idempotency_key="IDEM-1").count()
    created_count = sum(1 for _, c in results.values() if c)
    job_ids = {jid for jid, _ in results.values()}
    check("1: idempotent create under 6 concurrent threads yields exactly one row",
          n == 1 and created_count == 1 and len(job_ids) == 1)

    # --- 2. atomic claim: one queued job, many claimers, one winner ---------
    with application.app_context():
        js = fjdb.SqlJobStore(db)
        js.create({"job_id": "fj-claim", "operation": "image.inspect",
                         "source_evidence_id": src_eid, "params": {}, "idempotency_key": None,
                         "requested_by": "admin", "max_attempts": 1})[0]
    wins = []

    def claimer(i):
        with application.app_context():
            js = fjdb.SqlJobStore(db)
            got = js.claim("fj-claim", f"tok-{i}")
            if got:
                wins.append(f"tok-{i}")
            db.session.remove()

    threads = [threading.Thread(target=claimer, args=(i,)) for i in range(8)]
    [t.start() for t in threads]; [t.join() for t in threads]
    check("2: exactly one of 8 concurrent claimers wins the job", len(wins) == 1)

    # --- 3. concurrency cap enforced atomically -----------------------------
    with application.app_context():
        js = fjdb.SqlJobStore(db)
        for k in range(3):
            js.create({"job_id": f"fj-cap-{k}", "operation": "image.inspect",
                       "source_evidence_id": src_eid, "params": {}, "idempotency_key": None,
                       "requested_by": "admin", "max_attempts": 1})
    claimed = []

    def cap_claim(k):
        with application.app_context():
            js = fjdb.SqlJobStore(db)
            got = js.claim(f"fj-cap-{k}", f"captok-{k}", max_concurrent=2)
            if got:
                claimed.append(k)
            db.session.remove()

    threads = [threading.Thread(target=cap_claim, args=(k,)) for k in range(3)]
    [t.start() for t in threads]; [t.join() for t in threads]
    check("3: concurrency cap of 2 admits at most 2 running jobs", len(claimed) <= 2)
    with application.app_context():
        running = ForensicJob.query.filter_by(state="running").count()
    check("3: DB confirms running count never exceeds the cap", running <= 2)

    # --- 4. durable success + restart visibility ----------------------------
    with application.app_context():
        coord = fj.JobCoordinator(store, fjdb.SqlJobStore(db), fjdb.SqlEvidenceSink(db, store),
                                  processor=FakeProcessor(n_derived=2), max_concurrent=4,
                                  scratch_dir=scratch)
        valn.set_fixture_registry(fjdb.SqlTrustedFixtureRegistry(db))
        j = coord.submit(operation="image.inspect", source_evidence_id=src_eid, requester=ADMIN)
        done = coord.run(j["job_id"])
    with application.app_context():   # a FRESH store instance == a restarted process
        js2 = fjdb.SqlJobStore(db)
        reread = js2.get(j["job_id"])
        n_derived = EvidenceArtifact.query.filter_by(evidence_type="derived_artifact").count()
    check("4: job is durably succeeded and visible after a simulated restart",
          done["state"] == "succeeded" and reread["state"] == "succeeded"
          and reread["result_manifest"] and n_derived == 2)

    # --- 5. restart recovery of a stale running job -------------------------
    with application.app_context():
        js = fjdb.SqlJobStore(db)
        js.create({"job_id": "fj-stale", "operation": "image.inspect",
                   "source_evidence_id": src_eid, "params": {}, "idempotency_key": None,
                   "requested_by": "admin", "max_attempts": 1})
        js.claim("fj-stale", "stok")
        db.session.execute(db.text("UPDATE forensic_jobs SET claimed_at=:c WHERE job_id='fj-stale'"),
                           {"c": "2000-01-01T00:00:00+00:00"}); db.session.commit()
        coord = fj.JobCoordinator(store, fjdb.SqlJobStore(db), fjdb.SqlEvidenceSink(db, store),
                                  scratch_dir=scratch)
        rec = coord.recover_stale(timeout_seconds=300)
        after = fjdb.SqlJobStore(db).get("fj-stale")
    check("5: a stale running job is reclaimed across restart (re-queued or failed)",
          "fj-stale" in rec and after["state"] in ("queued", "failed"))

    # --- 6. cancellation during processing never commits a result ----------
    # The job runs in its own thread/connection; a real concurrent cancel arrives from the main
    # thread WHILE the processor is mid-flight (sequenced by events), then the job tries to finalize.
    src2, _ = _acquire_source(application, store, b"\x89PNG\r\n\x1a\n" + b"cancel" * 400, cand=2)
    started = threading.Event()
    may_finish = threading.Event()
    outcome = {}

    def blocking_hook():
        started.set()
        may_finish.wait(timeout=10)   # hold inside processing until the cancel has committed

    with application.app_context():
        jc = fj.JobCoordinator(store, fjdb.SqlJobStore(db), fjdb.SqlEvidenceSink(db, store),
                               scratch_dir=scratch).submit(
            operation="image.inspect", source_evidence_id=src2, requester=ADMIN)
        jcid = jc["job_id"]
        derived_before = EvidenceArtifact.query.filter_by(evidence_type="derived_artifact").count()

    def run_job():
        with application.app_context():
            valn.set_fixture_registry(fjdb.SqlTrustedFixtureRegistry(db))
            coord = fj.JobCoordinator(store, fjdb.SqlJobStore(db), fjdb.SqlEvidenceSink(db, store),
                                      processor=FakeProcessor(n_derived=2, hook=blocking_hook),
                                      max_concurrent=50, scratch_dir=scratch)
            try:
                coord.run(jcid)
                outcome["raised"] = None
            except fj.JobError as e:
                outcome["raised"] = e.code
            finally:
                db.session.remove()

    jt = threading.Thread(target=run_job); jt.start()
    started.wait(timeout=10)                     # processing has begun
    with application.app_context():              # concurrent cancel on the main connection
        fjdb.SqlJobStore(db).cancel(jcid)
        db.session.remove()
    may_finish.set()                             # let the job attempt to finalize
    jt.join(timeout=15)
    with application.app_context():
        final = fjdb.SqlJobStore(db).get(jcid)
        derived_after = EvidenceArtifact.query.filter_by(evidence_type="derived_artifact").count()
    check("6: a job canceled mid-processing ends canceled, never succeeded",
          final["state"] == "canceled" and outcome.get("raised") == "NOT_FINALIZED")
    check("6: no derived evidence from the canceled job is committed",
          derived_after == derived_before)

    # --- 7. blob lifecycle is transactionally safe under concurrency -------
    shared = b"\x89PNG\r\n\x1a\n" + b"blob" * 500
    with application.app_context():
        put = store.put_stream(io.BytesIO(shared), allowed_media_types={"image/png"})
        key = put.key
        life = fjdb.SqlBlobLifecycle(db, store)
        # two tenants reference the same object; a hold sits on one
        life.add_reference(key, "ev-b1", candidate_id=1, cohort="A")
        life.add_reference(key, "ev-b2", candidate_id=2, cohort="B")

    errors = []

    def worker(fnname, *args, **kw):
        def go():
            with application.app_context():
                try:
                    getattr(fjdb.SqlBlobLifecycle(db, store), fnname)(*args, **kw)
                except Exception as e:  # noqa
                    errors.append(f"{fnname}: {e}")
                finally:
                    db.session.remove()
        return go

    # concurrently: create a 3rd reference, place a hold, and attempt a delete of ev-b1
    art_b1 = {"evidence_id": "ev-b1", "object_key": key, "candidate_id": 1, "cohort": "A",
              "pathway": "parallax", "retention_class": "default"}
    ts = [threading.Thread(target=worker("add_reference", key, "ev-b3", candidate_id=3, cohort="C")),
          threading.Thread(target=worker("place_hold", key, on=True, evidence_id="ev-b2")),
          threading.Thread(target=worker("managed_delete", art_b1, reason="withdrew"))]
    [t.start() for t in ts]; [t.join() for t in ts]
    with application.app_context():
        still = store.exists(key)
        active = BlobReference.query.filter_by(object_key=key, active=True).count()
    check("7: shared object is never physically deleted while other refs/holds exist",
          still and active >= 1 and not errors)

    # now release every reference + hold, then a retention sweep reclaims the orphaned object
    with application.app_context():
        life = fjdb.SqlBlobLifecycle(db, store)
        life.place_hold(key, on=False)
        for eid in ("ev-b1", "ev-b2", "ev-b3"):
            life.revoke(key, evidence_id=eid, reason="cleanup")
        swept = life.sweep_object(key, reason="final")
        final_active = BlobReference.query.filter_by(object_key=key, active=True).count()
        exists_after = store.exists(key)
    check("7: once no active reference or hold remains, a sweep physically deletes the object",
          final_active == 0 and swept["physical"] and not exists_after)

    # --- 8. canceled job must NOT delete a deduplicated, actively-referenced blob -------------
    from models import CustodyEvent  # noqa
    shared_bytes = b"\x89PNG\r\n\x1a\n" + b"DEDUP" * 300
    with application.app_context():
        put = store.put_stream(io.BytesIO(shared_bytes), allowed_media_types={"image/png"})
        dkey = put.key
        # a committed, actively-referenced artifact already owns these exact bytes
        db.session.add(EvidenceArtifact(evidence_id="ev-existing", evidence_type="derived_artifact",
                       candidate_id=1, cohort="2026-A", pathway="parallax",
                       content_hash=put.sha256, validation_state="validated", object_key=dkey,
                       storage_backend="filesystem", scan_state="clean", retention_class="default",
                       blob_sha256=put.sha256, blob_media_type="image/png", blob_bytes=put.size))
        db.session.add(BlobReference(object_key=dkey, evidence_id="ev-existing", candidate_id=1,
                                     cohort="2026-A", pathway="parallax", active=True))
        db.session.commit()
        src8, _ = _acquire_source(application, store, b"\x89PNG\r\n\x1a\n" + b"src8" * 300, cand=1)
    started8 = threading.Event(); may8 = threading.Event(); out8 = {}

    def run_job8():
        with application.app_context():
            valn.set_fixture_registry(fjdb.SqlTrustedFixtureRegistry(db))
            coord = fj.JobCoordinator(store, fjdb.SqlJobStore(db), fjdb.SqlEvidenceSink(db, store),
                                      processor=FakeProcessor(n_derived=1, fixed_bytes=shared_bytes,
                                                              hook=lambda: (started8.set(),
                                                                            may8.wait(10))),
                                      max_concurrent=50, scratch_dir=scratch)
            try:
                coord.run(JOB8[0])
            except fj.JobError as e:
                out8["raised"] = e.code
            finally:
                db.session.remove()

    with application.app_context():
        JOB8[0] = fj.JobCoordinator(store, fjdb.SqlJobStore(db),
                                    fjdb.SqlEvidenceSink(db, store), scratch_dir=scratch).submit(
            operation="image.inspect", source_evidence_id=src8, requester=ADMIN)["job_id"]
    t8 = threading.Thread(target=run_job8); t8.start()
    started8.wait(10)
    with application.app_context():
        fjdb.SqlJobStore(db).cancel(JOB8[0]); db.session.remove()
    may8.set(); t8.join(15)
    with application.app_context():
        exists8 = store.exists(dkey)
        existing_ref = BlobReference.query.filter_by(object_key=dkey, evidence_id="ev-existing",
                                                     active=True).count()
    check("8: canceling a job whose derived bytes dedup onto an existing blob preserves that blob",
          exists8 and existing_ref == 1 and out8.get("raised") == "NOT_FINALIZED")

    # --- 9a. reference creation racing managed_delete never strands an active ref -------------
    k9 = None
    with application.app_context():
        p9 = store.put_stream(io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"race9" * 300),
                              allowed_media_types={"image/png"})
        k9 = p9.key
        fjdb.SqlBlobLifecycle(db, store).add_reference(k9, "ev-r1", candidate_id=1, cohort="A")

    def adder():
        with application.app_context():
            try:
                # realistic protected path: hold the per-object lock across (re)write + ref insert,
                # exactly as the job flow does via sink.lock_object before persist_derived.
                fjdb._xact_lock_text(db, k9)
                store.put_stream(io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"race9" * 300),
                                 allowed_media_types={"image/png"})
                fjdb.SqlBlobLifecycle(db, store).add_reference(k9, "ev-r2", candidate_id=2,
                                                               cohort="B")
            finally:
                db.session.remove()

    def deleter():
        with application.app_context():
            try:
                fjdb.SqlBlobLifecycle(db, store).managed_delete(
                    {"evidence_id": "ev-r1", "object_key": k9, "retention_class": "default"},
                    reason="race")
            finally:
                db.session.remove()

    ts = [threading.Thread(target=adder), threading.Thread(target=deleter)]
    [t.start() for t in ts]; [t.join() for t in ts]
    with application.app_context():
        active9 = BlobReference.query.filter_by(object_key=k9, active=True).count()
        exists9 = store.exists(k9)
    check("9a: ref-create vs delete never leaves an active reference pointing at missing bytes",
          not (active9 > 0 and not exists9))

    # --- 9b. concurrent custody appends on one source never duplicate a sequence --------------
    src9, _ = _acquire_source(application, store, b"\x89PNG\r\n\x1a\n" + b"src9" * 300, cand=2)
    cust_errors = []

    def appender(tag):
        with application.app_context():
            try:
                sink = fjdb.SqlEvidenceSink(db, store)
                ev = ep.custody_event("access", evidence_id=src9, actor=f"job-{tag}",
                                      detail={"tag": tag})
                sink.record_custody(ev)
                db.session.commit()
            except Exception as e:  # noqa
                cust_errors.append(str(e)[:80]); db.session.rollback()
            finally:
                db.session.remove()

    ts = [threading.Thread(target=appender, args=(i,)) for i in range(4)]
    [t.start() for t in ts]; [t.join() for t in ts]
    with application.app_context():
        rows = CustodyEvent.query.filter_by(evidence_id=src9).order_by(CustodyEvent.seq).all()
        seqs = [r.seq for r in rows]
        chain_ok = ci.verify_rows(rows)["ok"]
    check("9b: concurrent custody appends produce distinct seqs and a valid chain",
          len(seqs) == len(set(seqs)) and chain_ok and not cust_errors)

    # --- 10a. bounded retries: max_attempts is a hard ceiling --------------------------------
    src10, _ = _acquire_source(application, store, b"\x89PNG\r\n\x1a\n" + b"src10" * 300, cand=1)
    with application.app_context():
        valn.set_fixture_registry(fjdb.SqlTrustedFixtureRegistry(db))
        coord = fj.JobCoordinator(store, fjdb.SqlJobStore(db), fjdb.SqlEvidenceSink(db, store),
                                  processor=FailingProcessor(), max_concurrent=50, scratch_dir=scratch)
        j10 = coord.submit(operation="image.inspect", source_evidence_id=src10, requester=ADMIN,
                           max_attempts=2)
        coord.run(j10["job_id"])                 # attempt 1 -> requeued
        mid = fjdb.SqlJobStore(db).get(j10["job_id"])
        coord.run(j10["job_id"])                 # attempt 2 -> failed (ceiling)
        after = fjdb.SqlJobStore(db).get(j10["job_id"])
        third = None
        try:
            coord.run(j10["job_id"])             # no more attempts: not claimable
        except fj.JobError as e:
            third = e.code
    check("10a: a retriable job stops at max_attempts (no unlimited retry)",
          mid["state"] == "queued" and after["state"] == "failed" and after["attempts"] == 2
          and third == "NOT_CLAIMABLE")

    # --- 10b. recovery never overwrites a completed/canceled job -----------------------------
    with application.app_context():
        js = fjdb.SqlJobStore(db)
        js.create({"job_id": "fj-rec-done", "operation": "image.inspect",
                   "source_evidence_id": src10, "params": {}, "idempotency_key": None,
                   "requested_by": "admin", "max_attempts": 1})
        js.claim("fj-rec-done", "rtok")
        js.finalize_success("fj-rec-done", "rtok", {"finished_at": _now_iso(), "wall_ms": 1,
                            "result_manifest": "{}", "derived_evidence_ids": []})
        rec_done = js.recover("fj-rec-done", "rtok", requeue=True, error_code="X", error_detail="y")
        done_state = js.get("fj-rec-done")["state"]

        js.create({"job_id": "fj-rec-cancel", "operation": "image.inspect",
                   "source_evidence_id": src10, "params": {}, "idempotency_key": None,
                   "requested_by": "admin", "max_attempts": 1})
        js.claim("fj-rec-cancel", "ctok")
        js.cancel("fj-rec-cancel")
        rec_cancel = js.recover("fj-rec-cancel", "ctok", requeue=True, error_code="X",
                                error_detail="y")
        cancel_state = js.get("fj-rec-cancel")["state"]
    check("10b: stale recovery never overwrites a succeeded or canceled job",
          rec_done is False and done_state == "succeeded"
          and rec_cancel is False and cancel_state == "canceled")

    # --- 11. SAFEGUARD A: a persistence failure commits no partial evidence -------------------
    src11, _ = _acquire_source(application, store, b"\x89PNG\r\n\x1a\n" + b"src11" * 300, cand=1)

    class FailingSink(fjdb.SqlEvidenceSink):
        def __init__(self, *a, **k):
            super().__init__(*a, **k); self._n = 0

        def save_derived(self, artifact):
            self._n += 1
            if self._n >= 2:   # fail AFTER the first derived artifact has been staged
                raise RuntimeError("injected PostgreSQL failure during persistence")
            return super().save_derived(artifact)

    with application.app_context():
        valn.set_fixture_registry(fjdb.SqlTrustedFixtureRegistry(db))
        before_derived = EvidenceArtifact.query.filter_by(evidence_type="derived_artifact").count()
        before_src_chain = CustodyEvent.query.filter_by(evidence_id=src11).count()
        coord = fj.JobCoordinator(store, fjdb.SqlJobStore(db), FailingSink(db, store),
                                  processor=FakeProcessor(n_derived=3), max_concurrent=50,
                                  scratch_dir=scratch)
        j11 = coord.submit(operation="image.inspect", source_evidence_id=src11, requester=ADMIN)
        coord.run(j11["job_id"])
        j11f = fjdb.SqlJobStore(db).get(j11["job_id"])
        after_derived = EvidenceArtifact.query.filter_by(evidence_type="derived_artifact").count()
        after_src_chain = CustodyEvent.query.filter_by(evidence_id=src11).count()
        src_blob_ok = store.exists(EvidenceArtifact.query.filter_by(
            evidence_id=src11).first().object_key)
    check("11: a persistence failure marks the job failed (no false success)",
          j11f["state"] == "failed" and j11f["error_code"] == "PERSIST_FAILED")
    check("11: no partial derived evidence rows are committed",
          after_derived == before_derived)
    check("11: the source chain and source blob are untouched by the failed job",
          after_src_chain == before_src_chain and src_blob_ok)

    # --- 12. SAFEGUARD B: a failed op with partial outputs never succeeds ---------------------
    src12, _ = _acquire_source(application, store, b"\x89PNG\r\n\x1a\n" + b"src12" * 300, cand=2)
    with application.app_context():
        valn.set_fixture_registry(fjdb.SqlTrustedFixtureRegistry(db))
        before_d12 = EvidenceArtifact.query.filter_by(evidence_type="derived_artifact").count()
        coord = fj.JobCoordinator(store, fjdb.SqlJobStore(db), fjdb.SqlEvidenceSink(db, store),
                                  processor=PartialFailProcessor(), max_concurrent=50,
                                  scratch_dir=scratch)
        j12 = coord.submit(operation="image.inspect", source_evidence_id=src12, requester=ADMIN,
                           max_attempts=1)
        coord.run(j12["job_id"])
        j12f = fjdb.SqlJobStore(db).get(j12["job_id"])
        after_d12 = EvidenceArtifact.query.filter_by(evidence_type="derived_artifact").count()
        manifest_none = j12f["result_manifest"] in (None, "", "null")
    check("12: a failed op (ok=False) with partial outputs does NOT become succeeded",
          j12f["state"] == "failed" and j12f["error_code"] == "OPERATION_FAILED")
    check("12: the partial outputs of a failed op are not persisted as evidence",
          after_d12 == before_d12 and manifest_none)

    print("\n%d passed, %d failed" % (P["pass"], P["fail"]))
    assert P["fail"] == 0


class PartialFailProcessor:
    """Returns ok=False but WITH a partial derived output (the exact 1B failure mode)."""
    def run(self, op_id, source_path, *, params=None, trusted_fixture=False):
        r = fo.OpResult(op_id, fo.OPS[op_id]["category"])
        r.ok = False
        r.tool = "partial-fail/1"
        r.sandbox = {"runtime_version": "fake", "wall_ms": 1, "out_bytes": 0}
        r.errors = [{"code": "DECODE_ABORTED", "message": "failed after partial output"}]
        b = b"\x89PNG\r\n\x1a\n" + b"PARTIAL" * 100
        r.derived.append({"name": "partial.png", "bytes": b, "media_type": "image/png",
                          "kind": "frame", "sha256": hashlib.sha256(b).hexdigest()})
        return r


JOB8 = [None]


def _now_iso():
    import datetime as _d
    return _d.datetime.now(_d.timezone.utc).isoformat()


CANCEL_JOB_ID = [None]


def test_f41_persistence_pg():
    _pg_or_skip()
    with _pgtest.isolated_pg_database():
        _run_f41()


def test_f41_pg_isolation_guard():
    # these are pure-logic demonstrations (no DB needed) that the test-environment authorization
    # boundary refuses unsafe targets before any destructive act.
    assert _pgtest.assert_production_like_rejected()
    assert _pgtest.assert_remote_server_rejected()
    assert _pgtest.assert_missing_authorization_fails_closed()


if __name__ == "__main__":
    os.environ.setdefault("RANGER_TEST_DATABASE_URL",
                          "postgresql+psycopg2://postgres@127.0.0.1:5432/ranger_test_sentinel")
    os.environ.setdefault("RANGER_TEST_ALLOW_DB_MUTATION", "1")
    _pgtest.provision_sentinel()
    test_f41_persistence_pg()
