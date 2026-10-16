"""F4 - persistent, auditable bounded-forensic-processing job lifecycle.

A job runs exactly one authorized operation (siem/forensic_ops) over one preserved source
EvidenceArtifact, inside the OS-enforced sandbox (siem/forensic_sandbox), and persists its derived
evidence + a reproducible manifest + signed chain-of-custody. The lifecycle is explicit and
restart-recoverable, admin-controlled, and bounded - there is NO always-on worker and NO general
candidate execution. States: queued -> running -> (succeeded | failed | canceled | quarantined).

Guarantees implemented here:
  * authorization BEFORE a job is created (admin principal required);
  * bounded concurrency (a hard cap on simultaneously running jobs);
  * idempotent submit (same idempotency_key returns the existing job, never a duplicate);
  * atomic claim (a worker_token compare-and-set; two workers cannot both run one job);
  * retry limit + per-attempt accounting; wall-clock timeout (enforced by the sandbox);
  * cooperative cancellation;
  * restart recovery (a job left `running` by a crash is reclaimed by an admin-triggered sweep,
    not by an unrestricted daemon);
  * partial-output handling (already-persisted derived artifacts are real evidence and are kept and
    recorded; the temp source copy is always cleaned up);
  * safe handling of revoked/again-unauthorized source access (re-checked at run time).

The coordinator is storage-agnostic: it drives an injected JobStore and EvidenceSink. In-memory
implementations (for tests/demos) and the shape of the DB-backed implementations live here.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import secrets
import tempfile
import uuid

from . import evidence_persistence as ep
from . import evidence_validation as ev
from . import forensic_ops as fo
from . import blob_lifecycle as bl

JOB_CONTRACT_VERSION = 1
DEFAULT_MAX_CONCURRENT = 2


def _iso(ts=None):
    return (ts or _dt.datetime.now(_dt.timezone.utc)).isoformat()


def _now():
    return _dt.datetime.now(_dt.timezone.utc)


class JobError(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ========================= in-memory job store ==============================
class InMemoryJobStore:
    """Reference JobStore. The DB-backed store maps these operations to models.ForensicJob rows
    (a UNIQUE idempotency_key makes `create` idempotent; a conditional UPDATE on worker_token makes
    `claim` atomic; `list_running`/`list_stale` are indexed queries on `state`)."""

    def __init__(self):
        import threading
        self._by_id = {}
        self._by_idem = {}
        self._lock = threading.RLock()

    def create(self, job):
        with self._lock:
            idem = job.get("idempotency_key")
            if idem and idem in self._by_idem:
                return self._by_idem[idem], False
            self._by_id[job["job_id"]] = job
            if idem:
                self._by_idem[idem] = job
            return job, True

    def get(self, job_id):
        return self._by_id.get(job_id)

    def list_running(self):
        return [j for j in self._by_id.values() if j["state"] == "running"]

    def list_queued(self):
        return [j for j in self._by_id.values() if j["state"] == "queued"]

    def claim(self, job_id, worker_token, *, max_concurrent=None):
        with self._lock:
            j = self._by_id.get(job_id)
            if not j or j["state"] != "queued" or j.get("worker_token"):
                return None
            if max_concurrent is not None and \
               len([x for x in self._by_id.values() if x["state"] == "running"]) >= max_concurrent:
                return None  # cap reached: leave queued (atomic under the lock)
            j["worker_token"] = worker_token
            j["state"] = "running"
            j["attempts"] = j.get("attempts", 0) + 1
            j["claimed_at"] = _iso()
            j["started_at"] = _iso()
            return dict(j)

    def finalize_success(self, job_id, token, fields):
        """Atomic, token-checked transition running -> succeeded. Returns False if the job is no
        longer running under this token (e.g. it was canceled), so results are never committed."""
        with self._lock:
            j = self._by_id.get(job_id)
            if not j or j["state"] != "running" or j.get("worker_token") != token:
                return False
            j.update(fields)
            j["state"] = "succeeded"
            return True

    def fail(self, job_id, token, *, requeue, error_code, error_detail, wall_ms=None):
        with self._lock:
            j = self._by_id.get(job_id)
            if not j or j.get("worker_token") != token or j["state"] not in ("running",):
                return False  # do not override a concurrent cancel/terminal state
            if requeue:
                # requeue does NOT change attempts: the attempt already counted at claim stands, so
                # the configured max_attempts is a hard ceiling (no unlimited-retry loop).
                j.update(state="queued", worker_token=None, claimed_at=None, started_at=None,
                         error_code=error_code, error_detail=error_detail)
            else:
                j.update(state="failed", finished_at=_iso(), error_code=error_code,
                         error_detail=error_detail, wall_ms=wall_ms)
            return True

    def recover(self, job_id, token, *, requeue, error_code, error_detail):
        """Conditional stale recovery: only acts while the job is STILL running under the SAME
        worker token, so it never overwrites a job that completed, failed, was canceled, or was
        re-claimed by another worker in the meantime."""
        with self._lock:
            j = self._by_id.get(job_id)
            if not j or j["state"] != "running" or j.get("worker_token") != token:
                return False
            if requeue:
                j.update(state="queued", worker_token=None, claimed_at=None, started_at=None,
                         error_code=error_code, error_detail=error_detail)
            else:
                j.update(state="failed", worker_token=None, finished_at=_iso(),
                         error_code=error_code, error_detail=error_detail)
            return True

    def cancel(self, job_id):
        with self._lock:
            j = self._by_id.get(job_id)
            if not j or j["state"] in ("succeeded", "failed", "canceled", "quarantined"):
                return j
            j.update(state="canceled", finished_at=_iso(), worker_token=None)
            return j

    def update(self, job_id, **changes):
        with self._lock:
            j = self._by_id.get(job_id)
            if j:
                j.update(changes)
            return j

    def list_stale(self, older_than_iso):
        with self._lock:
            return [j for j in self._by_id.values()
                    if j["state"] == "running" and (j.get("claimed_at") or "") < older_than_iso]


# ========================= in-memory evidence sink ==========================
class InMemoryEvidenceSink:
    """Reference EvidenceSink. Holds the source artifacts, persisted derived artifacts, custody
    events (with per-evidence seq), and blob references. The DB-backed sink writes
    models.EvidenceArtifact / CustodyEvent / BlobReference rows inside the request transaction and
    uses evidence_persistence.custody_row / blob_lifecycle.ref_row_kwargs for the column mapping."""

    def __init__(self, store):
        self.store = store
        self.sources = {}            # evidence_id -> artifact dict
        self.artifacts = {}          # evidence_id -> artifact dict (derived)
        self.custody = []            # list of signed events (properly linked chains)
        self.refs = []               # blob references (blob_lifecycle dicts)
        self._seq = {}               # evidence_id -> next seq
        self._head = {}              # evidence_id -> head record_hash

    def add_source(self, artifact):
        self.sources[artifact["evidence_id"]] = artifact
        self._seq.setdefault(artifact["evidence_id"], 0)
        if artifact.get("object_key"):
            self._ensure_ref(artifact)

    def get_source(self, evidence_id):
        return self.sources.get(evidence_id)

    def lock_object(self, object_key):
        return None   # single-process in-memory store needs no cross-connection lock

    def abort(self):
        return None   # in-memory staging is immediate; discard_pending handles rollback

    def record_custody(self, signed):
        """Append an event to its evidence chain, RE-STAMPING its seq and parent_hash from the
        tracked head so the chain is always correctly linked and re-verifiable, regardless of how
        the producing call set them. Returns the stored (re-linked) signed event."""
        rec = signed["record"]
        eid = rec["evidence_id"]
        seq = self._seq.get(eid, 0)
        linked = ep.custody_event(rec["kind"], evidence_id=eid, actor=rec.get("actor"),
                                  candidate_id=rec.get("candidate_id"), cohort=rec.get("cohort"),
                                  pathway=rec.get("pathway"), detail=rec.get("detail"),
                                  parent_hash=self._head.get(eid), seq=seq)
        self.custody.append(linked)
        self._head[eid] = linked["record"]["record_hash"]
        self._seq[eid] = seq + 1
        return linked

    def save_derived(self, artifact):
        self.artifacts[artifact["evidence_id"]] = artifact
        self._ensure_ref(artifact)

    def chain(self, evidence_id):
        return [c for c in self.custody if c["record"]["evidence_id"] == evidence_id]

    def discard_pending(self, created, *, store=None):
        """Roll back derived outputs staged for a job that did not finalize (e.g. was canceled):
        drop the derived artifacts, their blob references and custody chains, trim the source
        chain back to its pre-job length, and delete the brand-new derived objects from the store.
        Nothing here touches the source object or any other artifact's bytes."""
        eids = set(created.get("evidence_ids") or [])
        self.custody = [c for c in self.custody if c["record"]["evidence_id"] not in eids]
        for eid in eids:
            self.artifacts.pop(eid, None)
            self._seq.pop(eid, None)
            self._head.pop(eid, None)
        self.refs = [r for r in self.refs if r["evidence_id"] not in eids]
        # trim the source chain back to its pre-job length and restore its head/seq
        seid = created.get("source_evidence_id")
        before = created.get("source_seq_before")
        if seid is not None and before is not None:
            kept = [c for c in self.custody if c["record"]["evidence_id"] != seid]
            src_events = [c for c in self.custody if c["record"]["evidence_id"] == seid][:before]
            self.custody = kept + src_events
            self._seq[seid] = before
            self._head[seid] = src_events[-1]["record"]["record_hash"] if src_events else None
        if store is not None:
            for key in created.get("object_keys") or []:
                # reference-safe: delete a newly-created object ONLY if no active reference remains
                # for it (another artifact that deduplicated onto the same bytes keeps it alive).
                if not [r for r in self.refs if r["object_key"] == key and r.get("active")]:
                    try:
                        store.delete(key, authorized_reason="canceled_job_result_discard")
                    except Exception:
                        pass

    def _ensure_ref(self, artifact):
        key = artifact.get("object_key")
        if not key:
            return
        if any(r["object_key"] == key and r["evidence_id"] == artifact["evidence_id"]
               for r in self.refs):
            return
        self.refs.append(bl.make_reference(key, artifact["evidence_id"],
                                           candidate_id=artifact.get("candidate_id"),
                                           cohort=artifact.get("cohort"),
                                           pathway=artifact.get("pathway")))


# ============================== coordinator =================================
class JobCoordinator:
    def __init__(self, store, jobstore, sink, *, processor=None, max_concurrent=DEFAULT_MAX_CONCURRENT,
                 scratch_dir=None):
        self.store = store
        self.jobs = jobstore
        self.sink = sink
        self.processor = processor or fo.ForensicProcessor()
        self.max_concurrent = max_concurrent
        self.scratch_dir = scratch_dir or tempfile.gettempdir()

    # ---- submit (authorize BEFORE create) ----
    def submit(self, *, operation, source_evidence_id, requester, params=None,
               idempotency_key=None, max_attempts=1):
        # NOTE: there is deliberately NO trusted_fixture parameter. Trust is derived server-side at
        # run time from the administrator-approved fixture registry (keyed by the server-computed
        # source hash). A caller cannot assert trust via a flag, job parameter, or metadata.
        if (requester or {}).get("role") != "admin":
            raise JobError("NOT_ADMIN", "forensic jobs are administrator-controlled")
        if operation not in fo.OPS:
            raise JobError("UNKNOWN_OPERATION", f"operation {operation!r} is not supported")
        src = self.sink.get_source(source_evidence_id)
        if src is None:
            raise JobError("SOURCE_NOT_FOUND", f"no source artifact {source_evidence_id!r}")
        job = {
            "job_id": "fj-" + uuid.uuid4().hex[:20], "operation": operation,
            "source_evidence_id": source_evidence_id, "case_id": src.get("case_id"),
            "candidate_id": src.get("candidate_id"), "cohort": src.get("cohort"),
            "pathway": src.get("pathway"), "params": params or {},
            "idempotency_key": idempotency_key, "state": "queued",
            "requested_by": requester.get("id") or requester.get("candidate_id") or "admin",
            "attempts": 0, "max_attempts": max_attempts, "worker_token": None,
            "claimed_at": None, "started_at": None, "finished_at": None, "wall_ms": None,
            "error_code": None, "error_detail": None, "result_manifest": None,
            "derived_evidence_ids": [], "created_at": _iso(),
        }
        job, created = self.jobs.create(job)
        return job

    # ---- run one job (atomic claim + execute) ----
    def run(self, job_id):
        token = secrets.token_hex(16)
        # the claim atomically enforces the concurrency cap: it returns None if the job is not
        # queued OR no slot is free, so compute is never over-committed (no post-claim re-queue race)
        job = self.jobs.claim(job_id, token, max_concurrent=self.max_concurrent)
        if job is None:
            existing = self.jobs.get(job_id)
            st = existing and existing.get("state")
            if st == "queued" and len(self.jobs.list_running()) >= self.max_concurrent:
                raise JobError("CONCURRENCY_LIMIT", "no free slot; job remains queued")
            raise JobError("NOT_CLAIMABLE", f"job {job_id} not queued/claimable (state={st})")
        start = _now()
        try:
            return self._execute(job, start)
        except JobError:
            raise
        except Exception as e:  # noqa
            # backstop: discard any uncommitted staged rows before recording the failure, so the
            # failure handler can never commit partial evidence.
            try:
                self.sink.abort()
            except Exception:
                pass
            self._fail(job, "RUN_ERROR", f"{type(e).__name__}: {e}", start)
            return self.jobs.get(job_id)

    def _execute(self, job, start):
        token = job.get("worker_token")
        src = self.sink.get_source(job["source_evidence_id"])
        # re-check authorization/availability AT RUN TIME (revocation/expiry since submit)
        if src.get("revoked") or src.get("validation_state") == "revoked":
            return self._fail(job, "SOURCE_REVOKED", "source evidence was revoked", start)
        op = fo.OPS[job["operation"]]
        media = op["category"] in ("audio", "video", "image")
        # trust is derived SERVER-SIDE from the approved registry; never from the job/params
        trusted = ev.is_trusted_fixture(src)
        if media:
            allowed, why = ev.can_enter_unsafe_workflow(src)
            if not allowed and not trusted:
                return self._fail(job, "UNSAFE_WORKFLOW_BLOCKED",
                                  f"source not eligible for media decoding: {why}", start)
        key = src.get("object_key")
        if not key or not self.store.exists(key):
            return self._fail(job, "SOURCE_MISSING", "source object is missing from the store", start)
        if not self.store.verify(key, src.get("content_hash")):
            return self._fail(job, "SOURCE_CORRUPT", "source bytes failed integrity re-check", start)
        data = self.store.get_bytes(key)
        fd, src_path = tempfile.mkstemp(prefix="fjsrc-", dir=self.scratch_dir)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.chmod(src_path, 0o400)
            result = self.processor.run(job["operation"], src_path, params=job["params"],
                                        trusted_fixture=trusted)
        finally:
            if os.path.exists(src_path):
                try:
                    os.remove(src_path)
                except OSError:
                    pass

        # SAFEGUARD B: a FAILED operation (ok=False) never becomes a successful job, even if it
        # produced partial `derived` output. We fail closed and do NOT persist the partial outputs
        # as evidence (preserving them would require an explicit, authorized, accurately-labeled
        # diagnostic path, which is not in scope here).
        if not result.ok:
            detail = {"errors": result.errors, "sandbox": result.sandbox,
                      "partial_outputs": len(result.derived),
                      "note": "operation failed; partial outputs were discarded, not persisted as evidence"}
            return self._fail(job, "OPERATION_FAILED", json.dumps(detail)[:4000], start,
                              retriable=True)

        # Persist derived outputs into the sink (pending, not yet durable for the SQL sink), then
        # COMMIT them only via a conditional finalize that still owns the job. SAFEGUARD A: if ANY
        # exception occurs while staging outputs (e.g. a DB error after the first artifact was
        # staged), roll back every pending row and ref-safe-clean any newly-created blob BEFORE
        # marking the job failed - the general failure handler must never commit partial evidence.
        src_seq_before = len(self.sink.chain(src["evidence_id"]))
        created = {"evidence_ids": [], "object_keys": [], "source_evidence_id": src["evidence_id"],
                   "source_seq_before": src_seq_before}
        try:
            self._persist_outputs(job, src, result, created)
            manifest = self._build_manifest(job, src, result, created["evidence_ids"], start)
            fields = {"finished_at": _iso(),
                      "wall_ms": int((_now() - start).total_seconds() * 1000),
                      "result_manifest": json.dumps(manifest),
                      "derived_evidence_ids": created["evidence_ids"],
                      "error_code": None, "error_detail": None}
            committed = self.jobs.finalize_success(job["job_id"], token, fields)
        except Exception as e:  # noqa
            self.sink.discard_pending(created, store=self.store)
            return self._fail(job, "PERSIST_FAILED", f"{type(e).__name__}: {e}", start,
                              retriable=False)
        if not committed:
            # cancellation (or lost ownership) won the race: roll back everything we staged
            self.sink.discard_pending(created, store=self.store)
            cur = self.jobs.get(job["job_id"])
            raise JobError("NOT_FINALIZED",
                           f"results discarded; job is {cur and cur.get('state')} (not succeeded)")
        return self.jobs.get(job["job_id"])

    def _persist_outputs(self, job, src, result, created):
        """Persist each derived output as a NEW evidence artifact (source never overwritten),
        sequence the child's first custody event, record a `derive` event on the SOURCE chain for
        lineage, and register a reference-counted blob reference. Appends ids/keys to `created` as it
        goes so a mid-way failure can be fully rolled back."""
        derived_ids, object_keys = created["evidence_ids"], created["object_keys"]
        for d in result.derived:
            # hold the per-object lock across the write AND the reference insert so a concurrent
            # delete/sweep cannot remove the bytes in between (the key is known from the hash).
            self.sink.lock_object("blob/" + d["sha256"])
            res = ep.persist_derived(self.store, src, d["bytes"],
                                     evidence_type="derived_artifact",
                                     transform=f"{job['operation']}:{d['kind']}",
                                     tool_version=result.tool or job["operation"],
                                     actor=f"forensic-job:{job['job_id']}", seq=0)
            art = res["artifact"]
            # track a NEWLY-created object for rollback BEFORE inserting its reference, so a failure
            # during save_derived/record_custody still cleans up the bytes we just wrote. A dedup hit
            # onto an already-stored object is never tracked (its bytes may belong to another tenant).
            if art.get("object_key") and res.get("put", {}).get("created"):
                object_keys.append(art["object_key"])
            self.sink.save_derived(art)
            self.sink.record_custody(res["custody"])         # child chain (sink stamps seq/parent)
            derived_ids.append(art["evidence_id"])
            self.sink.record_custody(ep.custody_event(
                "derive", evidence_id=src["evidence_id"], actor=f"forensic-job:{job['job_id']}",
                candidate_id=src.get("candidate_id"), cohort=src.get("cohort"),
                pathway=src.get("pathway"),
                detail={"produced": art["evidence_id"], "operation": job["operation"],
                        "derived_sha256": d["sha256"], "kind": d["kind"]}))
        if not result.derived:
            self.sink.record_custody(ep.custody_event(
                "verify", evidence_id=src["evidence_id"], actor=f"forensic-job:{job['job_id']}",
                candidate_id=src.get("candidate_id"), cohort=src.get("cohort"),
                pathway=src.get("pathway"),
                detail={"operation": job["operation"], "observed": True}))

    def _build_manifest(self, job, src, result, derived_ids, start):
        """The reproducible result manifest: everything an authorized verifier needs to repeat the
        operation and compare. Byte-for-byte reproducibility of derived media is NOT guaranteed
        (documented in limitations); the recorded hashes are observed-at-this-environment."""
        m = result.manifest()
        m.update({
            "job_contract_version": JOB_CONTRACT_VERSION,
            "job_id": job["job_id"], "operation": job["operation"],
            "source_evidence_id": src["evidence_id"], "source_sha256": src.get("content_hash"),
            "source_object_key": src.get("object_key"),
            "candidate_id": src.get("candidate_id"), "cohort": src.get("cohort"),
            "pathway": src.get("pathway"),
            "environment_version": fo.PROCESSOR_VERSION,
            "sandbox_runtime_version": result.sandbox.get("runtime_version"),
            "params": job["params"],
            "derived_evidence_ids": derived_ids,
            "derived_hashes": [{"name": d["name"], "sha256": d["sha256"], "bytes": len(d["bytes"]),
                                "kind": d["kind"]} for d in result.derived],
            "lineage": {"parent": src["evidence_id"], "children": derived_ids},
            "timestamps": {"started": _iso(start), "finished": _iso()},
            "resource_measurements": {"wall_ms_total": int((_now() - start).total_seconds() * 1000),
                                      "sandbox_wall_ms": result.sandbox.get("wall_ms"),
                                      "output_bytes": result.sandbox.get("out_bytes")},
            "reproducibility": {
                "repeatable": "an authorized verifier can retrieve source_object_key, re-run "
                              "operation with params under environment_version, and compare observations",
                "byte_for_byte_derived": False,
                "note": "derived media bytes depend on the codec/tool build and platform; compare "
                        "observed_facts and re-derive, do not assume identical derived sha256"},
            "custody_refs": {"source_chain": src["evidence_id"], "derived_chains": derived_ids},
        })
        return m

    # ---- failure / retry / cancel / recovery ----
    def _fail(self, job, code, detail, start, *, retriable=False):
        attempts = job.get("attempts", 1)
        can_retry = retriable and attempts < job.get("max_attempts", 1)
        # token-checked transition: never override a concurrent cancel of this job
        self.jobs.fail(job["job_id"], job.get("worker_token"),
                       requeue=can_retry, error_code=code, error_detail=detail,
                       wall_ms=int((_now() - start).total_seconds() * 1000))
        return self.jobs.get(job["job_id"])

    def cancel(self, job_id, *, requester):
        if (requester or {}).get("role") != "admin":
            raise JobError("NOT_ADMIN", "only an administrator may cancel a job")
        j = self.jobs.get(job_id)
        if not j:
            raise JobError("NOT_FOUND", job_id)
        # atomic transition: canceled only from a non-terminal state; a job that already
        # succeeded/failed is never reopened, and a canceled job can never become succeeded.
        self.jobs.cancel(job_id)
        return self.jobs.get(job_id)

    def recover_stale(self, *, timeout_seconds=300, now=None):
        """Restart recovery: a job left `running` past the timeout (e.g. a crash) is re-queued if
        attempts remain, else failed. Each transition is CONDITIONAL on the job still being running
        under the same worker token, so a job that completed, failed, was canceled, or was
        re-claimed between listing and recovery is never overwritten. Admin/sweep-triggered; there
        is no always-on reaper."""
        cutoff = _iso((now or _now()) - _dt.timedelta(seconds=timeout_seconds))
        recovered = []
        for j in self.jobs.list_stale(cutoff):
            requeue = j.get("attempts", 1) < j.get("max_attempts", 1)
            ok = self.jobs.recover(
                j["job_id"], j.get("worker_token"), requeue=requeue,
                error_code=("RECOVERED_STALE" if requeue else "STALE_TIMEOUT"),
                error_detail=("reclaimed after timeout; re-queued" if requeue
                              else "running past timeout with no attempts left"))
            if ok:
                recovered.append(j["job_id"])
        return recovered
