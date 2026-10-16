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
        self._by_id = {}
        self._by_idem = {}

    def create(self, job):
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

    def claim(self, job_id, worker_token):
        j = self._by_id.get(job_id)
        if not j or j["state"] != "queued" or j.get("worker_token"):
            return None
        j["worker_token"] = worker_token
        j["state"] = "running"
        j["attempts"] = j.get("attempts", 0) + 1
        j["claimed_at"] = _iso()
        j["started_at"] = _iso()
        return j

    def update(self, job_id, **changes):
        j = self._by_id.get(job_id)
        if j:
            j.update(changes)
        return j

    def list_stale(self, older_than_iso):
        out = []
        for j in self._by_id.values():
            if j["state"] == "running" and (j.get("claimed_at") or "") < older_than_iso:
                out.append(j)
        return out


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
               idempotency_key=None, max_attempts=1, trusted_fixture=False):
        if (requester or {}).get("role") != "admin":
            raise JobError("NOT_ADMIN", "forensic jobs are administrator-controlled")
        if operation not in fo.OPS:
            raise JobError("UNKNOWN_OPERATION", f"operation {operation!r} is not supported")
        src = self.sink.get_source(source_evidence_id)
        if src is None:
            raise JobError("SOURCE_NOT_FOUND", f"no source artifact {source_evidence_id!r}")
        # bounded concurrency counts running jobs (DB store counts reserved+running the same way)
        if len(self.jobs.list_running()) >= self.max_concurrent:
            # still create the job queued; it will run when a slot frees (never over-commit compute)
            state = "queued"
        else:
            state = "queued"
        job = {
            "job_id": "fj-" + uuid.uuid4().hex[:20], "operation": operation,
            "source_evidence_id": source_evidence_id, "case_id": src.get("case_id"),
            "candidate_id": src.get("candidate_id"), "cohort": src.get("cohort"),
            "pathway": src.get("pathway"), "params": params or {},
            "idempotency_key": idempotency_key, "state": state,
            "requested_by": requester.get("id") or requester.get("candidate_id") or "admin",
            "attempts": 0, "max_attempts": max_attempts, "worker_token": None,
            "claimed_at": None, "started_at": None, "finished_at": None, "wall_ms": None,
            "error_code": None, "error_detail": None, "result_manifest": None,
            "derived_evidence_ids": [], "trusted_fixture": bool(trusted_fixture),
            "created_at": _iso(),
        }
        job, created = self.jobs.create(job)
        return job

    # ---- run one job (atomic claim + execute) ----
    def run(self, job_id):
        token = secrets.token_hex(16)
        job = self.jobs.claim(job_id, token)
        if job is None:
            existing = self.jobs.get(job_id)
            raise JobError("NOT_CLAIMABLE",
                           f"job {job_id} not queued/claimable (state={existing and existing['state']})")
        if len(self.jobs.list_running()) > self.max_concurrent:
            # lost a concurrency race: release back to queued
            self.jobs.update(job_id, state="queued", worker_token=None, claimed_at=None,
                             started_at=None, attempts=job["attempts"] - 1)
            raise JobError("CONCURRENCY_LIMIT", "no free slot; re-queued")
        start = _now()
        src_path = None
        try:
            return self._execute(job, start)
        except JobError:
            raise
        except Exception as e:  # noqa
            self._fail(job, "RUN_ERROR", f"{type(e).__name__}: {e}", start)
            return self.jobs.get(job_id)
        finally:
            if src_path and os.path.exists(src_path):
                try:
                    os.remove(src_path)
                except OSError:
                    pass

    def _execute(self, job, start):
        src = self.sink.get_source(job["source_evidence_id"])
        # re-check authorization/availability AT RUN TIME (revocation/expiry since submit)
        if src.get("revoked") or src.get("validation_state") == "revoked":
            return self._fail(job, "SOURCE_REVOKED", "source evidence was revoked", start)
        op = fo.OPS[job["operation"]]
        media = op["category"] in ("audio", "video", "image")
        trusted = bool(job.get("trusted_fixture")) or ev.is_trusted_fixture(src)
        if media:
            allowed, why = ev.can_enter_unsafe_workflow(src)
            if not allowed and not trusted:
                return self._fail(job, "UNSAFE_WORKFLOW_BLOCKED",
                                  f"source not eligible for media decoding: {why}", start)
        # retrieve the preserved source bytes to a read-only temp copy for the sandbox
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

        if not result.ok and not result.derived:
            # operation failed with nothing usable -> job fails (retry if attempts remain)
            detail = {"errors": result.errors, "sandbox": result.sandbox}
            return self._fail(job, "OPERATION_FAILED", json.dumps(detail)[:4000], start,
                              retriable=True)

        derived_ids = self._persist_outputs(job, src, result)
        manifest = self._build_manifest(job, src, result, derived_ids, start)
        self.jobs.update(job["job_id"], state="succeeded", finished_at=_iso(),
                         wall_ms=int((_now() - start).total_seconds() * 1000),
                         result_manifest=json.dumps(manifest), derived_evidence_ids=derived_ids,
                         error_code=None, error_detail=None)
        return self.jobs.get(job["job_id"])

    def _persist_outputs(self, job, src, result):
        """Persist each derived output as a NEW evidence artifact (source never overwritten),
        sequence the child's first custody event, record a `derive` event on the SOURCE chain for
        lineage, and register a reference-counted blob reference. Returns derived evidence ids."""
        derived_ids = []
        for d in result.derived:
            res = ep.persist_derived(self.store, src, d["bytes"],
                                     evidence_type="derived_artifact",
                                     transform=f"{job['operation']}:{d['kind']}",
                                     tool_version=result.tool or job["operation"],
                                     actor=f"forensic-job:{job['job_id']}", seq=0)
            art = res["artifact"]
            self.sink.save_derived(art)
            self.sink.record_custody(res["custody"])         # child chain (sink stamps seq/parent)
            derived_ids.append(art["evidence_id"])
            # lineage event on the SOURCE chain (sink stamps seq + parent_hash)
            self.sink.record_custody(ep.custody_event(
                "derive", evidence_id=src["evidence_id"], actor=f"forensic-job:{job['job_id']}",
                candidate_id=src.get("candidate_id"), cohort=src.get("cohort"),
                pathway=src.get("pathway"),
                detail={"produced": art["evidence_id"], "operation": job["operation"],
                        "derived_sha256": d["sha256"], "kind": d["kind"]}))
        # an observation-only op (no derived bytes) still records a processing event on the source
        if not result.derived:
            self.sink.record_custody(ep.custody_event(
                "verify", evidence_id=src["evidence_id"], actor=f"forensic-job:{job['job_id']}",
                candidate_id=src.get("candidate_id"), cohort=src.get("cohort"),
                pathway=src.get("pathway"),
                detail={"operation": job["operation"], "observed": True}))
        return derived_ids

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
        self.jobs.update(job["job_id"],
                         state=("queued" if can_retry else "failed"),
                         worker_token=None if can_retry else job.get("worker_token"),
                         claimed_at=None if can_retry else job.get("claimed_at"),
                         finished_at=None if can_retry else _iso(),
                         wall_ms=int((_now() - start).total_seconds() * 1000),
                         error_code=code, error_detail=detail)
        return self.jobs.get(job["job_id"])

    def cancel(self, job_id, *, requester):
        if (requester or {}).get("role") != "admin":
            raise JobError("NOT_ADMIN", "only an administrator may cancel a job")
        j = self.jobs.get(job_id)
        if not j:
            raise JobError("NOT_FOUND", job_id)
        if j["state"] in ("succeeded", "failed", "canceled", "quarantined"):
            return j  # terminal; cancellation is a no-op
        self.jobs.update(job_id, state="canceled", finished_at=_iso(), worker_token=None)
        return self.jobs.get(job_id)

    def recover_stale(self, *, timeout_seconds=300, now=None):
        """Restart recovery: a job left `running` past the timeout (e.g. a crash) is re-queued if
        attempts remain, else failed. Admin/sweep-triggered; there is no always-on reaper."""
        cutoff = _iso((now or _now()) - _dt.timedelta(seconds=timeout_seconds))
        recovered = []
        for j in self.jobs.list_stale(cutoff):
            if j.get("attempts", 1) < j.get("max_attempts", 1):
                self.jobs.update(j["job_id"], state="queued", worker_token=None, claimed_at=None,
                                 started_at=None, error_code="RECOVERED_STALE",
                                 error_detail="reclaimed after timeout; re-queued")
            else:
                self.jobs.update(j["job_id"], state="failed", worker_token=None, finished_at=_iso(),
                                 error_code="STALE_TIMEOUT",
                                 error_detail="running past timeout with no attempts left")
            recovered.append(j["job_id"])
        return recovered
