# F4 — Bounded Forensic Processing (implementation, for review)

This milestone adds real, bounded forensic processing to the Ranger control plane. It processes
actual evidence inside an OS-enforced sandbox, produces defensible observations, preserves derived
artifacts with chain of custody, and lets an independent verifier reproduce the work. It is **not**
a deepfake detector or an "authenticity score": every result separates observed facts from
interpretation, and no tool output confers a qualification.

It builds strictly on the existing backend and does not fork the case/evidence/assessment model:
F1 (`7fb2f65`, pathway-aware assessment contracts), F2 (`54ba183`, typed evidence), F3 (`d1df8b1`,
secure persistence + custody). STRATA behaviour is untouched; PARALLAX qualification stays inactive.

## 1. Scope delivered

- Three F3 security corrections, each with regression tests (section 3).
- A versioned, provider-neutral `ForensicProcessor` with real operations across audio, video,
  image, digital-provenance and AI-agent-trace evidence (section 4).
- A real OS-enforced isolation sandbox for untrusted-media decoding, with empirical enforcement
  proof (section 5).
- A persistent, auditable, admin-controlled processing-job lifecycle with reproducible manifests,
  derived typed evidence, and signed custody (section 6).
- A full security/regression test suite and two end-to-end demos (section 7).

Out of scope by instruction and **not** done: Lab A/B, candidate workbench, STRATA scoring changes,
general candidate execution, always-on compute, production forensic deployment, F5, PARALLAX
activation, any paid infra/GPU/external media API. No production deploy was performed.

## 2. New / changed modules

| File | Purpose |
|---|---|
| `siem/forensic_sandbox.py` | Host-side driver for the namespace sandbox; tool allowlist; probe. |
| `siem/_sandbox_init.py` | In-namespace init (pid-1): builds the minimal read-only root, pivots, drops privileges, execs the pinned tool, streams `/work` back. |
| `siem/_sandbox_probe.py` | Trusted in-sandbox self-test that empirically exercises each control. |
| `siem/forensic_ops.py` | `ForensicProcessor` contract + real operations; observed-facts / interpretation / derived separation. |
| `siem/forensic_jobs.py` | Job lifecycle coordinator, in-memory JobStore + EvidenceSink, reproducible manifest builder. |
| `siem/evidence_validation.py` | F3 correction (A): scan/validation/observe/accept separation; admin-only promotion; guarded revision. |
| `siem/blob_lifecycle.py` | F3 correction (B): reference-counted shared-object lifecycle; scoped revocation; holds. |
| `siem/custody_integrity.py` | F3 correction (C): re-verify a chain from the DB; signed checkpoint/anchor; truncation detection. |
| `models.py` | New tables `forensic_jobs`, `custody_checkpoints`, `blob_references`; new `custody_events` columns `ts`, `seq`, `record_json`; `ensure_schema` entries. |
| `siem/evidence_persistence.py` | `custody_event`/`custody_row` now carry `seq` + full signed `record_json`; `persist_derived` accepts `seq`. |
| `siem/evidence_types.py` | `agent_trace`/`model_trace` are now blob-capable so their exact source bytes are preserved for independent re-parsing. |
| `siem/tests/test_forensic_f4.py` | 63-check F4 suite + Demo A (video) + Demo B (agent trace). |

## 3. F3 security corrections (with evidence)

**(A) Separate screening / format validation / observation / acceptance — close candidate
self-promotion.** `evidence_validation.py` makes the four decisions independent. A malware-scan
verdict is recorded only from a scanner that actually ran (`record_scan` raises `NO_SCANNER`
otherwise); we never claim scanning occurred. `promote_to_validated` is the only path to
`validated`: it requires a reviewer/admin in the artifact's cohort+pathway, passing structural
validation, and either a real clean scan **or** an explicitly registered trusted synthetic fixture.
A candidate can never promote, including via `revise()` — `guard_revision` blocks a candidate from
changing `validation_state`/`scan_state`/`revoked`/retention. Until a scanner is approved,
externally-submitted unscanned evidence is blocked from unsafe workflows (`can_enter_unsafe_workflow`),
and demos run only on trusted synthetic fixtures.
Evidence: suite section C — candidate promotion refused; unscanned promotion refused; no-scanner
verdict refused; clean-then-promote succeeds; infected → quarantined and unpromotable; guarded
revise blocks the candidate.

**(B) Reference-counted content-addressed storage.** `blob_lifecycle.py` + the `blob_references`
table reference-count each `blob/<sha256>` object. Deleting, revoking or quarantining one artifact
releases only its reference; the object's bytes are physically removed only when no active reference
and no hold remain (and F3's `can_delete` still gates the artifact). Revocation is scoped to
artifact / candidate / cohort. De-duplication never discloses cross-tenant sharing — authorization
stays per-artifact and the put result reveals nothing about other tenants.
Evidence: suite section D — two tenants sharing one object; deleting one preserves the other's
bytes; removing the last reference physically deletes; a hold blocks deletion; scoped revocation
touches only the named cohort; dedup grants no cross-tenant access.

**(C) Custody checkpoint/anchor + truncation detection.** The F3 chain was rewrite-evident but
truncation-blind (drop the last N events and the prefix still verifies). `custody_events` now
persists the exact `record_json`, `ts`, and a per-evidence `seq` (committed inside each signed
record), so the chain re-verifies **from the database**, not only from an in-memory list.
`custody_integrity.py` adds a separately-stored, signed, chained `custody_checkpoints` anchor over
the chain's head hash, head seq and event count; `assess` detects truncation (live count < anchored)
and head rewrites (equal count, different head). Honest limitation, documented in-code and below:
events and checkpoints share the server Ed25519 key, so a key holder could forge both — this
defends against DB-level tampering/truncation by anyone **without** the key, and a future external
transparency-log anchor (no paid infra) closes the same-key gap.
Evidence: suite section E and the PostgreSQL run — truncation and head-rewrite both detected against
a real anchor, including when a row is deleted from Postgres.

## 4. ForensicProcessor and operations

`forensic_ops.ForensicProcessor` is versioned (`f4-forensic-processor/1`, contract v1) and
provider-neutral: `run(op_id, source_path, params, trusted_fixture)` validates the operation,
enforces sandbox availability for media (fails closed when isolation is unverified), and returns an
`OpResult` that separates `observed_facts` (deterministic), `interpretations` (explicit uncertainty,
never verdicts), and `derived` (new bytes + sha256 + lineage). `manifest()` emits the reproducible
result record.

- **Audio** (`audio.inspect`, `audio.spectrogram`) — ffprobe container/codec/duration/sample-rate/
  channels/bitrate/metadata; ffmpeg STFT spectrogram. No speaker-identity or synthetic-speech claims.
- **Video** (`video.inspect`, `video.frames`) — ffprobe stream inspection that labels container
  values "reported" (self-declared metadata, not a full decode); bounded ffmpeg frame extraction
  (≤16 frames, decompression-guarded) producing derived PNG frames with per-frame sha256 and
  parent-child provenance.
- **Image** (`image.inspect`, `image.thumbnail`) — format/dimensions/decoder-integrity, 64 MP
  decompression guard before any raster; ordinary compression artifacts are explicitly **not**
  treated as manipulation; exiftool absence is reported honestly.
- **Digital provenance** (`provenance.c2pa`) — c2patool if present, else a bounded memory-safe
  marker scan to distinguish `missing_manifest` from `indeterminate`. States: verified / invalid /
  missing / unsupported / error / indeterminate. A missing manifest is never "fake"; a valid
  signature never proves depicted events.
- **AI agent-trace** (`agent_trace.inspect`) — strict bounded JSON parsing (byte/event/depth/field
  caps), schema-validated, reading only supported event types as **data**. It never executes
  embedded code, tool calls, model instructions or deserialized objects; it reports authorization
  decisions, tool calls, retrievals and data-access boundary crossings with 0-based source-event
  references, as observations, not findings.

## 5. Sandbox and empirical enforcement proof

Untrusted media is decoded only inside a throwaway set of Linux namespaces (user + mount + pid +
net + ipc + uts) created with `unshare`, pivoting into a minimal root. The in-sandbox probe
(`_sandbox_probe.py`) returned, on this environment:

```
required_ok = True
network_isolated=true  root_readonly=true  system_readonly=true  source_readonly=true(null when
no source)  host_root_detached=true  pid_isolated=true  no_new_privs=true  work_writable=true
visible_root=[bin, dev, etc, lib, lib64, op.py, proc, sbin, tmp, usr, work]   visible_pids=2
```

Enforced: unprivileged exec, empty network namespace (no egress), read-only system binds, read-only
`/input`, a single size-limited writable tmpfs `/work` (+ tiny `/tmp`), POSIX rlimits (address
space / CPU seconds / file size / process count / open files / core=0), `PR_SET_NO_NEW_PRIVS`,
host-root detachment via `pivot_root` + `MNT_DETACH`, pinned executable allowlist, structured argv
(never a shell), no candidate-provided code (python3 may run only pinned package scripts). The
processor **fails closed**: when required controls are unverified, untrusted media is refused and
only explicitly trusted synthetic fixtures run.

Measured (real runs): wall-clock timeout killed a looped 600 s ffmpeg at ~2 s (`timed_out=True,
killed=True`); output cap enforced; ffprobe metadata ~96 ms; 3-frame extraction ~107 ms / 22 KB;
spectrogram ~149 ms / 96 KB; probe ~73 ms. Tools pinned: ffprobe/ffmpeg 6.1.1-3ubuntu5. Default
limits: address space 1 GiB, CPU 30 s, file size 256 MB, nproc 64, nofile 256, `/work` 256 MB.

**Honest limitations (environment):** no Docker daemon and no delegated cgroup v2 controllers, so
memory/CPU are bounded by rlimits + wall-clock timeout rather than cgroups (`RLIMIT_AS` caps virtual
address space, not RSS); no seccomp syscall allowlist. These are documented by `probe_sandbox()`.
Production untrusted-media processing must run only where `required_ok` is verified.

## 6. Job lifecycle

`forensic_jobs.JobCoordinator` runs one authorized operation over one source artifact. Lifecycle:
`queued → running → succeeded | failed | canceled | quarantined`. It enforces authorization before
create (admin only — candidates get `NOT_ADMIN`), bounded concurrency (no job runs past the cap),
idempotent submit (same idempotency key → same job), atomic claim (worker-token compare-and-set),
retry limits, wall-clock timeout (via the sandbox), cooperative cancellation, restart recovery of
stale `running` jobs (admin-triggered sweep, no always-on daemon), temp-source cleanup on every
path, run-time re-check of source authorization/integrity (revoked/missing/corrupt → safe failure),
and resource accounting. Each success persists derived bytes via F3 `persist_derived` (source never
overwritten), creates typed `derived_artifact` evidence, registers a reference-counted blob
reference, appends sequenced signed custody on both the source and derived chains, and stores a
reproducible manifest (source id/hash, operation, tool+version, exact params, environment version,
deterministic observations, derived ids/sha256, lineage, timestamps, resource measurements,
reproducibility note, custody refs). Byte-for-byte reproducibility of derived media is **not**
claimed; recorded hashes are observed-at-this-environment and the manifest says so.

## 7. Tests, demos, database validation

- `cd siem && pytest` → **38 passed, 0 failed** (full offline regression; F1/F2/F3 intact).
- `test_forensic_f4.py` standalone → **63 checks passed, 0 failed, 0 unverified** on this host
  (real sandbox verified). The suite reports media tests as UNVERIFIED and asserts fail-closed
  behaviour where the sandbox is unavailable, rather than passing silently.
- Coverage: acquisition/retrieval; valid ops per category; malformed/unsupported/depth-bomb/oversized
  inputs; unauthorized + cross-candidate/cross-cohort access; revoked/missing/corrupt source;
  partial-output cleanup; timeout kill; output cap; network isolation; read-only root/source;
  idempotent + concurrent + canceled + stale-recovered jobs; derived hashes + lineage; custody
  re-verify + truncation + rewrite; shared-blob retention + holds + scoped revocation; missing/
  indeterminate C2PA; structured-trace parsing with no code execution; independent reproduction.
- **Demo A (video)**: acquire → preserve (F3) → authorize admin job → isolated metadata inspection +
  bounded frame extraction → persist frames as derived evidence with sha256 → append signed custody
  → independently reproduce from the preserved source → compare → custody chain verifies + anchors.
- **Demo B (agent trace)**: acquire synthetic trace → preserve → safely parse authorization + tool-use
  + boundary-crossing events into structured observations with source refs → sign custody → re-parse
  the preserved bytes independently → signatures verify; no embedded action executed.
- **PostgreSQL 16**: `create_all` builds the three new tables; `ensure_schema` adds the three new
  `custody_events` columns; a custody chain re-verifies from real PG rows; a checkpoint verifies;
  deleting the latest row is detected as `truncated` against the anchor; the existing pathway
  migration-safety test passes. Local SQLite/PG compatibility is not a claim of production readiness.

## 8. Validity separation and limitations

Observed facts, technical interpretations (with uncertainty), and assessment decisions are strictly
separated. No heuristic, model, anomaly or tool output independently confers qualification;
qualification remains the authorized Ranger contract's decision and PARALLAX stays inactive. Known
limitations are stated where they live: sandbox resource bounds are rlimit/wall-clock based (no
cgroups/seccomp here); derived-media reproduction is best-effort, not byte-identical; the custody
checkpoint shares the server signing key (external anchoring is the future, no-paid-infra fix);
c2patool/exiftool are absent in this environment and are reported honestly rather than guessed.

## 9. Blockers / items needing separate approval

None blocked this milestone within the authorized dev scope. For production untrusted-media
processing, two provisioning decisions are surfaced for separate approval (no spend incurred here):
a host where the sandbox `required_ok` is verified (ideally with cgroup v2 + seccomp), and an
approved malware scanner to move externally-submitted evidence past `unscanned`. c2patool/exiftool
installation would enable full provenance/metadata rather than honest `indeterminate` states.

## 10. Status

F4 implemented within the authorized development scope and committed for review. **STOP gate
honored:** no production deployment, no F5, no PARALLAX qualification activation, no new forensic
service deployed, website work not revisited.
