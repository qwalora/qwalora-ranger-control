# Ranger two-track platform — Cyber Operations + Cyber AI: integrated architecture & minimum viable qualification scope (for approval)

Status: **design and approval work only.** This document defines and submits for review the
day-one two-track Ranger platform. It gates the lock of M4.3.1: the deterministic cyber-ops
foundation (`siem/capability_inventory.py`, `siem/scenario_spec.py`, `siem/scenario_pipeline.py`,
`models.ScenarioCatalogEntry`, `Cohort.pathway/curriculum_version`, regression suite
`siem/tests/test_scenario_catalog.py`) is implemented and green, but **M4.3.1 is not locked and no
Cyber AI concrete (capability builder, media lab, scenario catalog, grader) is implemented** until
this blueprint and the Cyber AI assessment blueprint are approved.

Hard gates preserved (unchanged from prior reviews): no paid GPU processing; no acquisition of
non-licensed media; no Ludus/GOAD/Proxmox provisioning; no candidate activation; no change to
cyber-ops grading, `PASS_BAR = 95.0`, `score_board2`, `BoardResult`, Ed25519 signing, or hidden
truth; candidate access / act-as / unattended ingestion stay disabled. Combined infrastructure
target stays **under $300/month**; any projected overage is surfaced for approval before spend.

Cross-links: `siem/BOARD2_M4_3_ARCHITECTURE.md` (cohort-shared SOC, provisioning & lifecycle
orchestration, §15) and `siem/BOARD2_M4_AI_ARCHITECTURE.md` (the internal **AI Orchestration
Layer** — an untrusted advisor that proposes into a deterministic/human-gated pipeline). Note the
deliberate separation of two distinct uses of "AI":

- **AI Orchestration Layer** (BOARD2_M4_AI_ARCHITECTURE.md): internal tooling that *assists staff*
  authoring/operating *any* track. It is an untrusted advisor. Zone model Z0/Z1/Z2 unchanged.
- **Cyber AI pathway** (this document): a *candidate-facing qualification track* whose subject
  matter is AI/media security. It is a program, not a tool.

These never merge. The AI Orchestration Layer may help staff author Cyber AI scenarios exactly as
it helps author cyber-ops scenarios, under the same Z0/Z1/Z2 trust boundaries; it holds no
authority in either track.

---

## 0. Grounding — the two-track seams that already exist in code

The M4.3.1 foundation was built track-neutral, so "both pathways in the foundation now" is already
true at the envelope/abstraction layer. Concrete Cyber AI builders are intentionally withheld
pending this review.

| Seam | Symbol (implemented) | State |
|---|---|---|
| Pathway identity | `capability_inventory.PATHWAY_CYBER_OPS` / `PATHWAY_CYBER_AI`; `models.Cohort.PATHWAYS=("cyber-ops","cyber-ai")`, `Cohort.pathway` (default `cyber-ops`), `Cohort.curriculum_version` | present |
| Per-environment capability inventory | `capability_inventory.build_inventory(environment_type)` dispatch; `ENVIRONMENT_SOC_OPENSEARCH` implemented; `ENVIRONMENT_MEDIA_FORENSICS`, `ENVIRONMENT_LLM_REDTEAM` declared, raise `NotImplementedError` | SOC implemented; AI envs **gated** |
| Typed ScenarioSpec | `scenario_spec` common envelope + `spec_type`→payload-validator registry (`register_payload_validator`); `soc-investigation` implemented | envelope generic; AI spec_types **gated** |
| Polymorphic evidence | `KNOWN_EVIDENCE_KINDS` = event_reference (implemented) + media_asset/file_hash/model_trace/document/system_state (declared); `IMPLEMENTED_EVIDENCE_KINDS=(event_reference,)` | event impl; media/model **gated** |
| Out-of-DB media | `scenario_spec.BLOB_REF_CONTRACT` (uri, sha256, media_type, bytes, provenance, rights_consent, authenticity_assessment) | contract declared |
| Catalog record | `models.ScenarioCatalogEntry` (pathway-aware, `content_hash` immutability, STATUSES) | present |

What this document adds is the **first-class Cyber AI definitions** these seams were shaped to
carry, plus the common program/track layer above cohorts, plus the media-evidence subsystem — all
for approval before implementation.

---

## 1. Common Ranger program/track architecture (review item 1)

A **Program** is the platform. A **Track** (a.k.a. pathway) is an independently versioned
qualification line. Tracks share authentication, cohort orchestration, Case/CaseSubmission,
provenance, and Ed25519 signing; they do **not** share curriculum shape, scenario types, evidence
kinds, environment, or qualification standards.

```
Program (Ranger)
 └─ Track {pathway, name}                       cyber-ops | cyber-ai
     └─ CurriculumDefinition {pathway, curriculum_version}   independently versioned, immutable once published
         └─ AssessmentUnit[] {unit_type, order, blueprint_ref, environment_type}
             unit_type ∈ {board, module, lab-exercise, case-investigation}
     └─ QualificationPolicy {pathway, curriculum_version, pass rule, signing}
```

Key rule: **a Track does not inherit another Track's structure.** cyber-ops `CurriculumDefinition`
= the existing 26-week, six-board sequence (`unit_type=board`, environment `soc-opensearch`, and
later `ludus-goad`). cyber-ai `CurriculumDefinition` = its own ordered units
(`unit_type ∈ {module, lab-exercise, case-investigation}`, environments `media-forensics` /
`llm-redteam`) — **no six boards, no 95% bar by default.** The six-board constants and
`score_board2`/`PASS_BAR` are cyber-ops-scoped and untouched.

### Result records (preserve, then generalize additively)

`BoardResult` stays exactly as is for cyber-ops (objective fields, signature, 95% bar). Cyber AI
needs a signed, verifiable unit result without overloading `BoardResult`. Proposed additive model
`UnitResult` (pathway-scoped), produced by the **same** signing primitive (`signing.sign`) and the
**same** independent-verification discipline as `verify_evidence`:

```
UnitResult {id, candidate_id, cohort_id, pathway, curriculum_version,
            unit_type, unit_ref, score, passed, rubric_breakdown(json),
            submission_id -> CaseSubmission, signature, created_at}
```

`BoardResult` is unchanged; cyber-ops may keep writing it, or a later migration may make it a
`UnitResult` view — not in scope now. No cyber-ops row changes shape in this milestone.

### Curriculum versioning

`CurriculumDefinition` is immutable once published (content-hashed, same discipline as
`ScenarioCatalogEntry.content_hash`). A new cohort binds to one `(pathway, curriculum_version)`;
in-flight cohorts never change version. This is the cross-track generalization of the immutable
scenario-version binding already approved in M4.3 §5/§9.

---

## 2. Cyber AI capability inventory (review item 2)

Same contract as the SOC inventory (`capability_inventory.build_inventory`): a versioned,
machine-readable statement of what Ranger can **actually produce and verify**, grounded in real
tools, with an availability state per capability, and used as the authority a Cyber AI ScenarioSpec
is validated against. Two environment builders, both registered behind the existing dispatch:

### 2a. `media-forensics` environment

| Capability group | Concrete tool / method (open-source, CPU-first) | Availability (MVP) |
|---|---|---|
| Container/codec inspection | `ffprobe`, MP4 atom/box walk, Matroska/WebM parse, codec & encoder tag extraction | available |
| Frame/stream extraction | `ffmpeg` (bounded: max duration/frames/resolution), keyframe/GOP structure | available |
| Image tamper analysis | Error-Level Analysis (ELA), noise/PRNU residual, double-JPEG quantization, resampling traces (CPU) | available |
| Audio forensics | spectral/spectrogram analysis, sample-rate/codec consistency, splice/discontinuity detection, F0/formant continuity | available |
| Forensic metadata | EXIF/XMP/IPTC (`exiftool`), filesystem/container timestamps, geotags, software tags | available |
| Media provenance | **C2PA / Content Credentials** manifest verification, signature/claim validation, assertion chain | available (verify only) |
| Evidence hashing | `sha256` content hash (authoritative), perceptual hash (pHash/dHash) for derived-artifact linkage | available |
| Cross-modal consistency | lip-sync / audio-visual alignment, face-landmark temporal stability (CPU heuristics) | limited (heuristic MVP) |
| Learned deepfake detectors | open-source detector models (e.g. frequency-domain / CNN) run as **metered GPU** or slow-CPU jobs | limited (metered, optional) |

Authoritative-vs-advisory rule, enforced in schema (mirrors `BLOB_REF_CONTRACT.authenticity`):
**verified provenance** (hash match, C2PA signature validation, metadata extraction — reproducible,
machine-checkable) is authoritative; **model authenticity scores** are advisory and tagged
`authenticity_assessment`, never conflated with provenance and never themselves the ground truth.

### 2b. `llm-redteam` environment

| Capability group | Concrete method | Availability (MVP) |
|---|---|---|
| Sandboxed target model | a small local model (CPU) **or** metered inference endpoint, isolated harness, no tools/no network by default | limited (metered) |
| Prompt-injection exercises | direct & indirect injection corpora, success oracle on a declared canary/secret | available (CPU oracle) |
| Jailbreak / policy-evasion | attempt → deterministic policy oracle (did a declared forbidden behavior occur) | available |
| Tool/agent security | sandboxed agent with mock tools; exfiltration/over-privilege detection via trace inspection | limited |
| Model evaluation | structured-output conformance, refusal consistency, injection-resistance scoring | available |
| Evidence: `model_trace` | full prompt/response/tool-call trace, hashed, replayable | available (verify) |

Grounding discipline identical to SOC: the inventory builder observes real tool output (e.g.
`ffprobe`/`exiftool` on a licensed sample; a canary-oracle run) rather than hand-declaring fields,
so a Cyber AI ScenarioSpec cannot reference an observation Ranger cannot actually produce. Both
builders remain **gated** (return `NotImplementedError` today) until this inventory is approved.

---

## 3. Media-evidence architecture (review item 3)

Large binaries never enter Postgres or OpenSearch (this is why `BLOB_REF_CONTRACT` already exists).
The subsystem:

```
Ingest → sha256 (immutable source hash) → object store (content-addressed key = sha256)
       → MediaAsset row (BlobRef only) → CustodyEvent (signed, append-only)
Derive (any workbench transform) → derived BlobRef {derived_from, transform, params_hash}
       → provenance DAG (source → derived → derived…)
Serve  → short-TTL signed URL, candidate-scoped, never a public object ACL
Retain → retention window + legal-hold for open cases → scheduled reclamation
```

- **Object storage.** Railway bucket (S3-compatible; `mcp__Railway__create-bucket`) or equivalent.
  Objects are immutable and keyed by content hash; re-ingest of identical bytes dedupes.
- **Immutable source hash.** `sha256` computed at ingest, stored on `MediaAsset`, re-verified on
  every read; mismatch = integrity failure, access denied, custody event raised.
- **Derived-artifact tracking.** Every workbench output (extracted frame, ELA map, spectrogram,
  C2PA report) is itself a hashed BlobRef with `derived_from` + the transform + a hash of its
  parameters, forming a reproducible provenance DAG. Re-running a transform must reproduce the hash.
- **Chain of custody.** Append-only `CustodyEvent` log (actor, action, asset hash, timestamp, case),
  each event Ed25519-signed with the **existing** `signing` module — same primitive as evidence
  records. Tamper-evident; exportable for the submission.
- **Candidate access control.** A candidate may read only assets attached to a case assigned to
  them, served via short-TTL signed URLs minted server-side after an authz check (reuses existing
  authentication + cohort/case authorization). Restricted assets and their metadata never appear on
  any public API.
- **Secure retention.** Per-asset retention window; **legal-hold** blocks deletion while a case is
  open or under review; candidate-derived artifacts are reclaimed after retention; **source media
  is kept only within its documented license/consent terms** and purged otherwise.

Proposed additive models (for approval, not implemented): `MediaAsset`, `CustodyEvent`,
`EvidenceBundle` (the signed set attached to a case). No existing table changes.

---

## 4. Browser-based forensic workbench (review item 4)

A portal workbench page (reuses existing auth + portal shell) where a candidate selects an
authorized asset and runs forensic tools. **No tool runs in the request path**; every tool is a
bounded, queued job.

```
Workbench (browser) → enqueue ForensicJob {tool, asset_hash, params}
  → bounded CPU worker (sandboxed, see §7) → derived BlobRef + structured result + custody event
  → workbench renders result; candidate cites results as evidence in the case
Optional: GPU-backed detector job → metered inference → advisory authenticity_assessment (tagged)
```

- **Bounded CPU jobs.** Reuse the existing background-worker + `pg_try_advisory_lock` pattern
  (M4.3 §A.4 / scheduler) for a small job queue. Hard caps: wall-clock timeout, memory/cpu cgroup
  limits, output-size cap, max concurrent jobs per candidate.
- **Tool catalog.** `ffprobe`/`ffmpeg`, `exiftool`, ELA/noise (Pillow/numpy), audio spectral
  (librosa/numpy), C2PA verify, hashers — each a declarative tool descriptor mapping to an
  isolated runner; no arbitrary command execution (the `PRIVILEGED_DENYLIST` discipline from
  `scenario_spec` extends here: a job is data, not a shell).
- **Optional metered GPU.** Detector-model inference via HF Inference Providers pass-through
  (same metered, no-dedicated-GPU, cost-capped model as BOARD2_M4_AI_ARCHITECTURE §11), **off by
  default**, invoked only for specific detector tools, output always advisory.

MVP ships CPU tools only; GPU detectors are a declared, cost-gated extension.

---

## 5. Cyber AI scenario catalog & independently validated ground truth (review item 5)

New `spec_type`s on the existing registry (gated until approved):

- `media-forensics-investigation` → payload validator against the `media-forensics` inventory.
- `llm-redteam-exercise` → payload validator against the `llm-redteam` inventory.

Ground-truth model — the crux of a *defensible* media track:

| Case class | Ground truth | How established (independent of candidate & of any model) | Graded on |
|---|---|---|---|
| Genuine | authentic | documented capture source + unbroken provenance (C2PA / original files / licensed) | correctly finding no manipulation; not over-calling |
| Consent-based manipulated | manipulated, with a **known recorded manipulation** | the team itself produced it from licensed source under consent; the edit is logged as hidden truth | identifying manipulation + reproducible supporting observations |
| Ambiguous | **indeterminate** (truth = "cannot be established") | adjudicated: evidence genuinely insufficient | calibrated uncertainty + correct non-conclusion; over-confidence penalized |

"Independently validated" = truth is set by provenance/consent records held **outside** any
detector model and outside the candidate's view (evaluator-only, same discipline as
`scenario_spec` evaluator_only layer and SOC hidden truth). A learned detector's score is **never**
the ground truth — it is at most one advisory observation the candidate may weigh.

Media sourcing gate: only **genuine licensed** media and **consent-based** manipulations the team
creates from licensed source. No scraping, no non-licensed acquisition (hard gate). Ambiguous cases
are built from the same licensed pool.

---

## 6. Cyber AI assessment framework (review item 6) — *separately approved blueprint*

Four scored dimensions; the mix and pass rule are a **QualificationPolicy** that must be approved
on its own (this document proposes it; it does **not** assign cyber-ops' 95% bar to Cyber AI):

1. **Reproducible technical observations** — machine-verifiable: did the candidate extract the
   correct hash, metadata field, C2PA claim, codec/container fact, spliced audio segment? Verified
   deterministically against the media-evidence store (re-run the transform, compare hashes/values),
   exactly as `verify_evidence` checks SOC citations. This is the authoritative, auto-gradable core.
2. **Reasoning** — the chain from observations to conclusion (rubric-scored).
3. **Uncertainty calibration** — confidence appropriate to evidence; ambiguous cases reward correct
   non-conclusion and penalize over-confidence (rubric + scoring function).
4. **Defensible security recommendations** — e.g. a verification protocol and a fraud-response
   control; judged for soundness and defensibility (rubric).

Submission reuses `Case` / `CaseSubmission`; the result is a signed `UnitResult` (§1). Dimension 1
is independently verifiable the way SOC evidence is; dimensions 2–4 use a published rubric with
human (and optionally AI-Orchestration-advisory, Z1, never authoritative) review. **Proposed MVP
pass policy for approval:** a minimum on Dimension 1 (verifiable observations) *and* a rubric
threshold on 2–4, with no single numeric bar carried over from cyber-ops. Exact numbers are
deferred to your separately-approved Cyber AI assessment blueprint.

---

## 7. Isolation of all media processing (review item 7)

Every ingest and every job runs under:

- **File-type validation** by magic bytes / container probe, **not** extension; allowlist of
  containers/codecs; reject on mismatch.
- **Decoding limits** — max resolution, duration, frame count, pixel count, and output size;
  decompression-bomb and pixel-flood defenses; frame budget enforced in `ffmpeg` invocation.
- **Malware scanning** where appropriate (ClamAV) on every upload before any decode.
- **Timeouts** — hard wall-clock per job; killed on breach, custody event raised.
- **No privileged execution** — unprivileged sandbox: dropped Linux capabilities, seccomp profile,
  read-only root FS, no network egress for CPU forensic jobs, per-job cgroup CPU/memory caps,
  ephemeral scratch wiped after the job. Tools are invoked by descriptor with fixed argument
  templates — never an interpreted command string (no shell, consistent with
  `scenario_spec.PRIVILEGED_DENYLIST`).

Untrusted-input handling matches the platform rule: each uploaded/derived file lives in its own
empty directory and is passed to tools by path as an argument; no interpreter or build tool runs
from inside a media directory.

---

## 8. Pilot workload & cost projection (review item 8) — under $300/month preserved

Cyber-ops baseline (from `federated-pondering-clock.md` §A.3): ~$70–110/mo. Cyber AI MVP adds:

| Component | Host / mode | Est. $/mo |
|---|---|---|
| Object storage (media, GB-scale pilot) | Railway bucket / S3-compatible | $3–10 |
| CPU forensic worker (bounded, can share the control-plane node or a small burst node) | Railway / small always-on | $5–15 |
| Metered GPU detector inference (optional, capped) | HF Inference Providers pass-through | $0–30 (cap) |
| LLM red-team sandbox (small local CPU model or metered) | reuse metered allowance | within AI $15–30 cap |
| **Cyber AI MVP subtotal** | | **~$10–55/mo** |
| **Both tracks combined** | | **~$80–165/mo** |

Comfortably under $300/mo. No dedicated/always-on GPU, no Proxmox, no Ludus for Cyber AI. Pilot
sized to one cohort and a handful of curated cases. The dominant variable cost remains the
cyber-ops GOAD host (boards 5–6, future); a second GOAD host is the most likely overage trigger and
is surfaced for approval before being added — Cyber AI does not touch that lever.

---

## 9. Day-one milestones for both tracks (review item 9) — production-ready vs future

**Cyber Operations (unchanged plan):** M4.3.1 deterministic foundation (implemented, pending
lock) → M4.3.2… cohort provisioning/orchestration, real SOC team ops, rotation (per M4.3 §16).
Boards 5–6 Ludus/GOAD remain future and infra-gated.

**Cyber AI — day-one MVP (production-ready scope):**

- **CA-1 (foundation, free, no media processing):** common Track/CurriculumDefinition/AssessmentUnit
  + `UnitResult` seam; register `media-forensics`/`llm-redteam` inventories and the two new
  `spec_type` validators; `MediaAsset`/`CustodyEvent`/`EvidenceBundle` models + BlobRef wiring; all
  behind the existing gates. Regression tests mirroring `test_scenario_catalog.py`.
- **CA-2 (media-evidence + workbench, CPU-only, licensed sample):** object store, ingest+hash,
  signed custody, scoped signed-URL serving, bounded CPU tool runners (§4/§7), derived-artifact DAG.
- **CA-3 (catalog + assessment MVP):** a small curated case set across the three ground-truth
  classes (§5), Dimension-1 auto-verification + rubric for 2–4, signed `UnitResult`.
- **CA-4 (end-to-end pilot):** review item 10, below.

**Future (explicitly not day-one):** learned deepfake-detector GPU pipeline at scale, full LLM/agent
red-team lab, large case library, any always-on GPU. Declared, cost-gated, not implemented.

---

## 10. End-to-end pilot — executive deepfake impersonation & multimodal fraud (review item 10)

Narrative: a finance officer receives a video call clip + a voicemail + a follow-up email
purporting to be the CEO authorizing an urgent wire. Candidate must investigate authenticity and
recommend a response.

1. **Authorized evidence access.** Candidate opens the assigned case; portal authz grants
   short-TTL signed URLs to the video, audio, and email artifacts (licensed/consent-based source).
   Custody event logged + signed on each access.
2. **Workbench observations (reproducible).** Candidate runs bounded CPU jobs: container/codec &
   encoder tags (`ffprobe`), C2PA/Content-Credentials manifest verify, EXIF/XMP metadata, ELA +
   double-JPEG on key frames, audio spectral splice detection + F0 continuity, cross-modal
   lip-sync alignment, sha256 of each artifact. Each produces a hashed derived artifact in the
   provenance DAG.
3. **Reasoning + calibrated uncertainty.** Candidate synthesizes observations into an authenticity
   determination with explicit confidence; if the curated truth is "ambiguous," a calibrated
   non-conclusion scores well and over-confidence is penalized.
4. **Defensible recommendations.** e.g. an out-of-band verification protocol for executive wire
   authorizations and an immediate financial-control response to the attempted fraud.
5. **Independently verified, signed submission.** `CaseSubmission` captured; Dimension-1
   observations re-verified server-side against the media-evidence store (hashes/metadata/C2PA
   recomputed); rubric applied to 2–4; a signed `UnitResult` + exported signed chain-of-custody is
   produced. Any learned-detector score present is shown as advisory, tagged, and excluded from
   ground truth.

This exercises the whole stack — authz, media evidence, workbench isolation, provenance, assessment,
signing — on genuine licensed media, with no GPU dependency required for a pass.

---

## 11. Reuse map (explicit — review requirement)

| Existing infrastructure | Reused by Cyber AI as |
|---|---|
| Authentication (GitHub OAuth, the only auth) | unchanged; same sign-in for both tracks |
| Cohort orchestration & lifecycle (M4.3 §15) | `Cohort.pathway` selects the track; provisioning idempotency/validation/isolation reused; Cyber AI provisioning = tenant + object-store prefix + case set (no VM) |
| `Case` / `CaseSubmission` | the submission vehicle for Cyber AI investigations |
| Provenance & evidence verification (`case_contract.verify_evidence`) | the model for Dimension-1 auto-verification against the media-evidence store |
| Ed25519 signing (`signing`) | signs `UnitResult` and every `CustodyEvent`; no new crypto |
| ScenarioSpec envelope + registry (`scenario_spec`) | carries the two new `spec_type`s; `evaluator_only` carries hidden media truth |
| Capability-inventory dispatch (`capability_inventory`) | hosts the two new environment builders |
| AI Orchestration Layer (Z0/Z1/Z2) | may *assist staff* authoring Cyber AI scenarios; holds no authority; distinct from the pathway |

No second control plane, no second auth, no second signing authority, no forked platform.

---

## 12. Minimum viable qualification scope (for approval)

The smallest Cyber AI that is a **genuine, defensible qualification** (not a landing page):

- One `media-forensics` cohort, one `CurriculumDefinition` (cyber-ai-v1), a handful of
  `case-investigation` units across genuine / consent-manipulated / ambiguous classes.
- CPU-only workbench (the §4 tool catalog), media-evidence subsystem with signed custody, candidate
  access control, retention.
- Assessment: Dimension-1 auto-verified + rubric for 2–4, signed `UnitResult`, under a
  **separately approved QualificationPolicy** (no inherited 95% bar).
- The §10 pilot as the acceptance case.
- Stays within the <$300/mo combined target; no GPU required to qualify.

LLM/agent red-team (`llm-redteam`) ships its inventory + spec_type seam in CA-1 but its full lab is
a fast-follow after the media MVP, to keep the first qualification tight and reviewable.

---

## 13. Minimal foundational changes to admit both tracks now

Already in code (M4.3.1): pathway enums, `Cohort.pathway`/`curriculum_version`, per-environment
inventory dispatch, typed spec registry, polymorphic evidence kinds + `BLOB_REF_CONTRACT`,
pathway-aware `ScenarioCatalogEntry`.

Proposed additive changes (schema/interface only; **for approval**, implemented post-review, each
idempotent `ensure_schema` ALTER, no existing row reshaped):

- Models: `CurriculumDefinition`, `AssessmentUnit`, `UnitResult`, `MediaAsset`, `CustodyEvent`,
  `EvidenceBundle`, `ForensicJob`.
- `capability_inventory`: implement `_build_media_forensics_inventory` + `_build_llm_redteam_inventory`
  behind the existing dispatch (lifts the two `NotImplementedError`s).
- `scenario_spec`: register `media-forensics-investigation` + `llm-redteam-exercise` validators; move
  `media_asset`/`model_trace` into `IMPLEMENTED_EVIDENCE_KINDS` as each lands.
- `signing`: no change (reused for `UnitResult` + `CustodyEvent`).
- `BoardResult`, `score_board2`, `PASS_BAR`, SOC inventory, cohort grading: **no change**.

---

## 14. Invariants & gates (must hold)

- Backward compatibility: existing cohorts are `cyber-ops` by default; no grading, access, truth,
  signing, or 95%-bar change. Cyber AI additions are purely additive and gated.
- No paid GPU, no non-licensed media, no Ludus/GOAD/Proxmox, no candidate activation, no always-on
  GPU — none without explicit approval.
- Combined infra under $300/mo; overage surfaced before spend.
- Cyber AI is **not** forced into six boards and inherits **no** cyber-ops qualification standard;
  its blueprint is approved separately.
- The AI Orchestration Layer stays an untrusted advisor, distinct from the Cyber AI pathway.

---

## Deliverable summary — what needs approval before locking M4.3.1

1. This integrated two-track architecture (§1–§7, §11, §13–§14).
2. The Cyber AI MVP qualification scope (§12) and its separate **QualificationPolicy/assessment
   blueprint** (§6).
3. The pilot & cost projection (§8) within the <$300/mo target.
4. The day-one milestone split (§9) and the §10 end-to-end pilot as acceptance.

On approval: lift the gates in the sequence CA-1 → CA-2 → CA-3 → CA-4, each committed/tested/
documented and stopped for review, exactly as cyber-ops milestones run. Until then M4.3.1 stays
**unlocked**; the cyber-ops deterministic foundation is complete and green and does not depend on
any Cyber AI work.
