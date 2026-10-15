# Ranger two-pathway platform — STRATA + PARALLAX: integrated architecture (for review)

Status: **design and approval work only.** Ranger is an advanced, independent technical
**qualification** platform for experienced practitioners (senior security engineers, red-team
specialists, AI-security specialists, security architects). It is **not** a training, teaching,
or course platform. Its purpose is to establish whether a candidate can independently investigate
unfamiliar complex systems, find genuine weaknesses, make defensible technical decisions,
implement solutions, and prove outcomes with verifiable evidence. Qwalora may publish educational
material separately; that is never a Ranger assessment.

This document and the linked PARALLAX blueprint (`siem/RANGER_PARALLAX_BLUEPRINT.md`) gate the
lock of M4.3.1. The deterministic foundation (`siem/capability_inventory.py`,
`siem/scenario_spec.py`, `siem/scenario_pipeline.py`, `pathways.py`, `models.ScenarioCatalogEntry`,
`Cohort.pathway/curriculum_version`, `siem/tests/test_scenario_catalog.py`) is implemented and
green and is **preserved**; **M4.3.1 is not locked** and no PARALLAX concrete is implemented until
this architecture and the PARALLAX blueprint are approved.

Hard gates preserved: no paid GPU processing; no non-licensed media; no Ludus/GOAD/Proxmox;
no always-on GPU; no candidate activation; no change to STRATA grading, `PASS_BAR = 95.0`,
`score_board2`, `BoardResult`, Ed25519 signing, or hidden truth; candidate access / act-as /
unattended ingestion stay disabled. Combined infrastructure target stays **under $300/month**;
any projected overage is surfaced for approval before spend.

Cross-links: `siem/BOARD2_M4_3_ARCHITECTURE.md` (STRATA cohort-shared SOC + provisioning
orchestration), `siem/BOARD2_M4_AI_ARCHITECTURE.md` (the internal **AI Orchestration Layer** — a
governed, non-instructional, untrusted advisor), `siem/RANGER_PARALLAX_BLUEPRINT.md` (PARALLAX
qualification blueprint).

---

## 0. Pathway identity (finalized) and the two "AI" uses that never merge

| | RANGER STRATA | RANGER PARALLAX |
|---|---|---|
| Stable internal id | `strata` | `parallax` |
| Public branding (display-only, configurable) | "RANGER STRATA — Enterprise Defense & Adversarial Systems" | "RANGER PARALLAX — AI Security, Adversarial Systems & Digital Trust" |
| Structure | existing 26-week, six-board, 130 graded days | **own** challenge architecture (not six boards by default) |
| Qualification standard | 95% (`PASS_BAR`), unchanged | **separately approved** (no inherited 95%) |
| Environment | OpenSearch SOC (+ future Ludus/GOAD) | Valyria Financial AI env (§3): CPU/sandbox/OpenSearch/browser/metered inference |

Stable ids are the only values used in authorization, grading, qualification, persistence,
validation, and tests (`pathways.py`). Marketing names never appear in logic. The two distinct
uses of "AI" are kept separate and neither gets uncontrolled infrastructure privilege or authority
over qualification:

- **AI Orchestration Layer** (internal, staff-facing): proposes/analyzes/stress-tests challenges
  and gives advisory post-submission review. Governed, non-instructional, untrusted. No live
  candidate coaching, no hidden-truth disclosure, no grading authority.
- **RANGER PARALLAX** (candidate-facing qualification): the pathway in which candidates
  investigate, attack in authorized labs, defend, and assure AI systems, and prove it with
  verifiable evidence.

---

## 1. Common pathway architecture (shared control plane, no duplication)

```
Ranger (one control plane, one auth, one signing authority)
 └─ Pathway {id: strata|parallax}
     └─ CurriculumDefinition {pathway, curriculum_version}   independently versioned, immutable once published
         └─ AssessmentUnit[] {unit_type, order, blueprint_ref, environment_type}
             unit_type ∈ {board, lab-challenge, case-investigation, design-review}
     └─ QualificationPolicy {pathway, curriculum_version, pass rule, signing}
```

A pathway never inherits another's structure. STRATA's `CurriculumDefinition` = the six-board,
130-graded-day sequence (`unit_type=board`, env `soc-opensearch`, later `ludus-goad`), 95% bar —
unchanged. PARALLAX's `CurriculumDefinition` is defined in the blueprint (`unit_type ∈
{lab-challenge, case-investigation, design-review}`, envs under §3), with its own qualification
policy.

Result records: `BoardResult` is untouched for STRATA. PARALLAX produces a signed, pathway-scoped
`UnitResult` from the **same** `signing.sign` primitive and the **same** independent-verification
discipline as `case_contract.verify_evidence`. `PASS_BAR`/`score_board2` stay STRATA-scoped.
Curriculum definitions are content-hashed and immutable once published (same discipline as
`ScenarioCatalogEntry.content_hash`); an in-flight cohort never changes version.

---

## 2. RANGER PARALLAX — six competency domains (not six boards)

PARALLAX is an advanced AI-security qualification spanning six domains. These are competency
domains, **not** an automatic one-board-per-domain mapping; the blueprint composes them into a
smaller number of **integrated, multi-disciplinary challenges**. Summary (full treatment in the
blueprint):

| # | Domain | Representative senior-level challenge focus |
|---|---|---|
| D1 | Agentic AI security, authorization & tool-use boundaries | confine a tool-using agent: authorization scoping, confused-deputy, unsafe tool chaining, privilege boundaries |
| D2 | LLM & RAG security | prompt injection (direct/indirect), retrieval authorization, cross-tenant data isolation, context/trust-boundary failures |
| D3 | AI red teaming & adversarial evaluation | structured adversarial evaluation of a model/app, mitigation design, and **validation that the mitigation holds** |
| D4 | AI infrastructure, model artifacts, data provenance & supply chain | model/artifact integrity, unsafe deserialization, poisoned/backdoored artifacts, provenance & supply-chain controls |
| D5 | Synthetic-media forensics, identity abuse & multimodal fraud | deepfake/multimodal investigation with provenance, metadata, and reproducible forensic observations |
| D6 | AI security monitoring, incident response, assurance & recovery | detect/triage/respond to an AI-system incident with telemetry, then assure and recover |

Every domain is scored on real engineering and investigative reasoning, secure design, and
**independent verification** of outcomes — never on completing a scripted walkthrough.

### Compute mapping (no Ludus, no always-on GPU)

| Activity | Runs on | GPU? |
|---|---|---|
| Agent/RAG/LLM app behavior (D1, D2) | sandboxed CPU applications (the Valyria AI apps, §3), candidate drives them via API/browser | no |
| Prompt-injection / jailbreak / tool-abuse oracles (D1–D3) | deterministic CPU oracles over canary/secret + trace inspection | no |
| Target-model responses where a model is needed | small local CPU model **or** **metered** hosted inference (capped) | metered only |
| Adversarial evaluation harness (D3) | CPU harness + structured scoring | no |
| Artifact/supply-chain analysis (D4) | CPU: hashing, unpickling-in-sandbox detection, manifest/provenance checks | no |
| Media forensics (D5) | CPU: ffprobe/ffmpeg (bounded), exiftool, ELA/noise, audio spectral, C2PA verify, sha256/pHash | no (learned detectors optional, metered) |
| Security telemetry, detection, hunting (D6) | **OpenSearch** (reuses the existing cluster + Security Analytics) | no |
| Evidence, custody, submission, verification | Postgres + object store + `signing` (reused) | no |

Only optional learned-detector / target-model inference touches GPU, and only via **metered**
hosted inference within the capped allowance — never a dedicated or always-on GPU.

---

## 3. The Valyria Financial AI environment (integrated PARALLAX target)

A single fictional environment — Valyria Financial's AI platform — gives PARALLAX challenges a
coherent, enterprise-realistic system to investigate, attack (in authorized labs), defend, and
assure. It extends the existing fictional Valyria org (shared lore with STRATA) without sharing
STRATA's SOC qualification surface.

Components (all CPU/sandboxed/metered, no Ludus):

- **Controlled LLM applications** — e.g. a customer-support assistant and an internal
  "analyst copilot", each with system prompts, guardrails, and deliberately realistic trust-boundary
  weaknesses for specific challenges.
- **Retrieval services (RAG)** — vector/keyword retrieval over tenant-partitioned document stores,
  with authorization boundaries candidates must test (D2).
- **Tool-using agents** — agents with scoped tool access (ticketing, "payments" sandbox, file
  retrieval) exercising authorization and confused-deputy surfaces (D1).
- **Model artifacts & registry** — stored model/adapter artifacts with provenance manifests and
  supply-chain metadata; some challenges seed integrity/poisoning issues (D4). Artifacts are
  content-addressed BlobRefs (§4), analyzed in sandbox.
- **Security telemetry** — application, agent, retrieval, and inference logs shipped into
  **OpenSearch** so D6 monitoring/IR challenges use the real cluster + Security Analytics (reuses
  the STRATA SIEM infrastructure, separate indices/tenant).
- **Synthetic-media evidence** — licensed genuine + consent-based manipulated + ambiguous media
  artifacts attached to D5 cases via the media-evidence subsystem (§4).

Hidden ground truth (the injected weakness, the manipulation log, the poisoned artifact) lives in
the evaluator-only layer and is recomputed/verified server-side; it is never in a candidate path.

---

## 4. Evidence architecture — AI artifacts, model traces & media (reuses BlobRef + signing)

Large/binary evidence never enters Postgres or OpenSearch (why `scenario_spec.BLOB_REF_CONTRACT`
exists). One subsystem serves all PARALLAX evidence kinds:

```
Ingest → sha256 (immutable source hash) → content-addressed object store → BlobRef row
       → CustodyEvent (Ed25519-signed, append-only)
Derive (any workbench transform / tool run) → derived BlobRef {derived_from, transform, params_hash}
       → provenance DAG; re-running a transform reproduces the hash
Serve  → short-TTL, candidate-scoped signed URL (never a public object ACL)
Retain → retention window + legal-hold for open cases → scheduled reclamation
```

Evidence kinds (polymorphic, from `scenario_spec`): `event_reference` (implemented, OpenSearch
telemetry), and — for PARALLAX, gated — `model_trace` (prompt/response/tool-call trace, hashed,
replayable), `file_hash`, `media_asset` (BlobRef + provenance + rights/consent +
authenticity_assessment), `document`, `system_state`. **Verified provenance** (hash match, C2PA
signature, extracted metadata, a replayed trace) is authoritative; a **learned-model score** is
advisory, tagged `authenticity_assessment`, and never the ground truth.

Chain of custody, candidate access control, and retention are as in the media subsystem: every
access/transform is a signed `CustodyEvent`; candidates read only assets on their assigned case;
source media kept only within its license/consent terms.

---

## 5. Candidate workbench (qualification-first, no solution path)

A browser workbench (reuses existing auth + portal shell) where a candidate independently works a
challenge in the Valyria AI environment. It presents **operational instructions, environment
specs, challenge objectives, scope-of-engagement rules, tooling documentation, and
evidence-submission requirements** — and nothing that reveals the solution path. No live AI
coaching, no hints, no walkthrough.

```
Workbench → act on the live sandboxed AI apps/agents/retrieval (D1–D3), analyze artifacts (D4),
            run bounded CPU forensic tools (D5), query OpenSearch telemetry (D6)
          → each action/result is captured as hashed evidence + a signed custody event
          → candidate cites evidence and submits via Case/CaseSubmission
Optional  → metered detector/target-model inference (off by default; advisory output only)
```

All tool runs are bounded, queued CPU jobs (§6 isolation); tools are invoked by descriptor with
fixed argument templates (no shell), consistent with `scenario_spec.PRIVILEGED_DENYLIST`.

---

## 6. Isolation of all media and model processing

Every ingest and job runs under: magic-byte file-type validation (not extension; container/codec
allowlist); decode limits (max resolution/duration/frames/pixels/output size; decompression-bomb
defense); malware scanning (ClamAV) on uploads before decode; hard per-job wall-clock timeouts;
and **no privileged execution** — unprivileged sandbox, dropped capabilities, seccomp, read-only
root FS, no network egress for CPU jobs, per-job CPU/memory cgroup caps, ephemeral scratch wiped
after each job. Untrusted artifacts (uploaded media, model artifacts) each live in their own empty
directory and are passed to tools by path; no interpreter or build tool runs from inside such a
directory. Model-artifact analysis (D4) treats deserialization as hostile (sandboxed, no
auto-execution).

---

## 7. PARALLAX assessment (summary; full blueprint linked)

Scored dimensions (detailed, with the proposed qualification policy, in
`siem/RANGER_PARALLAX_BLUEPRINT.md`): reproducible technical observations (machine-verifiable
against the evidence store, like `verify_evidence`); investigative reasoning; secure-design and
remediation quality (does the fix actually hold — re-verified); uncertainty calibration (ambiguous
cases reward correct non-conclusion, penalize overconfidence); defensible recommendations and
alternatives. Submission reuses `Case`/`CaseSubmission`; result is a signed `UnitResult`.
**No STRATA 95% bar is applied**; the PARALLAX policy is approved separately.

---

## 8. Day-one assessed labs (genuine candidate actions + independent verification)

Two labs are proposed as the day-one PARALLAX minimum. "Documented" is **not** "production-ready":
a lab is production-ready only after it is built, its ground truth is independently established,
its reproducible evidence checks pass end-to-end, and a signed submission verifies — demonstrated,
not described.

### Lab A — Agent/RAG security challenge (D1 + D2, integrated)
- Environment: the Valyria support assistant + RAG over a tenant-partitioned store + a tool-using
  agent with a scoped "payments" sandbox and a planted cross-tenant/authorization weakness.
- Genuine candidate actions: probe and characterize the trust boundary; demonstrate an authorized
  exploit (e.g. indirect prompt injection via a retrieved document that induces a cross-tenant read
  or an out-of-scope tool call) against a declared canary; then propose and **implement** a
  mitigation (retrieval authorization / tool-scope fix) and show it holds.
- Independent verification: the canary-access oracle and the `model_trace` evidence are re-checked
  server-side (did the exploit reach the canary before, and fail after the fix); reproducible,
  signed `UnitResult`. CPU + metered inference only.

### Lab B — Synthetic-media forensic investigation (D5; the executive-deepfake fraud case)
- Environment: a finance officer receives a video clip + voicemail + follow-up email purporting to
  authorize an urgent wire (licensed/consent-based media; truth may be genuine, manipulated, or
  ambiguous).
- Genuine candidate actions: authorized evidence access (signed custody); bounded CPU forensic
  tools (container/codec & encoder tags, C2PA/Content-Credentials verify, EXIF/XMP, ELA + double-JPEG,
  audio spectral splice/F0, cross-modal lip-sync, sha256 of each artifact); an authenticity
  determination with calibrated confidence; and defensible recommendations (out-of-band wire
  verification protocol + fraud response).
- Independent verification: Dimension-1 observations recomputed server-side against the
  media-evidence store (hashes/metadata/C2PA); rubric for reasoning/uncertainty/recommendations;
  signed `UnitResult` + exported signed chain of custody. CPU-only to pass; any learned detector is
  advisory and tagged.

---

## 9. Infrastructure & cost (under $300/month preserved)

STRATA baseline (from `federated-pondering-clock.md` §A.3): ~$70–110/mo. PARALLAX day-one adds:

| Component | Mode | Est. $/mo |
|---|---|---|
| Object store (model artifacts + media, pilot) | content-addressed bucket | $3–10 |
| Sandboxed AI apps + CPU job workers (Valyria apps, forensic + oracle jobs) | small always-on / burst CPU | $5–20 |
| OpenSearch telemetry (D6) | **reuses** the existing STRATA cluster (separate indices/tenant) | $0 incremental |
| Metered hosted inference (target model + optional detectors) | HF Inference Providers pass-through, capped | $0–30 (cap) |
| **PARALLAX day-one subtotal** | | **~$10–60/mo** |
| **Both pathways combined** | | **~$80–170/mo** |

Under $300/mo. No dedicated/always-on GPU, no Proxmox, no Ludus for PARALLAX. The dominant variable
cost stays STRATA's future GOAD host; PARALLAX does not touch that lever.

---

## 10. Reuse map (shared foundation, no second control plane)

| Existing infrastructure | Reused by PARALLAX as |
|---|---|
| Authentication (GitHub OAuth, only auth) | unchanged; one sign-in for both pathways |
| Cohort orchestration & lifecycle (M4.3 §15) | `Cohort.pathway=parallax` selects the pathway; idempotent provisioning/validation/isolation reused; PARALLAX provisioning = tenant + object-store prefix + OpenSearch indices + case set (no VM) |
| `Case` / `CaseSubmission` | the submission vehicle for PARALLAX challenges |
| Evidence verification (`case_contract.verify_evidence`) | the model for Dimension-1 auto-verification across model_trace/media/telemetry |
| Ed25519 signing (`signing`) | signs `UnitResult` + every `CustodyEvent`; no new crypto |
| ScenarioSpec envelope + registry (`scenario_spec`) | carries PARALLAX `spec_type`s; `evaluator_only` holds hidden truth |
| Capability-inventory dispatch (`capability_inventory`) | hosts the PARALLAX environment builders |
| OpenSearch + Security Analytics | the D6 telemetry/detection surface |
| AI Orchestration Layer | staff-side authoring/stress-test/review only; no authority, no candidate coaching |

---

## 11. Minimal foundational changes to admit both pathways now

Already in code (M4.3.1, preserved): `pathways.py` (stable ids + legacy normalization + display
branding), `Cohort.pathway/curriculum_version`, per-environment inventory dispatch, typed spec
registry + pathway validation, polymorphic evidence kinds + `BLOB_REF_CONTRACT`, pathway-aware
`ScenarioCatalogEntry`.

Proposed additive changes (schema/interface only; **for approval**, implemented post-review,
idempotent `ensure_schema` ALTERs, no existing row reshaped): models `CurriculumDefinition`,
`AssessmentUnit`, `UnitResult`, `MediaAsset`, `CustodyEvent`, `EvidenceBundle`, `ForensicJob`,
`ModelArtifact`; PARALLAX environment builders behind the existing dispatch (lifts the two
`NotImplementedError`s); PARALLAX `spec_type` validators; move `model_trace`/`media_asset` into
`IMPLEMENTED_EVIDENCE_KINDS` as each lands. `BoardResult`, `score_board2`, `PASS_BAR`, STRATA
inventory and grading: **no change**.

---

## 12. Backward compatibility & migration (non-destructive)

The interim ids `cyber-ops`/`cyber-ai` from commit `5518796` are normalized to `strata`/`parallax`
at read time by `pathways.normalize_pathway`, so correctness never depends on rewriting a row.
Persisted values: the `Cohort.pathway` column was newly added in M4.3.1 with default `strata`; no
`parallax` cohort exists (PARALLAX is not live), so the only possible legacy value is `cyber-ops`
on any cohort created against an earlier build of the column — read as `strata` automatically.
Optional, reversible realignment (not run here, not required): `UPDATE cohorts SET
pathway='strata' WHERE pathway='cyber-ops'`. No destructive migration.

---

## 13. Website positioning (prepare; do not deploy)

The public Ranger site must present STRATA and PARALLAX as advanced, selective qualification
pathways — **not** a course, academy, tutorial service, or beginner program. Emphasis: selective
admission, senior-level technical challenges, independent investigation, verifiable evidence, and
earned qualification; and an accurate operational-vs-under-development status per pathway. The
site lives in a separate repo (not attached here); changes are prepared and reviewed, then
deployed only after content, admission flow, and capability claims are approved. Links already
distributed make this a priority item in the milestone plan, but deployment stays gated.

---

## 14. Invariants & gates (must hold)

- STRATA unchanged: six boards, 130 graded days, signed evidence, 95% bar, SOC architecture.
- PARALLAX: separately approved curriculum + assessment blueprint + qualification policy; no
  inherited 95% bar; six domains composed into integrated challenges, not forced into six boards.
- Qualification-first: no candidate coaching, hints, walkthroughs, tutorial-driven completion,
  adaptive solution-revealing guidance, or instructor-dependent progression anywhere.
- Governed AI: proposes/analyzes/stress-tests challenges and gives post-submission advisory review
  only; never live-coaches, reveals truth, grants qualification, alters signed scores, or overrides
  deterministic verification. Neither the AI layer nor PARALLAX candidates gain uncontrolled
  infrastructure privilege.
- Gates: no paid GPU, no non-licensed media, no Ludus/GOAD/Proxmox, no always-on GPU, no candidate
  activation; combined infra < $300/mo (overage surfaced first).
- "Documented" ≠ "production-ready": a lab is production-ready only when built, with independently
  established truth and passing end-to-end reproducible verification + signed submission.

---

## Deliverable summary — what needs approval before locking M4.3.1

1. This integrated two-pathway, qualification-first architecture (§0–§7, §10–§14).
2. The PARALLAX qualification blueprint (`siem/RANGER_PARALLAX_BLUEPRINT.md`): six domains,
   integrated challenge architecture, curriculum duration/structure/prerequisites, and the
   separately-approved QualificationPolicy (no inherited 95%).
3. The two day-one assessed labs (§8) as the PARALLAX minimum qualification scope, with genuine
   candidate actions and independent evidence verification.
4. Infrastructure/cost within <$300/mo (§9) and the website positioning plan (§13, prepare-only).

On approval: implement in gated steps (PARALLAX foundation → evidence/workbench → Lab A → Lab B),
each committed/tested/documented and stopped for review, exactly as STRATA milestones run. Until
then M4.3.1 stays **unlocked**; the STRATA deterministic foundation is complete, green, and
independent of any PARALLAX work.
