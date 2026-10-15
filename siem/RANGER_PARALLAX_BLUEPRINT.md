# RANGER PARALLAX — qualification blueprint (for approval)

Pathway id: `parallax`. Public branding (display-only): "RANGER PARALLAX — AI Security,
Adversarial Systems & Digital Trust". Companion to `siem/RANGER_TWO_TRACK_ARCHITECTURE.md`.
**Design and approval work only.** PARALLAX is defined independently of STRATA; it does **not**
inherit STRATA's six-board structure or its 95% standard, and nothing here is implemented or
activated until approved. All candidate-access, spending, infrastructure, and grading gates remain
in force.

PARALLAX is an **advanced, independent technical qualification** for experienced practitioners
(senior/staff security engineers, red-team specialists, AI-security specialists, security
architects). It establishes whether a candidate can independently investigate unfamiliar AI
systems, find genuine weaknesses, make defensible decisions, implement solutions, and prove
outcomes with verifiable evidence. It is **not** a course and contains no teaching, mentoring,
walkthroughs, or solution hints.

---

## 1. Competency domains → what a PARALLAX holder can demonstrably do

- **D1 Agentic AI security, authorization & tool-use boundaries** — scope and confine a tool-using
  agent; find and prove authorization failures (confused deputy, over-broad tool scope, unsafe
  tool chaining, out-of-scope side effects); implement boundaries that hold under re-test.
- **D2 LLM & RAG security** — find and prove trust-boundary / data-isolation failures (direct and
  indirect prompt injection, retrieval authorization bypass, cross-tenant leakage, context
  poisoning); remediate verifiably.
- **D3 AI red teaming & adversarial evaluation** — run a structured adversarial evaluation,
  characterize failure modes with reproducible evidence, design mitigations, and **validate the
  mitigations hold**.
- **D4 AI infrastructure, model artifacts, data provenance & supply chain** — investigate model/
  artifact integrity and provenance (unsafe deserialization, tampered/poisoned artifacts, broken
  provenance, supply-chain exposure); design controls and prove integrity.
- **D5 Synthetic-media forensics, identity abuse & multimodal fraud** — conduct a defensible
  forensic investigation of synthetic/real media with provenance, metadata, and reproducible
  observations; reach a calibrated determination and defensible response.
- **D6 AI security monitoring, incident response, assurance & recovery** — detect, triage, and
  respond to an AI-system incident from telemetry; assure and recover, with evidence.

These are **competency domains, not assessment boards.** PARALLAX composes them into a smaller set
of **integrated challenges** because real AI-security work is cross-disciplinary.

---

## 2. Challenge architecture (integrated, not one-board-per-domain)

Unit types (reused generic `AssessmentUnit`): **lab-challenge** (authorized hands-on engagement in
the Valyria Financial AI environment: investigate, attack in scope, remediate, verify),
**case-investigation** (forensic/IR investigation → defensible determination + evidence),
**design-review** (secure-design / assurance deliverable, checked against adversarial evaluation).

Qualifying portfolio (challenge → primary domains → unit type):

| Challenge | Primary domains | Unit type |
|---|---|---|
| C1 Agent & RAG trust-boundary engagement | D1, D2 | lab-challenge |
| C2 Adversarial evaluation & mitigation validation | D3, D2 | lab-challenge |
| C3 Model-artifact & supply-chain integrity | D4 | case-investigation + design-review |
| C4 Synthetic-media / multimodal fraud investigation | D5 | case-investigation |
| C5 AI incident response, assurance & recovery | D6, D1-D4 | lab-challenge |
| C6 Integrative capstone | all | lab-challenge + design-review |

Day-one minimum delivers **C1 (Lab A)** and **C4 (Lab B)** as genuine, independently verified
assessed labs (§7). C2/C3/C5/C6 are sequenced, separately gated milestones.

### 2.1 Duration is provisional — define these before recommending a schedule

The earlier ~10–14-week figure is **provisional and not to be optimized around a course calendar.**
Before a final schedule is recommended, define and approve:

- **Assessment dependency graph** — which challenges are prerequisites for which (capability-based,
  not course sequencing). Draft dependency: C1 → C2 (agent/RAG understanding precedes adversarial
  evaluation of it); C3, C4 independent; C1–C4 → C5 (IR assumes the attack surfaces); all → C6
  (capstone). To confirm.
- **Required technical outcomes per challenge** — the concrete, verifiable artifacts/changes each
  challenge must produce (see per-challenge field 6 below).
- **Individual qualification requirements** — which challenges are required vs elective, and the
  per-challenge pass conditions (§5).
- **Expected workload** — a realistic effort estimate per challenge (engagement hours + evidence
  write-up), from which a schedule is derived *after* the above are fixed.

Only once these are settled is a calendar proposed; the qualification is defined by outcomes, not
by weeks.

---

## 3. Senior-level challenge engineering principles

Every challenge is hard because of the engineering and reasoning required, **not** artificial
obscurity. Each includes: complex, enterprise-realistic dependencies; multiple plausible root
causes with conflicting or incomplete evidence; realistic operational constraints and
scope-of-engagement rules; adversarial behavior; architectural tradeoffs with more than one
defensible answer; independent investigation (no solution path); actual remediation / system
change; reproducible outcome verification; and room for alternative defensible approaches scored on
soundness. Candidates receive operational instructions, environment specs, objectives,
scope-of-engagement rules, tooling documentation, and evidence-submission requirements — never the
solution, hints, or a walkthrough.

---

## 4. Per-challenge specifications

Each challenge specifies the ten required fields: **Required competencies; Authorized technical
environment; Candidate-visible objectives; Hidden evaluator truth; Independently verifiable
evidence; Required technical changes/findings; Alternative valid solutions; Critical failure
conditions; Human-review boundaries; Signed assessment records.** C1 and C4 are day-one; C2, C3,
C5, C6 are defined here as draft specs pending their build milestone.

### C1 — Agent & RAG trust-boundary engagement (D1, D2) — DAY-ONE (Lab A)
1. **Required competencies:** agent authorization scoping; tool-use boundary analysis; indirect
   prompt injection via retrieved content; RAG retrieval authorization / tenant isolation.
2. **Authorized technical environment:** Valyria support assistant + RAG over a tenant-partitioned
   store + a tool-using agent with a scoped "payments" sandbox tool; CPU sandboxed apps; target
   model via metered inference or small local CPU model. Scope-of-engagement: only the assigned
   tenant's surfaces; no infra outside the sandbox.
3. **Candidate-visible objectives:** characterize the agent/RAG trust boundary; demonstrate an
   authorized exploit reaching a declared canary; implement a mitigation; prove it holds.
4. **Hidden evaluator truth:** the injected weakness (e.g. a retrieved document that induces a
   cross-tenant read or out-of-scope tool call) and the canary secret, in the evaluator-only layer;
   recomputed server-side, never in a candidate path.
5. **Independently verifiable evidence:** `model_trace` (prompt/tool-call chain) + canary-access
   oracle result, hashed; re-run server-side to confirm the exploit reached the canary pre-fix and
   fails post-fix.
6. **Required technical changes/findings:** a working proof of the exploit **and** an implemented
   mitigation (retrieval authorization filter or tool-scope constraint) that the oracle confirms
   holds.
7. **Alternative valid solutions:** mitigation at the retrieval-authorization layer, the tool-scope
   layer, or an input-provenance/trust-tagging layer — any that demonstrably closes the canary path
   without breaking legitimate function.
8. **Critical failure conditions:** no reproducible exploit; a "fix" that fails the oracle or breaks
   legitimate retrieval; out-of-scope actions; fabricated/non-reproducible evidence.
9. **Human-review boundaries:** reviewer scores reasoning, design soundness, and tradeoff
   discussion; reviewer does **not** re-grade the machine-verified canary result; no AI coaching
   at any point; post-submission AI review is advisory only.
10. **Signed assessment records:** signed `UnitResult` + signed custody of all `model_trace`
    evidence; immutable.

### C4 — Synthetic-media / multimodal fraud investigation (D5) — DAY-ONE (Lab B)
1. **Required competencies:** container/codec & metadata forensics; C2PA/provenance verification;
   image/audio tamper analysis; cross-modal consistency; calibrated authenticity reasoning.
2. **Authorized technical environment:** the executive-deepfake case — a video clip + voicemail +
   email (licensed genuine / consent-based manipulated / ambiguous); CPU forensic tools (ffprobe/
   ffmpeg bounded, exiftool, ELA/noise, audio spectral, C2PA verify, hashing); bounded, no network.
3. **Candidate-visible objectives:** investigate the media's authenticity; reach a determination
   with calibrated confidence; recommend a defensible response to the attempted fraud.
4. **Hidden evaluator truth:** the ground-truth class and, for manipulated media, the consent-based
   manipulation log; for ambiguous media, the adjudicated "indeterminate" verdict. Evaluator-only.
5. **Independently verifiable evidence:** sha256 of each artifact; extracted metadata/C2PA claims;
   each forensic transform recorded as a reproducible derived artifact — recomputed server-side.
6. **Required technical changes/findings:** a set of reproducible forensic observations supporting
   the determination, plus a written determination + response recommendation.
7. **Alternative valid solutions:** multiple evidence combinations can support a correct
   determination; for ambiguous cases a well-justified non-conclusion is correct.
8. **Critical failure conditions:** determination unsupported by reproducible evidence;
   over-confidence on an ambiguous case; conflating a learned-detector score with verified
   provenance; broken chain of custody.
9. **Human-review boundaries:** reviewer scores reasoning, calibration, and recommendation quality;
   machine-verified observations are not re-graded; no AI coaching.
10. **Signed assessment records:** signed `UnitResult` + exported signed chain of custody.

### C2 — Adversarial evaluation & mitigation validation (D3, D2) — draft (gated)
1. **Competencies:** structured adversarial evaluation design; failure-mode taxonomy; mitigation
   design; validation methodology. 2. **Environment:** a Valyria LLM application with a defined
   abuse surface; CPU harness + metered inference. 3. **Objectives:** produce a reproducible
   adversarial evaluation, design mitigations, and demonstrate they hold. 4. **Hidden truth:** the
   seeded failure modes + a holdout probe set (evaluator-only). 5. **Evidence:** evaluation run
   records + `model_trace`, replayable; holdout re-run server-side. 6. **Required findings:** a
   documented evaluation + mitigations that pass the holdout. 7. **Alternatives:** input-side,
   model-config, or system-prompt/guardrail mitigations, judged on efficacy + tradeoffs.
   8. **Critical failures:** non-reproducible evaluation; mitigation overfit to the visible set,
   failing holdout. 9. **Review boundaries:** reviewer scores methodology/tradeoffs; holdout result
   machine-verified; no coaching. 10. **Records:** signed `UnitResult` + evidence custody.

### C3 — Model-artifact & supply-chain integrity (D4) — draft (gated)
1. **Competencies:** artifact integrity; unsafe-deserialization analysis; provenance/supply-chain
   controls. 2. **Environment:** Valyria model registry with artifacts + provenance manifests;
   sandboxed CPU analysis (no auto-execution of artifacts). 3. **Objectives:** determine whether an
   artifact is tampered/poisoned and design provenance controls. 4. **Hidden truth:** the injected
   tampering/poisoning + the true provenance chain (evaluator-only). 5. **Evidence:** `file_hash`,
   `model_artifact` BlobRef, provenance `document`; hashes/signatures recomputed server-side.
   6. **Required findings:** a correct integrity determination + a control design that establishes
   provenance. 7. **Alternatives:** signing/attestation, hash-pinning, or build-provenance
   approaches. 8. **Critical failures:** executing a hostile artifact; determination unsupported by
   hashes/provenance. 9. **Review boundaries:** reviewer scores the control design; integrity facts
   machine-verified. 10. **Records:** signed `UnitResult` + artifact custody.

### C5 — AI incident response, assurance & recovery (D6, D1-D4) — draft (gated)
1. **Competencies:** AI-incident detection/triage from telemetry; response; assurance; recovery.
   2. **Environment:** the Valyria AI platform emitting security telemetry into **OpenSearch**
   (reuses the existing cluster); a seeded incident. 3. **Objectives:** detect/triage the incident,
   respond, then assure and recover. 4. **Hidden truth:** the incident timeline + root cause
   (evaluator-only; recomputed from seed). 5. **Evidence:** `event_reference` telemetry +
   `system_state`; detection/correlation and recovery state recomputed server-side. 6. **Required
   findings:** a correct reconstruction + a verified recovery/assurance action. 7. **Alternatives:**
   multiple valid containment/recovery sequences. 8. **Critical failures:** missing the true
   incident; unverified recovery; destructive out-of-scope action. 9. **Review boundaries:**
   reviewer scores IR judgment; telemetry correlation machine-verified. 10. **Records:** signed
   `UnitResult` + telemetry/evidence custody.

### C6 — Integrative capstone (all domains) — draft (gated)
A multi-domain engagement requiring synthesis across D1–D6 (e.g. an agentic-fraud incident involving
a poisoned artifact and manipulated media). All ten fields are instantiated per the composed
domains; the capstone requires both a working technical outcome and a defensible design-review
deliverable, each with independent verification and signed records.

---

## 5. Qualification policy (defensible; no inherited 95%)

- **Per-challenge pass** combines a **hard minimum on machine-verifiable outcomes** (field 5/6 —
  the exploit+holding-fix, the reproducible forensic observations, the recomputed telemetry) with a
  **rubric threshold** on reasoning, secure design, uncertainty calibration, and recommendations.
  The machine-verifiable minimum is gating: a candidate cannot pass on narrative alone.
- **PARALLAX qualification** = passing the **required portfolio** + the C6 capstone, each producing
  a signed `UnitResult`; the overall decision is deterministic over the portfolio. Required-vs-
  elective split (recommended required: C1, C3, C4, C5, C6; C2 required or elective) is confirmed on
  approval.
- **No single numeric bar is inherited from STRATA.** Exact thresholds and weights are set here on
  approval. Rationale: PARALLAX outcomes are heterogeneous (an exploit+fix, a forensic
  determination, an IR reconstruction), so a single percentage is not meaningful; a per-challenge
  gating-minimum-plus-rubric model is more defensible than a blanket 95%.
- All results signed (`signing.sign`), independently verifiable; the deterministic engine and human
  reviewers hold all authority. Governed AI never sets or alters a result.

---

## 6. Evidence requirements by domain

| Domain | Primary evidence kinds | Independent verification |
|---|---|---|
| D1 agentic | `model_trace`, `event_reference` | replay trace; canary/authorization oracle; re-test after fix |
| D2 LLM/RAG | `model_trace`, `document`, `event_reference` | injection/isolation oracle on a declared canary; re-test |
| D3 red team | `model_trace`, evaluation run records | reproduce evaluation; confirm mitigation holds on holdout |
| D4 artifacts | `file_hash`, `model_artifact` BlobRef, `document` | recompute hashes; validate provenance/signature; sandbox check |
| D5 media | `media_asset` BlobRef, `file_hash`, `document` | recompute hash/metadata/C2PA; reproduce transform |
| D6 monitoring/IR | `event_reference` (OpenSearch), `system_state` | recompute detection/correlation; verify recovery state |

Large/binary evidence is a content-addressed BlobRef (never in Postgres/OpenSearch); every access
and transform is a signed `CustodyEvent`; hidden truth stays evaluator-only, recomputed server-side.

---

## 7. Governed AI role in PARALLAX (no coaching, no authority)

The internal AI Orchestration Layer may: propose challenge specifications; analyze scenario
diversity and difficulty; run technical compatibility reviews; generate scenario-generation test
cases; adversarially evaluate **proposed** challenges (pre-promotion stress test); and provide
**advisory post-submission** technical assessment review for a human reviewer. It must **not**:
coach a candidate on an active challenge; reveal the solution path or hidden truth; grant
qualification; alter signed scores; or override deterministic verification. PARALLAX candidates gain
**no** infrastructure privileges beyond the scoped, sandboxed challenge environment.

---

## 8. Minimal implementation sequence (gated; exact deliverables + acceptance tests)

Begin only after the pathway-migration validation is accepted (done this milestone, 13/13 real-DB
checks). Implement the **foundational PARALLAX engineering only**; do **not** auto-implement or
activate the six challenges. Lab A and Lab B are separately gated milestones after the foundation.
Each step is committed/tested/documented and stopped for review.

| Step | Deliverable | Acceptance test |
|---|---|---|
| **F1 Pathway-aware assessment contracts** | `CurriculumDefinition`, `AssessmentUnit`, `UnitResult` models (additive, idempotent `ensure_schema`); pathway-scoped; `UnitResult` signed via existing `signing` | offline suite: a `parallax` curriculum/unit persists and round-trips; `UnitResult` signs + verifies; STRATA `BoardResult`/`score_board2`/`PASS_BAR` unchanged (regression) |
| **F2 Typed evidence & media artifact interfaces** | register `model_trace`/`media_asset`/`file_hash` payload+evidence interfaces in `scenario_spec`; `media-forensics` + `llm-redteam` capability-inventory builders (lift the two `NotImplementedError`s) | offline suite: specs citing the new kinds validate; capability inventories build + `validate_refs` gates unknown refs; unimplemented kinds still rejected until wired |
| **F3 Secure evidence persistence & provenance** | `MediaAsset`/`ModelArtifact` content-addressed store (BlobRef only in DB), `CustodyEvent` (signed, append-only), `EvidenceBundle`; scoped signed-URL serving | offline suite: ingest→sha256→retrieve round-trips; tamper (hash mismatch) is detected + denied; custody log verifies; candidate-scope access control blocks cross-candidate reads |
| **F4 Bounded forensic processing architecture** | job runner for CPU tools (ffprobe/exiftool/ELA/audio/C2PA/hash) under the §6 isolation (timeouts, decode limits, no-net, unprivileged, descriptor-not-shell) | offline suite: a tool job runs within limits and emits a hashed derived artifact; a decode-limit/timeout breach is enforced; no shell execution path exists |
| **F5 Initial candidate workbench foundation** | portal workbench scaffold (reuses auth + Case/CaseSubmission): list authorized assets, run a bounded job, cite results as evidence, submit — **no** solution path, no AI coaching | route tests: candidate sees only assigned-case assets; a job → evidence → `CaseSubmission` round-trips; unauthorized asset access denied; no coaching/hint endpoint exists |
| **Lab A (C1)** *(separately gated)* | the agent/RAG trust-boundary challenge end-to-end on F1–F5 | the C1 field-5/6 acceptance: exploit reaches canary pre-fix, fails post-fix, server-side verified; signed `UnitResult`; CPU + metered only |
| **Lab B (C4)** *(separately gated)* | the synthetic-media forensic investigation end-to-end on F1–F5 | the C4 field-5/6 acceptance: observations recomputed server-side; calibrated determination; signed `UnitResult` + exported signed custody; CPU-only to pass |

"Documented" ≠ "production-ready": a step is done only when its acceptance test passes end-to-end,
committed and reviewed.

---

## 9. Invariants & gates

- Independent of STRATA: own curriculum, assessment, evidence requirements, and qualification
  policy; no inherited 95% bar; six domains composed into integrated challenges, not six boards.
- Qualification-first: no teaching, mentoring, hints, walkthroughs, adaptive solution guidance,
  course-completion qualification, or instructor-dependent progression.
- Reuse-only infrastructure: existing auth, cohort orchestration, Case/CaseSubmission, evidence
  verification, Ed25519 signing, OpenSearch; no second control plane; no Ludus/GOAD/Proxmox; no
  always-on/dedicated GPU; metered inference capped within <$300/mo combined.
- Governed AI: advisory/backend only; never coaches, reveals truth, or touches signed results.
- No general candidate access, act-as, unattended ingestion, paid inference, new GPU, or
  Ludus/GOAD without explicit approval. STRATA six-board rules + 95% unchanged.
- Duration is provisional until §2.1 is defined and approved; the qualification is defined by
  outcomes, not a calendar.
