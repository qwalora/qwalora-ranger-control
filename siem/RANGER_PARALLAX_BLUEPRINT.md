# RANGER PARALLAX — qualification blueprint (for approval)

Pathway id: `parallax`. Public branding (display-only): "RANGER PARALLAX — AI Security,
Adversarial Systems & Digital Trust". Companion to `siem/RANGER_TWO_TRACK_ARCHITECTURE.md`.
**Design and approval work only.** This blueprint defines PARALLAX independently of STRATA; it
does **not** inherit STRATA's six-board structure or its 95% standard, and nothing here is
implemented or activated until approved. All candidate-access, spending, infrastructure, and
grading gates remain in force.

PARALLAX is an **advanced, independent technical qualification** for experienced practitioners
(senior/staff security engineers, red-team specialists, AI-security specialists, security
architects). It establishes whether a candidate can independently investigate unfamiliar AI
systems, find genuine weaknesses, make defensible decisions, implement solutions, and prove
outcomes with verifiable evidence. It is **not** a course and contains no teaching, mentoring,
walkthroughs, or solution hints.

---

## 1. Competency domains → what a PARALLAX holder can demonstrably do

Six domains (from the refinement directive). Each line states the *capability being qualified*,
not a lesson.

- **D1 Agentic AI security, authorization & tool-use boundaries.** Independently scope and confine
  a tool-using agent: find and prove authorization failures (confused deputy, over-broad tool
  scope, unsafe tool chaining, out-of-scope side effects), then design and implement boundaries
  that hold under re-test.
- **D2 LLM & RAG security.** Find and prove trust-boundary and data-isolation failures in an
  LLM/RAG application (direct and indirect prompt injection, retrieval authorization bypass,
  cross-tenant leakage, context poisoning), then remediate verifiably.
- **D3 AI red teaming & adversarial evaluation.** Run a structured adversarial evaluation of a
  model/application, characterize failure modes with reproducible evidence, design mitigations,
  and **validate the mitigations actually hold** (not merely proposed).
- **D4 AI infrastructure, model artifacts, data provenance & supply chain.** Investigate model/
  artifact integrity and provenance: unsafe deserialization, tampered/poisoned/backdoored
  artifacts, broken provenance, supply-chain exposure; design controls and prove integrity.
- **D5 Synthetic-media forensics, identity abuse & multimodal fraud.** Conduct a defensible
  forensic investigation of synthetic/real media with provenance, metadata, and reproducible
  observations; reach a calibrated determination and defensible response.
- **D6 AI security monitoring, incident response, assurance & recovery.** Detect, triage, and
  respond to an AI-system security incident from telemetry; then assure the system and recover,
  with evidence.

These are **competency domains, not assessment boards.** PARALLAX composes them into a smaller set
of **integrated challenges** (below), each deliberately spanning multiple domains, because real AI
security work is cross-disciplinary.

---

## 2. Challenge architecture (integrated, not one-board-per-domain)

Unit types (reused generic `AssessmentUnit`, §1 of the two-track doc):

- **lab-challenge** — an authorized hands-on engagement in the Valyria Financial AI environment:
  investigate, attack within scope, remediate, verify.
- **case-investigation** — a forensic/IR investigation producing a defensible determination and
  evidence (e.g. media forensics, incident reconstruction).
- **design-review** — a secure-design / assurance deliverable: an architecture or control design
  the candidate must justify and that is checked against adversarial evaluation.

Recommended qualifying portfolio (**for approval** — a recommendation, not a fixed law):

| Challenge | Primary domains | Unit type | Nature |
|---|---|---|---|
| C1 Agent & RAG trust-boundary engagement | D1, D2 | lab-challenge | exploit an authorized weakness, then implement a holding mitigation |
| C2 Adversarial evaluation & mitigation validation | D3, D2 | lab-challenge | structured red-team + prove mitigation holds |
| C3 Model-artifact & supply-chain integrity | D4 | case-investigation + design-review | investigate a tampered artifact; design provenance controls |
| C4 Synthetic-media / multimodal fraud investigation | D5 | case-investigation | the executive-deepfake fraud case; calibrated determination |
| C5 AI incident response, assurance & recovery | D6, D1–D4 | lab-challenge | detect/triage/respond via OpenSearch telemetry; assure + recover |
| C6 Integrative capstone | all | lab-challenge + design-review | a multi-domain engagement requiring synthesis |

Day-one minimum (§8 of the two-track doc) delivers **C1 (Lab A)** and **C4 (Lab B)** as genuine,
independently verified assessed labs; C2/C3/C5/C6 are sequenced, gated milestones.

### Recommended structure, duration & prerequisites (independent of STRATA)

- **Admission (selective):** PARALLAX screens for demonstrated senior AI/security experience
  before enrollment; it is not open-entry and not a beginner path. (Admission criteria are an
  admin/program policy, approved separately.)
- **Duration/structure (recommendation for approval):** a challenge-portfolio format, roughly a
  **10–14 week** qualification window (independent of STRATA's 26 weeks), each integrated challenge
  a multi-day engagement with its own scope-of-engagement and evidence requirements. There is no
  day-count parity with STRATA and none is implied.
- **Prerequisites between challenges:** capability-based, not course-completion. A later challenge
  may require an earlier qualifying result where the engineering genuinely depends on it; there is
  no tutorial-driven or instructor-dependent progression.

---

## 3. Senior-level challenge engineering principles

Every PARALLAX challenge must be hard because of the engineering and reasoning required, **not**
artificial obscurity. Each qualifying challenge deliberately includes:

- complex, enterprise-realistic dependencies (the Valyria AI platform, not a toy);
- multiple plausible root causes and **conflicting or incomplete evidence**;
- realistic operational constraints and scope-of-engagement rules;
- adversarial behavior to reason about;
- architectural tradeoffs with more than one technically defensible answer;
- **independent** investigation (no provided solution path);
- **actual remediation / system change**, not just a written finding;
- **reproducible outcome verification** (the fix is re-tested server-side; the observation is
  recomputed);
- room for **alternative defensible approaches**, scored on soundness rather than matching a single
  expected answer.

Candidates receive: operational instructions, environment specifications, challenge objectives,
scope-of-engagement rules, tooling documentation, and evidence-submission requirements. They do
**not** receive: the solution, hints, adaptive guidance, or a walkthrough.

---

## 4. Assessment framework & scored dimensions

Each challenge is scored on dimensions weighted per its blueprint. Dimension 1 is
machine-verifiable; the rest are rubric-scored by human reviewers (optionally with governed,
post-submission AI advisory review that never sets the result).

1. **Reproducible technical observations (authoritative).** Did the candidate produce the correct,
   verifiable facts — a canary reached/blocked, a hash, an extracted C2PA claim, a replayable
   `model_trace`, a telemetry correlation? Recomputed server-side against the evidence store,
   exactly as `case_contract.verify_evidence` checks SOC citations.
2. **Investigative reasoning.** The chain from evidence to conclusion under conflicting/incomplete
   information.
3. **Secure design & remediation quality.** For attack+fix challenges: does the implemented
   mitigation **actually hold** on re-test (authoritative, re-verified), and is the design sound
   and defensible?
4. **Uncertainty calibration.** Confidence appropriate to evidence; ambiguous cases reward correct
   non-conclusion and penalize overconfidence.
5. **Defensible recommendations & alternatives.** Soundness of the recommended response and
   recognition of valid alternative approaches and tradeoffs.

### Proposed qualification policy (for approval — not STRATA's 95%)

- Each required challenge has a **blueprint pass threshold** combining a **hard minimum on
  Dimension 1** (verifiable observations / a holding mitigation) with a **rubric threshold** on the
  remaining dimensions. Dimension 1 is gating: a candidate cannot pass a challenge on narrative
  alone.
- PARALLAX qualification = passing the **required portfolio** (recommended: C1, C3, C4, C5, plus
  the C6 capstone; C2 required or elective — to confirm) and the capstone, each producing a signed
  `UnitResult`. The overall qualification decision is deterministic over the portfolio.
- **No single numeric bar is inherited from STRATA.** Exact thresholds, weights, and the
  required-vs-elective split are set in this blueprint on approval.

All results are signed (`signing.sign`) and independently verifiable; the deterministic engine and
human reviewers hold all authority.

---

## 5. Evidence requirements by domain

| Domain | Primary evidence kinds | Independent verification |
|---|---|---|
| D1 agentic | `model_trace` (prompt/tool-call chain), `event_reference` (agent/tool telemetry) | replay trace; canary/authorization oracle; re-test after fix |
| D2 LLM/RAG | `model_trace`, `document` (retrieved artifacts), `event_reference` | injection/isolation oracle on a declared canary; re-test after fix |
| D3 red team | `model_trace`, evaluation run records | reproduce the evaluation; confirm mitigation holds |
| D4 artifacts | `file_hash`, `model_artifact` BlobRef, `document` (provenance manifest) | recompute hashes; validate provenance/signature; sandbox integrity check |
| D5 media | `media_asset` BlobRef, `file_hash`, `document` | recompute hash/metadata/C2PA; reproduce forensic transform |
| D6 monitoring/IR | `event_reference` (OpenSearch telemetry), `system_state` | recompute detection/correlation from telemetry; verify recovery state |

Large/binary evidence is a content-addressed BlobRef (never in Postgres/OpenSearch); every access
and transform is a signed `CustodyEvent`; hidden truth stays evaluator-only and is recomputed
server-side.

---

## 6. Governed AI role in PARALLAX (no coaching, no authority)

The internal AI Orchestration Layer may: propose challenge specifications; analyze scenario
diversity and difficulty; run technical compatibility reviews; generate scenario-generation test
cases; **adversarially evaluate proposed challenges** (pre-promotion stress test); and provide
**advisory post-submission** technical assessment review for a human reviewer.

It must **not**: provide live candidate coaching on an active challenge; reveal the solution path
or hidden truth; independently grant qualification; alter signed objective scores; or override
deterministic verification. PARALLAX candidates likewise gain **no** infrastructure privileges
beyond the scoped, sandboxed challenge environment.

---

## 7. Day-one minimum qualification scope (the two assessed labs)

Delivered first, and only called production-ready once built + independently truth-established +
end-to-end reproducible-verification-passing + signed-submission-verifying:

- **Lab A (C1): Agent/RAG security** — exploit an authorized trust-boundary weakness against a
  declared canary, implement a mitigation, prove it holds. Independent verification via the
  canary oracle + replayed `model_trace`. CPU + metered inference only.
- **Lab B (C4): Synthetic-media forensic investigation** — the executive-deepfake multimodal-fraud
  case; reproducible CPU forensic observations recomputed server-side; calibrated determination;
  defensible response; signed submission + exported signed chain of custody. CPU-only to pass.

Both exercise the full stack (auth, Valyria AI environment, evidence + custody, workbench
isolation, assessment, signing) with genuine candidate actions and independent evidence
verification, and neither requires GPU or Ludus.

---

## 8. Invariants & gates

- Independent of STRATA: own curriculum, assessment, evidence requirements, and qualification
  policy; no inherited 95% bar; six domains composed into integrated challenges, not six boards.
- Qualification-first: no teaching, mentoring, hints, walkthroughs, adaptive solution guidance,
  course-completion qualification, or instructor-dependent progression.
- Reuse-only infrastructure: existing auth, cohort orchestration, Case/CaseSubmission, evidence
  verification, Ed25519 signing, OpenSearch; no second control plane; no Ludus/GOAD/Proxmox;
  no always-on/dedicated GPU; metered inference capped within <$300/mo combined.
- Governed AI: advisory and backend only; never coaches candidates, reveals truth, or touches
  signed results.
- STRATA unchanged throughout.
