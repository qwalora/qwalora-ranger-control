# PARALLAX — AI Security, Adversarial Systems & Digital Trust (Phase 1 foundations)

PARALLAX is Qwalora Ranger's advanced qualification pathway for **AI-security, adversarial-systems,
and digital-trust engineering**. It shares the Ranger platform with STRATA (cybersecurity) but is
architecturally distinct. PARALLAX is **not** a general machine-learning engineering qualification and
**not** a curriculum in statistics or reproducible ML experimentation. It measures an engineer's
ability to find, prove, and reason about security and trust failures in AI systems through bounded,
executable investigations with server-protected grading truth and independently verifiable evidence.

This document is the Phase 1 foundation and the mission of record. It is design plus one working,
executable first assessment (Lab A). Board count, duration, overall passing threshold, and
qualification authority are **not** assigned here and must not be set without separate approval.

## Mission and competency domains

PARALLAX's established competency domains (these are domains, not necessarily boards):

1. **Agent and tool authorization security** — a tool-using AI agent stays within its authorized tool
   and resource scope; unauthorized or out-of-scope tool use and cross-tenant access are detected.
2. **LLM and RAG trust boundaries, prompt injection, and data isolation** — untrusted retrieved or
   user content cannot subvert authorization or exfiltrate tenant-isolated data.
3. **AI red teaming and adversarial evaluation** — systematic adversarial probing and the honest
   evaluation of model/system robustness and failure modes.
4. **Model and AI supply-chain security** — integrity and provenance of models, weights, datasets, and
   pipeline artifacts; detection of tampering and poisoning.
5. **Synthetic media, multimodal fraud, and digital provenance** — detection and provenance
   verification for manipulated or synthetic media.
6. **AI incident response and forensic investigation** — investigating an AI-involved incident,
   reconstructing what happened, and producing defensible, evidence-backed findings.

For any domain to become a graded board, it must first define all ten of: (1) what the engineer must
demonstrate; (2) authorized tools + execution environment; (3) prerequisites; (4) the task/investigation;
(5) the artifact produced; (6) independent evaluation; (7) critical-failure conditions; (8) repeatability
and integrity; (9) safely revealed feedback; (10) why it measures competence, not memorization.

## One platform, two tracks (compatibility architecture)

Reused unchanged (pathway-neutral): `pathways` (PARALLAX identity); `siem.assessment_contract.decide`
(the shared ten-concern decision engine, STRATA and PARALLAX policy branches); the `siem.evaluator`
Evaluator / signed ObjectiveCheckResult / ProtectedTruthHandle / EvaluatorScope contract; top-level
`signing` (Ed25519); `siem.schema.keyed_mac`; and the pathway-scoped, signed `models.UnitResult`
record. STRATA grading is untouched: its objective bar stays `program.PASS_BAR = 95.0`.

Kept STRATA-isolated (PARALLAX builds parallels, never extends): the six-board STRATA ladder
(`program.py`), `siem/board_variants.py`, STRATA scenario generators/graders, Board 2 qualification.

Hard isolation invariant (enforced by `assessment_contract.decide` and by the pathway-qualification
engine): a PARALLAX decision requires a PARALLAX-scoped authorization and a PARALLAX blueprint, so a
PARALLAX submission can never award STRATA credit and vice versa.

## Qualification boundary (assessment completion is NOT pathway qualification)

Two distinct levels, deliberately separated:

- **Assessment completion** — the outcome of one lab: a signed assessment record stating whether that
  lab's objective checks passed, its critical-failure vetoes are clear, and its human review passed. A
  single-assessment decision is **assessment-only**: `assessment_contract.decide` returns
  `qualified=False` for every PARALLAX assessment **regardless of any activation flag** (the prior
  coupling to `RANGER_PARALLAX_QUALIFICATION_ACTIVE` at the assessment level is removed; that flag is
  now only an informational surface flag). No score, remediation, reviewer pass, signature, or flag can
  make a lab read as a final award.
- **Pathway qualification** — a separate decision (`parallax.pathway_qualification.decide_pathway`)
  that requires ALL of: a **signed, authorized portfolio approval** (`governance.approve_portfolio`)
  binding the exact required-competency inventory — there is no caller-controlled `approved` boolean; a
  verified, signed, passing assessment record for every required competency whose OWN signed identity
  (candidate, cohort, assessment id, attempt, provenance) matches the slot, so a valid signature
  transplanted from another candidate or assessment is rejected; an independent **authorized, assigned
  reviewer adjudication** bound to that same identity and provenance for each; and a separately-
  authorized platform activation (`RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE`, OFF). It fails closed
  on any missing piece. No approved portfolio exists yet, so pathway qualification is currently
  impossible by construction.

The pathway gate (`RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE`) is the only qualification activation,
and it is OFF and kept off in Phase 1.

### Governance, reviewer authority, and binding

- **Versioned approval governance** replaces any hardcoded `approved=True`. An assessment spec binds a
  candidate instance only when an authorized admin has issued a signed approval record binding the
  **complete consequential scoring specification** — the spec identity, metric and threshold, and the
  full blueprint hash (rubric dimensions, critical-failure conditions, objective evaluator/checks,
  decision policy, evidence requirements, environment version) (`parallax.governance`). Any material
  change to the spec or blueprint moves the scoring-spec hash and invalidates the approval until it is
  reissued. An unapproved or drifted assessment cannot produce an instance.
- **Authenticated, assigned reviewer authority** (`parallax.review`): a reviewer adjudication is
  accepted only when the reviewer is an authorized reviewer AND was assigned to this
  (candidate, cohort, assessment, attempt), and the adjudication is a signed record bound to that
  identity and to the assessment record's hash. A mere non-empty reviewer id is rejected. Reviewer
  decisions and rubric scores are never accepted from the candidate-accessible boundary.
- **Cryptographic + logical binding**: the signed final assessment record binds the submission content
  hash, the evidence/citation references, the evaluator's signed result, the verified reviewer
  adjudication, the spec/blueprint hash, the instance-contract MAC, and the
  candidate/cohort/assessment/attempt identity. Tampering with any part invalidates the record.

## PX-1 (leakage-safe model evaluation): experimental component only

PX-1 remains in the tree as a **clearly-labeled, reusable experimental assessment component** for
data-integrity / leakage reasoning. It is **not** a mandatory PARALLAX qualification, **not** the first
PARALLAX assessment, and does **not** drive the approved progression. The previously-proposed general-ML
"P2" progression is **cancelled**. PX-1 is retained only because its leakage-ablation evaluation pattern
is a useful, well-tested building block that an AI-security lab may reuse.

## Lab A — Agent & Tool Authorization Security (the actual first assessment)

Competency 1 (agent/tool authorization security) with material overlap into competency 2 (RAG trust
boundaries / data isolation). Implemented in this phase as a working vertical slice.

**Environment (bounded, offline, deterministic).** An enterprise simulator with: an AI agent serving
multiple tenants; a fixed tool catalog (read/search/share/export/delete/escalate class tools); an
authorization policy (per-principal, per-tenant tool and resource scope); tenant-scoped documents; a
realistic sequence of observable agent events (tool calls with principal, tenant, resource, and an
OBSERVED outcome); approved/benign operations that must keep working; and adversarial events driven by
untrusted retrieved content (RAG) carrying injected instructions that attempt cross-tenant access,
out-of-scope tools, or privilege escalation. No live model, no network, no GPU, no external inference,
no execution of candidate-supplied code.

**Task.** The candidate investigates the observable event log and the authorization policy and submits
**evidence-backed findings**: for each event they flag, a classification (actual unauthorized access /
blocked attempt / legitimate) with a cited event id as evidence, plus a short written root-cause /
policy-gap analysis. The grading truth (the true per-event classification and the injected-instruction
provenance) is sealed server-side and never shown to the candidate.

**Objective evaluation (deterministic, replay-based).** The evaluator independently replays the policy
over the sealed event log to recompute truth, then scores the candidate's findings: it distinguishes
actual unauthorized access (a breach that occurred), successfully blocked attempts, unsupported claims
(a flagged event with no valid supporting citation), and legitimate activity. Precision and recall over
breaches are both scored, so flagging everything as a breach fails (false positives on benign ops tank
precision; "deny everything" cannot pass). Critical-failure vetoes: missing an actual cross-tenant
breach that occurred, or asserting a breach with no valid evidence citation. The narrative analysis is
human-reviewed. Per-candidate instances differ (principals, tenants, which events are breaches vs
blocked), so solutions do not transfer. Simulated incidents are always labeled as simulated; they are
never presented as externally observed.

## What Phase 1 delivers (this branch)

Governance (`governance`), reviewer authority (`review`), pathway-qualification separation
(`pathway_qualification`); the Lab A simulator (`laba_sim`), the implemented `agent_authorization`
evaluator (`laba_evaluator`), the Lab A spec/blueprint (`laba_blueprint`), the candidate-safe brief
(`laba_brief`), and the end-to-end orchestration (`laba_assessment`); an optional workbench route behind
a default-off flag; and tests (positive, negative, tampering, authorization, cross-candidate,
cross-tenant, replay, concurrency, STRATA regression). PX-1 is retained as an experimental component.

Phase 1 enables no public enrollment and no real awards. No board count, duration, overall threshold,
or qualification authority is declared. No paid services, GPUs, or external model APIs are used.
