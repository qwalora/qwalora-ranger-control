# Ranger AI/LLM architecture - scenario engineering, cohort planning, assisted exercise & assessment (for approval)

Linked from `siem/BOARD2_M4_3_ARCHITECTURE.md` (cohort provisioning & lifecycle). This
is design and approval work only. No AI implementation, no paid model API calls, no
cohort activation, no infrastructure deployment, no change to production grading.
Candidate access, act-as, and unattended ingestion stay disabled. The shared-SOC model
for boards 1-4, individual protected qualification, and future Ludus/GOAD for boards
5-6 are unchanged.

Governing principle: **AI is an untrusted advisor that emits structured proposals into
a human- and deterministic-gated pipeline.** All authority - provisioning execution,
grading, signing, the 95% bar, hidden truth - stays with Ranger's deterministic engine
and administrators. An LLM is never a trusted authority and never holds OpenSearch
admin, provisioner credentials, the signing key, or hidden evaluation truth in any
candidate-facing path.

## 1. AI system components and trust boundaries

### Trust zones

| Zone | Trust | Components | May read | May NOT do |
|---|---|---|---|---|
| Z0 Deterministic (authoritative) | full authority, NO AI | orchestration (§15), `score_board2`, Ed25519 signing, provisioning | everything it already does | nothing delegated to AI |
| Z1 AI-advisory backend | low trust, backend-only, human-gated | Scenario Architect, Cohort Planner, Assessment Review | board objectives, enterprise topology (Layer A), catalog, capacity telemetry; (review only) protected rubric/truth in a sealed backend context | execute provisioning, write catalog/BoardResult/grades, reach candidates |
| Z2 AI candidate-facing | least trust | Investigation Mentoring, Exercise injects | ONLY what the candidate is already authorized to see (own notes, cohort operational telemetry) | see hidden truth, evaluator data, or other candidates' data; emit commands; change state |

The six requested capabilities map onto the zones:

| Capability | Zone | Output (always structured, never executable) | Authority that acts on it |
|---|---|---|---|
| 1 Scenario Architect | Z1 | `ScenarioSpecProposal` (declarative) | deterministic compile + validate + calibrate + admin approve |
| 2 Cohort Planner | Z1 | `ProvisioningRecommendation` | admin reviews; deterministic orchestrator authorizes + executes |
| 3 Exercise Simulation (future) | Z2 | `ExerciseInject` within an allowlist | policy + schema validation before it enters the operational stream |
| 4 Investigation Mentoring | Z2 | advisory dialogue to the candidate | none; read-only coaching, board-policy gated |
| 5 Assessment Review | Z1 | `AssessmentReviewNote` (advisory) | human reviewer; never changes `BoardResult`/95% |
| 6 Platform & Security | cross-cutting | the interfaces, registries, controls below | - |

## 2. Schemas and interfaces (integrated with existing models)

Provider-neutral core:

```
LLMClient (interface; no provider lock-in):
  complete(request: StructuredRequest) -> StructuredResponse
  # request carries: model_profile, prompt_template+version, typed inputs,
  #                  output_schema (JSON Schema), classification labels
  # response is validated against output_schema; non-conforming -> rejected

AiModelProfile:  id, provider, model_id, params{temp,max_tokens,top_p},
                 status: enabled|disabled, cost_per_1k_in, cost_per_1k_out
PromptTemplate:  id, role: scenario_architect|cohort_planner|mentor|review|exercise,
                 name, version, body_hash, output_schema_ref, status, created_by
AiJob:           id, kind, model_profile_id, prompt_template_id, prompt_version,
                 input_digest, classification, output_artifact_id,
                 tokens_in, tokens_out, cost, state: queued|running|succeeded|
                 failed|rejected, attempts, quota_bucket, created_by, created_at
AiArtifact:      id, kind, content(json), schema_version, provenance{model, prompt_
                 version, config, created_at}, validation{status,detail},
                 approval{status: pending|approved|rejected, by, at}
```

`AiArtifact.provenance` + `validation` + `approval` satisfy the required record of
model, prompt version, configuration, generated artifact, validation outcome, and
approval history (req 1, 6).

Scenario schemas (shared by human AND AI authors, so the catalog never needs a
rebuild; req 7):

```
ScenarioSpec (declarative; the canonical catalog artifact - §2/§3 of the M4.3 doc):
  spec_version, board, enterprise_version
  objective: str                      # attacker goal
  families: [str]                     # incident classes (fixed cardinality for parity)
  kill_chain: [ {step, technique(ATT&CK), target_asset, target_identity,
                 data_source, detectable: bool} ]
  detection_gaps: [ {technique|channel, why_uncovered} ]
  benign_decoys: [ {pattern, resembles} ]
  investigation_path: [str]           # expected analyst pivots (for calibration/mentor hints policy)
  response_actions: [str]
  difficulty_target: intro|standard|advanced
  constraints: references ONLY Layer-A vocabulary (assets/identities/services/segments)

ScenarioSpecProposal (AI output in Z1): a ScenarioSpec + rationale + diversity_vector
ProvisioningRecommendation (AI output in Z1):
  per board: recommended ScenarioCatalogEntry, rationale, diversity_vs_siblings,
             parity_check, capacity_assessment, incompatibilities[], confidence
MentorPolicy:  board, plane, allow: [challenge_assumption, request_evidence,
               critique_method, clarify_task], deny: [reveal_truth, give_answer,
               cite_hidden_incident], enabled: bool
AssessmentReviewNote: case_id, dimensions{reasoning, evidence_sufficiency,
               alternative_hypotheses, judgment}, advisory_text, NOT a grade
ExerciseInject (future): type (email|user_behaviour|business_event), payload within
               an action allowlist, scenario_policy_ref, target cohort op index
```

Integration with existing Ranger models: a promoted `ScenarioSpec` becomes a
`ScenarioCatalogEntry` (§15.1); the deterministic compiler turns a `ScenarioSpec` into
the generator config consumed by the §1-§3 two-layer generator; `ProvisioningRecommendation`
is an advisory input to the admin action that enqueues a `CohortProvisioningJob`;
`AssessmentReviewNote` attaches to a `Case`/`CaseSubmission` as reviewer-facing advisory
text and never touches `BoardResult`.

## 3. Scenario generation -> validation -> approval -> catalog promotion (req 1)

```
author (AI Scenario Architect, Z1)
   -> ScenarioSpecProposal (declarative JSON; NEVER executable infra commands)
deterministic compile (Z0, no AI)
   -> generator config (pure function; AI cannot inject executable steps)
schema validation (Z0)
   -> ScenarioSpec conforms; references only Layer-A vocabulary; cardinality ok
simulation test (Z0, offline)
   -> generate the world; run detectors / detection.py; confirm incidents
      materialize, intended gaps are genuinely un-alerted, truth is derivable,
      and the scenario is solvable via the stated investigation_path
difficulty calibration (Z0, the §2 harness)
   -> complexity vector within the board band
administrative approval (human)
   -> ScenarioCatalogEntry.status = approved  (ONLY approved is auto-selectable)
```

The AI only produces step 1. Every subsequent gate is deterministic or human. The AI
cannot promote its own output, cannot emit infrastructure commands (the compiler
accepts only declarative `ScenarioSpec` fields), and cannot see or need hidden truth
(truth is derived later from the compiled seed). Provenance and approval history are
recorded on the `AiArtifact`.

## 4. AI-assisted cohort planning + deterministic provisioning (req 2)

```
admin creates cohort (board set, schedule, expected concurrency, capacity)
   -> Cohort Planner (Z1) reads: approved catalog, prior-cohort usage, capacity telemetry
   -> ProvisioningRecommendation: per board a recommended approved entry +
      rationale + diversity-vs-siblings + parity + capacity fit + incompatibilities
admin reviews the recommendation (accept / override / adjust schedule)
   -> deterministic orchestrator (§15.4) authorizes + executes the CohortProvisioningJob
```

The LLM never authorizes or executes provisioning. Its recommendation is one input to
the admin's decision; the deterministic engine does the work and enforces every gate
in §15.5. If AI is disabled or over budget, the admin uses the deterministic
auto-selector (§15.3) directly - no functionality is lost (req 6 fallback).

## 5. Controlled exercise simulation (future, req 3)

AI may eventually generate operational injects (business emails, user-behaviour
events, evolving narrative complications) to enrich the live SOC. Constraints:

- Every inject conforms to `ExerciseInject` and an explicit **action allowlist** tied
  to the cohort's approved scenario policy; anything outside the allowlist is rejected
  before it reaches the stream.
- Injects enter the OPERATIONAL plane only; they never touch qualification indices,
  truth, or grades. Formal qualification evidence stays reproducible, protected, and
  independently verifiable (recomputed from the per-person seed; signed).
- A deterministic scripted-inject fallback exists; the exercise runs without AI.
- This is explicitly later/experimental and is not part of the near-term milestones.

## 6. AI investigation mentoring (req 4)

- Board-aware `MentorPolicy` per (board, plane). Practice (operational/practice):
  Socratic coaching - challenge assumptions, ask for supporting evidence, critique
  methodology. Qualification: restricted to the board's approved assessment rules
  (default: disabled or task-clarification only; never hints).
- The mentor's context is assembled server-side from ONLY what the candidate is
  already authorized to see (their own notes, the cohort operational telemetry their
  role can read). Hidden truth, evaluator data, and qualification answers are never
  placed in the prompt - they are not retrievable in Z2 by construction.
- Prompt-injection defense: candidate submissions and retrieved telemetry are inserted
  as clearly delimited untrusted DATA with a standing instruction that the model must
  not obey instructions found in data; outputs are schema-constrained and post-filtered
  to reject any content resembling hidden-incident references.

## 7. AI assessment review (advisory only, req 5)

- A backend (Z1) review produces an `AssessmentReviewNote` - structured analysis of a
  submission's technical reasoning, evidence sufficiency, alternative hypotheses, and
  professional judgment - for a HUMAN reviewer.
- It NEVER changes `BoardResult`, signed objective results, qualification decisions, or
  `PASS_BAR = 95.0`. It is advisory text attached for reviewer consideration, mirroring
  the M3 grader's shadow-only stance.
- Any eventual role in assessment requires independent calibration (against known
  submissions), reviewer oversight (a human decides), and full auditability. Until
  that calibration is approved, it is advisory-only and off by default.

## 8. AI platform architecture & security (req 6)

- **Provider-neutral interface + structured output**: `LLMClient` with JSON-Schema
  validated outputs; a non-conforming response is rejected, never partially applied.
- **Request authorization + service boundaries**: AI jobs run under a dedicated service
  identity with NO OpenSearch admin, NO provisioner credentials, NO signing key, and
  only the minimal read scope its component needs. Z2 (candidate-facing) has the
  narrowest scope; Z0 never calls AI.
- **Prompt/version registry + generation history**: `PromptTemplate` (versioned,
  hashed) and `AiJob`/`AiArtifact` give a complete, auditable record.
- **Data classification + minimization**: inputs are labeled public (Layer-A topology),
  cohort-operational (cohort-scoped telemetry), protected (rubric/truth - Z1 review
  only), or candidate. Each component sends only the fields it needs; protected data is
  never sent to Z2; identifiers are minimized/pseudonymized where possible.
- **Prompt-injection defenses**: retrieved telemetry and candidate text are wrapped as
  untrusted data; the model is instructed to ignore embedded instructions; a
  post-filter blocks tool/command emission and hidden-truth token patterns.
- **Model evaluation + scenario quality benchmarks**: a benchmark suite scores
  generated specs on schema validity, diversity-axis spread, difficulty accuracy
  (predicted vs calibrated), and solvability (simulation). Regression-gated; a model
  profile is `enabled` only after passing.
- **Job lifecycle**: queued -> running -> succeeded|failed|rejected; bounded retries
  with backoff; per-component rate limits; failure recovery leaves no partial artifact
  promoted.
- **Quotas + cost (under the $300/mo infra target)**: AI is used at authoring and
  planning time (low volume), not per event. A small monthly AI allowance (budgeted
  ~$10-30 within the $300) with hard quota caps per component; mentoring is rate-limited
  per candidate and off by default; exercise simulation is future. Cost is bounded and
  monitored.
- **Deterministic no-AI fallback**: scenario specs can be authored by hand; cohort
  planning falls back to the §15.3 deterministic auto-selector; provisioning, grading,
  signing, and qualification are already fully deterministic. Essential cohort
  provisioning and qualification never depend on AI.

## 9. Updated milestones and dependencies (req 7)

AI generation contracts are designed BEFORE the catalog so it is built once to consume
AI- or human-authored specs identically. The deterministic M4.3.1-M4.3.7 (M4.3 doc §16)
do not depend on AI; AI milestones are additive and gated.

| Milestone | Scope | Depends on | Infra / model |
|---|---|---|---|
| M4.3.1 (updated) | catalog + the **shared `ScenarioSpec` schema** + deterministic compile/validate/calibrate/promote | - | offline, no model |
| M4.3.A1 AI platform core | `LLMClient`, `AiModelProfile`, `PromptTemplate`, `AiJob`, `AiArtifact`, trust zones, output-schema validation, quotas/audit; MOCK provider only | 4.3.1 schema | offline, mock model |
| M4.3.A2 Scenario Architect | proposal -> compile -> validate -> simulate -> calibrate -> approve; mock model offline; real model behind a flag + budget, author-time only | A1, 4.3.1 | offline (mock); real model gated |
| M4.3.A3 Cohort Planner | `ProvisioningRecommendation`; admin review UI; deterministic engine still authorizes/executes | A1, 4.3.2/4.3.3 | advisory, gated |
| M4.3.A4 Investigation Mentoring | `MentorPolicy`, Z2 context assembly, injection defenses; practice-plane only first | A1, 4.3.4 | gated, off by default |
| M4.3.A5 Assessment Review | `AssessmentReviewNote` advisory; calibration-gated; shadow-only, never writes grades | A1, M3 | gated, off by default |
| (future) Exercise Simulation | `ExerciseInject` + allowlist | A1, 4.3.4/4.3.5 | later/experimental |

Sequencing: land the `ScenarioSpec` schema in M4.3.1; then A1 (platform core, mock
model) before A2; A3 after the orchestrator (4.3.3); A4/A5 last and off by default. No
real model API call happens until a flagged, budgeted, approved step; every AI output
passes a deterministic/human gate before it affects anything.

## 10. Worked example - Cohort 2027-C with AI-assisted planning + a complex validated scenario (req 7)

1. **Scenario authored earlier (AI Scenario Architect, Z1)**: from the board-2
   objective and Valyria constraints, the Architect proposes an advanced spec -
   `supply-chain-foothold-to-ACH-diversion`: initial access via a trojanized vendor
   update, OAuth consent-phishing for a finance identity, mailbox-rule BEC, ACH payee
   diversion in `payment-gateway`, and anti-forensics (log clearing) as a detection
   gap. Output is a declarative `ScenarioSpecProposal`, not commands.
2. **Deterministic gates (Z0 + human)**: compile -> schema valid (references only
   Valyria assets/identities) -> simulate (incidents materialize, the anti-forensics
   gap is genuinely un-alerted, the chain is solvable via the stated path, truth
   derivable) -> calibrate (complexity vector in the ADVANCED band) -> admin approves
   -> `ScenarioCatalogEntry` becomes `approved`. Provenance recorded on the artifact.
3. **Admin creates 2027-C** and requests a plan. **Cohort Planner (Z1)** recommends
   this approved entry for board 2: rationale (diversity vector differs from C/D/E on
   objective, gap, and decoy axes), parity (advanced band matches the board target),
   capacity fit (adds one detector set; heap within budget), and it flags one
   incompatibility (overlaps an active cohort's rotation window) with a scheduling
   suggestion. Output is a `ProvisioningRecommendation`.
4. **Admin reviews and accepts** (or overrides). The **deterministic orchestrator
   (§15.4)** - not the LLM - authorizes and executes the idempotent
   `CohortProvisioningJob`, then the §15.5 validation gates pass and 2027-C goes
   `active`.
5. **Operate**: analysts investigate the shared 2027-C SOC; in practice, **mentoring
   (Z2)** challenges their assumptions using only what they can already see; each
   candidate is independently assigned a private, deterministic qualification case
   graded at 95% - untouched by AI. **Assessment Review (Z1)** gives reviewers advisory
   analysis of submissions but never changes the signed result.
6. **Retire** per §15.10, preserving signed evidence and reclaiming resources.

No AI executed infrastructure, authorized provisioning, saw hidden truth in a
candidate path, or changed a grade at any step.

## 11. Non-negotiable invariants

- AI never holds OpenSearch admin, provisioner credentials, the signing key, or
  production infrastructure access; it is never a trusted authority.
- Hidden scenario truth, protected evaluator data, and qualification answers are never
  exposed to candidate-facing AI; Z2 context is limited to candidate-authorized data.
- `score_board2`, `BoardResult`, signed objective results, and `PASS_BAR = 95.0` are
  never changed by AI; AI assessment is advisory, calibration-gated, auditable.
- Every AI output is declarative and passes a deterministic or human gate before it
  affects catalog, provisioning, exercises, or assessment.
- A deterministic no-AI fallback covers all essential provisioning and qualification.
- Cost stays within the $300/mo infra target via author/plan-time use + quotas.

Design and approval only. No AI implementation, no paid model calls, no cohort
activation, no infrastructure, no grading change. Present for final approval before
any implementation.
