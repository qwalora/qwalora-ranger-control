# Ranger AI/LLM architecture - scenario engineering, cohort planning, assisted exercise & assessment (for approval)

Linked from `siem/BOARD2_M4_3_ARCHITECTURE.md` (cohort provisioning & lifecycle). This
is design and approval work only.

> Scope note: this document describes the internal **AI Orchestration Layer** (an untrusted
> advisor that helps staff author/operate *any* pathway). It is **not** the candidate-facing
> **RANGER PARALLAX** pathway (AI security, adversarial systems & digital trust), which is
> defined in `siem/RANGER_TWO_TRACK_ARCHITECTURE.md` with its qualification blueprint in
> `siem/RANGER_PARALLAX_BLUEPRINT.md`. The two are deliberately distinct: this layer holds no
> authority in any pathway, and PARALLAX candidates gain no infrastructure privileges.
 No AI implementation, no paid model API calls, no
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

> **Qualification-first correction (supersedes any teaching framing below).** Ranger is an
> independent technical **qualification** platform for experienced practitioners, not a training
> or teaching service. The internal AI is therefore **governed and non-instructional**: it may
> propose challenge specifications, analyze scenario diversity/difficulty, run technical
> compatibility reviews, generate scenario-generation test cases, adversarially evaluate *proposed*
> challenges, and provide **advisory post-submission** technical assessment review. It must **not**
> provide live candidate coaching on an active qualification challenge, reveal the solution path,
> disclose hidden truth, grant qualification, alter signed objective scores, or override
> deterministic verification. The former candidate-facing "investigation mentoring" / live-hint
> capability is **withdrawn** (see the corrected Z2 row and capability table). Candidates receive
> operational instructions, environment specs, challenge objectives, scope-of-engagement rules,
> tooling documentation, and evidence-submission requirements — never the solution path.

## 1. AI system components and trust boundaries

### Trust zones

| Zone | Trust | Components | May read | May NOT do |
|---|---|---|---|---|
| Z0 Deterministic (authoritative) | full authority, NO AI | orchestration (§15), `score_board2`, Ed25519 signing, provisioning | everything it already does | nothing delegated to AI |
| Z1 AI-advisory backend | low trust, backend-only, human-gated | Scenario Architect, Cohort Planner, Assessment Review | board objectives, enterprise topology (Layer A), catalog, capacity telemetry; (review only) protected rubric/truth in a sealed backend context | execute provisioning, write catalog/BoardResult/grades, reach candidates |
| Z2 AI candidate-facing | **withdrawn under the qualification-first model** | none (no live coaching, no solution hints, no mentoring on active challenges) | n/a | provide any live assistance on an active qualification challenge; reveal the solution path or hidden truth |

The six requested capabilities map onto the zones:

| Capability | Zone | Output (always structured, never executable) | Authority that acts on it |
|---|---|---|---|
| 1 Scenario Architect | Z1 | `ScenarioSpecProposal` (declarative) | deterministic compile + validate + calibrate + admin approve |
| 2 Cohort Planner | Z1 | `ProvisioningRecommendation` | admin reviews; deterministic orchestrator authorizes + executes |
| 3 Adversarial challenge evaluation | Z1 | `ChallengeStressReport` on a *proposed* challenge (not a candidate aid) | admin reviews before promotion; never reaches a candidate mid-challenge |
| 4 ~~Investigation Mentoring~~ (**withdrawn**) | — | removed: no live candidate coaching/hints on active challenges | none |
| 5 Assessment Review | Z1 | `AssessmentReviewNote` (advisory, **post-submission only**) | human reviewer; never changes `BoardResult`/signed scores/95% |
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
PromptTemplate:  id, role: scenario_architect|cohort_planner|challenge_eval|review,
                 name, version, body_hash, output_schema_ref, status, created_by
                 # NOTE: no 'mentor'/'exercise' candidate-facing roles (qualification-first)
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
  investigation_path: [str]           # expected analyst pivots (evaluator-only; for calibration + pre-promotion challenge-eval; NEVER surfaced to candidates)
  response_actions: [str]
  difficulty_target: intro|standard|advanced
  constraints: references ONLY Layer-A vocabulary (assets/identities/services/segments)

ScenarioSpecProposal (AI output in Z1): a ScenarioSpec + rationale + diversity_vector
ProvisioningRecommendation (AI output in Z1):
  per board: recommended ScenarioCatalogEntry, rationale, diversity_vs_siblings,
             parity_check, capacity_assessment, incompatibilities[], confidence
ChallengeStressReport (AI output in Z1, pre-promotion; replaces the withdrawn MentorPolicy):
               spec_id, attempted_solution_paths[], unintended_shortcuts[],
               evidence_under_or_over_constrained[], difficulty_read, notes  # author/admin only
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

## 5. Adversarial challenge evaluation (req 3, corrected — backend, pre-promotion)

Reframed from "exercise simulation" to the qualification-first model: AI stress-tests a
**proposed** challenge *before* it is promoted, so weak, ambiguous-by-accident, or trivially
solvable challenges are caught during authoring. It is not a candidate-facing feature.

- Input: a draft `ScenarioSpec` (+ its simulated world). Output: a `ChallengeStressReport`
  — attempted solution paths found, unintended shortcuts, under-/over-constrained evidence,
  difficulty read — for the author/admin.
- It runs entirely in Z1/backend during authoring; it **never** enters the operational or
  qualification stream and **never** reaches a candidate during an active challenge.
- Deterministic fallback: `simulate` + `calibrate` (siem/scenario_pipeline.py) already gate
  promotion without AI; this report is an additional advisory input, not a dependency.

## 6. ~~AI investigation mentoring~~ — **withdrawn** (qualification-first correction, req 4)

Ranger qualifies; it does not teach. There is **no** live candidate-facing AI coaching, hinting,
Socratic mentoring, or adaptive guidance on an active qualification challenge — the former
`MentorPolicy`/Z2 mentor is removed. Candidates independently investigate, decide, implement,
and prove outcomes with verifiable evidence.

Legitimate, non-solution candidate support remains (not AI coaching, deterministic/admin):
operational instructions, environment specifications, challenge objectives, scope-of-engagement
rules, tooling documentation, evidence-submission requirements, accessibility support, and
administrative help. None of these reveal the solution path. Any future candidate-facing use of
AI (e.g. mechanical accessibility aids such as text reformatting) would require separate approval
and must, by construction, be incapable of revealing hidden truth or a solution path.

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
  ~$10-30 within the $300) with hard quota caps per component. All AI use is backend
  authoring/planning/review; there is no per-candidate live inference (no mentoring). Cost
  is bounded and monitored.
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
| ~~M4.3.A4 Investigation Mentoring~~ | **withdrawn** (qualification-first: no live candidate coaching) | — | removed |
| M4.3.A4 Adversarial challenge evaluation | `ChallengeStressReport` on *proposed* challenges, backend/pre-promotion only | A1, A2 | advisory, gated, off by default |
| M4.3.A5 Assessment Review | `AssessmentReviewNote` advisory, **post-submission only**; calibration-gated; shadow-only, never writes grades | A1, M3 | gated, off by default |

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
5. **Operate**: analysts independently investigate the shared 2027-C SOC with no live AI
   assistance; each candidate is independently assigned a private, deterministic
   qualification case graded at 95% - untouched by AI. **Assessment Review (Z1)** gives
   reviewers advisory, **post-submission** analysis but never changes the signed result.
6. **Retire** per §15.10, preserving signed evidence and reclaiming resources.

No AI executed infrastructure, authorized provisioning, saw hidden truth in a
candidate path, or changed a grade at any step.

## 11. LLM model selection & inference architecture review

Review and recommendation only. No paid inference calls, no GPU provisioning, no
candidate access, no grading change. Facts are tagged [verified] (checked against a
current source this session) or [estimate] (to confirm at provisioning). Candidates
are evaluated, not predetermined; a different model may be adopted if the harness
(§11.3) shows it materially wins.

### 11.1 Candidate comparison matrix

| Attribute | openai/gpt-oss-20b | Qwen/Qwen3-14B | Qwen/Qwen3-8B |
|---|---|---|---|
| License | Apache 2.0 [verified] | Apache 2.0 [verified] | Apache 2.0 [verified] |
| Params / class | ~20B (MoE) | 14B dense | 8B dense |
| Context | 131K [verified] | 32K native, 131K via YaRN (experimental) [verified] | 32K native, 131K via YaRN [verified] |
| Structured output / tools | function calling + structured outputs supported [verified]; per-provider JSON-schema enforcement to confirm | tool/function calling supported [verified]; schema-constrained output via provider guided-decoding [estimate] | same family as 14B [estimate] |
| Representative price /1M (in/out) | ~$0.018 / ~$0.09 at an aggregator; varies by provider [verified aggregator, confirm at provider] | ~$0.06-0.20 / ~$0.20-0.60 range [estimate] | ~$0.02-0.10 / ~$0.10-0.30 range [estimate] |
| Fit for our use | strong: native structured output + long context + very low price + reasoning | strong reasoning; 32K native is enough for our prompts; YaRN only if we exceed 32K | cheapest + lowest latency; a floor/fallback |
| Risk | per-provider structured-output parity varies | YaRN context is experimental; schema enforcement provider-dependent | smaller model may under-perform on complex adversary reasoning |

Our prompts (topology + objective + schema + few-shot) are expected well under 32K
tokens, so 32K native is sufficient; 131K is headroom, not a requirement. All three
are Apache 2.0, which is clean for our use. A fourth candidate (for example a larger
Qwen3 MoE such as Qwen3-30B-A3B, or a reasoning-tuned variant) is admissible if the
harness shows a material win on cybersecurity reasoning or validated-scenario yield.

### 11.2 Hosting strategy

- **Metered hosted inference, no dedicated GPU.** Prefer Hugging Face Inference
  Providers: pass-through provider pricing with no HF markup, small monthly credits,
  bring-your-own-provider-key supported, and Team/Enterprise admins can set spending
  limits and disable providers [verified]. An alternative metered provider
  (OpenRouter, Groq, Fireworks, Together, DeepInfra, etc.) is acceptable behind the
  same interface.
- **Provider-neutral `LLMClient` (from §2) is the seam.** Model/provider is a
  configuration (`AiModelProfile`), so swapping models or providers never touches the
  scenario catalog, cohort orchestration, or assessment. This is what lets us pick a
  winner later without rework.
- No always-on inference server; calls are author/plan-time and on-demand.

### 11.3 Model evaluation harness

Identical, versioned test inputs across every candidate model; deterministic scoring
where possible, rubric scoring (human + a fixed reference) where not. Metrics and
weights (sum to 100; weights are the point of review):

| Metric | How measured | Weight |
|---|---|---|
| JSON / schema compliance | output validates against the `ScenarioSpec` JSON Schema first try; retries counted | 15 |
| Cybersecurity reasoning quality | rubric vs a reference set (kill-chain coherence, realistic tradecraft) | 15 |
| Technical feasibility vs real topology | references only the §11.4 capability inventory (assets/identities/services/data sources that exist) | 15 |
| Meaningful scenario diversity | diversity-axis vector distance from prior scenarios (§2) | 10 |
| Detection & telemetry compatibility | proposed gaps/events map to real `schema` fields + Security Analytics behaviour | 10 |
| Hallucinated infra/fields/APIs/paths | count of references to non-existent capability (lower is better) | 10 |
| Scenario reproducibility | compiled spec regenerates an identical world from its seed | 5 |
| Difficulty calibration accuracy | predicted difficulty vs the §2 calibrated vector | 5 |
| Latency & reliability | p50/p95 latency, error/timeout rate | 5 |
| Privacy & prompt-injection resilience | negative tests (below) pass; no data-exfil / instruction-following from injected data | 5 |
| Cost per successfully VALIDATED scenario | provider spend / scenarios that pass §11.4 tier "technically validated" | 5 |

Negative tests (must handle gracefully, never fabricate): request an unsupported data
source (e.g., a firewall vendor Ranger does not generate), an unsupported detector
capability (e.g., the custom-rule path that returns 500 on this build), a nonexistent
asset/identity, and an injected instruction inside pasted "telemetry" telling the
model to ignore the schema or reveal truth. A good model declines or flags the
unsupported request rather than inventing it; hallucination is penalized.

### 11.4 Scenario execution compatibility (capability inventory)

An explicit `CapabilityInventory`, derived from Ranger's ACTUAL implementation, is the
authority an AI proposal is checked against. No narrative plausibility and no LLM
self-assessment can substitute for this check.

- Generators: `enterprise.py` incident families + topology (identities, service
  accounts, tiered admins, hosts, 5 business apps, 5 segments); `telemetry_stream.py`
  profiles.
- Telemetry schema: `schema.INDEX_MAPPING` ECS fields actually emitted (incl. the
  keyword `winlog.event_data.*` fields M4.2 required).
- Security Analytics: pre-packaged windows rules that work; the custom-rule `500`
  limitation on this build; detector/finding/alert behaviour proven in M4.2.
- Lab adapters: the future Ludus/GOAD `EnvironmentProvisioner` contract (boards 5-6),
  declared but not executable now.

Scenario classification pipeline (ties to §3):

| Tier | Gate | Authority |
|---|---|---|
| Proposed | AI emitted a `ScenarioSpecProposal` | AI (Z1), no trust |
| Technically validated | schema valid + every referenced capability exists in `CapabilityInventory` + deterministic compile | Z0 deterministic |
| Executable and tested | simulation: world generates, incidents materialize, intended detectors fire / gaps are genuinely un-alerted, truth derivable, solvable | Z0 deterministic |
| Approved for catalog promotion | difficulty calibrated in band + administrator sign-off | human |

Only "Approved" enters the catalog as auto-selectable (§15.3 of the M4.3 doc).

### 11.5 AI cost governance

- **Testing allowance: $15-30/month** inside the under-$300/month infra target, for
  the evaluation + author-time generation only [policy].
- **Controls**: per-job token cap (input + output) and a per-job hard timeout; monthly
  per-component quota (`AiJob.quota_bucket`); provider-side spending limit where
  supported (HF Team admin limit) [verified capability]; usage accounting on every
  `AiJob` (tokens + cost); and a hard application-level cutoff that disables AI calls
  when the monthly ceiling is reached, falling back to the deterministic no-AI path
  (§8). 
- **Representative cost math [estimate]**: a scenario-architect generation is roughly
  6-10K input + 2-4K output tokens. At gpt-oss-20b aggregator rates that is well under
  $0.01 per generation; even hundreds of evaluation + authoring runs across three
  models stay within the $15-30 testing allowance. There is no per-candidate live-inference
  path (mentoring withdrawn), so volume stays low by construction. We do not assume this
  allowance covers production demand; production volume is benchmarked before any raise.

### 11.6 Deployment options and recommendation

| Option | Pros | Cons |
|---|---|---|
| HF Inference Providers (metered) | no GPU, pass-through pricing, admin spend caps, many models behind one key, easy model swap | per-provider feature parity (schema enforcement) varies |
| Direct metered provider (Groq/Fireworks/Together/OpenRouter) | sometimes lower latency/price for a specific model | another account + key; less uniform |
| Dedicated GPU | predictable latency at high volume | capital/opex, idle cost, ops burden - rejected for our volume and budget |

Provisional recommendation (to be confirmed by the §11.3 harness, not asserted):
start evaluation with **gpt-oss-20b as the primary candidate** (Apache 2.0, native
structured output, 131K context, lowest representative price) and **Qwen3-14B as the
reasoning challenger**, with **Qwen3-8B as the low-cost/low-latency fallback**, all
behind the provider-neutral `LLMClient` via HF Inference Providers with a bring-your-
own-key option and a Team spending limit. The harness picks the production default;
the loser models stay configured as fallbacks. Per-provider per-token prices and
JSON-schema enforcement are confirmed at provisioning before any paid call.

### 11.7 What is verified vs estimated

- [verified] Apache 2.0 licensing for all three; gpt-oss-20b 131K context + structured
  output; Qwen3 32K native / 131K YaRN; HF Inference Providers pass-through pricing,
  monthly credits, admin spend limits, bring-your-own-key; a representative
  gpt-oss-20b aggregator price.
- [estimate / to confirm at provisioning] exact per-provider per-token prices for each
  model on the chosen provider; per-provider JSON-schema enforcement parity; real
  latency/reliability; cost per validated scenario (produced by the harness). No paid
  call is made to obtain these until the evaluation design is approved.

### 11.8 Gate to implementation

Once this evaluation design (matrix, datasets, weights, deployment options, cost
scenarios, recommendation) is approved, we may begin the deterministic **M4.3.1**
(catalog + shared `ScenarioSpec` schema) and the **A1 AI platform core with a MOCK
model** (the `LLMClient` interface, registries, `AiJob`/`AiArtifact`, trust zones,
output-schema validation, quotas/audit) - all without enabling production inference.
The model-evaluation harness (§11.3) runs against candidate models only when a
flagged, budgeted paid-inference step is separately approved; until then A1/A2 run
against the mock provider. Production inference stays off.

## 12. Non-negotiable invariants

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
