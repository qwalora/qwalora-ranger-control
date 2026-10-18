# PARALLAX — AI Engineering Qualification (Phase 1 architecture foundations)

PARALLAX is Qwalora Ranger's rigorous, evidence-based AI-engineering qualification track. It shares
the Ranger platform with STRATA (cybersecurity) but is architecturally distinct. This document is the
Phase 1 foundation: the compatibility architecture, the competency framework, the qualification-system
design, and the first vertical slice. It is design plus a working first slice, not a finished program.
Board count, duration, and passing criteria are derived from the qualification design and remain
subject to architectural review; they are not copied from STRATA.

## What PARALLAX is (and is not)

PARALLAX measures demonstrated AI-engineering competence through reproducible experiments, real
technical deliverables, controlled evaluations, and independently verifiable evidence. It is not a
prompt-engineering quiz, a chatbot tutorial, a generic ML course, an attendance certificate, a
multiple-choice test, or a renamed clone of STRATA. A passing result must represent demonstrated
engineering ability, never an attractive model output.

## One platform, two tracks (compatibility architecture)

Shared (reused, never forked): GitHub-OAuth identity and the candidate lifecycle; cohort governance;
the versioned, approved spec + integrity-contract pattern (generation contract hash/MAC); objective
grading with a pass bar and a mandatory human-review gate for narrative artifacts; the Ed25519 signing
primitive for evidence and decisions; immutable qualification records; evidence preservation; and the
test harness.

Isolated (must never cross): STRATA scenarios, seeds, and scoring truth vs PARALLAX datasets, holdouts,
and grading truth; per-track assessment specs and bindings; and per-track credit. A hard invariant,
enforced by code and tests: a PARALLAX submission can never produce STRATA credit and vice versa. The
pathway is carried on the candidate/binding and checked at every award and every candidate-facing read.

Boundary rule: reuse a STRATA primitive only where it is pathway-agnostic. Where a primitive encodes
STRATA domain meaning (incident families, SIEM, GOAD ranges, Board 2 citation grading), PARALLAX gets
its own module in a `parallax_*` namespace rather than overloading the STRATA one.

## Competency framework

Candidate competency domains (candidate list, not a final board list; each becomes a board only after
architectural review):

1. Data engineering and dataset integrity (leakage, split hygiene, provenance).
2. Reproducible computational experimentation (seeds, pinned environments, deterministic re-runs).
3. ML implementation and evaluation (honest held-out metrics, baselines, uncertainty).
4. Generalization, robustness, and failure analysis (distribution shift, ablations).
5. Statistical reasoning and experimental design (power, confidence intervals, significance).
6. Model security and misuse resistance (data poisoning, extraction, prompt/eval injection).
7. Responsible and trustworthy AI engineering (bias measurement, documented limitations).
8. Serving, observability, and operational reliability (latency, drift monitoring, rollback).
9. AI systems integration and engineering trade-offs (cost/quality/latency decisions with evidence).

Every assessment, before it becomes a board, must define all ten of: (1) what the engineer must
demonstrate; (2) authorized tools + execution environment; (3) prerequisite knowledge; (4) the task or
experiment; (5) the artifact produced; (6) how it is independently evaluated; (7) what constitutes a
critical failure; (8) how repeatability and integrity are maintained; (9) what feedback is safely
revealed; (10) why it measures competence, not memorization.

## Qualification-system design (evidence-based)

- **Versioned, approved assessment specifications** — each spec has a semantic version and an approval
  state; only approved specs may bind.
- **Distinct scenario instances** — a per-candidate, per-attempt instance derived from a reproducible
  seed and a generation contract (same integrity pattern STRATA pins with `gen_hash`/content-hash).
- **Controlled data and model artifacts** — datasets and sealed holdouts are generated deterministically
  from the contract; the holdout and its labels are never disclosed to the candidate.
- **Objective grading** — the evaluator re-derives the instance from the contract independently and
  scores against a sealed holdout with explicit metrics, uncertainty, a baseline, and a threshold.
- **Independent verification** — grading is reproducible from the signed submission + the contract by a
  third party, with no access to candidate-only state.
- **Research/experimental logs** — the evaluator records inputs, metrics, and verdict rationale into an
  immutable, signed record.
- **Candidate-safe briefs** — the brief discloses the task, public schema, metric, and threshold, but
  never the holdout, the planted-trap identity, or grading internals.
- **Signed submissions and decisions** — both are Ed25519-signed (the platform's existing primitive).
- **Human review where applicable** — narrative artifacts (for example a written failure analysis) pass
  the platform's mandatory human-approval gate, exactly as STRATA report approval does.
- **Anti-replay and non-transfer** — holdout labels are never released, so predictions cannot be
  precomputed from them; per-candidate instances differ, so a solution tuned to one does not transfer.
- **Attempt and cohort isolation** — instance = f(spec, pathway, cohort, candidate, attempt).
- **Critical-failure veto** — a disqualifying engineering error (e.g. depending on leakage) vetoes a
  pass regardless of headline metric.
- **Immutable qualification records** — append-only, signed.
- **Simulation vs experiment** — synthetic data is explicitly labeled as a fixture; the evaluation is a
  genuine executed computation, never a hypothetical presented as external validation.

Leakage/contamination controls: the holdout is sealed; the candidate never sees holdout labels;
evaluation runs server-side; the grader detects and penalizes dependence on a planted leak via a
controlled ablation; per-candidate instances prevent candidate-to-candidate transfer.

## Proposed assessment progression (indicative, pending review)

P1 Data integrity and leakage-safe evaluation (first slice, implemented) → P2 reproducible experiment
with uncertainty → P3 robustness/failure analysis under shift → P4 model security (poisoning/extraction)
→ P5 responsible-AI measurement → capstone: an integrated systems build with an operational-reliability
and trade-off defense. Count and gating are indicative only.

## First vertical slice — PX-1: Leakage-Safe Model Evaluation

**Competency:** data integrity + honest generalization. **Environment:** offline Python, numpy +
scikit-learn only; no network, no GPU, no paid APIs. **Prerequisite:** supervised learning basics,
train/validation/test hygiene, data leakage.

**Task.** The candidate is bound to a per-candidate instance: a deterministically generated tabular
binary-classification dataset with (a) a disclosed training split, (b) a disclosed public validation
split, (c) a sealed holdout the candidate never sees, and (d) exactly one planted "leakage" feature that
is highly predictive on train/validation but is a target leak that will not generalize. The candidate
submits a declarative solution: the feature set to use (by name), a model configuration drawn from a
pinned allowed family, and a short written leakage analysis. No arbitrary candidate code is executed;
the grader fits the pinned model family with the candidate's declared features and hyperparameters.

**Artifact.** A signed submission `{feature_set, model_config, leakage_analysis}`.

**Independent evaluation (objective, deterministic).** The evaluator re-derives the dataset from the
contract, fits the pinned model on the training split using the candidate's declared features, and
scores on the sealed holdout (accuracy + AUC with bootstrap confidence intervals), against a baseline
and a pass threshold. It then runs a leakage ablation: if the declared feature set contains the planted
leak, or if the solution's holdout performance collapses to baseline when the leak column is permuted
(i.e. the solution depended on the leak), a **critical-failure veto** is applied. A pass requires
holdout metric at or above threshold AND no leakage veto AND the written analysis approved by a human
reviewer.

**Why it measures competence, not memorization.** The candidate must identify and exclude the leak,
choose features and a configuration that generalize to unseen data, and explain the leak. Per-candidate
instances and a sealed holdout defeat memorization and transfer; the ablation defeats "accidentally
high" leak-driven scores.

## Phase 1 implementation scope (this branch)

A. **Pathway integration** — register a PARALLAX pathway alongside STRATA without touching STRATA state.
B. **Qualification contracts** — `parallax_assessment.py`: versioned spec, generation contract with an
   integrity hash, and per-candidate instance binding (reusing the STRATA contract-integrity pattern).
C. **Candidate-safe experience** — a brief builder that exposes only safe metadata.
D. **Evaluator architecture** — `parallax_eval.py`: deterministic dataset regeneration, objective
   scoring, leakage ablation, critical-failure veto, and a signed result.
E. **First vertical slice** — PX-1 end to end: spec → instance → submission → offline evaluation →
   signed decision.
F. **Tests** — positive (leakage-safe pass), negative (leakage veto; below-threshold fail), isolation
   (no cross-track credit; per-candidate instances differ), and regression (STRATA baseline unaffected).

Phase 1 does not enable public candidate enrollment or real qualification awards. No paid services, GPUs,
cloud resources, or third-party model APIs are used or provisioned.
