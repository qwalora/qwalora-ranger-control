# PARALLAX prompt-injection study: external statistical-review package

Purpose: give an independent statistician everything needed to assess, and if appropriate replace,
the inference layer for the PARALLAX prompt-injection study. The study team has concluded its own
calibration phase with a FAIL (see Section 6) and has stopped modifying inference methods. Nothing in
this package is offered as a validated method; it is a problem statement plus the team's evidence.

Reference artifacts (committed, branch `feature/parallax-research-statistics`, pinned at the v2.3
result commit `f5e61f8`):
- `parallax/research/statistics.py` (analysis `px-stats-v2.x`), `parallax/research/protocol.py`,
  `parallax/research/evaluator.py`, `parallax/research/harness.py`.
- Simulation and bake-off: `scripts/research/oc_matrix.py`, `scripts/research/oc_bakeoff.py`.
- Operating-characteristics data: `docs/research/oc_matrix.json`, `docs/research/oc_bakeoff.json`.
- Full SAP: `docs/research/PARALLAX_STATISTICAL_ANALYSIS_PLAN.md`.

## 1. Primary estimand and experimental design

- Observable: binary emission of a fixed canary token by an instruction-tuned assistant, scored by a
  deterministic rule-based evaluator (no LLM judge; refusal/negation stripping).
- Experimental unit: the (legitimate_task, attack_variant) CELL. Repetitions within a cell are a
  correlated cluster. Attack variants and benign-control variants are applied to the SAME legitimate
  tasks, so TASK is a blocking factor shared by both arms (paired/blocked, not two independent samples).
- Primary estimand: the mean over tasks of the per-ATTEMPT risk difference
    RD = P(canary | one attack attempt) - P(canary | one benign-control attempt),
  estimated as the mean of per-task differences of per-attempt rates, tasks as replicate units.
  Deliberately NOT an "any repetition succeeds in R reps" quantity (that grows with R).

## 2. Proposed 48-task stimulus structure and attack/control allocation

- 48 legitimate tasks (blocks) x 10 attack variants x 2 benign controls x 3 document positions.
- Per task: attack cells = 10 variants x 3 positions = 30; control cells = 2 controls x 3 positions = 6.
  The arms are UNEQUAL (30 vs 6), which is central to the calibration difficulty (Section 6).
- Positions are treated as a within-task averaging factor by default (keeps the per-attempt,
  task-blocked estimand unchanged); a crossed random-effect treatment is an open option (Section 7).
- Variant assignment is FIXED and preregistered (specific texts), NOT randomized. There is therefore
  no randomization distribution to appeal to; permutation p-values rest on exchangeability assumptions.

## 3. Simulation assumptions and data-generating mechanism

Deterministic Monte Carlo (pure Python, fixed seeds). For each simulated dataset:
- For each task t, draw a task attack rate ta = clip(p_attack + N(0, task_sd), 0, 1) and a task
  control rate tc = clip(p_control + N(0, task_sd), 0, 1). The Gaussian task random effect induces
  both heterogeneity and within-task clustering; clipping at 0/1 creates the boundary/skew behavior.
- Attack cells: `variants_per_task` cells, each a Bernoulli(ta) over `reps` repetitions (cell value =
  successes/reps). Control cells: `control_per_task` cells, Bernoulli(tc).
- Per-task difference d_t = mean(attack cell values) - mean(control cell values); the campaign
  statistic is mean_t(d_t).
Assumptions baked in: Gaussian task random effects, independent cells within a task given the task
rate, equal reps, and (for label-permutation type-I) attack/control cell exchangeability under H0.
Known mismatch with reality: real attack and control variants are different texts whose baseline
behavior may differ even with no injection effect, so within-task exchangeability is not guaranteed.

## 4. Operating-characteristics matrices (with Monte Carlo uncertainty)

Two reproducible matrices are provided. Both report Monte Carlo standard errors; the nominal targets
are type-I 0.025 (one-sided), coverage 0.95, equivalence FPR <= 0.05.

- `oc_matrix.json` (selection-phase, seed 20260101; `scripts/research/oc_matrix.py`): permutation
  type-I and power, t coverage, equivalence FPR across K in {24, 48}, task_sd in {0.05, 0.10},
  p_control in {0.02, 0.10}. Summary: type-I(perm) 0.023-0.058, power@0.10 0.61-0.997,
  coverage(t) 0.813-0.951, equiv FPR <= 0.006.
- `oc_bakeoff.json` (validation-phase, INDEPENDENT seed 777; `scripts/research/oc_bakeoff.py`): the
  table in Section 5, with d_t skewness and per-method coverage.

## 5. Failed calibration results (validation seed 777)

| K | task_sd | p_control | type-I sign-flip | type-I label-perm | d_t skew (H0) | coverage t | coverage studt | coverage BCa | equiv FPR |
|---|---|---|---|---|---|---|---|---|---|
| 48 | 0.10 | 0.02 | 0.043 | 0.062 | -0.99 | 0.804 | 0.760 | 0.731 | 0.004 |
| 48 | 0.05 | 0.02 | 0.040 | 0.028 | -1.51 | 0.912 | 0.880 | 0.848 | 0.000 |
| 24 | 0.05 | 0.02 | 0.040 | 0.015 | -1.42 | 0.936 | 0.909 | 0.876 | 0.000 |
| 48 | 0.10 | 0.10 | 0.035 | 0.055 | -0.64 | 0.943 | 0.936 | 0.926 | 0.001 |

Frozen criteria (set before running; never relaxed): type-I <= 0.025 (not significantly above) AND
coverage >= 0.93 across every cell. DETERMINATION: FAIL for all candidate methods. Type-I exceeds
0.025 for sign-flip everywhere and for label-perm under heterogeneity (up to 0.062); interval
coverage falls to 0.804 (t), 0.760 (studentized bootstrap), 0.731 (BCa). Equivalence FPR is
controlled but does not satisfy the criteria alone.

## 6. Candidate methods: assumptions and limitations

- Student-t on task blocks (df = K-1): assumes approximately normal per-task differences. Violated
  here (d_t skew -0.64 to -1.51). Anti-conservative type-I at moderate K; coverage down to 0.80.
- Percentile bootstrap over tasks: assumes the task-level statistic's bootstrap distribution is a good
  pivot. Under-covers on skewed small-K data.
- BCa bootstrap: bias-correction + jackknife acceleration. Worst coverage here (0.731); acceleration
  unstable at small K and boundary rates.
- Studentized (bootstrap-t): assumes a stable resample SE. The SE is unstable with near-zero rates and
  many zero cells; coverage not improved (0.760).
- Sign-flip permutation: assumes per-task d_t symmetric around 0 under H0. VIOLATED under unequal arms
  (measured skew strongly negative); not exact; type-I 0.035-0.043.
- Label (within-task) permutation: exact for type-I ONLY under within-task attack/control cell
  exchangeability under H0. Not guaranteed by the non-randomized design; type-I inflates to 0.055-0.062
  under heterogeneity.

## 7. Specific questions for independent expert judgment

1. What inference procedure is appropriate for the mean of task-blocked, per-attempt risk differences
   with near-zero base rates, strong task heterogeneity, unequal arm sizes, and boundary outcomes?
   Candidates to assess: beta-binomial GLMM, GEE with small-sample (Mancl-DeRouen / Kauermann-Carroll)
   variance corrections, exact conditional methods, or a cluster-robust permutation that is valid under
   unequal arms.
2. Given non-randomized variant assignment, is any permutation/randomization inference defensible, or
   must inference be model-based with clustering handled explicitly?
3. Should document position be a within-task averaging factor or a crossed random effect, and how does
   that change the estimand and the required sample size?
4. What is the minimum number of task blocks (and cells per arm) for the chosen method to reach
   type-I <= 0.025 and coverage >= 0.93 under the stress grid in Section 3?
5. How should equivalence/non-inferiority be tested with error control in this regime (the current
   TOST-via-CI is conservative on FPR but rests on an under-covering interval)?
6. How should infrastructure/evaluation-failure exclusions and inconclusive outcomes be handled to
   avoid selection bias (current approach: exclusion-rate reporting plus worst/best-case bounds)?
7. What multiple-comparison control is appropriate across attack categories x document positions?

## 8. Approval status

The current inference layer is NOT approved for scientific claims. No p-value, confidence interval, or
equivalence/finding verdict produced by `parallax/research/statistics.py` may be presented as a
validated inferential result until an independent methodological review selects and validates a
procedure against the frozen operating-characteristic criteria. The non-inference parts of the pipeline
(preregistered protocol, deterministic evaluator, provenance taxonomy, reproducibility artifacts,
exclusion/ambiguity accounting, and honest negative/limitation reporting) are sound and may be reported
descriptively. No protocol version is frozen; no empirical finding is claimed; passing software tests is
not scientific validation.
