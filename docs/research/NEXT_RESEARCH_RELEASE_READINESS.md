# PARALLAX next research release: readiness assessment and PR #4 integration plan

Scope: review the research integration branch and PR #4, state what is implemented/tested/
incomplete, record the scientific-rigor weaknesses and the safe improvements made, and give a
controlled integration plan for PR #4 without merging or deploying it.

Branches: review on `integration/parallax-research-platform` (`2dd429e`); rigor work implemented
on `feature/parallax-research-statistics`; design work on `feature/parallax-design-completion`
(PR #4, open, unmerged).

## 1. Research stack: implemented / tested / incomplete

Implemented and tested (on `integration/parallax-research-platform`):
- Preregistered protocol (`protocol.py`): research question, fixed legitimate tasks, basic and
  advanced attack taxonomies, fixed outcome categories and conditions.
- Deterministic rule-based evaluator (`evaluator.py`) with refusal/negation stripping; no
  LLM-judge.
- Harness (`harness.py`): controlled trials, provenance on every record (infrastructure_backed vs
  simulated), infra/eval failures never scored as results, metrics with explicit denominators and
  exclusions; trial cap and per-trial timeout.
- Backends (`model_backend.py`): host-authorized real HTTP/transformers backends (loopback or
  allow-listed only), a disclosed deterministic stub, weights-digest capture, and validated-model
  gating via `RANGER_RESEARCH_VALIDATED_MODELS`.
- Reproducibility (`reproduce.py`): canonical-JSON artifacts, SHA-256 artifact index, normalized
  records for byte-for-byte scientific reproducibility.
- Signed evidence and provenance taxonomy (`store.py`): Ed25519 + SHA-256, owner-scoped,
  per-record finding-eligibility (validated model AND measured). Reviewer-only adjudication.
- Test coverage: `siem/tests/test_parallax_research*.py`, `tests/test_research_execution.py`
  (55 passed together with the new statistics suite).

Incomplete before this change:
- No interval estimates, significance test, or control comparison in the reported metrics.
- Repetitions pooled as if independent (pseudoreplication); the per-repetition breakdown promised
  in the docstring was not computed.
- No aggregate finding-eligibility (even validated, measured records were not tested for adequate
  power or a significant effect before being presentable as a finding).
- No explicit negative-result reporting and no written scientific-limitations statement.

## 2. Scientific-rigor weaknesses and the safe fixes made

Implemented on `feature/parallax-research-statistics` (additive; no change to signing, the
per-record taxonomy, historical evidence, or infrastructure):
- `parallax/research/statistics.py`: Wilson confidence intervals; Fisher's exact test and a
  Newcombe risk-difference interval for attack vs control; cell-level (independent-unit) estimation
  that collapses correlated repetitions; per-category and per-repetition breakdowns; an aggregate
  finding-eligibility verdict (plumbing_only / proof_of_concept / underpowered / negative_result /
  finding_supported); and a plain-language interpreter with explicit negative-result wording.
- `reproduce.py`: emits a new deterministic `statistics.json` artifact (metrics.json unchanged for
  continuity) and prints the eligibility verdict and interpretation.
- `tests/test_research_statistics.py` (14 tests): Wilson endpoints and a known value, Fisher exact
  against hand-computed p-values, cell-level pseudoreplication handling, per-category breakdown, and
  every eligibility verdict. Full research regression: 55 passed.

Remaining weaknesses (documented, not yet addressed; require design expansion, not code):
- Low statistical power: the fixed stimulus set yields few independent cells, so most single-model
  runs are `underpowered` by design. Powering a finding needs an expanded preregistered task/variant
  pool, which is a protocol change to be preregistered separately.
- Single behavior, single corpus, single template: external validity is limited (see the protocol's
  limitations section).

## 3. Readiness assessment for the next research release

- Methodology and reproducibility: READY. The pipeline now produces interval estimates, a control
  comparison with an exact test, pseudoreplication-aware estimates, genuine negative results, and a
  written limitations statement.
- Empirical findings: NOT YET. No validated capable model has been run through this pipeline here
  (model acquisition is an environment/ops matter, deliberately out of scope for this change), and
  the current stimulus set is underpowered for a defensible finding. The honest release posture is:
  methodology and negative-result reporting are release-ready; any positive finding requires a
  validated model and an expanded, preregistered stimulus pool.
- Integrity and security: unchanged and preserved. Signing, owner-scoping, reviewer boundaries,
  entitlement isolation, and the per-record provenance taxonomy are untouched.

## 4. Controlled integration plan for PR #4 (no merge, no deploy)

PR #4 (`feature/parallax-design-completion` into `integration/parallax-research-platform`) is the
researcher-experience design/accessibility completion. It is independent of the research-methodology
work here and of the RC release line. Controlled integration, to be executed only on explicit
authorization:

1. Keep PR #4 open and unmerged; do not deploy it. It carries no runtime dependency, schema change,
   or new route (CSS/templates + tests + evidence only).
2. Review gate: confirm the PR diff remains design/accessibility/security-test/evidence only (no
   `store.py`, `model_backend.py`, `harness.py`, `parallax_routes.py`, `app.py`, signing-key, or
   historical-evidence changes). This was verified at commit `63aabd6`.
3. Sequencing: land the research-methodology branch (`feature/parallax-research-statistics`) first
   via its own PR into `integration/parallax-research-platform`, since it touches only
   `parallax/research/*` and tests and cannot conflict with PR #4's CSS/templates.
4. Merge PR #4 into `integration/parallax-research-platform` only (never a protected branch),
   after its CI gate (axe 0, 25 tests, 10/10 journey) and a human review. Do not fast-forward to
   `parallax-nonprod`, `parallax-rc`, or production.
5. Post-integration, before any deploy: run the combined suite on the integration branch and a
   fresh accessibility pass, then stop. Deployment remains separately authorized.

## 5. Deliverables in this change

- Code: `parallax/research/statistics.py`, `reproduce.py` (additive wiring).
- Tests: `tests/test_research_statistics.py` (14), research regression 55 passed.
- Docs: `PARALLAX_EVALUATION_PROTOCOL.md` (reproducible protocol + explicit limitations), this
  readiness assessment and PR #4 integration plan.
- No fabricated experiments, findings, or measurements; no infrastructure; no signing/baseline/
  historical changes; PR #4 left open and unmerged.

## 6. v2 revision: scientific-validation gate (addressing peer-review critique)

The first implementation was reclassified from "promising" to "not yet publication-ready" and
revised (analysis version `px-stats-v2`, `parallax/research/statistics.py`). Each raised issue is
addressed; see `PARALLAX_STATISTICAL_ANALYSIS_PLAN.md` for the full plan.

1. negative_result corrected. Failure to reject H0 is no longer read as "defense held." Three cases
   are distinguished: `inconclusive` (interval admits negligible and meaningful effects),
   `bounded_small_effect` (effect bounded below the meaningful size, incl. the exact zero-event
   bound), and `equivalence_supported` (TOST: 90% CI within the margin, from a real variance).
2. Cell estimand fixed. The primary estimand is the per-ATTEMPT rate, not "any repetition succeeds"
   (which grows with repetition count R). Per-cell proportions are reported separately as an R-aware
   secondary, with a nondeterminism flag on within-cell disagreement.
3. Dependence handled. Attack and control are paired by task; the primary analysis is task-blocked
   (tasks are the replicate units). Unstratified Fisher/Newcombe is demoted to a flagged secondary
   sensitivity analysis.
4. Power replaces the arbitrary count. The `MIN_CELLS=10` gate is removed; eligibility is driven by a
   precision target (CI half-width) plus a two-proportion power/sample-size calculation with
   documented delta, alpha, and power. Degenerate zero-variance intervals do not count as precise.
5. Exclusions, ambiguity, multiplicity, CI interpretation, reproducibility: exclusion rate + worst/
   best-case sensitivity bounds; inconclusive-as-success sensitivity; Holm-Bonferroni across
   categories; frequentist CI interpretation stated; nondeterminism and digest assumptions surfaced.
6. Stimulus expansion is preregistered from the power calculation, never tuned on observed results.
7. Independent validation added: cross-checks vs `scipy.stats` (Fisher, t.ppf, norm.ppf, Wilson via
   binomtest) plus hand-computed references. 19 statistics tests; research regression 60 passed.
8. Reviewer-ready SAP delivered (`PARALLAX_STATISTICAL_ANALYSIS_PLAN.md`): outcomes, units,
   hypotheses, estimand, effect sizes, stopping rules, exclusions, multiplicity, equivalence, limits.

Scientific-readiness: analysis methodology is reviewer-defensible and cross-validated (READY); no
empirical finding is claimed (NOT ESTABLISHED) pending a validated capable model and a preregistered
expanded stimulus pool. Passing software tests is explicitly not treated as scientific validation.

## 7. Draft pull request

`feature/parallax-research-statistics` is to be opened as a DRAFT PR into
`integration/parallax-research-platform` (no merge, no deploy). It touches only
`parallax/research/*`, `tests/`, and `docs/research/*`; it changes no signing, per-record taxonomy,
historical evidence, entitlement, or infrastructure. It is independent of PR #4 and can land first.

## 8. v2.1 final-review corrections and readiness decision

Addressed the three statistical-review findings (analysis version `px-stats-v2.1`):
1. Clustered zero-event bound is now task-aware (independent task blocks, not pooled correlated
   attempts); adversarial tests confirm many repeated zero-event attempts across few tasks yield
   `inconclusive`, not a spuriously tight bound.
2. Power/eligibility now rest on a deterministic cluster-aware Monte Carlo simulation
   (`simulate_operating_characteristics`) with validated coverage, type-I, power, and equivalence
   behavior; the independent-sample formula is demoted to a rough aid. `MIN_TASK_BLOCKS=12` is
   simulation-justified and enforced for both positive and equivalence verdicts.
3. `t_crit` uses Cornish-Fisher for df>30, cross-validated against scipy incl. df 40/60/100/120/500.

Independent validation re-run: research regression 67 passed; statistics suite 26 tests incl. scipy
cross-checks and simulation operating-characteristics. A side-by-side of the two implementations is in
`PARALLAX_METHODOLOGY_COMPARISON.md`; they are NOT merged.

Unresolved limitations (carried, not hidden): the task-blocked t-interval under-covers (~0.84) for
large heterogeneous effects near the 0/1 boundary; equivalence is reliable only at large K; all
conclusions remain conditional on one prompt template, one corpus, one behavior.

READINESS DECISION: the statistical METHODOLOGY is reviewer-defensible and independently validated,
and is ready to go to review as a DRAFT (PR #5). It is NOT publication-ready as an empirical result:
no validated capable model has been run, the current fixed stimulus set is underpowered by the
cluster-aware simulation, and the coverage limitation above is open. Software tests passing is not
treated as scientific validation. A defensible empirical result requires a validated model plus the
adequately powered, preregistered design (e.g., the independent 48x10x2x3 protocol), analyzed with
this methodology.

## 9. v2.2 inference-validation and freeze decision

Final-review findings addressed (analysis version `px-stats-v2.2`):
- The Student-t and bootstrap intervals are anti-conservative on skewed clustered data; the SELECTED
  significance procedure is now a within-task permutation test (type-I controlled), chosen on
  prespecified operating-characteristic criteria, not on observed model results.
- Full operating-characteristics matrix produced and committed (`scripts/research/oc_matrix.py`,
  `docs/research/oc_matrix.json`) across task heterogeneity and base rates, with Monte Carlo SEs:
  type-I (perm) 0.023-0.058, power@0.10 (perm) 0.61-0.997, coverage (t) 0.813-0.951, equivalence FPR
  <=0.006. Deterministic seeds/generators; reproducible.
- Zero-event bound relabeled as per-TASK susceptibility (a different quantity from the per-attempt RD)
  and removed from the verdict; equivalence/bounded conclusions are explicitly provisional.
- Research regression re-run: 71 passed; statistics suite 30 tests incl. permutation type-I,
  bootstrap, and Monte Carlo-uncertainty checks.

FREEZE DECISION: DO NOT FREEZE a new protocol version. The method is substantially better and the
permutation test is the right direction, but prespecified criteria (type-I <= 0.025 within MC error
AND coverage >= 0.93 across the whole grid) are not uniformly met (type-I up to 0.058 under unequal
arms; coverage down to 0.813 under high heterogeneity with a low base rate). Required before freeze:
a stratified/label permutation exact under unequal arms, and a calibrated interval validated to
coverage >= 0.93 across the grid. No empirical finding, no publication readiness; passing software
tests is not scientific validation.

## 10. v2.3 calibration bake-off: explicit FAIL, stopping rule invoked

Final bounded-inference calibration (scripts/research/oc_bakeoff.py, validation seed 777 independent
of the selection seed; data docs/research/oc_bakeoff.json). Frozen criteria (not redefined after
results): type-I <= 0.025 (not significantly above) AND coverage >= 0.93 across the grid.

RESULT: FAIL. No method passes. The per-task difference is strongly negatively skewed under H0
(skewness -0.64 to -1.51) from unequal arms and near-zero boundary-prone rates, so sign-flip is not
exact; sign-flip type-I 0.035-0.043 and label-perm up to 0.062 exceed 0.025, and interval coverage
falls to 0.804 (t), 0.760 (studentized bootstrap), 0.731 (BCa). Equivalence FPR is controlled but
does not satisfy the criteria alone.

STOPPING RULE APPLIED: method modification stops. The task-blocked inference on clustered rare-event
proportion differences is not adequately calibrated by the standard methods tried. Recommendation:
(1) report DESCRIPTIVELY (per-task rates and the point estimate, with the exclusion/ambiguity
accounting) without a validated inferential claim; and (2) obtain independent biostatistical
consultation to select and preregister a validated method (beta-binomial/GEE mixed model or an exact
conditional method) before any inferential claim or protocol freeze.

FINAL READINESS: the pipeline (preregistration, deterministic evaluator, provenance, reproducibility,
honest negative/limitation reporting) is sound; the INFERENCE layer is NOT calibration-validated and
must not be presented as such. No empirical finding, no protocol freeze, no publication readiness.
Passing software tests is not scientific validation. PR #5 remains a draft.
