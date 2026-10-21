# PARALLAX: side-by-side of the two research implementations

Two implementations are NOT to be auto-merged. This document compares them on the dimensions that
matter for inference, so a reconciliation decision can be made deliberately.

- A. PR #5 statistics (`px-stats-v2.1`, `parallax/research/statistics.py`) applied to the CURRENT
  fixed stimulus set (3 legitimate tasks x the preregistered attack variants, single document
  position).
- B. The independent public evaluation protocol design: 48 tasks x 10 attack variants x 2 benign
  controls x 3 document positions.

## Comparison

| Dimension | A. PR #5 statistics (current stimulus set) | B. Independent public protocol (48x10x2x3) |
|---|---|---|
| Experimental unit | (task, variant) cell; repetitions are a within-cell cluster; TASK is the blocking/replicate unit | (task, variant, document-position) cell; TASK is the block; position is an additional within-task factor |
| Replicate count | K = 3 task blocks (as currently fixed) | K = 48 task blocks; 30 attack cells and 6 control cells per task |
| Estimand | mean over tasks of the per-ATTEMPT attack canary rate minus control false-positive rate | same per-attempt, task-blocked estimand is directly applicable; position becomes a reported factor or a within-task average |
| Primary interval | task-blocked Student-t CI, df = K-1 (df = 2 at K=3: very wide) | same method, df = 47: narrow, usable |
| Control comparison | paired/blocked by task; unstratified Fisher/Newcombe only as flagged secondary | same; the 2 benign controls per task strengthen the per-task control estimate |
| Zero-event bound | exact, on the number of independent TASK BLOCKS (3 -> wide, ~0.63) | exact on 48 task blocks (-> ~0.06, usable) |
| Power basis | cluster-aware Monte Carlo simulation; current K=3 gives ~0.16 power for even a large effect | same simulation at K=48: type-I ~0.039, power ~0.97 for the meaningful 0.10 effect, ~1.0 for a large effect |
| Eligibility gate | precision (real-variance CI half-width <= 0.15) AND K >= MIN_TASK_BLOCKS (12) | satisfiable: K=48 >> floor, and precision achievable |
| Likely verdict today | inconclusive / bounded (underpowered by design) | finding_supported or a genuine negative is attainable, given a validated model |
| Multiplicity | Holm-Bonferroni across attack categories | same; more categories/positions imply more comparisons to correct |

## Reconciliation (recommended, not executed)

The two are complementary, not competing: A is the ANALYSIS methodology; B is an adequately powered
STIMULUS DESIGN. The defensible path is to keep the PR #5 analysis layer and adopt the independent
protocol's larger design (or a preregistered equivalent), after reconciling three definitional
points, all fixed BEFORE any results are viewed:

1. Position factor: decide whether document position is a within-task averaging factor (keeps the
   task-blocked estimand unchanged) or a third crossed factor requiring a mixed-effects extension.
   The current task-blocked t-method handles the averaging option directly; the crossed-factor option
   is a methodology extension (random effects) that would need its own operating-characteristics
   validation.
2. Control definition: map the 2 benign controls to the per-task control rate used in the risk
   difference.
3. Multiplicity scope: the family of secondary comparisons grows with categories x positions; the
   Holm correction must be preregistered over the agreed family.

Do not merge the two implementations automatically. Any adoption is a preregistered protocol change,
and no experimental condition is tuned on observed outcomes.

## Honest status

- Analysis methodology (A): reviewer-defensible and independently cross-validated, with documented
  coverage limitations (Section 14.4 of the SAP).
- Stimulus design (B): adequately powered on paper (by the cluster-aware simulation), but no
  validated capable model has been run under it here; no finding is claimed.
- Neither implementation, alone or merged, establishes an empirical finding without a validated model
  and a preregistered, adequately powered run.
