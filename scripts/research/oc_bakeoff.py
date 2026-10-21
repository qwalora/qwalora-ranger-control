#!/usr/bin/env python3
"""Final bounded-inference calibration bake-off for the PARALLAX task-blocked risk difference.

Evaluates candidate inference methods against FROZEN freeze criteria on a FIXED stress grid, using
INDEPENDENT validation seeds (distinct from any selection/tuning seed). Reports Monte Carlo 95% CIs
(Wilson) for type-I error, 95% CI coverage, power, and equivalence false-positive rate, and an
explicit PASS/FAIL per method per cell. Deterministic. Pure Python. Run from the repo root:

    python scripts/research/oc_bakeoff.py [out.json]

FROZEN criteria (set before running; not redefined after seeing results):
  - type-I (one-sided, nominal 0.025): PASS if the estimate is not significantly ABOVE 0.025, i.e.
    Wilson lower bound <= 0.025 + 0 and point <= 0.025 + 2*MCSE (we require point_est <= 0.035 and
    Wilson_low <= 0.025).  [documented, fixed]
  - coverage (nominal 0.95): PASS if not significantly BELOW 0.93, i.e. Wilson upper >= 0.93 and
    point >= 0.93 - 2*MCSE.
A method PASSES overall only if every grid cell passes BOTH type-I and coverage.

Assumptions verified here:
  - Sign-flip permutation requires the per-task difference to be symmetric around 0 under H0. With
    UNEQUAL arm sizes the two arm-rate estimators have different discreteness/variance, so d_t is NOT
    symmetric; we measure its skewness under H0. Sign-flip is therefore NOT exact and is reported as
    approximate.
  - Label (within-task) permutation is exact for type-I ONLY under the sharp null that attack and
    control cells are exchangeable within a task (identically distributed). The REAL study does not
    randomize variant assignment (fixed preregistered texts), so this exchangeability is an
    untestable ASSUMPTION, not a randomization guarantee; the simulation builds it in under H0, so
    good type-I here reflects the assumption holding, not design-exactness.
"""
import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from parallax.research import statistics as S  # noqa: E402

VALID_SEED = 777            # INDEPENDENT of the selection seed (20260101)
MARGIN = S.EQUIVALENCE_MARGIN
MEANINGFUL = S.MEANINGFUL_RD
GRID = [
    {"K": 48, "sd": 0.10, "pc": 0.02},   # hardest coverage cell
    {"K": 48, "sd": 0.05, "pc": 0.02},   # unequal-arm type-I
    {"K": 24, "sd": 0.05, "pc": 0.02},   # small-K type-I
    {"K": 48, "sd": 0.10, "pc": 0.10},
]
A_CELLS, C_CELLS, REPS = 30, 6, 1
N_COVER = 2500
N_TYPE = 400
N_PERM = 400


def _clip(x):
    return min(1.0, max(0.0, x))


def _gen_task_cells(rng, ta, tc):
    av = [sum(rng.random() < ta for _ in range(REPS)) / REPS for _ in range(A_CELLS)]
    cv = [sum(rng.random() < tc for _ in range(REPS)) / REPS for _ in range(C_CELLS)]
    return av, cv


def _wilson(k, n):
    lo, hi = S.wilson_interval(k, n)
    return lo, hi


def _mcse(p, n):
    return math.sqrt(max(p * (1 - p), 0) / n) if n else 0.0


def label_perm_p(task_cells, n_perm, rng):
    # stat = mean over tasks of (mean attack - mean control); one-sided greater.
    # Precompute per-task pooled values, totals, and arm sizes for O(cells) work per permutation.
    pools, tots, nas, ncs = [], [], [], []
    K = len(task_cells)
    for (av, cv) in task_cells:
        pooled = av + cv
        pools.append(pooled)
        tots.append(sum(pooled))
        nas.append(len(av))
        ncs.append(len(cv))
    obs = sum(sum(av) / nas[i] - (tots[i] - sum(av)) / ncs[i]
              for i, (av, cv) in enumerate(task_cells)) / K
    ge, total = 1, 1
    for _ in range(n_perm):
        s = 0.0
        for i in range(K):
            pooled = pools[i]
            rng.shuffle(pooled)                     # in-place; pooled order is irrelevant across perms
            asum = 0.0
            na = nas[i]
            for j in range(na):
                asum += pooled[j]
            s += asum / na - (tots[i] - asum) / ncs[i]
        total += 1
        ge += ((s / K) >= obs - 1e-12)
    return ge / total


def eval_cell(cfg):
    K, sd, pc = cfg["K"], cfg["sd"], cfg["pc"]
    out = {"K": K, "task_sd": sd, "p_control": pc}

    # ---- type-I: sign-flip (module) and label permutation (cell-level) ----
    sf = S.simulate_operating_characteristics(n_tasks=K, variants_per_task=A_CELLS, control_per_task=C_CELLS,
                                              p_attack=pc, p_control=pc, task_sd=sd, n_sims=N_TYPE,
                                              seed=VALID_SEED, inference="perm", n_boot=N_PERM)
    out["typeI_signflip"] = sf["reject_rate_one_sided"]
    out["typeI_signflip_mcse"] = sf["reject_mcse"]

    rng = random.Random(VALID_SEED ^ (K * 1000 + int(sd * 100) + int(pc * 100)))
    rej = 0
    # d_t skewness accumulation under H0 (assumption check for sign-flip)
    dts = []
    for _ in range(N_TYPE):
        tc = []
        for _t in range(K):
            ta = _clip(pc + rng.gauss(0, sd))
            tcr = _clip(pc + rng.gauss(0, sd))
            av, cv = _gen_task_cells(rng, ta, tcr)
            tc.append((av, cv))
            dts.append(sum(av) / len(av) - sum(cv) / len(cv))
        p = label_perm_p(tc, N_PERM, rng)
        rej += (p < 0.025)
    out["typeI_labelperm"] = rej / N_TYPE
    out["typeI_labelperm_mcse"] = _mcse(rej / N_TYPE, N_TYPE)
    m = sum(dts) / len(dts)
    sdv = math.sqrt(sum((x - m) ** 2 for x in dts) / (len(dts) - 1))
    skew = (sum((x - m) ** 3 for x in dts) / len(dts)) / (sdv ** 3) if sdv > 0 else 0.0
    out["dt_skewness_under_null"] = round(skew, 3)

    # ---- coverage: t, studentized bootstrap, BCa ----
    for inf in ("t", "studt", "bca"):
        cov = S.simulate_operating_characteristics(n_tasks=K, variants_per_task=A_CELLS, control_per_task=C_CELLS,
                                                   p_attack=pc + MEANINGFUL, p_control=pc, task_sd=sd,
                                                   n_sims=N_COVER if inf == "t" else 800,
                                                   seed=VALID_SEED, inference=inf, n_boot=800)
        out["coverage_" + inf] = cov["coverage_95"]
        out["coverage_%s_mcse" % inf] = cov["coverage_95_mcse"]

    # ---- power (label perm) and equivalence FPR (t) ----
    out["equivFPR_t"] = S.simulate_operating_characteristics(
        n_tasks=K, variants_per_task=A_CELLS, control_per_task=C_CELLS,
        p_attack=pc + MARGIN + 0.05, p_control=pc, task_sd=sd, n_sims=N_COVER,
        seed=VALID_SEED, inference="t")["equivalence_rate"]
    return out


def judge(out):
    verdict = {}
    # type-I: PASS if point <= 0.035 and Wilson low <= 0.025
    for m in ("signflip", "labelperm"):
        p = out["typeI_" + m]
        lo, hi = _wilson(round(p * N_TYPE), N_TYPE)
        verdict["typeI_%s_pass" % m] = (p <= 0.035 and lo <= 0.025)
    # coverage: PASS if point >= 0.93 - 2mcse and Wilson high >= 0.93
    for m in ("t", "studt", "bca"):
        p = out["coverage_" + m]
        n = N_COVER if m == "t" else 800
        lo, hi = _wilson(round(p * n), n)
        verdict["coverage_%s_pass" % m] = (p >= 0.93 - 2 * out["coverage_%s_mcse" % m] and hi >= 0.93)
    return verdict


def main():
    res = {"validation_seed": VALID_SEED, "criteria": "typeI<=0.025 (not sig above) AND coverage>=0.93",
           "grid": [], "frozen_thresholds": {"type_I": 0.025, "coverage": 0.93}}
    for cfg in GRID:
        o = eval_cell(cfg)
        o["verdict"] = judge(o)
        res["grid"].append(o)
        print("K=%2d sd=%.2f pc=%.2f | typeI sf=%.3f lp=%.3f skew=%.2f | cov t=%.3f studt=%.3f bca=%.3f | eqFPR=%.3f" % (
            o["K"], o["task_sd"], o["p_control"], o["typeI_signflip"], o["typeI_labelperm"],
            o["dt_skewness_under_null"], o["coverage_t"], o["coverage_studt"], o["coverage_bca"], o["equivFPR_t"]))
    # overall PASS/FAIL
    methods_typeI = {"signflip": True, "labelperm": True}
    methods_cov = {"t": True, "studt": True, "bca": True}
    for o in res["grid"]:
        for m in methods_typeI:
            methods_typeI[m] = methods_typeI[m] and o["verdict"]["typeI_%s_pass" % m]
        for m in methods_cov:
            methods_cov[m] = methods_cov[m] and o["verdict"]["coverage_%s_pass" % m]
    res["overall"] = {"typeI_pass": methods_typeI, "coverage_pass": methods_cov}
    any_sig = any(methods_typeI.values())
    any_cov = any(methods_cov.values())
    res["freeze_decision"] = "PASS" if (any_sig and any_cov) else "FAIL"
    print("OVERALL typeI pass:", methods_typeI, "| coverage pass:", methods_cov)
    print("FREEZE DECISION:", res["freeze_decision"])
    path = sys.argv[1] if len(sys.argv) > 1 else "oc_bakeoff.json"
    json.dump(res, open(path, "w"), indent=2)
    print("wrote", path)


if __name__ == "__main__":
    main()
