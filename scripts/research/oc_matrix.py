#!/usr/bin/env python3
"""Operating-characteristics matrix for the PARALLAX task-blocked inference (SAP validation).

Stress-tests the inference procedures across task heterogeneity and baseline event rates, reporting
type-I error (permutation), power (permutation), 95% CI coverage (Student-t), and the equivalence
false-positive rate (TOST via the t 90% CI, at a true effect OUTSIDE the margin), each with a Monte
Carlo standard error. Deterministic: fixed seeds and generators. Pure Python; run from the repo root:

    python scripts/research/oc_matrix.py [out.json]

This is software validation of the ANALYSIS procedure's operating characteristics, not a scientific
result about any model.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from parallax.research import statistics as S  # noqa: E402

MARGIN = S.EQUIVALENCE_MARGIN
GRID = []
for K in (24, 48):
    for task_sd in (0.05, 0.10):
        for p_control in (0.02, 0.10):
            GRID.append({"n_tasks": K, "task_sd": task_sd, "p_control": p_control,
                         "variants_per_task": 30, "control_per_task": 6})

N_TYPE = 600      # sims for permutation type-I / power
N_PERM = 500      # permutation resamples
N_COVER = 2500    # sims for t coverage / equivalence FPR
SEED = 20260101


def cell(cfg):
    pc = cfg["p_control"]
    common = dict(n_tasks=cfg["n_tasks"], variants_per_task=cfg["variants_per_task"],
                  control_per_task=cfg["control_per_task"], task_sd=cfg["task_sd"],
                  p_control=pc, seed=SEED)
    typ = S.simulate_operating_characteristics(p_attack=pc, inference="perm", n_sims=N_TYPE,
                                               n_boot=N_PERM, **common)
    powr = S.simulate_operating_characteristics(p_attack=pc + S.MEANINGFUL_RD, inference="perm",
                                                n_sims=N_TYPE, n_boot=N_PERM, **common)
    cov = S.simulate_operating_characteristics(p_attack=pc + S.MEANINGFUL_RD, inference="t",
                                               n_sims=N_COVER, **common)
    eqfp = S.simulate_operating_characteristics(p_attack=pc + MARGIN + 0.05, inference="t",
                                                n_sims=N_COVER, **common)
    return {
        "n_tasks": cfg["n_tasks"], "task_sd": cfg["task_sd"], "p_control": pc,
        "type_I_perm": round(typ["reject_rate_one_sided"], 4), "type_I_mcse": round(typ["reject_mcse"], 4),
        "power_perm_at_0.10": round(powr["reject_rate_one_sided"], 4), "power_mcse": round(powr["reject_mcse"], 4),
        "coverage95_t": round(cov["coverage_95"], 4), "coverage_mcse": round(cov["coverage_95_mcse"], 4),
        "equiv_FPR_t_outside_margin": round(eqfp["equivalence_rate"], 4), "equiv_FPR_mcse": round(eqfp["equivalence_mcse"], 4),
    }


def main():
    out = {"nominal": {"type_I_one_sided": 0.025, "coverage95": 0.95, "equiv_FPR_target": 0.05},
           "settings": {"n_sims_type_power": N_TYPE, "n_perm": N_PERM, "n_sims_cover_equiv": N_COVER,
                        "seed": SEED, "margin": MARGIN, "meaningful_rd": S.MEANINGFUL_RD},
           "rows": []}
    for cfg in GRID:
        row = cell(cfg)
        out["rows"].append(row)
        print("K=%2d sd=%.2f pc=%.2f | typeI=%.3f+-%.3f power=%.3f cover=%.3f equivFPR=%.3f" % (
            row["n_tasks"], row["task_sd"], row["p_control"], row["type_I_perm"], row["type_I_mcse"],
            row["power_perm_at_0.10"], row["coverage95_t"], row["equiv_FPR_t_outside_margin"]))
    path = sys.argv[1] if len(sys.argv) > 1 else "oc_matrix.json"
    json.dump(out, open(path, "w"), indent=2)
    print("wrote", path)


if __name__ == "__main__":
    main()
