"""Regression + independent-validation tests for parallax.research.statistics (v2).

Two kinds of test:
- Deterministic reference tests against hand-computed values (always run, no third-party dep).
- Cross-validation against scipy (scipy.stats) where an established implementation exists; these
  skip cleanly if scipy is not installed, so the production module stays dependency-free.

Covers: Wilson intervals, exact zero-event bound, Fisher exact, Student-t and inverse-normal
tables, Holm-Bonferroni, the two-proportion sample-size aid, the task-blocked primary analysis,
the equivalence (TOST) logic, the degenerate zero-variance guards, exclusion sensitivity, and every
finding-eligibility verdict.
"""
import math

import pytest

from parallax.research import statistics as S
from parallax.research import protocol as P
from parallax.research import corpus as C, model_backend as mb, harness

try:
    import scipy.stats as _ss  # noqa: F401
    HAVE_SCIPY = True
except Exception:  # pragma: no cover
    HAVE_SCIPY = False


# ----------------------------------------------------------------- deterministic reference tests

def test_wilson_endpoints_and_known():
    assert S.wilson_interval(0, 0) == (None, None)
    lo, hi = S.wilson_interval(0, 10)
    assert lo == 0.0 and 0 < hi < 1
    lo, hi = S.wilson_interval(10, 10)
    assert abs(hi - 1.0) < 1e-3 and abs(lo - 0.7225) < 1e-3
    lo, hi = S.wilson_interval(8, 10)
    assert abs(lo - 0.4902) < 1e-3 and abs(hi - 0.9433) < 1e-3


def test_clopper_pearson_zero_event():
    # exact one-sided 95% upper bound for 0/n successes is 1 - 0.05**(1/n)
    assert abs(S.clopper_pearson_upper_zero(30) - (1 - 0.05 ** (1 / 30))) < 1e-12
    assert S.clopper_pearson_upper_zero(0) is None


def test_fisher_known_values():
    assert abs(S.fisher_exact_two_sided(3, 1, 1, 3) - 0.4857142857) < 1e-6
    assert abs(S.fisher_exact_two_sided(5, 5, 5, 5) - 1.0) < 1e-9
    assert abs(S.fisher_exact_two_sided(10, 0, 0, 10) - (2.0 / math.comb(20, 10))) < 1e-9


def test_holm_bonferroni_reference():
    # classic ordered p-values; Holm adjusted are max-running of (m-rank)*p
    res = S.holm_bonferroni([0.01, 0.04, 0.03], alpha=0.05)
    adj = [r["p_adj"] for r in res]
    assert abs(adj[0] - 0.03) < 1e-9      # 3*0.01
    assert abs(adj[2] - 0.06) < 1e-9      # 2*0.03
    assert abs(adj[1] - 0.06) < 1e-9      # max(2*0.03, 1*0.04)=0.06 monotone
    assert res[0]["reject"] is True and res[1]["reject"] is False


def test_required_n_monotonic_and_none():
    assert S.required_n_two_proportion(0.5, 0.5) is None
    big = S.required_n_two_proportion(0.07, 0.02)      # small effect
    small = S.required_n_two_proportion(0.30, 0.02)    # large effect
    assert big > small > 0


# ----------------------------------------------------------------- scipy cross-validation

@pytest.mark.skipif(not HAVE_SCIPY, reason="scipy not installed")
def test_fisher_matches_scipy():
    import scipy.stats as ss
    for tbl in ([[3, 1], [1, 3]], [[8, 2], [1, 5]], [[12, 0], [0, 6]], [[2, 8], [7, 3]]):
        mine = S.fisher_exact_two_sided(tbl[0][0], tbl[0][1], tbl[1][0], tbl[1][1])
        ref = ss.fisher_exact(tbl, alternative="two-sided")[1]
        assert abs(mine - ref) < 1e-9


@pytest.mark.skipif(not HAVE_SCIPY, reason="scipy not installed")
def test_tcrit_matches_scipy():
    import scipy.stats as ss
    for df in (1, 2, 3, 5, 10, 20, 30):
        assert abs(S.t_crit(df, 0.95) - ss.t.ppf(0.975, df)) < 5e-4
        assert abs(S.t_crit(df, 0.90) - ss.t.ppf(0.95, df)) < 5e-4


@pytest.mark.skipif(not HAVE_SCIPY, reason="scipy not installed")
def test_inv_norm_matches_scipy():
    import scipy.stats as ss
    for p in (0.025, 0.05, 0.1, 0.5, 0.8, 0.9, 0.975, 0.99):
        assert abs(S._inv_norm(p) - ss.norm.ppf(p)) < 1e-6


@pytest.mark.skipif(not HAVE_SCIPY, reason="scipy not installed")
def test_wilson_matches_scipy_binomtest():
    import scipy.stats as ss
    for k, n in ((8, 10), (0, 10), (10, 10), (3, 25), (17, 40)):
        ci = ss.binomtest(k, n).proportion_ci(confidence_level=0.95, method="wilson")
        lo, hi = S.wilson_interval(k, n)
        assert abs(lo - ci.low) < 1e-9 and abs(hi - ci.high) < 1e-9


# ----------------------------------------------------------------- synthetic records / analysis

def _mk(task, variant, condition, attempts, outcome, *, real=True, model="cap-model",
        category="direct_instruction", rep=1):
    return {"backend_is_real": real, "model": {"id": model},
            "condition": condition, "attempts_injection": attempts, "outcome": outcome,
            "attack_category": category if condition == P.CONDITION_EXPERIMENTAL else None,
            "legitimate_task_id": task, "adversarial_input_id": variant, "repetition": rep,
            "evaluation": {"task_ok": None}}


def _task_block(task, attack_succ, attack_fail, ctrl_succ, ctrl_fail, **kw):
    recs = []
    for i in range(attack_succ):
        recs.append(_mk(task, "av%d" % i, P.CONDITION_EXPERIMENTAL, True,
                        "successful_unauthorized_behavior", **kw))
    for i in range(attack_fail):
        recs.append(_mk(task, "av%d" % (100 + i), P.CONDITION_EXPERIMENTAL, True,
                        "boundary_preserved", **kw))
    for i in range(ctrl_succ):
        recs.append(_mk(task, "cv%d" % i, P.CONDITION_EXPERIMENTAL, False,
                        "successful_unauthorized_behavior", category="benign_instruction_like", **kw))
    for i in range(ctrl_fail):
        recs.append(_mk(task, "cv%d" % (100 + i), P.CONDITION_EXPERIMENTAL, False,
                        "boundary_preserved", category="benign_instruction_like", **kw))
    return recs


VALID_ENV = {"RANGER_RESEARCH_VALIDATED_MODELS": "cap-model"}


def test_primary_is_task_blocked():
    recs = _task_block("t1", 8, 2, 0, 5) + _task_block("t2", 9, 1, 0, 5)
    out = S.analyze(recs, env=VALID_ENV)["real_backend"]["primary_task_blocked"]
    assert out["n_task_blocks"] == 2 and len(out["per_task"]) == 2
    assert "per-attempt" in out["estimand"]


def test_verdict_finding_supported_with_variance():
    # many task blocks, varied strong effects, real between-block variance, narrow CI, lo>0
    rates = [8, 9, 10, 9, 8, 10, 9, 9, 10, 8, 9, 10]
    recs = []
    for i, s in enumerate(rates):
        recs += _task_block("t%d" % i, s, 10 - s, 0, 10)
    el = S.analyze(recs, env=VALID_ENV)["real_backend"]
    assert el["primary_task_blocked"]["sd"] > 0
    assert el["power_precision"]["precise_enough"] is True
    assert el["finding_eligibility"]["verdict"] == "finding_supported"


def test_verdict_equivalence_supported():
    # near-zero effects with small real variance: 90% CI within +/- margin
    recs = []
    for i in range(12):
        asucc = 1 if i in (3, 8) else 0        # a little variance, tiny effect
        recs += _task_block("t%d" % i, asucc, 10 - asucc, 0, 10)
    el = S.analyze(recs, env=VALID_ENV)["real_backend"]
    assert el["primary_task_blocked"]["sd"] > 0
    assert el["equivalence"]["equivalent"] is True
    assert el["finding_eligibility"]["verdict"] == "equivalence_supported"


def test_verdict_bounded_small_effect_zero_events():
    # zero attack successes across enough attempts -> exact upper bound below the meaningful margin
    recs = []
    for i in range(6):
        recs += _task_block("t%d" % i, 0, 10, 0, 5)
    el = S.analyze(recs, env=VALID_ENV)["real_backend"]
    assert el["primary_task_blocked"].get("zero_between_block_variance") is True
    assert el["zero_event_bound"]["one_sided_upper_95"] < S.MEANINGFUL_RD
    assert el["finding_eligibility"]["verdict"] == "bounded_small_effect"


def test_verdict_inconclusive_wide_ci():
    recs = _task_block("t1", 2, 8, 0, 5) + _task_block("t2", 8, 2, 0, 5)   # K=2, huge spread
    el = S.analyze(recs, env=VALID_ENV)["real_backend"]
    assert el["power_precision"]["precise_enough"] is False
    assert el["finding_eligibility"]["verdict"] == "inconclusive"


def test_verdict_proof_of_concept_not_validated():
    recs = []
    for i in range(12):
        recs += _task_block("t%d" % i, 9, 1, 0, 10)
    el = S.analyze(recs, env={"RANGER_RESEARCH_VALIDATED_MODELS": ""})["real_backend"]
    assert el["finding_eligibility"]["verdict"] == "proof_of_concept"


def test_verdict_plumbing_only_stub():
    recs = _task_block("t1", 9, 1, 0, 5, real=False, model="stub/rule-v1")
    out = S.analyze(recs)
    assert out["findings_available"] is False
    assert out["simulated_backend"]["finding_eligibility"]["verdict"] == "plumbing_only"
    assert "plumbing" in S.interpret(out).lower()


def test_per_cell_nondeterminism_flag():
    # one cell, mixed repetitions -> flagged as nondeterministic; cell-level is R-aware (not any-success)
    recs = [_mk("t1", "v1", P.CONDITION_EXPERIMENTAL, True, "successful_unauthorized_behavior", rep=1),
            _mk("t1", "v1", P.CONDITION_EXPERIMENTAL, True, "boundary_preserved", rep=2)]
    pc = S.analyze(recs, env=VALID_ENV)["real_backend"]["per_cell_secondary"]
    assert pc["nondeterminism_detected"] is True and pc["cells_with_mixed_repetitions"] == 1
    assert abs(pc["mean_cell_proportion"] - 0.5) < 1e-9


def test_exclusion_sensitivity_bounds():
    recs = (_task_block("t1", 3, 3, 0, 5) +
            [_mk("t1", "x%d" % i, P.CONDITION_EXPERIMENTAL, True, "infrastructure_failure") for i in range(4)])
    sens = S.analyze(recs, env=VALID_ENV)["real_backend"]["sensitivity"]
    assert sens["excluded_attack_trials"] == 4
    assert sens["bound_excluded_as_failure"] <= sens["primary_rate"] <= sens["bound_excluded_as_success"]


def test_integration_with_stub_campaign():
    backend = mb.DeterministicStubBackend()
    camp = harness.run_campaign(backend, C.default_corpus(), repetitions=2)
    out = S.analyze(camp["records"])
    assert out["findings_available"] is False and out["real_backend"]["n"] == 0
    assert out["simulated_backend"]["n"] > 0
