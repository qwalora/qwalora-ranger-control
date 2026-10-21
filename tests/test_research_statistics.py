"""Regression tests for parallax.research.statistics.

Deterministic and dependency-free. Verifies the Wilson interval endpoints and a known value,
Fisher's exact test against hand-computed p-values, cell-level (pseudoreplication-aware) estimation,
the attack-vs-control comparison, and every aggregate finding-eligibility verdict.
"""
import math

from parallax.research import statistics as S
from parallax.research import protocol as P
from parallax.research import corpus as C, model_backend as mb, harness


# --------------------------------------------------------------------------- intervals

def test_wilson_endpoints_and_empty():
    assert S.wilson_interval(0, 0) == (None, None)
    lo, hi = S.wilson_interval(0, 10)
    assert lo == 0.0 and 0 < hi < 1
    lo, hi = S.wilson_interval(10, 10)   # all-success: Wilson upper ~1.0 (not exactly), lower ~0.7225
    assert abs(hi - 1.0) < 1e-3 and abs(lo - 0.7225) < 1e-3
    lo, hi = S.wilson_interval(5, 10)
    assert abs((lo + hi) / 2 - 0.5) < 1e-9  # symmetric around 0.5


def test_wilson_known_value():
    lo, hi = S.wilson_interval(8, 10)  # phat=0.8, 95%
    assert abs(lo - 0.4902) < 1e-3 and abs(hi - 0.9433) < 1e-3


def test_proportion_structure():
    pr = S.proportion(3, 12)
    assert pr["k"] == 3 and pr["n"] == 12 and abs(pr["p"] - 0.25) < 1e-9
    assert 0 <= pr["ci_low"] < pr["p"] < pr["ci_high"] <= 1


# --------------------------------------------------------------------------- Fisher exact

def test_fisher_known_values():
    assert abs(S.fisher_exact_two_sided(3, 1, 1, 3) - 0.4857142857) < 1e-6
    assert abs(S.fisher_exact_two_sided(5, 5, 5, 5) - 1.0) < 1e-9
    assert S.fisher_exact_two_sided(10, 0, 0, 10) < 1e-4          # perfect separation -> tiny p
    assert abs(S.fisher_exact_two_sided(10, 0, 0, 10) - (2.0 / math.comb(20, 10))) < 1e-9


def test_fisher_degenerate_margins():
    assert S.fisher_exact_two_sided(0, 0, 0, 0) == 1.0
    assert S.fisher_exact_two_sided(0, 5, 0, 5) == 1.0           # no successes in either group


def test_risk_difference_direction():
    rd = S.risk_difference(9, 10, 1, 10)
    assert rd["diff"] > 0 and rd["ci_low"] < rd["diff"] < rd["ci_high"]


# --------------------------------------------------------------------------- synthetic records

def _rec(*, real=True, validated_id="cap-model", condition, attempts, outcome,
         task, variant, rep=1, category="direct_instruction", task_ok=None):
    return {"backend_is_real": real, "model": {"id": validated_id},
            "condition": condition, "attempts_injection": attempts, "outcome": outcome,
            "attack_category": category if condition == P.CONDITION_EXPERIMENTAL else None,
            "legitimate_task_id": task, "adversarial_input_id": variant, "repetition": rep,
            "evaluation": {"task_ok": task_ok}}


def _attack_cells(n_success, n_fail, real=True, model="cap-model"):
    recs = []
    i = 0
    for _ in range(n_success):
        recs.append(_rec(real=real, validated_id=model, condition=P.CONDITION_EXPERIMENTAL,
                         attempts=True, outcome="successful_unauthorized_behavior",
                         task="t%d" % i, variant="v%d" % i)); i += 1
    for _ in range(n_fail):
        recs.append(_rec(real=real, validated_id=model, condition=P.CONDITION_EXPERIMENTAL,
                         attempts=True, outcome="boundary_preserved",
                         task="t%d" % i, variant="v%d" % i)); i += 1
    return recs


def _control_cells(n_fp, n_ok, real=True, model="cap-model"):
    recs = []
    i = 0
    for _ in range(n_fp):
        recs.append(_rec(real=real, validated_id=model, condition=P.CONDITION_EXPERIMENTAL,
                         attempts=False, outcome="successful_unauthorized_behavior",
                         task="c%d" % i, variant="b%d" % i, category="benign_instruction_like")); i += 1
    for _ in range(n_ok):
        recs.append(_rec(real=real, validated_id=model, condition=P.CONDITION_EXPERIMENTAL,
                         attempts=False, outcome="boundary_preserved",
                         task="c%d" % i, variant="b%d" % i, category="benign_instruction_like")); i += 1
    return recs


def test_cell_level_collapses_repetitions():
    # one attack cell, three repetitions all success -> ONE independent success cell, not three
    recs = [_rec(condition=P.CONDITION_EXPERIMENTAL, attempts=True,
                 outcome="successful_unauthorized_behavior", task="t1", variant="v1", rep=r)
            for r in (1, 2, 3)]
    out = S.analyze(recs, env={"RANGER_RESEARCH_VALIDATED_MODELS": "cap-model"})
    cell = out["real_backend"]["cell_level"]
    assert cell["n_attack_cells"] == 1 and cell["ASR"]["k"] == 1
    # pooled trial-level counts all three trials (and is explicitly flagged)
    assert out["real_backend"]["pooled_trial_level"]["ASR"]["n"] == 3


def test_verdict_finding_supported():
    recs = _attack_cells(12, 0) + _control_cells(0, 6)      # strong effect, validated, powered
    out = S.analyze(recs, env={"RANGER_RESEARCH_VALIDATED_MODELS": "cap-model"})
    el = out["real_backend"]["finding_eligibility"]
    assert el["adequately_powered"] and el["significant"]
    assert el["verdict"] == "finding_supported"
    assert out["real_backend"]["comparison"]["fisher_exact_p"] < 0.05


def test_verdict_negative_result_when_no_effect():
    # validated + powered, but attacks never succeed and controls never false-positive
    recs = _attack_cells(0, 12) + _control_cells(0, 6)
    out = S.analyze(recs, env={"RANGER_RESEARCH_VALIDATED_MODELS": "cap-model"})
    el = out["real_backend"]["finding_eligibility"]
    assert el["adequately_powered"] and not el["significant"]
    assert el["verdict"] == "negative_result"
    assert "genuine negative result" in S.interpret(out)


def test_verdict_underpowered_small_n():
    recs = _attack_cells(3, 0) + _control_cells(0, 2)       # only 3 attack cells < MIN
    out = S.analyze(recs, env={"RANGER_RESEARCH_VALIDATED_MODELS": "cap-model"})
    assert out["real_backend"]["finding_eligibility"]["verdict"] == "underpowered"


def test_verdict_proof_of_concept_when_model_not_validated():
    recs = _attack_cells(12, 0) + _control_cells(0, 6)      # strong effect but model NOT validated
    out = S.analyze(recs, env={"RANGER_RESEARCH_VALIDATED_MODELS": ""})
    assert out["real_backend"]["finding_eligibility"]["verdict"] == "proof_of_concept"


def test_verdict_plumbing_only_for_stub():
    recs = _attack_cells(12, 0, real=False, model="stub/rule-v1")
    out = S.analyze(recs)
    assert out["findings_available"] is False
    assert out["simulated_backend"]["finding_eligibility"]["verdict"] == "plumbing_only"
    assert "plumbing" in S.interpret(out).lower()


def test_per_category_breakdown():
    recs = (_attack_cells(4, 0) +
            [_rec(condition=P.CONDITION_EXPERIMENTAL, attempts=True, outcome="boundary_preserved",
                  task="tz%d" % i, variant="vz%d" % i, category="obfuscated_directive") for i in range(3)])
    out = S.analyze(recs, env={"RANGER_RESEARCH_VALIDATED_MODELS": "cap-model"})
    cats = out["real_backend"]["asr_by_category"]
    assert cats["direct_instruction"]["p"] == 1.0
    assert cats["obfuscated_directive"]["p"] == 0.0


def test_integration_with_stub_campaign():
    backend = mb.DeterministicStubBackend()
    camp = harness.run_campaign(backend, C.default_corpus(), repetitions=2)
    out = S.analyze(camp["records"])
    assert out["findings_available"] is False          # stub only -> no findings
    assert out["real_backend"]["n"] == 0
    assert out["simulated_backend"]["n"] > 0
