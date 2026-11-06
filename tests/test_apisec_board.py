"""PX-A1 (Board 3) API object-level authorization board tests.

Proves the board grades the candidate's actual authorization behavior, deterministically and with no
model, and that the manual's signature discipline holds: the known-vulnerable baseline (the negative
control) MUST score 0 / critical-fail, a correct fix passes, and gaming shapes (deny-everything,
trusting client-supplied authorization hints) fail closed.
"""
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("SECRET_KEY", "pxa1-test")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest  # noqa: E402

from parallax import apisec_content as AC, apisec_harness as AH, apisec_evaluator as APE  # noqa: E402
from parallax import apisec_assessment as APA, apisec_blueprint as BP, governance  # noqa: E402
from parallax import pid_sandbox as SB  # noqa: E402

COHORT = "2026-A"
ADMINS = {"pxa1-admin"}
SEED = 0xA1A1

CORRECT = (
    "def handle(req):\n"
    "    if not req.get('token_valid'):\n        return {'status': 401}\n"
    "    store = req.get('store') or {}\n    rid = req.get('resource_id')\n"
    "    if rid not in store:\n        return {'status': 404}\n"
    "    if store[rid].get('owner') != req.get('subject'):\n        return {'status': 403}\n"
    "    return {'status': 200, 'body': store[rid].get('content')}\n"
)
DENY_ALL = (
    "def handle(req):\n"
    "    if not req.get('token_valid'):\n        return {'status': 401}\n"
    "    return {'status': 403}\n"
)
# Trusts a client-supplied authorization hint - leaks on the spoof probes.
SPOOF_TRUSTING = (
    "def handle(req):\n"
    "    if not req.get('token_valid'):\n        return {'status': 401}\n"
    "    store = req.get('store') or {}\n    rid = req.get('resource_id')\n"
    "    if rid not in store:\n        return {'status': 404}\n"
    "    if req.get('is_owner') or store[rid].get('owner') == req.get('subject'):\n"
    "        return {'status': 200, 'body': store[rid].get('content')}\n"
    "    return {'status': 403}\n"
)


def _approval():
    return governance.approve_spec(BP.APISEC_SPEC, BP.blueprint(), approver_id="pxa1-admin",
                                   authorized_admins=ADMINS)


def _measure(code, seed=SEED):
    inst = AC.generate_instance(seed, n_notes=10)
    sha = hashlib.sha256(code.encode("utf-8")).hexdigest()
    return APE.measure_authz(code, inst, defense_hash=sha), sha


def _run(code, cand="cand-1"):
    m, sha = _measure(code)
    return APA.run_assessment(measurement=m, cohort=COHORT, candidate_key=cand, approval=_approval(),
                              authorized_admins=ADMINS, code_sha=sha)


# ---- harness discrimination -------------------------------------------------------------------

def test_harness_discriminates_fix_from_vulnerable():
    inst = AC.generate_instance(SEED, n_notes=10)
    for code, exp_deny in ((CORRECT, 1.0), (AC.VULNERABLE_BASELINE, 0.0)):
        s = AH.build_session(code)
        try:
            m = AH.run_campaign(s, inst)["metrics"]
        finally:
            s.close()
        assert m["allow_rate"] == 1.0
        assert m["deny_rate"] == exp_deny


# ---- the negative-control invariant -----------------------------------------------------------

def test_vulnerable_baseline_fails_critical():
    """The known-vulnerable BOLA baseline must be a critical failure (score 0). This is the proof the
    board's measurement actually discriminates a real fix - the manual's negative-control discipline."""
    r = _run(AC.VULNERABLE_BASELINE)
    assert r["assessment_passed"] is False
    assert r["objective_result"]["critical"] is True
    assert r["objective_result"]["detail"]["outcome"] == "authz_bypass"
    assert r["candidate_feedback"]["verdict"] == "critical_failure"


def test_correct_fix_passes_with_high_score():
    r = _run(CORRECT)
    assert r["assessment_passed"] is True
    assert r["objective_result"]["critical"] is False
    assert (r["candidate_feedback"]["final_score"] or 0) >= BP.OBJECTIVE_PASS
    assert r["candidate_feedback"]["measured_leak_rate"] == 0.0


def test_deny_all_fails_overblock():
    r = _run(DENY_ALL)
    assert r["assessment_passed"] is False
    assert r["objective_result"]["critical"] is True
    assert r["objective_result"]["detail"]["outcome"] == "authz_overblock"


def test_spoof_trusting_handler_leaks_and_fails():
    r = _run(SPOOF_TRUSTING)
    assert r["assessment_passed"] is False
    assert r["objective_result"]["critical"] is True
    assert r["objective_result"]["detail"]["outcome"] == "authz_bypass"


# ---- no model in the scoring path -------------------------------------------------------------

def test_assessment_is_not_ai_involved():
    r = _run(CORRECT)
    assert r["candidate_feedback"]["ai_involved"] is False
    decision = r["assessment_decision"]
    assert decision.get("ai_involved") is False
    assert r["pathway_qualified"] is False


# ---- binding + safety -------------------------------------------------------------------------

def test_code_hash_binding_mismatch_rejected():
    m, _ = _measure(CORRECT)
    # a measurement cannot be paired with a different code hash
    from siem.evaluator import EvaluatorScope
    import siem.evaluator as ev
    scope = EvaluatorScope(allowed_index="parallax-pxa1",
                           truth_handle=APE.make_truth_handle(m, objective_pass=75, leak_ceiling=0.1,
                                                              allow_floor=0.5))
    res = ev.get_evaluator(APE.KIND).verify({"code": True, "defense_hash": "deadbeef"}, scope, reader=None)
    assert res["passed"] is False
    assert res["detail"]["outcome"] == "code_measurement_mismatch"


@pytest.mark.parametrize("code", [
    "import os\ndef handle(req):\n    return {'status': 200}\n",
    "def handle(req):\n    return ().__class__.__bases__\n",
    "def helper(x):\n    return x\n",   # no handle()
])
def test_static_check_rejects_unsafe_or_missing_interface(code):
    assert SB.static_check(code, interface=("handle",))


def test_per_instance_stores_differ():
    a = AC.generate_instance(1, n_notes=10)["store"]
    b = AC.generate_instance(2, n_notes=10)["store"]
    assert a != b   # different cohorts/candidates get different sealed stores
