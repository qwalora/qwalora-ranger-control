"""PX-AR1 (Board 5) secure-architecture-review board tests.

Proves the board grades the candidate's actual review behavior, deterministically and with no model,
and that the negative-control discipline holds: the naive (find-nothing) baseline MUST score 0 /
critical gap, a correct review passes, and a flag-everything review fails closed (overblock on the
sound design). ai_involved is False (objective-only).
"""
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECRET_KEY", "pxar1-test")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest  # noqa: E402

from parallax import architecture_content as AC, architecture_harness as AH, architecture_evaluator as AE  # noqa: E402
from parallax import architecture_assessment as AA, architecture_blueprint as BP, governance  # noqa: E402
from parallax import pid_sandbox as SB  # noqa: E402

ADMINS = {"pxar1-admin"}
SEED = 0xA5A5

CORRECT = (
    "def review(architecture):\n    v=[]\n"
    "    for d in (architecture.get('datastores') or []):\n"
    "        if d.get('public'): v.append('EXPOSED_DATASTORE')\n"
    "        if d.get('contains_pii') and not d.get('encrypted'): v.append('UNENCRYPTED_PII')\n"
    "    for l in (architecture.get('links') or []):\n"
    "        if l.get('carries_pii') and not l.get('encrypted'): v.append('PLAINTEXT_PII_LINK')\n"
    "    for s in (architecture.get('services') or []):\n"
    "        if s.get('exposure')=='public' and s.get('auth')=='none': v.append('NO_AUTH_PUBLIC')\n"
    "    red=architecture.get('redundancy') or {}\n"
    "    for n in (architecture.get('critical_services') or []):\n"
    "        r=red.get(n) or {}\n"
    "        if not r.get('multi_az') and not r.get('backups'): v.append('SPOF_CRITICAL')\n"
    "    return v\n"
)
FLAG_ALL = "def review(architecture):\n    return ['EXPOSED_DATASTORE','UNENCRYPTED_PII','PLAINTEXT_PII_LINK','NO_AUTH_PUBLIC','SPOF_CRITICAL']\n"


def _approval():
    return governance.approve_spec(BP.ARCHITECTURE_SPEC, BP.blueprint(), approver_id="pxar1-admin",
                                   authorized_admins=ADMINS)


def _run(code, cand="c"):
    inst = AC.generate_instance(SEED)
    sha = hashlib.sha256(code.encode("utf-8")).hexdigest()
    m = AE.measure_review(code, inst, defense_hash=sha)
    return AA.run_assessment(measurement=m, cohort="2026-A", candidate_key=cand, approval=_approval(),
                             authorized_admins=ADMINS, code_sha=sha)


def test_harness_discriminates_correct_from_naive():
    inst = AC.generate_instance(SEED)
    for code, exp_recall in ((CORRECT, 1.0), (AC.NAIVE_BASELINE, 0.0)):
        s = AH.build_session(code)
        try:
            m = AH.run_campaign(s, inst)["metrics"]
        finally:
            s.close()
        assert m["security_rate"] == exp_recall
        assert m["task_rate"] == 1.0   # neither over-flags the sound design


def test_naive_baseline_fails_critical():
    """The find-nothing baseline must be a critical gap (score 0) - the negative control proving the
    board discriminates a real review from a no-op."""
    r = _run(AC.NAIVE_BASELINE)
    assert r["assessment_passed"] is False
    assert r["objective_result"]["critical"] is True
    assert r["objective_result"]["detail"]["outcome"] == "architecture_gap"


def test_correct_review_passes_with_high_score():
    r = _run(CORRECT)
    assert r["assessment_passed"] is True
    assert r["objective_result"]["critical"] is False
    assert (r["candidate_feedback"]["final_score"] or 0) >= BP.OBJECTIVE_PASS
    assert r["candidate_feedback"]["measured_recall"] == 1.0
    assert r["candidate_feedback"]["ai_involved"] is False


def test_flag_everything_fails_overblock():
    r = _run(FLAG_ALL)
    assert r["assessment_passed"] is False
    assert r["objective_result"]["critical"] is True
    assert r["objective_result"]["detail"]["outcome"] == "architecture_overblock"


def test_ai_not_involved():
    r = _run(CORRECT)
    assert r["assessment_decision"]["ai_involved"] is False
    assert r["pathway_qualified"] is False


def test_static_check_rejects_unsafe_review():
    assert SB.static_check("import os\ndef review(a):\n    return []\n", interface=("review",))
    assert not SB.static_check(CORRECT, interface=("review",))


def test_instances_differ_by_seed():
    assert AC.generate_instance(0x1).get("flawed") != AC.generate_instance(0x2).get("flawed")
