"""PX-S1 (Board 4) secure-release-gate board tests.

Proves the board grades the candidate's actual gate behavior, deterministically and with no model,
and that the negative-control discipline holds: the permissive baseline MUST score 0 / critical-fail,
a correct gate set passes, and a block-everything gate set fails closed (overblock).
"""
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECRET_KEY", "pxs1-test")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest  # noqa: E402

from parallax import devsecops_content as DC, devsecops_harness as DH, devsecops_evaluator as DE  # noqa: E402
from parallax import devsecops_assessment as DA, devsecops_blueprint as BP, governance  # noqa: E402
from parallax import pid_sandbox as SB  # noqa: E402

ADMINS = {"pxs1-admin"}
SEED = 0x5151

CORRECT = (
    "def scan_secrets(text):\n    f=[]\n"
    "    if re.search(r'AKIA[A-Z2-7]{16}',text): f.append('aws')\n"
    "    if re.search(r'ghp_[a-z0-9]{36}',text): f.append('gh')\n"
    "    if 'BEGIN PRIVATE KEY' in text: f.append('pem')\n"
    "    if re.search(r'(password|api_key|secret|token)\\s*=\\s*[\"\\']',text): f.append('hc')\n"
    "    return f\n\n"
    "def allow_merge(ci):\n    t=ci.get('tests') or {}\n    return t.get('failed',0)==0 and ci.get('lint_errors',0)==0\n\n"
    "def allow_release(sbom):\n    for d in (sbom or []):\n"
    "        if d.get('severity') in ('high','critical'): return False\n"
    "        if d.get('license') in ('GPL-3.0','AGPL-3.0'): return False\n    return True\n"
)
BLOCK_ALL = (
    "def scan_secrets(text):\n    return ['x']\n\n"
    "def allow_merge(ci):\n    return False\n\n"
    "def allow_release(sbom):\n    return False\n"
)


def _approval():
    return governance.approve_spec(BP.DEVSECOPS_SPEC, BP.blueprint(), approver_id="pxs1-admin",
                                   authorized_admins=ADMINS)


def _run(code, cand="c"):
    inst = DC.generate_instance(SEED)
    sha = hashlib.sha256(code.encode("utf-8")).hexdigest()
    m = DE.measure_gates(code, inst, defense_hash=sha)
    return DA.run_assessment(measurement=m, cohort="2026-A", candidate_key=cand, approval=_approval(),
                             authorized_admins=ADMINS, code_sha=sha)


def test_harness_discriminates_correct_from_permissive():
    inst = DC.generate_instance(SEED)
    for code, exp_sec in ((CORRECT, 1.0), (DC.PERMISSIVE_BASELINE, 0.0)):
        s = DH.build_session(code)
        try:
            m = DH.run_campaign(s, inst)["metrics"]
        finally:
            s.close()
        assert m["security_rate"] == exp_sec
        assert m["task_rate"] == 1.0   # both allow legitimate cases; only security differs


def test_permissive_baseline_fails_critical():
    """The permissive (allow-everything) baseline must be a critical bypass (score 0) - the negative
    control that proves the board discriminates real gates from a no-op."""
    r = _run(DC.PERMISSIVE_BASELINE)
    assert r["assessment_passed"] is False
    assert r["objective_result"]["critical"] is True
    assert r["objective_result"]["detail"]["outcome"] == "gate_bypass"


def test_correct_gates_pass_with_high_score():
    r = _run(CORRECT)
    assert r["assessment_passed"] is True
    assert r["objective_result"]["critical"] is False
    assert (r["candidate_feedback"]["final_score"] or 0) >= BP.OBJECTIVE_PASS
    assert r["candidate_feedback"]["measured_security_rate"] == 1.0


def test_block_everything_fails_overblock():
    r = _run(BLOCK_ALL)
    assert r["assessment_passed"] is False
    assert r["objective_result"]["critical"] is True
    assert r["objective_result"]["detail"]["outcome"] == "gate_overblock"


def test_not_ai_involved():
    r = _run(CORRECT)
    assert r["candidate_feedback"]["ai_involved"] is False
    assert r["assessment_decision"].get("ai_involved") is False
    assert r["pathway_qualified"] is False


@pytest.mark.parametrize("code", [
    "import subprocess\ndef scan_secrets(text):\n    return []\n",
    "def scan_secrets(text):\n    return open('/etc/passwd').read()\n",
    "def helper(x):\n    return x\n",   # none of the gate interface defined
])
def test_static_check_rejects_unsafe_or_missing_interface(code):
    assert SB.static_check(code, interface=DH.INTERFACE)


def test_per_instance_batteries_differ():
    a = DC.generate_instance(1)["battery"]
    b = DC.generate_instance(2)["battery"]
    assert a != b
