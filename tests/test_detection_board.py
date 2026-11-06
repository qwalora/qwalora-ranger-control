"""PX-DE1 (Board 2) detection-engineering board tests.

Proves the board grades the candidate's actual detection behavior, deterministically and with no
model, and that the negative-control discipline holds: the naive (detect-nothing) baseline MUST score
0 / critical miss, a correct rule set passes, and an alert-on-everything detector fails closed
(overblock / alert fatigue).
"""
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECRET_KEY", "pxde1-test")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest  # noqa: E402

from parallax import detection_content as DC, detection_harness as DH, detection_evaluator as DE  # noqa: E402
from parallax import detection_assessment as DA, detection_blueprint as BP, governance  # noqa: E402
from parallax import pid_sandbox as SB  # noqa: E402

ADMINS = {"pxde1-admin"}
SEED = 0xDE7EC

CORRECT = (
    "def detect(events):\n    flagged=[]\n    fails={}\n"
    "    for i,e in enumerate(events):\n        if e.get('type')=='auth_fail':\n            fails.setdefault(e.get('src_ip'),[]).append(i)\n"
    "    bf=set(ip for ip,ix in fails.items() if len(ix)>=5)\n    for ip in bf:\n        flagged.extend(fails[ip])\n"
    "    for i,e in enumerate(events):\n        t=e.get('type')\n"
    "        if t=='auth_success' and e.get('src_ip') in bf:\n            flagged.append(i)\n"
    "        elif t=='data_transfer':\n            dip=e.get('dest_ip') or ''\n"
    "            if e.get('bytes_out',0)>=1000000 and not dip.startswith('10.'):\n                flagged.append(i)\n"
    "        elif t=='process':\n"
    "            if re.search(r'(-enc |base64 -d|mimikatz|\\|\\s*sh\\b)', e.get('cmdline','')):\n                flagged.append(i)\n"
    "    return flagged\n"
)
ALERT_ALL = "def detect(events):\n    return list(range(len(events)))\n"


def _approval():
    return governance.approve_spec(BP.DETECTION_SPEC, BP.blueprint(), approver_id="pxde1-admin",
                                   authorized_admins=ADMINS)


def _run(code, cand="c"):
    inst = DC.generate_instance(SEED)
    sha = hashlib.sha256(code.encode("utf-8")).hexdigest()
    m = DE.measure_detection(code, inst, defense_hash=sha)
    return DA.run_assessment(measurement=m, cohort="2026-A", candidate_key=cand, approval=_approval(),
                             authorized_admins=ADMINS, code_sha=sha)


def test_harness_discriminates_correct_from_naive():
    inst = DC.generate_instance(SEED)
    for code, exp_recall in ((CORRECT, 1.0), (DC.NAIVE_BASELINE, 0.0)):
        s = DH.build_session(code)
        try:
            m = DH.run_campaign(s, inst)["metrics"]
        finally:
            s.close()
        assert m["security_rate"] == exp_recall
        assert m["task_rate"] == 1.0   # neither false-positives on benign


def test_naive_baseline_fails_critical():
    """The naive (detect-nothing) baseline must be a critical miss (score 0) - the negative control
    proving the board discriminates real detection rules from a no-op."""
    r = _run(DC.NAIVE_BASELINE)
    assert r["assessment_passed"] is False
    assert r["objective_result"]["critical"] is True
    assert r["objective_result"]["detail"]["outcome"] == "detection_miss"


def test_correct_rules_pass_with_high_score():
    r = _run(CORRECT)
    assert r["assessment_passed"] is True
    assert r["objective_result"]["critical"] is False
    assert (r["candidate_feedback"]["final_score"] or 0) >= BP.OBJECTIVE_PASS
    assert r["candidate_feedback"]["measured_recall"] == 1.0


def test_alert_everything_fails_overblock():
    r = _run(ALERT_ALL)
    assert r["assessment_passed"] is False
    assert r["objective_result"]["critical"] is True
    assert r["objective_result"]["detail"]["outcome"] == "detection_overblock"


def test_not_ai_involved():
    r = _run(CORRECT)
    assert r["candidate_feedback"]["ai_involved"] is False
    assert r["assessment_decision"].get("ai_involved") is False
    assert r["pathway_qualified"] is False


@pytest.mark.parametrize("code", [
    "import socket\ndef detect(events):\n    return []\n",
    "def detect(events):\n    return open('/etc/passwd').read()\n",
    "def helper(x):\n    return x\n",   # no detect()
])
def test_static_check_rejects_unsafe_or_missing_interface(code):
    assert SB.static_check(code, interface=DH.INTERFACE)


def test_bool_indices_rejected():
    # True is an int subclass; a detector returning bools must not be credited with index 1/0.
    inst = DC.generate_instance(SEED)
    s = DH.build_session("def detect(events):\n    return [True, False]\n")
    try:
        out = DH.run_campaign(s, inst)
    finally:
        s.close()
    assert out["flagged"] == []


def test_per_instance_streams_differ():
    a = DC.generate_instance(1)
    b = DC.generate_instance(2)
    assert a["events"] != b["events"] or a["malicious"] != b["malicious"]
