"""PX-CAP capstone board tests.

Proves the capstone composes the four component boards (authz / detection / gates / architecture) with
no model and the all-must-pass + critical-veto discipline: four correct components pass with a real
mean composite and ai_involved=False; any single failing component (a negative-control baseline) makes
the whole capstone a critical capstone_component_failure; the combined code SHA binds the measurement;
and the submit-time contract rejects a missing/unsafe component file.
"""
import hashlib
import io
import os
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECRET_KEY", "pxcap-test")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest  # noqa: E402

from parallax import capstone_content as CC, capstone_harness as CH  # noqa: E402
from parallax import capstone_assessment as CA, capstone_blueprint as BP  # noqa: E402
from parallax import capstone_submission as CS, governance  # noqa: E402

COHORT = "2026-A"
ADMINS = {"pxcap-admin"}
SEED = 0xCA9507

# Correct component solutions (same shapes proven by each component board's own test).
AUTHZ_OK = (
    "def handle(req):\n"
    "    if not req.get('token_valid'):\n        return {'status': 401}\n"
    "    store = req.get('store') or {}\n    rid = req.get('resource_id')\n"
    "    if rid not in store:\n        return {'status': 404}\n"
    "    if store[rid].get('owner') != req.get('subject'):\n        return {'status': 403}\n"
    "    return {'status': 200, 'body': store[rid].get('content')}\n"
)
DETECT_OK = (
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
GATES_OK = (
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
ARCH_OK = (
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
OK_MAP = {"authz": AUTHZ_OK, "detect": DETECT_OK, "gates": GATES_OK, "architecture": ARCH_OK}
WRITEUP = ("Capstone writeup. " * 40)  # comfortably over MIN_WRITEUP_CHARS


def _approval():
    return governance.approve_spec(BP.CAPSTONE_SPEC, BP.blueprint(), approver_id="pxcap-admin",
                                   authorized_admins=ADMINS)


def _snapshot(code_map, writeup=WRITEUP, include=("authz", "detect", "gates", "architecture")):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        def _add(name, data):
            b = data.encode("utf-8")
            ti = tarfile.TarInfo("repo/" + name)
            ti.size = len(b)
            tf.addfile(ti, io.BytesIO(b))
        for comp, fname in [("authz", "authz.py"), ("detect", "detect.py"),
                            ("gates", "gates.py"), ("architecture", "architecture.py")]:
            if comp in include and comp in code_map:
                _add(fname, code_map[comp])
        if writeup is not None:
            _add("writeup.md", writeup)
    return buf.getvalue()


def _measure(code_map):
    inst = CC.generate_instance(SEED)
    res = CH.run_components(code_map, inst)
    combined = CS.combined_sha(code_map)
    return {"metrics": res["metrics"], "components": res["components"],
            "defense_hash": combined}, combined


def _run(code_map, cand="cand-1"):
    m, sha = _measure(code_map)
    return CA.run_assessment(measurement=m, cohort=COHORT, candidate_key=cand, approval=_approval(),
                             authorized_admins=ADMINS, code_sha=sha)


# ---- harness composition ----------------------------------------------------------------------

def test_all_correct_components_pass():
    inst = CC.generate_instance(SEED)
    res = CH.run_components(OK_MAP, inst)
    m = res["metrics"]
    assert m["all_passed"] is True
    assert m["any_critical"] is False
    assert m["passed_components"] == 4
    assert m["mean_composite"] is not None and m["mean_composite"] >= BP.OBJECTIVE_PASS
    for name in CH.ORDER:
        assert res["components"][name]["ok"] is True


def test_one_naive_component_fails_whole_capstone():
    bad = dict(OK_MAP)
    bad["detect"] = CC.DETECT_BASELINE if hasattr(CC, "DETECT_BASELINE") else "def detect(events):\n    return []\n"
    inst = CC.generate_instance(SEED)
    res = CH.run_components(bad, inst)
    m = res["metrics"]
    assert m["all_passed"] is False
    assert "detect" in m["failed_names"]
    assert m["any_critical"] is True


# ---- end-to-end assessment --------------------------------------------------------------------

def test_capstone_passes_and_is_model_free():
    r = _run(OK_MAP)
    assert r["assessment_passed"] is True
    assert r["pathway_qualified"] is False
    assert r["objective_result"]["critical"] is False
    assert r["candidate_feedback"]["ai_involved"] is False
    assert r["assessment_decision"]["ai_involved"] is False
    assert (r["candidate_feedback"]["final_score"] or 0) >= BP.OBJECTIVE_PASS


def test_capstone_critical_when_a_component_fails():
    bad = dict(OK_MAP)
    bad["architecture"] = "def review(architecture):\n    return []\n"  # naive -> architecture_gap
    r = _run(bad, cand="cand-2")
    assert r["assessment_passed"] is False
    assert r["objective_result"]["critical"] is True
    assert r["objective_result"]["detail"]["outcome"] == "capstone_component_failure"
    assert "architecture" in (r["objective_result"]["detail"]["failed"] or [])
    assert r["candidate_feedback"]["ai_involved"] is False


def test_combined_hash_binds_measurement():
    m, sha = _measure(OK_MAP)
    # a mismatched submission hash must not score
    bad = CA.run_assessment(measurement=m, cohort=COHORT, candidate_key="cand-3", approval=_approval(),
                            authorized_admins=ADMINS, code_sha="deadbeef")
    assert bad["assessment_passed"] is False
    assert bad["objective_result"]["detail"]["outcome"] == "code_measurement_mismatch"


# ---- submit-time contract ---------------------------------------------------------------------

def test_validate_accepts_four_correct_components():
    snap = _snapshot(OK_MAP)
    res = CS.validate_code(snap)
    assert res["ok"] is True
    assert res["code_present"] is True
    assert res["code_sha256"] == CS.combined_sha(OK_MAP)


def test_validate_rejects_missing_component():
    snap = _snapshot(OK_MAP, include=("authz", "detect", "gates"))  # architecture.py missing
    res = CS.validate_code(snap)
    assert res["ok"] is False
    assert any(u["id"] == "architecture_code" for u in res["unmet"])


def test_validate_rejects_unsafe_component():
    bad = dict(OK_MAP)
    bad["authz"] = "import os\ndef handle(req):\n    return {'status': 200}\n"  # import banned
    snap = _snapshot(bad)
    res = CS.validate_code(snap)
    assert res["ok"] is False
    assert any(u["id"] == "authz_code" for u in res["unmet"])


def test_validate_rejects_short_writeup():
    snap = _snapshot(OK_MAP, writeup="too short")
    res = CS.validate_code(snap)
    assert res["ok"] is False
    assert any(u["id"] == "writeup" for u in res["unmet"])


def test_instances_differ_by_seed():
    a = CC.generate_instance(0x1111)
    b = CC.generate_instance(0x2222)
    assert a != b
