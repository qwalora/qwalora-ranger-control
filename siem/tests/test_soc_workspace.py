"""STRATA Board-1 SOC triage workspace: portal-served, OpenSearch-free, entitlement +
ownership scoped, answer-free, server-side graded. Tests the ACTUAL launch + data fetch +
submission round-trip (real WSGI), not button rendering.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "soc-workspace-test")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

_JSON = {"Accept": "application/json"}
_POST = {"Accept": "application/json", "X-CSRF-Token": "t"}


_ENV_KEYS = ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV", "RANGER_STRATA_PORTFOLIOS")


@pytest.fixture()
def ctx():
    # Save and RESTORE the process-wide env we clear, so this suite never leaks an unset
    # RANGER_ENV into a later suite (e.g. test_strata_s5_board2 sets it at import and needs it).
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    for k in _ENV_KEYS:
        os.environ.pop(k, None)
    import importlib
    import app as appmod
    importlib.reload(appmod)
    from models import db, Candidate, Cohort, ProgramMembership
    application = appmod.create_app()
    c = application.app_context(); c.push()
    db.drop_all(); db.create_all()
    db.session.add(Cohort(name="2026-A", sequence=1, status="active", pathway="strata")); db.session.commit()

    def mk(h, board=1):
        x = Candidate(handle=h, name=h, email=h + "@e", cohort="2026-A", github_id=h,
                      status="active", current_board=board, token="t-" + h)
        db.session.add(x); db.session.commit(); return x

    def mem(x, p, s):
        db.session.add(ProgramMembership(candidate_id=x.id, program=p, status=s, cohort="2026-A")); db.session.commit()

    p = {}
    p["strata"] = mk("w_strata"); mem(p["strata"], "strata", "active")
    p["strata2"] = mk("w_strata2"); mem(p["strata2"], "strata", "active")
    p["px"] = mk("w_px"); mem(p["px"], "parallax", "active")
    p["susp"] = mk("w_susp"); mem(p["susp"], "strata", "suspended")
    yield application, db, p
    c.pop()
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _sess(application, cid):
    cl = application.test_client()
    with cl.session_transaction() as s:
        s.clear(); s["cand"] = cid; s["csrf"] = "t"
    return cl


def test_launch_page_entitlement(ctx):
    application, db, p = ctx
    assert _sess(application, p["strata"].id).get("/me/workspace").status_code == 200
    # PARALLAX-only is denied the STRATA workspace (API path -> 403; browser path -> redirect)
    assert _sess(application, p["px"].id).get("/me/workspace", headers=_JSON).status_code == 403
    # suspended STRATA membership -> denied
    assert _sess(application, p["susp"].id).get("/me/workspace", headers=_JSON).status_code == 403
    # unauthenticated
    assert application.test_client().get("/me/workspace").status_code in (301, 302, 401)


def test_dataset_is_answer_free_and_owned(ctx):
    application, db, p = ctx
    r = _sess(application, p["strata"].id).get("/me/workspace/data", headers=_JSON)
    assert r.status_code == 200
    d = r.get_json()
    alerts = d["alerts"]
    assert len(alerts) >= 12
    # answer key never leaves the server
    banned = {"_key", "verdict", "severity", "technique", "attack_technique", "iocs"}
    for a in alerts:
        assert banned.isdisjoint(a.keys()), a
        assert set(a.keys()) == {"id", "timestamp", "host", "signal", "raw"}
    # ownership: a different candidate gets a different (own-seed) dataset; no client input is honored
    d2 = _sess(application, p["strata2"].id).get("/me/workspace/data", headers=_JSON).get_json()
    assert [a["raw"] for a in alerts] != [a["raw"] for a in d2["alerts"]]
    # PARALLAX-only denied
    assert _sess(application, p["px"].id).get("/me/workspace/data", headers=_JSON).status_code == 403


def test_submit_grades_server_side_flags_only(ctx):
    application, db, p = ctx
    cl = _sess(application, p["strata"].id)
    alerts = cl.get("/me/workspace/data", headers=_JSON).get_json()["alerts"]
    sub = {"alerts": [{"id": a["id"], "verdict": "false_positive", "severity": "low"} for a in alerts]}
    r = cl.post("/me/workspace/submit", json={"submission": sub}, headers=_POST)
    assert r.status_code == 200
    b = r.get_json()
    assert isinstance(b["score"], (int, float)) and b["pass_bar"] == 95.0
    # feedback is correctness flags only - never the correct values
    for pa in b["per_alert"]:
        assert set(pa.keys()) <= {"id", "verdict_correct", "severity_correct", "technique_correct"}
    # grading discriminates (all-FP vs all-TP differ)
    subtp = {"alerts": [{"id": a["id"], "verdict": "true_positive", "severity": "high",
                         "attack_technique": "T1000", "iocs": ["x"]} for a in alerts]}
    s_tp = cl.post("/me/workspace/submit", json={"submission": subtp}, headers=_POST).get_json()["score"]
    assert s_tp != b["score"]
    # PARALLAX-only cannot submit
    assert _sess(application, p["px"].id).post(
        "/me/workspace/submit", json={"submission": sub}, headers=_POST).status_code == 403


def test_submit_requires_csrf(ctx):
    application, db, p = ctx
    cl = _sess(application, p["strata"].id)
    alerts = cl.get("/me/workspace/data", headers=_JSON).get_json()["alerts"]
    sub = {"alerts": [{"id": a["id"], "verdict": "false_positive", "severity": "low"} for a in alerts]}
    # no X-CSRF-Token -> rejected
    assert cl.post("/me/workspace/submit", json={"submission": sub},
                   headers={"Accept": "application/json"}).status_code == 400
