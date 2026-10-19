"""Server-side draft persistence + completeness validation for the STRATA Board-1 incident
investigation (reusing the shared drafts.py service; separate 'board1_incident' kind).

Covers the confirmed defect and its requirements:
  - save then reload restores incidents, assignments, entry/chain/hosts/accounts/evidence,
  - new session restores (same candidate),
  - multiple incidents persist independently; an incident removal persists,
  - a draft save NEVER grades or records a signed IncidentAssessment attempt,
  - optimistic concurrency rejects stale writes,
  - ownership + program isolation (cross-candidate / cross-program / suspended),
  - the triage draft ('board1_triage') and incident draft ('board1_incident') are independent,
  - incomplete submissions (no incident / zero assigned alerts) are rejected server-side (not graded),
  - a complete submission still grades.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "inc-draft-test")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

H = {"X-CSRF-Token": "t", "Content-Type": "application/json", "Accept": "application/json"}


def _payload(hosts="test-draft-host", assign=None, incidents=None):
    incs = incidents if incidents is not None else [
        {"key": "inc1", "label": "Incident 1", "entry": "", "chain": "T1078, T1021.002",
         "hosts": hosts, "accts": "", "evidence": "sevenkingdoms\\jon"}]
    return {"incidents": incs, "assign": (assign or {}), "nextInc": 2, "selKey": "inc1"}


@pytest.fixture()
def ctx():
    import importlib
    import app as appmod
    importlib.reload(appmod)
    from models import db, Candidate, ProgramMembership
    application = appmod.create_app()
    appctx = application.app_context()
    appctx.push()
    db.create_all()

    def mk(handle, program="strata", status="active", board=1):
        c = Candidate(handle=handle, name=handle, email=handle + "@e", cohort="2026-A",
                      github_id=handle, status=status, current_board=board, token="tok-" + handle)
        db.session.add(c)
        db.session.commit()
        db.session.add(ProgramMembership(candidate_id=c.id, program=program,
                                         status="active", cohort="2026-A"))
        db.session.commit()
        return c

    data = {"a": mk("inc_a"), "b": mk("inc_b"),
            "px": mk("inc_px", program="parallax"), "susp": mk("inc_susp", status="suspended")}
    yield application, data
    appctx.pop()


def _cl(application, cid):
    cl = application.test_client()
    with cl.session_transaction() as s:
        s.clear()
        s["cand"] = cid
        s["csrf"] = "t"
    return cl


def _first_alert(cl):
    return cl.get("/me/workspace/incident/data").get_json()["alerts"][0]["id"]


def test_reproduction_incident_and_host_persist(ctx):
    application, d = ctx
    cl = _cl(application, d["a"].id)
    assert cl.get("/me/workspace/incident/data").get_json()["draft"] is None
    r = cl.post("/me/workspace/incident/draft", headers=H,
                data=json.dumps({"payload": _payload(), "base_version": 0}))
    assert r.status_code == 200 and r.get_json()["version"] == 1
    draft = cl.get("/me/workspace/incident/data").get_json()["draft"]
    inc = draft["payload"]["incidents"][0]
    assert inc["hosts"] == "test-draft-host" and inc["label"] == "Incident 1"
    assert inc["chain"] == "T1078, T1021.002" and inc["evidence"] == "sevenkingdoms\\jon"


def test_new_session_restores(ctx):
    application, d = ctx
    _cl(application, d["a"].id).post("/me/workspace/incident/draft", headers=H,
                                     data=json.dumps({"payload": _payload(), "base_version": 0}))
    draft = _cl(application, d["a"].id).get("/me/workspace/incident/data").get_json()["draft"]
    assert draft and draft["payload"]["incidents"][0]["hosts"] == "test-draft-host"


def test_assignment_and_multiple_incidents_and_removal(ctx):
    application, d = ctx
    cl = _cl(application, d["a"].id)
    aid = _first_alert(cl)
    two = [{"key": "inc1", "label": "Incident 1", "entry": "", "chain": "", "hosts": "h1",
            "accts": "", "evidence": ""},
           {"key": "inc2", "label": "Incident 2", "entry": "", "chain": "", "hosts": "h2",
            "accts": "", "evidence": ""}]
    p = {"incidents": two, "assign": {aid: "inc1"}, "nextInc": 3, "selKey": "inc2"}
    cl.post("/me/workspace/incident/draft", headers=H, data=json.dumps({"payload": p, "base_version": 0}))
    dr = cl.get("/me/workspace/incident/data").get_json()["draft"]
    assert len(dr["payload"]["incidents"]) == 2 and dr["payload"]["assign"][aid] == "inc1"
    # remove incident 2 -> persists
    p2 = {"incidents": [two[0]], "assign": {aid: "inc1"}, "nextInc": 3, "selKey": "inc1"}
    cl.post("/me/workspace/incident/draft", headers=H, data=json.dumps({"payload": p2, "base_version": 1}))
    dr2 = cl.get("/me/workspace/incident/data").get_json()["draft"]
    assert [i["key"] for i in dr2["payload"]["incidents"]] == ["inc1"]


def test_draft_never_grades(ctx):
    application, d = ctx
    from models import IncidentAssessment
    cl = _cl(application, d["a"].id)
    cl.post("/me/workspace/incident/draft", headers=H, data=json.dumps({"payload": _payload(), "base_version": 0}))
    assert IncidentAssessment.query.filter_by(candidate_id=d["a"].id).first() is None


def test_optimistic_concurrency(ctx):
    application, d = ctx
    cl = _cl(application, d["a"].id)
    cl.post("/me/workspace/incident/draft", headers=H, data=json.dumps({"payload": _payload(), "base_version": 0}))
    r = cl.post("/me/workspace/incident/draft", headers=H, data=json.dumps({"payload": _payload(), "base_version": 0}))
    assert r.status_code == 409 and r.get_json()["conflict"] is True


def test_isolation(ctx):
    application, d = ctx
    _cl(application, d["a"].id).post("/me/workspace/incident/draft", headers=H,
                                     data=json.dumps({"payload": _payload(), "base_version": 0}))
    # cross-candidate
    assert _cl(application, d["b"].id).get("/me/workspace/incident/data").get_json()["draft"] is None
    # cross-program (PARALLAX-only denied the STRATA incident route)
    assert _cl(application, d["px"].id).post("/me/workspace/incident/draft", headers=H,
              data=json.dumps({"payload": _payload(), "base_version": 0})).status_code == 403
    # suspended denied
    assert _cl(application, d["susp"].id).post("/me/workspace/incident/draft", headers=H,
              data=json.dumps({"payload": _payload(), "base_version": 0})).status_code == 409


def test_triage_and_incident_drafts_independent(ctx):
    application, d = ctx
    cl = _cl(application, d["a"].id)
    # save a triage draft and an incident draft; neither overwrites the other (separate kinds)
    cl.post("/me/workspace/draft", headers=H, data=json.dumps(
        {"payload": {"adjudications": {"ALRT-1": {"verdict": "true_positive", "severity": "high",
                                                  "technique": "", "iocs": ""}}}, "base_version": 0}))
    cl.post("/me/workspace/incident/draft", headers=H, data=json.dumps({"payload": _payload(), "base_version": 0}))
    tri = cl.get("/me/workspace/data").get_json()["draft"]
    inc = cl.get("/me/workspace/incident/data").get_json()["draft"]
    assert tri["payload"]["adjudications"]["ALRT-1"]["severity"] == "high"
    assert inc["payload"]["incidents"][0]["hosts"] == "test-draft-host"


def test_incomplete_submission_rejected_server_side(ctx):
    application, d = ctx
    from models import IncidentAssessment
    cl = _cl(application, d["a"].id)
    # no incidents
    r1 = cl.post("/me/workspace/incident/submit", headers=H,
                 data=json.dumps({"submission": {"incidents": []}}))
    assert r1.status_code == 400 and "at least one incident" in r1.get_json()["error"].lower()
    # an incident with zero assigned alerts
    r2 = cl.post("/me/workspace/incident/submit", headers=H,
                 data=json.dumps({"submission": {"incidents": [{"alert_ids": []}]}}))
    assert r2.status_code == 400 and "assign at least one alert" in r2.get_json()["error"].lower()
    # neither recorded a graded attempt
    assert IncidentAssessment.query.filter_by(candidate_id=d["a"].id).first() is None


def test_complete_submission_still_grades(ctx):
    application, d = ctx
    from models import IncidentAssessment
    cl = _cl(application, d["a"].id)
    aid = _first_alert(cl)
    r = cl.post("/me/workspace/incident/submit", headers=H, data=json.dumps(
        {"submission": {"incidents": [{"alert_ids": [aid], "entry_alert_id": aid,
                                       "technique_chain": ["T1078"], "affected_hosts": ["h"],
                                       "affected_accounts": [], "evidence": ["e"]}]}}))
    assert r.status_code == 200 and r.get_json()["ok"] is True
    assert IncidentAssessment.query.filter_by(candidate_id=d["a"].id).first() is not None
