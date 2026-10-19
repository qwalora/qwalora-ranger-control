"""Server-side draft persistence for the STRATA Board-1 written report (shared drafts.py service,
'strata_report' kind). Save Progress is separate from Submit report and never submits or grades.

Covers:
  - save then dashboard restores the report text (the reproduction),
  - new session restores,
  - long reports persist; oversized drafts rejected,
  - a draft save NEVER creates a Report, submits, or grades,
  - optimistic concurrency rejects stale writes,
  - ownership + program isolation (cross-candidate / cross-program / suspended),
  - the triage / incident / report drafts are independent,
  - empty report submission rejected server-side (existing policy, unchanged),
  - a successful final submission still creates the Report AND clears the draft (no resurface).
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "report-draft-test")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

H = {"X-CSRF-Token": "t", "Content-Type": "application/json", "Accept": "application/json"}
TXT = "DRAFT PERSISTENCE TEST — This is temporary text, not a final report."


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

    data = {"a": mk("rep_a"), "b": mk("rep_b"),
            "px": mk("rep_px", program="parallax"),
            "susp": mk("rep_susp", status="suspended"),
            "rev": mk("rep_rev", status="revoked")}
    yield application, data
    appctx.pop()


def _cl(application, cid):
    cl = application.test_client()
    with cl.session_transaction() as s:
        s.clear()
        s["cand"] = cid
        s["csrf"] = "t"
    return cl


def _save(cl, body, base=0):
    return cl.post("/me/report/draft", headers=H,
                   data=json.dumps({"payload": {"body": body}, "base_version": base}))


def test_reproduction_dashboard_restores_report(ctx):
    application, d = ctx
    cl = _cl(application, d["a"].id)
    assert _save(cl, TXT).status_code == 200
    html = cl.get("/me").data.decode()
    assert TXT in html, "dashboard must restore the saved report draft into the textarea"
    assert 'id="report-save"' in html  # Save progress button present


def test_new_session_restores(ctx):
    application, d = ctx
    _save(_cl(application, d["a"].id), TXT)
    assert TXT in _cl(application, d["a"].id).get("/me").data.decode()


def test_long_report_persists_and_oversized_rejected(ctx):
    application, d = ctx
    cl = _cl(application, d["a"].id)
    import drafts
    long_body = "Technical incident report paragraph.\n" * 2000
    assert _save(cl, long_body).status_code == 200
    # confirm via the dashboard restore path
    assert long_body[:60] in cl.get("/me").data.decode()
    # oversized draft rejected
    assert _save(cl, "B" * (drafts.MAX_REPORT_BODY_CHARS + 1), base=1).status_code == 400


def test_draft_save_never_creates_report_or_grades(ctx):
    application, d = ctx
    from models import Report
    cl = _cl(application, d["a"].id)
    _save(cl, TXT)
    assert Report.query.filter_by(candidate_id=d["a"].id).count() == 0


def test_optimistic_concurrency(ctx):
    application, d = ctx
    cl = _cl(application, d["a"].id)
    _save(cl, TXT, base=0)
    r = _save(cl, TXT + " edited", base=0)  # stale base
    assert r.status_code == 409 and r.get_json()["conflict"] is True
    assert _save(cl, TXT + " v2", base=1).status_code == 200


def test_isolation(ctx):
    application, d = ctx
    _save(_cl(application, d["a"].id), TXT)
    # cross-candidate: B's dashboard does not contain A's report text
    assert TXT not in _cl(application, d["b"].id).get("/me").data.decode()
    # cross-program: a PARALLAX-only candidate is denied the STRATA report draft route
    assert _save(_cl(application, d["px"].id), TXT).status_code == 403
    # suspended / revoked denied
    assert _save(_cl(application, d["susp"].id), TXT).status_code == 409
    assert _save(_cl(application, d["rev"].id), TXT).status_code == 409


def test_report_triage_incident_drafts_independent(ctx):
    application, d = ctx
    cl = _cl(application, d["a"].id)
    _save(cl, TXT)
    cl.post("/me/workspace/draft", headers=H, data=json.dumps(
        {"payload": {"adjudications": {"ALRT-1": {"verdict": "false_positive", "severity": "low",
                                                  "technique": "", "iocs": ""}}}, "base_version": 0}))
    cl.post("/me/workspace/incident/draft", headers=H, data=json.dumps(
        {"payload": {"incidents": [{"key": "inc1", "label": "I1", "entry": "", "chain": "",
                                    "hosts": "h", "accts": "", "evidence": ""}],
                     "assign": {}, "nextInc": 2, "selKey": "inc1"}, "base_version": 0}))
    # all three coexist and restore independently
    assert TXT in cl.get("/me").data.decode()
    assert cl.get("/me/workspace/data").get_json()["draft"]["payload"]["adjudications"]["ALRT-1"]["verdict"] == "false_positive"
    assert cl.get("/me/workspace/incident/data").get_json()["draft"]["payload"]["incidents"][0]["hosts"] == "h"


def test_empty_submission_rejected_server_side(ctx):
    application, d = ctx
    from models import Report
    cl = _cl(application, d["a"].id)
    # existing report policy: a non-empty body is required (no new min-length invented)
    r = cl.post("/me/report", headers={"X-CSRF-Token": "t"}, data={"csrf": "t", "body": "   "})
    assert r.status_code in (302, 303)
    assert "report_error" in r.headers.get("Location", "")
    assert Report.query.filter_by(candidate_id=d["a"].id).count() == 0


def test_final_submission_creates_report_and_clears_draft(ctx):
    application, d = ctx
    from models import Report
    cl = _cl(application, d["a"].id)
    _save(cl, TXT)
    r = cl.post("/me/report", headers={"X-CSRF-Token": "t"},
                data={"csrf": "t", "body": "My real board 1 written analysis."})
    assert r.status_code in (302, 303) and "report_ok" in r.headers.get("Location", "")
    assert Report.query.filter_by(candidate_id=d["a"].id).count() == 1
    # the draft was superseded by the submission; it does not resurface (report now pending anyway)
    import drafts
    # the report is now pending, so report_open is False and the textarea is hidden; confirm the
    # submitted text is NOT re-served as an unsubmitted draft by checking the draft row is gone
    from models import WorkspaceDraft
    assert WorkspaceDraft.query.filter_by(candidate_id=d["a"].id, kind="strata_report").count() == 0
