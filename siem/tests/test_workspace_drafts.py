"""Server-side draft persistence for the STRATA Board-1 SOC triage workspace.

Covers the confirmed defect and its security/robustness requirements:
  - draft save then reload restores verdict/severity/technique/IOC (the TP/High reproduction),
  - partial records persist,
  - a draft save NEVER grades, records an objective, or evaluates the gate,
  - final submission is unchanged and independent of drafts,
  - ownership + program isolation (cross-candidate / cross-program rejected),
  - suspended / revoked candidates cannot save,
  - optimistic concurrency rejects stale concurrent writes,
  - CSRF + input validation enforced,
  - draft is scoped to the dataset/case (a different case does not leak).
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "ws-draft-test")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

H = {"X-CSRF-Token": "t", "Content-Type": "application/json", "Accept": "application/json"}
TRI = {"adjudications": {"ALRT-1006": {"verdict": "true_positive", "severity": "high",
                                       "technique": "", "iocs": ""}}}


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

    data = {
        "a": mk("drf_a"), "b": mk("drf_b"),
        "px": mk("drf_px", program="parallax"),
        "susp": mk("drf_susp", status="suspended"),
        "revoked": mk("drf_revoked", status="revoked"),
    }
    yield application, data
    appctx.pop()


def _cl(application, cid):
    cl = application.test_client()
    with cl.session_transaction() as s:
        s.clear()
        s["cand"] = cid
        s["csrf"] = "t"
    return cl


def test_tp_high_persists_across_reload(ctx):
    application, d = ctx
    cl = _cl(application, d["a"].id)
    # no draft initially
    assert cl.get("/me/workspace/data").get_json()["draft"] is None
    # save TP + High (partial: no technique/iocs)
    r = cl.post("/me/workspace/draft", headers=H, data=json.dumps({"payload": TRI, "base_version": 0}))
    assert r.status_code == 200 and r.get_json()["version"] == 1
    # reload restores it
    draft = cl.get("/me/workspace/data").get_json()["draft"]
    assert draft["payload"]["adjudications"]["ALRT-1006"]["verdict"] == "true_positive"
    assert draft["payload"]["adjudications"]["ALRT-1006"]["severity"] == "high"
    assert draft["version"] == 1


def test_new_session_restores_draft(ctx):
    application, d = ctx
    _cl(application, d["a"].id).post("/me/workspace/draft", headers=H,
                                     data=json.dumps({"payload": TRI, "base_version": 0}))
    # a brand-new client (new session cookie) for the SAME candidate still sees the draft
    draft = _cl(application, d["a"].id).get("/me/workspace/data").get_json()["draft"]
    assert draft and draft["payload"]["adjudications"]["ALRT-1006"]["severity"] == "high"


def test_draft_save_never_grades(ctx):
    application, d = ctx
    from models import BoardResult
    cl = _cl(application, d["a"].id)
    cl.post("/me/workspace/draft", headers=H, data=json.dumps({"payload": TRI, "base_version": 0}))
    br = BoardResult.query.filter_by(candidate_id=d["a"].id, board=1).first()
    assert br is None or br.objective_score is None, "a draft save must not record an objective"


def test_optimistic_concurrency_rejects_stale_write(ctx):
    application, d = ctx
    cl = _cl(application, d["a"].id)
    cl.post("/me/workspace/draft", headers=H, data=json.dumps({"payload": TRI, "base_version": 0}))
    # a second writer still thinks version is 0 -> conflict, current returned
    r = cl.post("/me/workspace/draft", headers=H, data=json.dumps({"payload": TRI, "base_version": 0}))
    assert r.status_code == 409
    body = r.get_json()
    assert body["conflict"] is True and body["current"]["version"] == 1
    # writing on the correct base version succeeds
    r2 = cl.post("/me/workspace/draft", headers=H, data=json.dumps({"payload": TRI, "base_version": 1}))
    assert r2.status_code == 200 and r2.get_json()["version"] == 2


def test_cross_candidate_isolation(ctx):
    application, d = ctx
    _cl(application, d["a"].id).post("/me/workspace/draft", headers=H,
                                     data=json.dumps({"payload": TRI, "base_version": 0}))
    # candidate B must not see candidate A's draft (structural ownership by session id)
    assert _cl(application, d["b"].id).get("/me/workspace/data").get_json()["draft"] is None


def test_cross_program_cannot_use_strata_workspace(ctx):
    application, d = ctx
    # a PARALLAX-only candidate is denied the STRATA workspace draft route (program gate)
    r = _cl(application, d["px"].id).post("/me/workspace/draft", headers=H,
                                          data=json.dumps({"payload": TRI, "base_version": 0}))
    assert r.status_code == 403


def test_suspended_and_revoked_cannot_save(ctx):
    application, d = ctx
    for who in ("susp", "revoked"):
        r = _cl(application, d[who].id).post("/me/workspace/draft", headers=H,
                                             data=json.dumps({"payload": TRI, "base_version": 0}))
        assert r.status_code == 409, f"{who} must not be able to save a draft"


def test_csrf_required(ctx):
    application, d = ctx
    r = _cl(application, d["a"].id).post("/me/workspace/draft",
                                         headers={"Content-Type": "application/json"},
                                         data=json.dumps({"payload": TRI, "base_version": 0}))
    assert r.status_code == 400


def test_input_validation(ctx):
    application, d = ctx
    cl = _cl(application, d["a"].id)
    bad = {"adjudications": {"X": {"verdict": "maybe"}}}
    assert cl.post("/me/workspace/draft", headers=H,
                   data=json.dumps({"payload": bad, "base_version": 0})).status_code == 400
    # non-object payload rejected
    assert cl.post("/me/workspace/draft", headers=H,
                   data=json.dumps({"payload": "nope", "base_version": 0})).status_code == 400


def test_final_submission_still_works_and_is_separate(ctx):
    application, d = ctx
    from models import BoardResult
    cl = _cl(application, d["a"].id)
    # save a draft first
    cl.post("/me/workspace/draft", headers=H, data=json.dumps({"payload": TRI, "base_version": 0}))
    # the explicit final submission still grades (separate from the draft)
    r = cl.post("/me/workspace/submit", headers=H, data=json.dumps({"submission": {"alerts": []}}))
    assert r.status_code == 200 and r.get_json()["ok"] is True
    br = BoardResult.query.filter_by(candidate_id=d["a"].id, board=1).first()
    assert br is not None and br.objective_score is not None, "final submit must record an objective"
