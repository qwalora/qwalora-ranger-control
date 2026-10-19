"""Durable draft persistence for the PARALLAX research workspace (shared drafts.py service,
kinds 'parallax_experiment' and 'parallax_investigation').

Save Progress is NOT Run and NOT Submit: the draft endpoints call only drafts.save / drafts.load,
so a draft save never launches a model execution, consumes trial quota, submits, signs evidence,
or changes qualification. The immutable Ed25519-signed ParallaxResearchRun records are untouched.

Covers the task's 22-point matrix (PARALLAX-relevant items):
  partial save + restore (experiment + analysis), hard refresh / new session, multi-scenario +
  protocol-version isolation, two simultaneous sessions (optimistic concurrency), interrupted
  autosave preserves values, invalid/oversized payload, CSRF rejection, rate limiting,
  cross-candidate isolation, STRATA-only denied, suspended/revoked denied, save without model
  execution / signed evidence / grading, and that real trial execution + signed-evidence
  verification + the investigation submission lifecycle still operate unchanged.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px-research-drafts")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["DEFAULT_COHORT"] = "2026-A"
os.environ["RANGER_PARALLAX_LABA"] = "1"
os.environ["RANGER_PARALLAX_LABA_ENV"] = "test"
for _m in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
    os.environ.pop(_m, None)

import pytest  # noqa: E402

H = {"X-CSRF-Token": "t", "Content-Type": "application/json", "Accept": "application/json"}
EXP_URL = "/parallax/research/experiment/draft"
INV_URL = "/parallax/research/investigation/draft"
LOAD_URL = "/parallax/research/draft"


@pytest.fixture()
def ctx():
    import importlib
    import app as appmod
    importlib.reload(appmod)
    from models import db, Candidate, ProgramMembership
    application = appmod.create_app()
    appctx = application.app_context()
    appctx.push()
    db.drop_all()
    db.create_all()

    def mk(handle, program="parallax", status="active"):
        c = Candidate(handle=handle, name=handle, email=handle + "@e", cohort="2026-A",
                      github_id=handle, status=status, current_board=1)
        db.session.add(c)
        db.session.commit()
        db.session.add(ProgramMembership(candidate_id=c.id, program=program,
                                         status="active", cohort="2026-A"))
        db.session.commit()
        return c

    data = {
        "alice": mk("gh-alice"),
        "bob": mk("gh-bob"),
        "strata": mk("gh-strata", program="strata"),         # STRATA-only (no PARALLAX membership)
        "susp": mk("gh-susp", status="suspended"),           # suspended PARALLAX candidate
        "rev": mk("gh-rev", status="revoked"),               # revoked PARALLAX candidate
    }
    import parallax_routes as pr
    pr._RUN_HITS.clear()                                     # isolate the in-process rate-limit window
    yield application, db, data
    appctx.pop()


def _cl(application, cid):
    cl = application.test_client()
    with cl.session_transaction() as s:
        s.clear()
        s["cand"] = cid
        s["csrf"] = "t"
    return cl


def _save(cl, url, payload, base=0):
    return cl.post(url, headers=H, data=json.dumps({"payload": payload, "base_version": base}))


# ----------------------------- partial save + restore -----------------------------

def test_save_partial_experiment_and_restore(ctx):
    application, _db, d = ctx
    cl = _cl(application, d["alice"].id)
    r = _save(cl, EXP_URL, {"task_id": "", "attack_text": "draft attacker doc in progress"})
    assert r.status_code == 200 and r.get_json()["ok"] is True and r.get_json()["version"] == 1
    # navigate away and return: the restore endpoint serves it back
    got = cl.get(LOAD_URL, headers=H).get_json()
    assert got["ok"] is True
    assert got["experiment"]["payload"]["attack_text"] == "draft attacker doc in progress"
    assert got["investigation"] is None


def test_save_partial_analysis_and_restore_all_fields(ctx):
    application, _db, d = ctx
    cl = _cl(application, d["alice"].id)
    assert _save(cl, INV_URL, {"evidence_run_id": "run-abc123",
                               "analysis": "partial trust-boundary analysis"}).status_code == 200
    inv = cl.get(LOAD_URL, headers=H).get_json()["investigation"]["payload"]
    assert inv["evidence_run_id"] == "run-abc123"
    assert inv["analysis"] == "partial trust-boundary analysis"


def test_hard_refresh_and_new_session_restore(ctx):
    application, _db, d = ctx
    _save(_cl(application, d["alice"].id), EXP_URL, {"task_id": "", "attack_text": "survives reload"})
    # a brand-new authenticated client (fresh cookie jar) = hard refresh / new browser session
    got = _cl(application, d["alice"].id).get(LOAD_URL, headers=H).get_json()
    assert got["experiment"]["payload"]["attack_text"] == "survives reload"


# ----------------------------- isolation (scenario / protocol / candidate / program) -----------------------------

def test_experiment_and_investigation_drafts_independent(ctx):
    application, _db, d = ctx
    cl = _cl(application, d["alice"].id)
    _save(cl, EXP_URL, {"task_id": "", "attack_text": "EXP"})
    _save(cl, INV_URL, {"evidence_run_id": "", "analysis": "INV"})
    got = cl.get(LOAD_URL, headers=H).get_json()
    assert got["experiment"]["payload"]["attack_text"] == "EXP"
    assert got["investigation"]["payload"]["analysis"] == "INV"


def test_protocol_version_change_segregates_draft(ctx, monkeypatch):
    application, _db, d = ctx
    cl = _cl(application, d["alice"].id)
    _save(cl, EXP_URL, {"task_id": "", "attack_text": "composed under protocol v1"})
    assert cl.get(LOAD_URL, headers=H).get_json()["experiment"] is not None
    # bump the research protocol version: the case_key changes, so the old draft must NOT reattach
    from parallax.research import protocol as P
    monkeypatch.setattr(P, "PROTOCOL_VERSION", "px2a-protocol-vNEXT")
    assert cl.get(LOAD_URL, headers=H).get_json()["experiment"] is None


def test_cross_candidate_isolation(ctx):
    application, _db, d = ctx
    _save(_cl(application, d["alice"].id), EXP_URL, {"task_id": "", "attack_text": "alice only"})
    bob = _cl(application, d["bob"].id).get(LOAD_URL, headers=H).get_json()
    assert bob["experiment"] is None   # bob never sees alice's draft


def test_strata_only_candidate_denied(ctx):
    application, _db, d = ctx
    cl = _cl(application, d["strata"].id)
    assert _save(cl, EXP_URL, {"task_id": "", "attack_text": "x"}).status_code == 403
    assert _save(cl, INV_URL, {"evidence_run_id": "", "analysis": "x"}).status_code == 403
    assert cl.get(LOAD_URL, headers=H).status_code == 403


def test_suspended_and_revoked_denied(ctx):
    application, _db, d = ctx
    assert _save(_cl(application, d["susp"].id), EXP_URL, {"attack_text": "x"}).status_code == 401
    assert _save(_cl(application, d["rev"].id), EXP_URL, {"attack_text": "x"}).status_code == 401
    assert _cl(application, d["susp"].id).get(LOAD_URL, headers=H).status_code == 401


# ----------------------------- concurrency + failure handling -----------------------------

def test_optimistic_concurrency_two_sessions(ctx):
    application, _db, d = ctx
    one = _cl(application, d["alice"].id)
    two = _cl(application, d["alice"].id)   # a second simultaneous session for the same candidate
    assert _save(one, EXP_URL, {"attack_text": "v1"}, base=0).status_code == 200
    # the second session still believes base 0 -> its save is a stale write and is rejected
    r = _save(two, EXP_URL, {"attack_text": "racing v1b"}, base=0)
    assert r.status_code == 409 and r.get_json()["conflict"] is True
    assert r.get_json()["current"]["version"] == 1
    # the first session advances cleanly with the version it holds
    assert _save(one, EXP_URL, {"attack_text": "v2"}, base=1).status_code == 200


def test_interrupted_autosave_preserves_server_value(ctx):
    application, _db, d = ctx
    cl = _cl(application, d["alice"].id)
    _save(cl, EXP_URL, {"attack_text": "KEEP THIS"}, base=0)
    # a stale write (simulating a lost/overlapping autosave) is rejected and must not clobber
    assert _save(cl, EXP_URL, {"attack_text": "should-not-win"}, base=0).status_code == 409
    assert cl.get(LOAD_URL, headers=H).get_json()["experiment"]["payload"]["attack_text"] == "KEEP THIS"


def test_invalid_and_oversized_payload_rejected(ctx):
    application, _db, d = ctx
    cl = _cl(application, d["alice"].id)
    # non-object payload
    assert cl.post(EXP_URL, headers=H,
                   data=json.dumps({"payload": "nope", "base_version": 0})).status_code == 400
    # oversized attacker document (> 4000 chars)
    assert _save(cl, EXP_URL, {"attack_text": "A" * 4001}).status_code == 400
    # oversized analysis (> 20000 chars)
    assert _save(cl, INV_URL, {"evidence_run_id": "", "analysis": "B" * 20001}).status_code == 400
    # unknown task_id rejected at the route (program rule)
    assert _save(cl, EXP_URL, {"task_id": "not-a-real-task", "attack_text": ""}).status_code == 400
    # empty task_id is allowed for a draft (work not yet configured)
    assert _save(cl, EXP_URL, {"task_id": "", "attack_text": ""}).status_code == 200


def test_csrf_rejected(ctx):
    application, _db, d = ctx
    cl = _cl(application, d["alice"].id)
    # cookie-authed POST with no CSRF token (and no header-token auth) is rejected
    r = cl.post(EXP_URL, headers={"Content-Type": "application/json", "Accept": "application/json"},
                data=json.dumps({"payload": {"attack_text": "x"}, "base_version": 0}))
    assert r.status_code == 400


def test_rate_limited(ctx, monkeypatch):
    application, _db, d = ctx
    monkeypatch.setenv("RANGER_RESEARCH_DRAFT_LIMIT_PER_MIN", "2")
    import parallax_routes as pr
    pr._RUN_HITS.clear()
    cl = _cl(application, d["alice"].id)
    assert _save(cl, EXP_URL, {"attack_text": "1"}, base=0).status_code == 200
    assert _save(cl, EXP_URL, {"attack_text": "2"}, base=1).status_code == 200
    # third save within the window trips the per-candidate draft rate limit
    assert _save(cl, EXP_URL, {"attack_text": "3"}, base=2).status_code == 429


# ----------------------------- Save Progress is not Run / Submit / grade -----------------------------

def test_draft_save_never_runs_model_signs_evidence_or_submits(ctx):
    application, _db, d = ctx
    from models import ParallaxResearchRun
    cl = _cl(application, d["alice"].id)
    # many experiment + analysis saves
    for i in range(3):
        _save(cl, EXP_URL, {"task_id": "", "attack_text": "iter %d" % i}, base=i)
    _save(cl, INV_URL, {"evidence_run_id": "run-x", "analysis": "analysis draft"}, base=0)
    # NOT ONE signed research run / trial / submission was created by draft saving
    assert ParallaxResearchRun.query.count() == 0


def test_draft_save_does_not_invoke_backend(ctx, monkeypatch):
    application, _db, d = ctx
    # make any model backend construction explode: a draft save must never reach it
    from parallax.research import model_backend as mb

    def _boom(*a, **k):
        raise AssertionError("draft save must never construct a model backend")

    monkeypatch.setattr(mb, "from_config", _boom)
    cl = _cl(application, d["alice"].id)
    assert _save(cl, EXP_URL, {"task_id": "", "attack_text": "no model please"}).status_code == 200
    assert _save(cl, INV_URL, {"evidence_run_id": "", "analysis": "still no model"}).status_code == 200


# ----------------------------- existing lifecycle still operates (regression) -----------------------------

def test_existing_trial_execution_and_signed_evidence_still_operate(ctx):
    application, _db, d = ctx
    cl = _cl(application, d["alice"].id)
    # a draft exists first (to prove drafts don't interfere with real execution)
    _save(cl, EXP_URL, {"task_id": "t-storage", "attack_text": "benign"})
    r = cl.post("/parallax/research/trial", headers=H, data=json.dumps({"task_id": "t-storage"}))
    assert r.status_code == 201, r.get_data(as_text=True)
    body = r.get_json()
    tid = body["trial_id"]
    from models import ParallaxResearchRun
    import signing
    row = ParallaxResearchRun.query.filter_by(run_id=tid).first()
    assert row is not None
    # the signed evidence verifies (signing lifecycle intact)
    assert signing.verify(json.loads(row.run_record), row.signature, kid=row.signing_kid) is True


def test_existing_investigation_submission_still_operates(ctx):
    application, _db, d = ctx
    cl = _cl(application, d["alice"].id)
    tid = cl.post("/parallax/research/trial", headers=H,
                  data=json.dumps({"task_id": "t-storage"})).get_json()["trial_id"]
    # an analysis draft can coexist, but SUBMIT is the explicit, separate signed action
    _save(cl, INV_URL, {"evidence_run_id": tid, "analysis": "draft analysis"})
    r = cl.post("/parallax/research/investigation", headers=H,
                data=json.dumps({"evidence_run_id": tid, "analysis": "final submitted analysis"}))
    assert r.status_code == 201
    assert r.get_json()["bound_to"] == tid and r.get_json()["pathway_qualified"] is False
