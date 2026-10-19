"""Program-entitlement authorization matrix (STRATA / PARALLAX).

One Ranger identity, independently authorized programs, least-privilege, server-side.
Covers identities A-I from the spec and the cross-cutting checks: dashboard visibility,
direct-URL/API access, cross-program denial, admin-action authz, revocation freshness
(effect without re-login), and forged client-side program selection.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "prog-entitlements-test")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ.setdefault("ADMIN_TOKEN", "entitlements-admin-token")

import pytest  # noqa: E402

ADMIN = {"Authorization": "Bearer entitlements-admin-token"}
_PX_ENV = ("RANGER_PARALLAX_LABA", "RANGER_PARALLAX_LABA_ENV", "RANGER_ENV",
           "APP_ENV", "ENVIRONMENT", "FLASK_ENV")


@pytest.fixture()
def ctx():
    # Force PARALLAX nonprod on for this suite; restore the environment afterwards so we never
    # clobber a var another suite relies on.
    saved = {k: os.environ.get(k) for k in _PX_ENV}
    os.environ["RANGER_PARALLAX_LABA"] = "1"
    os.environ["RANGER_PARALLAX_LABA_ENV"] = "test"
    for k in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
        os.environ.pop(k, None)
    import importlib
    import app as appmod
    importlib.reload(appmod)
    from models import db, Candidate, Cohort, ProgramMembership
    application = appmod.create_app()
    c = application.app_context(); c.push()
    db.drop_all(); db.create_all()
    db.session.add_all([Cohort(name="2026-A", sequence=1, status="active", pathway="strata"),
                        Cohort(name="2026-PX", sequence=2, status="active", pathway="parallax")])
    db.session.commit()

    def mk(handle, status="active", board=1, cohort="2026-A"):
        x = Candidate(handle=handle, name=handle.upper(), email=handle + "@e", cohort=cohort,
                      github_id=handle, status=status, current_board=board, token="tok-" + handle)
        db.session.add(x); db.session.commit()
        return x

    def mem(x, program, status):
        db.session.add(ProgramMembership(candidate_id=x.id, program=program, status=status,
                                         cohort=x.cohort)); db.session.commit()

    people = {}
    people["strata"] = mk("c_strata"); mem(people["strata"], "strata", "active")
    people["px"] = mk("c_px"); mem(people["px"], "parallax", "active")
    people["dual"] = mk("c_dual"); mem(people["dual"], "strata", "active"); mem(people["dual"], "parallax", "active")
    people["none"] = mk("c_none"); mem(people["none"], "strata", "pending")   # authed, no ACTIVE membership
    people["px_susp"] = mk("c_pxsusp"); mem(people["px_susp"], "strata", "active"); mem(people["px_susp"], "parallax", "suspended")
    people["strata_susp"] = mk("c_strsusp"); mem(people["strata_susp"], "strata", "suspended"); mem(people["strata_susp"], "parallax", "active")
    yield application, db, people
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


def _anon(application):
    return application.test_client()


# ---- A: unauthenticated visitor ---------------------------------------------------------------
def test_A_unauth_denied_everywhere(ctx):
    application, db, _ = ctx
    cl = _anon(application)
    assert cl.get("/me").status_code in (301, 302, 401)
    assert cl.get("/parallax/workspace").status_code in (301, 302)          # -> login
    assert cl.get("/parallax/research/brief").status_code == 401
    assert cl.post("/labs/start", json={"handle": "c_strata"}).status_code in (400, 401)
    assert cl.get("/admin/program-access").status_code in (301, 302, 401)


# ---- B: authenticated candidate, no active membership -----------------------------------------
def test_B_no_membership_denied_both_programs(ctx):
    application, db, p = ctx
    cid = p["none"].id
    html = _sess(application, cid).get("/me").data.decode()
    assert "No program access yet" in html
    assert "Your record" not in html and "research console" not in html
    assert _sess(application, cid).get("/parallax/workspace").status_code == 302
    assert _sess(application, cid).get("/parallax/research/brief").status_code == 401
    assert _sess(application, cid).post("/labs/start", json={"handle": "c_none"},
                                        headers={"X-Candidate-Token": "tok-c_none"}).status_code == 403


# ---- C: STRATA-only ---------------------------------------------------------------------------
def test_C_strata_only_sees_strata_not_parallax(ctx):
    application, db, p = ctx
    cid = p["strata"].id
    html = _sess(application, cid).get("/me").data.decode()
    assert "Your record" in html or "Board 1" in html
    assert "research console" not in html and "research workspace" not in html
    assert 'aria-label="Your programs"' not in html          # no switcher for single program
    assert _sess(application, cid).post("/labs/start", json={"handle": "c_strata"},
                                        headers={"X-Candidate-Token": "tok-c_strata"}).status_code == 200
    # cross-program denial
    assert _sess(application, cid).get("/parallax/workspace").status_code == 302
    assert _sess(application, cid).get("/parallax/research/brief").status_code == 401


def test_C_forged_program_selection_ignored(ctx):
    """A STRATA-only candidate forcing ?program=parallax still gets STRATA; the switcher
    value is cosmetic and never an authorization decision."""
    application, db, p = ctx
    html = _sess(application, p["strata"].id).get("/me?program=parallax").data.decode()
    assert "Your record" in html or "Board 1" in html
    assert "research console" not in html


# ---- D: PARALLAX-only -------------------------------------------------------------------------
def test_D_parallax_only_sees_parallax_not_strata(ctx):
    application, db, p = ctx
    cid = p["px"].id
    html = _sess(application, cid).get("/me").data.decode()
    assert "research console" in html or "research workspace" in html
    assert "Your record" not in html
    assert _sess(application, cid).get("/parallax/workspace").status_code == 200
    assert _sess(application, cid).get("/parallax/research/brief").status_code == 200
    # cross-program denial: no STRATA
    assert _sess(application, cid).post("/labs/start", json={"handle": "c_px"},
                                        headers={"X-Candidate-Token": "tok-c_px"}).status_code == 403


# ---- E: both --------------------------------------------------------------------------------
def test_E_dual_can_use_both_with_switcher(ctx):
    application, db, p = ctx
    cid = p["dual"].id
    html = _sess(application, cid).get("/me").data.decode()
    assert 'aria-label="Your programs"' in html
    assert _sess(application, cid).post("/labs/start", json={"handle": "c_dual"},
                                        headers={"X-Candidate-Token": "tok-c_dual"}).status_code == 200
    assert _sess(application, cid).get("/parallax/workspace").status_code == 200
    html_px = _sess(application, cid).get("/me?program=parallax").data.decode()
    assert "research console" in html_px


# ---- F: suspended from STRATA, active in PARALLAX ---------------------------------------------
def test_F_strata_suspended_parallax_active(ctx):
    application, db, p = ctx
    cid = p["strata_susp"].id
    assert _sess(application, cid).post("/labs/start", json={"handle": "c_strsusp"},
                                        headers={"X-Candidate-Token": "tok-c_strsusp"}).status_code == 403
    assert _sess(application, cid).get("/parallax/workspace").status_code == 200


# ---- G: suspended from PARALLAX, active in STRATA ---------------------------------------------
def test_G_parallax_suspended_strata_active(ctx):
    application, db, p = ctx
    cid = p["px_susp"].id
    assert _sess(application, cid).get("/parallax/workspace").status_code == 302
    assert _sess(application, cid).get("/parallax/research/brief").status_code == 401
    assert _sess(application, cid).post("/labs/start", json={"handle": "c_pxsusp"},
                                        headers={"X-Candidate-Token": "tok-c_pxsusp"}).status_code == 200


# ---- H: authorized reviewer (admin) -----------------------------------------------------------
def test_H_admin_can_administer_program_access(ctx):
    application, db, p = ctx
    cl = application.test_client()
    assert cl.get("/admin/program-access", headers=ADMIN).status_code == 200
    # grant PARALLAX to the STRATA-only candidate, independently
    r = cl.post("/admin/program-access/%d/parallax/grant" % p["strata"].id, headers=ADMIN)
    assert r.status_code in (200, 302)
    assert _sess(application, p["strata"].id).get("/parallax/workspace").status_code == 200
    # the STRATA side is untouched
    assert _sess(application, p["strata"].id).post(
        "/labs/start", json={"handle": "c_strata"},
        headers={"X-Candidate-Token": "tok-c_strata"}).status_code == 200


# ---- I: unauthorized candidate attempting admin actions ---------------------------------------
def test_I_candidate_cannot_perform_admin_actions(ctx):
    application, db, p = ctx
    cl = _sess(application, p["strata"].id)      # a candidate session, not an admin
    assert cl.get("/admin/program-access").status_code in (301, 302, 401)
    r = cl.post("/admin/program-access/%d/parallax/grant" % p["strata"].id)
    assert r.status_code in (301, 302, 400, 401, 403)
    # and no membership was created by the unauthorized attempt
    from models import ProgramMembership
    assert ProgramMembership.query.filter_by(candidate_id=p["strata"].id, program="parallax").first() is None


# ---- revocation freshness: effect without re-login --------------------------------------------
def test_revocation_takes_effect_without_relogin(ctx):
    application, db, p = ctx
    cid = p["px"].id
    live = _sess(application, cid)                 # one session, reused across the revocation
    assert live.get("/parallax/workspace").status_code == 200
    application.test_client().post("/admin/program-access/%d/parallax/suspend" % cid, headers=ADMIN)
    assert live.get("/parallax/workspace").status_code == 302      # same session, now denied
    application.test_client().post("/admin/program-access/%d/parallax/reinstate" % cid, headers=ADMIN)
    assert live.get("/parallax/workspace").status_code == 200


# ---- cross-program data isolation on the research API -----------------------------------------
def test_strata_candidate_cannot_reach_parallax_research_run_api(ctx):
    application, db, p = ctx
    # a STRATA-only candidate cannot initiate a research run (experiment initiation gate)
    r = _sess(application, p["strata"].id).post(
        "/parallax/research/trial", json={"task_id": "t-storage"}, headers={"X-CSRF-Token": "t"})
    assert r.status_code in (401, 403)
