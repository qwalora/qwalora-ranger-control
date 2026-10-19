"""WS4 admin operations page: admin-only, real measured signals, no candidate exposure."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "admin-ops-test")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

ADMIN = {"Authorization": "Bearer ops-admin-token"}


@pytest.fixture()
def ctx():
    # ADMIN_TOKEN is read live per request (app.py admin_required). Set it only for this suite
    # and restore it, so a bare import-time set never pins a token for another suite whose own
    # import-time setdefault would then no-op (that suite's admin header would stop matching).
    _saved_tok = os.environ.get("ADMIN_TOKEN")
    os.environ["ADMIN_TOKEN"] = "ops-admin-token"
    import importlib
    import app as appmod
    importlib.reload(appmod)
    from models import db, Candidate, Cohort, ProgramMembership
    application = appmod.create_app()
    c = application.app_context(); c.push()
    db.drop_all(); db.create_all()
    db.session.add(Cohort(name="2026-A", sequence=1, status="active", pathway="strata")); db.session.commit()
    st = Candidate(handle="o_st", name="O St", email="o@e", cohort="2026-A", github_id="o_st",
                   status="active", current_board=1, token="t-ost")
    db.session.add(st); db.session.commit()
    db.session.add(ProgramMembership(candidate_id=st.id, program="strata", status="active", cohort="2026-A"))
    db.session.commit()
    yield application, db, st
    c.pop()
    if _saved_tok is None:
        os.environ.pop("ADMIN_TOKEN", None)
    else:
        os.environ["ADMIN_TOKEN"] = _saved_tok


def test_ops_is_admin_only(ctx):
    application, db, st = ctx
    # admin can view
    r = application.test_client().get("/admin/ops", headers=ADMIN)
    assert r.status_code == 200
    assert b"Environment readiness" in r.data and b"operationally verified" in r.data
    # a candidate session cannot reach the admin ops page
    cl = application.test_client()
    with cl.session_transaction() as s:
        s["cand"] = st.id; s["csrf"] = "t"
    assert cl.get("/admin/ops").status_code in (301, 302, 401)
    # unauthenticated
    assert application.test_client().get("/admin/ops").status_code in (301, 302, 401)


def test_ops_shows_real_measured_signals(ctx):
    application, db, st = ctx
    r = application.test_client().get("/admin/ops", headers=ADMIN)
    # the Board-1 grader self-test actually ran (real, in-process)
    assert b"grader self-test ok" in r.data
    # real candidate activity + investigation sections are present
    assert b"Candidate activity" in r.data and b"Investigation status" in r.data
    # STRATA authorized count reflects the seeded active membership (1)
    assert b"STRATA authorized" in r.data


def test_candidate_nav_exposes_no_admin(ctx):
    application, db, st = ctx
    cl = application.test_client()
    with cl.session_transaction() as s:
        s["cand"] = st.id; s["csrf"] = "t"
    me = cl.get("/me").data
    assert b"/admin" not in me
