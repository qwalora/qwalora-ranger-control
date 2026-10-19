"""STRATA entitlement enforcement on the flag-gated STRATA surfaces (/case, /workbench).

These surfaces are OFF in parallax-nonprod; this suite ENABLES their feature flags IN-TEST to
prove the server-side STRATA program gate denies a PARALLAX-only candidate even when the flag is
on (so the gate, not the flag, is the control). The /soc gateway requires JWT + OpenSearch
configuration to register and is covered by code review + the shared _strata_ok gate.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "flagged-surfaces-test")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["RANGER_CASE_UI"] = "1"          # enable /case in-test (OFF in nonprod)
os.environ["RANGER_WORKBENCH"] = "1"        # enable /workbench in-test (OFF in nonprod)

import pytest  # noqa: E402

_FLAGS = ("RANGER_CASE_UI", "RANGER_WORKBENCH", "RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV")


@pytest.fixture()
def ctx():
    saved = {k: os.environ.get(k) for k in _FLAGS}
    os.environ["RANGER_CASE_UI"] = "1"
    os.environ["RANGER_WORKBENCH"] = "1"
    for k in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
        os.environ.pop(k, None)
    import importlib
    import app as appmod
    importlib.reload(appmod)
    from models import db, Candidate, Cohort, ProgramMembership
    application = appmod.create_app()
    c = application.app_context(); c.push()
    db.drop_all(); db.create_all()
    db.session.add(Cohort(name="2026-A", sequence=1, status="active", pathway="strata")); db.session.commit()

    def mk(handle, board=2):
        x = Candidate(handle=handle, name=handle, email=handle + "@e", cohort="2026-A",
                      github_id=handle, status="active", current_board=board, token="tok-" + handle)
        db.session.add(x); db.session.commit()
        return x

    def mem(x, program, status):
        db.session.add(ProgramMembership(candidate_id=x.id, program=program, status=status,
                                         cohort="2026-A")); db.session.commit()

    p = {}
    p["strata"] = mk("f_strata"); mem(p["strata"], "strata", "active")
    p["px"] = mk("f_px"); mem(p["px"], "parallax", "active")      # PARALLAX-only, board 2
    p["legacy"] = mk("f_legacy")                                   # zero-row -> legacy STRATA
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


def test_case_denies_parallax_only_even_with_flag_on(ctx):
    application, db, p = ctx
    # PARALLAX-only candidate is denied the STRATA /case surface (program gate, not the flag)
    assert _sess(application, p["px"].id).get("/case").status_code == 403
    # STRATA-entitled candidates pass the program gate (not a 403-for-program)
    assert _sess(application, p["strata"].id).get("/case").status_code != 403
    assert _sess(application, p["legacy"].id).get("/case").status_code != 403


def test_workbench_denies_parallax_only_even_with_flag_on(ctx):
    application, db, p = ctx
    # /workbench returns the locked page (403) for a PARALLAX-only candidate
    assert _sess(application, p["px"].id).get("/workbench").status_code == 403
    # STRATA-entitled candidates are not locked out by the program gate
    assert _sess(application, p["strata"].id).get("/workbench").status_code != 403
    assert _sess(application, p["legacy"].id).get("/workbench").status_code != 403


def test_case_still_404_when_flag_off(ctx):
    application, db, p = ctx
    os.environ["RANGER_CASE_UI"] = "0"
    try:
        assert _sess(application, p["strata"].id).get("/case").status_code == 404
    finally:
        os.environ["RANGER_CASE_UI"] = "1"
