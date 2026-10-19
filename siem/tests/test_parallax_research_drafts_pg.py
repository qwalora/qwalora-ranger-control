"""PARALLAX research-workspace draft persistence on GENUINE PostgreSQL (production dialect).

The functional draft matrix is covered on SQLite in test_parallax_research_drafts.py. This suite
re-exercises the critical persistence paths for the two new draft kinds against a real, disposable
PostgreSQL database (created and dropped via the authorized _pgtest harness), because production
runs PostgreSQL: the version-guarded conditional UPDATE used for optimistic concurrency and the
program/candidate scoping must behave identically on the real dialect. SKIPS (never touches
production) when the authorized disposable server is not configured.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px-drafts-pg")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["RANGER_PARALLAX_LABA"] = "1"
os.environ["RANGER_PARALLAX_LABA_ENV"] = "test"
for _m in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
    os.environ.pop(_m, None)

import pytest  # noqa: E402

import _pgtest  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)

H = {"X-CSRF-Token": "t", "Content-Type": "application/json", "Accept": "application/json"}
EXP_URL = "/parallax/research/experiment/draft"
LOAD_URL = "/parallax/research/draft"


def _mk(db, Candidate, ProgramMembership, handle, program="parallax", status="active"):
    c = Candidate(handle=handle, name=handle, email=handle + "@e", cohort="2026-A",
                  github_id=handle, status=status, current_board=1)
    db.session.add(c)
    db.session.commit()
    db.session.add(ProgramMembership(candidate_id=c.id, program=program, status="active",
                                     cohort="2026-A"))
    db.session.commit()
    return c.id


def _cl(application, cid):
    cl = application.test_client()
    with cl.session_transaction() as s:
        s.clear()
        s["cand"] = cid
        s["csrf"] = "t"
    return cl


def _save(cl, url, payload, base=0):
    return cl.post(url, headers=H, data=json.dumps({"payload": payload, "base_version": base}))


def test_pg_parallax_draft_save_load_concurrency_and_isolation():
    with _pgtest.isolated_pg_database():
        import importlib
        import app as appmod
        importlib.reload(appmod)                     # rebind the engine to the disposable PG URL
        import parallax_routes as pr
        pr._RUN_HITS.clear()
        from models import db, Candidate, ProgramMembership, ParallaxResearchRun, WorkspaceDraft
        application = appmod.create_app()
        with application.app_context():
            assert db.engine.dialect.name == "postgresql"   # prove this is REAL PostgreSQL
            db.create_all()
            alice = _mk(db, Candidate, ProgramMembership, "gh-alice")
            bob = _mk(db, Candidate, ProgramMembership, "gh-bob")
            strata = _mk(db, Candidate, ProgramMembership, "gh-strata", program="strata")

        # save + restore on real PG
        ca = _cl(application, alice)
        assert _save(ca, EXP_URL, {"task_id": "", "attack_text": "pg draft"}).status_code == 200
        got = ca.get(LOAD_URL, headers=H).get_json()
        assert got["experiment"]["payload"]["attack_text"] == "pg draft"

        # optimistic concurrency: a stale write is rejected by the version-guarded conditional UPDATE
        cb = _cl(application, alice)   # second session, still at base 0
        assert _save(cb, EXP_URL, {"attack_text": "stale"}, base=0).status_code == 409
        assert ca.get(LOAD_URL, headers=H).get_json()["experiment"]["payload"]["attack_text"] == "pg draft"
        assert _save(ca, EXP_URL, {"attack_text": "v2"}, base=1).status_code == 200

        # cross-candidate isolation and STRATA-only denial hold on PG
        assert _cl(application, bob).get(LOAD_URL, headers=H).get_json()["experiment"] is None
        assert _save(_cl(application, strata), EXP_URL, {"attack_text": "x"}).status_code == 403

        # a draft save created NO signed research run (no execution / evidence / submission)
        with application.app_context():
            assert ParallaxResearchRun.query.count() == 0
            assert WorkspaceDraft.query.filter_by(kind="parallax_experiment").count() == 1
