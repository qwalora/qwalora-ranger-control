"""PARALLAX Phase 1E - the integrated HTTP lifecycle against GENUINE disposable PostgreSQL.

Drives the real Flask routes (candidate submit, admin assign, reviewer adjudicate, candidate status)
through the application over a real PostgreSQL database, and covers client-retry idempotency and
process-restart persistence. Gated by _pgtest (skips fail-closed when unauthorized).
"""
import importlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1e-pg")
os.environ["DEFAULT_COHORT"] = "2026-A"
os.environ["RANGER_PARALLAX_LABA"] = "1"
os.environ["RANGER_PARALLAX_LABA_ENV"] = "test"
for _m in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
    os.environ.pop(_m, None)

import pytest  # noqa: E402

import _pgtest  # noqa: E402
from parallax import registry, laba_assessment as LA, laba_blueprint as BP, laba_sim as sim  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)
COHORT = "2026-A"
CSRF = {"X-CSRF-Token": "t"}


def _fresh_app():
    import app as appmod
    importlib.reload(appmod)
    from models import db
    return appmod, appmod.create_app(), db


def _seed(db):
    from models import AdminUser, Candidate
    db.session.add_all([
        AdminUser(github_id="admin-1", login="admin-1", role="reviewer"),
        AdminUser(github_id="rev-1", login="rev-1", role="reviewer"),
        Candidate(handle="gh-alice", name="A", email="a@e", cohort=COHORT, github_id="gh-alice",
                  status="active", current_board=1)])
    db.session.commit()
    from models import AdminUser
    registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(),
                                 principal=AdminUser.query.filter_by(github_id="admin-1").first())


def _cid(db, handle):
    from models import Candidate
    return Candidate.query.filter_by(handle=handle).first().id


def _as_candidate(client, db, handle):
    with client.session_transaction() as s:
        s.clear(); s["cand"] = _cid(db, handle); s["csrf"] = "t"


def _as_admin(client, gid):
    with client.session_transaction() as s:
        s.clear(); s["admin"] = True; s["admin_gid"] = gid; s["admin_login"] = gid; s["csrf"] = "t"


def _submission(db):
    approval = registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint())
    admins = registry.authorized_admins(db)
    spec, con, inst = LA.bind_instance(cohort=COHORT, candidate_key="gh-alice", approval=approval,
                                       authorized_admins=admins)
    t = sim.truth(inst)
    return {"findings": [{"event_id": b, "classification": "unauthorized_access", "evidence": [b]}
                         for b in sorted(t["breaches"])], "analysis": "rc"}


def test_http_lifecycle_and_retry_idempotency_and_restart_on_pg():
    with _pgtest.isolated_pg_database():
        appmod, application, db = _fresh_app()
        ctx = application.app_context(); ctx.push()
        try:
            assert db.engine.dialect.name == "postgresql"
            db.create_all(); _seed(db)
            client = application.test_client()

            _as_candidate(client, db, "gh-alice")
            sub = _submission(db)
            r1 = client.post("/parallax/laba/assessment", json={"submission": sub}, headers=CSRF)
            assert r1.status_code == 201, r1.get_data(as_text=True)
            # client retry after an "interrupted response": same submission -> idempotent, one row
            r2 = client.post("/parallax/laba/assessment", json={"submission": sub}, headers=CSRF)
            assert r2.status_code == 201
            from models import UnitResult
            assert UnitResult.query.filter_by(kind="qualification_decision").count() == 1

            _as_admin(client, "admin-1")
            assert client.post("/parallax/laba/admin/assign-reviewer",
                               json={"reviewer_id": "rev-1", "candidate_key": "gh-alice",
                                     "cohort": COHORT}, headers=CSRF).status_code == 201
            _as_admin(client, "rev-1")
            rub = {d["dimension"]: 95 for d in BP.blueprint()["rubric_dimensions"]}
            assert client.post("/parallax/laba/review/adjudicate",
                               json={"candidate_key": "gh-alice", "decision": "pass",
                                     "rubric_scores": rub}, headers=CSRF).status_code == 201

            # simulate a process restart: dispose the engine, then a fresh status request re-verifies
            db.session.remove(); db.engine.dispose()
            _as_candidate(client, db, "gh-alice")
            st = client.get("/parallax/laba/assessment/status").get_json()
            assert st["verdict"] == "VALID"
            assert st["disposition"]["requirements_met"] is True
            assert st["disposition"]["qualified"] is False and st["pathway_qualified"] is False
        finally:
            ctx.pop()
