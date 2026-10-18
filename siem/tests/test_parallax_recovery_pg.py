"""PARALLAX Phase 1C Workstream E - database and operational recovery on GENUINE PostgreSQL.

Gated by _pgtest (skips fail-closed when unauthorized). Covers process restart, transaction rollback,
connection interruption during commit, backup/restore with post-recovery signature + audit-chain
verification, and fail-closed behavior when the database is unreachable. Concurrent reviewer assignment
and idempotent client retries are validated in test_parallax_persistence_pg.py.
"""
import importlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1c-recovery")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402

import _pgtest  # noqa: E402
from parallax import registry, auditlog, audit_integrity as AI, pathway_persistent  # noqa: E402
from parallax import laba_blueprint as BP  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)
_PGBIN = "/usr/lib/postgresql/16/bin"
COHORT = "2026-A"


def _fresh_app():
    import app as appmod
    importlib.reload(appmod)
    from models import db
    return appmod, appmod.create_app(), db


def _seed(db):
    from models import AdminUser, Candidate
    db.session.add_all([
        AdminUser(github_id="admin-1", login="admin-1", role="reviewer"),
        Candidate(handle="gh-alice", name="A", email="a@e", cohort=COHORT, github_id="gh-alice",
                  status="active", current_board=1)])
    db.session.commit()


def _admin(db):
    from models import AdminUser
    return AdminUser.query.filter_by(github_id="admin-1").first()


def test_restart_between_issuance_and_verification():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            db.create_all(); _seed(db)
            registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
        # simulate process restart: dispose the engine entirely, then a fresh context verifies
        with application.app_context():
            db.session.remove(); db.engine.dispose()
            assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is not None
            assert auditlog.verify_chain(db) is True


def test_rollback_after_partial_operation_persists_nothing():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            db.create_all(); _seed(db)
            from models import ParallaxAuditEvent
            before = ParallaxAuditEvent.query.count()
            auditlog.append(db, action="partial", actor_id="admin-1", subject_kind="x",
                            subject_ref="r", detail={})
            db.session.rollback()                                  # partial op abandoned
            assert ParallaxAuditEvent.query.count() == before
            assert auditlog.verify_chain(db) is True


def test_connection_interruption_during_commit_fails_closed():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            db.create_all(); _seed(db)
            from models import ParallaxAuditEvent
            before = ParallaxAuditEvent.query.count()
            auditlog.append(db, action="doomed", actor_id="admin-1", subject_kind="x",
                            subject_ref="r", detail={})
            # forcibly kill the underlying DBAPI connection before the commit lands
            raw = db.session.connection().connection
            raw.close()
            with pytest.raises(Exception):                         # commit cannot succeed
                db.session.commit()
            db.session.rollback(); db.engine.dispose()
            # nothing partial persisted; the store still works afterwards
            assert ParallaxAuditEvent.query.count() == before
            assert auditlog.verify_chain(db) is True


def test_backup_restore_preserves_signatures_and_audit_chain():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        url = make_url(os.environ["DATABASE_URL"])
        with application.app_context():
            db.create_all(); _seed(db)
            registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
            for i in range(3):
                auditlog.append(db, action="evt%d" % i, actor_id="admin-1", subject_kind="x",
                                subject_ref="r%d" % i, detail={"i": i})
            db.session.commit()
            AI.write_checkpoint(db, principal=_admin(db))
            db.session.remove(); db.engine.dispose()

        env = dict(os.environ)
        dump_path = os.path.join("/tmp", "px1c_recovery_%s.sql" % url.database)
        # 1) back up the disposable database
        dump = subprocess.run([os.path.join(_PGBIN, "pg_dump"), "--clean", "--if-exists",
                               "-h", url.host, "-p", str(url.port), "-U", url.username,
                               "-d", url.database, "-f", dump_path], env=env,
                              capture_output=True, text=True)
        assert dump.returncode == 0, dump.stderr
        # 2) simulate data loss: drop the signed-record tables
        with application.app_context():
            from sqlalchemy import text
            db.session.execute(text("DROP TABLE IF EXISTS parallax_audit_checkpoints CASCADE"))
            db.session.execute(text("DROP TABLE IF EXISTS parallax_audit_events CASCADE"))
            db.session.execute(text("DROP TABLE IF EXISTS parallax_approvals CASCADE"))
            db.session.commit(); db.session.remove(); db.engine.dispose()
        # 3) restore from the backup
        restore = subprocess.run([os.path.join(_PGBIN, "psql"), "-h", url.host, "-p", str(url.port),
                                  "-U", url.username, "-d", url.database, "-f", dump_path],
                                 env=env, capture_output=True, text=True)
        assert restore.returncode == 0, restore.stderr
        # 4) after recovery, signatures and the audit chain verify, truncation anchor is intact
        with application.app_context():
            assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is not None
            assert auditlog.verify_chain(db) is True
            assert AI.assess(db)["status"] == AI.OK
        try:
            os.remove(dump_path)
        except OSError:
            pass


def test_unretrievable_records_fail_closed():
    # When authoritative records cannot be retrieved (here: the governing table is gone), a
    # consequential verification must fail closed - never silently qualify.
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            db.create_all(); _seed(db)
            from sqlalchemy import text
            db.session.execute(text("DROP TABLE IF EXISTS parallax_approvals CASCADE"))
            db.session.commit()
            out = pathway_persistent.decide_pathway_persistent(db, candidate_key="gh-alice",
                                                               cohort=COHORT)
            assert out["qualified"] is False
            assert out["reason"] == "infrastructure_unavailable"


def test_dead_connection_app_cannot_masquerade_as_qualified():
    # A verifier pointed at a dead database must raise/fail, never return qualified=True. We assert the
    # failure surfaces (fail-closed) rather than yielding a positive result.
    saved = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = "postgresql+psycopg2://postgres@127.0.0.1:55999/nope"
    try:
        with pytest.raises(Exception):
            _appmod, application, db = _fresh_app()   # cannot even construct against a dead DB
    finally:
        if saved is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = saved
