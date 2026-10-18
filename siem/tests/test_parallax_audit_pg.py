"""PARALLAX Phase 1C Workstream C - audit chain under GENUINE concurrent PostgreSQL.

Gated by _pgtest (skips fail-closed when unauthorized). Validates that concurrent appends allocate a
gap-free, uniquely-sequenced chain, that a rolled-back transaction leaves no orphan audit event
(atomic allocation), and that the checkpoint catches truncation on a real database.
"""
import importlib
import os
import sys
import threading
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1c-audit-pg")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

import _pgtest  # noqa: E402
from parallax import auditlog, audit_integrity as AI  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)


def _fresh_app():
    import app as appmod
    importlib.reload(appmod)
    from models import db
    return appmod, appmod.create_app(), db


def _admin(db):
    from models import AdminUser
    return AdminUser.query.filter_by(github_id="admin-1").first()


def test_concurrent_appends_and_rollback_atomicity_and_truncation():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            assert db.engine.dialect.name == "postgresql"
            db.create_all()
            from models import AdminUser
            db.session.add(AdminUser(github_id="admin-1", login="admin-1", role="reviewer"))
            db.session.commit()

        # --- concurrent appends: N threads each append+commit one event ---------------------------
        N = 8
        barrier = threading.Barrier(N)
        errs = [None] * N

        def worker(i):
            try:
                with application.app_context():
                    barrier.wait()
                    auditlog.append(db, action="concurrent", actor_id="admin-1", subject_kind="x",
                                    subject_ref="r%d" % i, detail={"i": i})
                    db.session.commit()
            except BaseException:  # noqa: BLE001
                errs[i] = traceback.format_exc()
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert all(e is None for e in errs), [e for e in errs if e]
        with application.app_context():
            from models import ParallaxAuditEvent
            seqs = sorted(e.seq for e in ParallaxAuditEvent.query.all())
            assert seqs == list(range(N))               # gap-free, unique, exactly N
            assert auditlog.verify_chain(db) is True

        # --- rollback atomicity: an append rolled back leaves no orphan event ---------------------
        with application.app_context():
            from models import ParallaxAuditEvent
            before = ParallaxAuditEvent.query.count()
            auditlog.append(db, action="will_rollback", actor_id="admin-1", subject_kind="x",
                            subject_ref="r", detail={"doomed": True})
            db.session.rollback()                        # rollback BEFORE commit
            assert ParallaxAuditEvent.query.count() == before
            assert auditlog.verify_chain(db) is True

        # --- checkpoint then truncation on real PG ------------------------------------------------
        with application.app_context():
            AI.write_checkpoint(db, principal=_admin(db))
            from models import ParallaxAuditEvent
            tail = (ParallaxAuditEvent.query.order_by(ParallaxAuditEvent.seq.desc()).limit(2).all())
            for e in tail:
                db.session.delete(e)
            db.session.commit()
            assert auditlog.verify_chain(db) is True     # prefix still valid
            assert AI.assess(db)["status"] == AI.TRUNCATED   # anchor catches it
