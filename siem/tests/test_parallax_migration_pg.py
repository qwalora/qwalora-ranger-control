"""PARALLAX Phase 1C Workstream B - UnitResult uniqueness migration on GENUINE disposable PostgreSQL.

Gated by the _pgtest positive-authorization boundary (opt-in, dedicated test URL, loopback/allow-listed
host, sentinel DB, throwaway per-test database). Skips (fail-closed) when unauthorized; never touches a
real database. Simulates a pre-existing production table by dropping the constraint create_all adds,
then validates preflight/apply across every required scenario.
"""
import importlib
import os
import sys
import threading
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1c-migrate")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402
from sqlalchemy import text  # noqa: E402

import _pgtest  # noqa: E402
from parallax import evidence_migration as M  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)

COHORT = "2026-A"


def _fresh_app():
    import app as appmod
    importlib.reload(appmod)
    from models import db
    application = appmod.create_app()
    return appmod, application, db


def _drop_constraint(db):
    db.session.execute(text("ALTER TABLE unit_results DROP CONSTRAINT IF EXISTS uq_unit_result_record"))
    db.session.commit()


def _seed_candidate(db):
    from models import Candidate
    c = Candidate(handle="gh-alice", name="A", email="a@e", cohort=COHORT, github_id="gh-alice",
                  status="active", current_board=1)
    db.session.add(c); db.session.commit()
    return c.id


def _ur(db, cid, record_hash, *, kind="qualification_decision", unit_ref="LAB-A@1"):
    from models import UnitResult
    r = UnitResult(candidate_id=cid, pathway="parallax", unit_ref=unit_ref, kind=kind,
                   qualified=False, record_hash=record_hash)
    db.session.add(r); db.session.commit()
    return r


def test_empty_database_ready_then_applied_idempotent():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            assert db.engine.dialect.name == "postgresql"
            db.create_all()
            _drop_constraint(db)                       # simulate a pre-existing DB without the constraint
            pre = M.preflight(db)
            assert pre["decision"] == "ready" and pre["constraint_present"] is False
            assert M.apply_migration(db)["status"] == "applied"
            assert M.constraint_present(db) is True
            assert M.apply_migration(db)["status"] == "noop"      # idempotent
            assert M.apply_migration(db)["status"] == "noop"      # repeated execution


def test_existing_constraint_is_noop():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            db.create_all()                            # create_all already added the constraint
            assert M.preflight(db)["decision"] == "noop"
            assert M.apply_migration(db)["status"] == "noop"


def test_populated_no_duplicates_preserves_rows_and_applies():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            db.create_all(); _drop_constraint(db)
            cid = _seed_candidate(db)
            _ur(db, cid, "h1"); _ur(db, cid, "h2")
            _ur(db, cid, None, kind="reviewer_adjudication")      # NULL record_hash never conflicts
            from models import UnitResult
            before = UnitResult.query.count()
            assert M.apply_migration(db)["status"] == "applied"
            assert UnitResult.query.count() == before            # non-destructive: rows preserved
            # post-migration the constraint is enforced at the DB
            from sqlalchemy.exc import IntegrityError
            with pytest.raises(IntegrityError):
                _ur(db, cid, "h1")                               # duplicate identity rejected
            db.session.rollback()


def test_conflicting_duplicates_block_and_do_not_mutate():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            db.create_all(); _drop_constraint(db)
            cid = _seed_candidate(db)
            _ur(db, cid, "dup"); _ur(db, cid, "dup")             # two rows share the identity
            from models import UnitResult
            before = UnitResult.query.count()
            pre = M.preflight(db)
            assert pre["decision"] == "blocked" and pre["duplicate_rows"] == 2
            res = M.apply_migration(db)
            assert res["status"] == "blocked"
            assert M.constraint_present(db) is False             # not added
            assert UnitResult.query.count() == before            # duplicates NOT removed (no auto-survivor)


def test_interrupted_migration_rolls_back_and_is_recoverable():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            db.create_all(); _drop_constraint(db)
            cid = _seed_candidate(db)
            _ur(db, cid, "h1")
            # simulate an interruption: begin the ALTER then roll back instead of committing
            db.session.execute(text(
                "ALTER TABLE unit_results ADD CONSTRAINT uq_unit_result_record "
                "UNIQUE (candidate_id, unit_ref, kind, record_hash)"))
            db.session.rollback()
            assert M.constraint_present(db) is False             # interruption left no constraint
            # forward recovery: re-run completes cleanly
            assert M.apply_migration(db)["status"] == "applied"
            assert M.constraint_present(db) is True


def test_concurrent_migrators_exactly_one_applies():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            db.create_all(); _drop_constraint(db)
        barrier = threading.Barrier(2)
        out = {}

        def worker(i):
            try:
                with application.app_context():
                    barrier.wait()
                    out[i] = M.apply_migration(db)["status"]
            except BaseException:  # noqa: BLE001
                out[i] = "error:" + traceback.format_exc().splitlines()[-1]
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        statuses = sorted(out.values())
        assert statuses == ["applied", "noop"], (statuses, out)   # serialized; exactly one applies
        with application.app_context():
            assert M.constraint_present(db) is True
