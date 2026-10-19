"""Admin evidence verifier on GENUINE PostgreSQL (production dialect).

Proves store.admin_verify_run reads and verifies a persisted signed run on real PostgreSQL, is
strictly read-only (the row is byte-for-byte unchanged afterward), and that a DB-level tamper is
detected. SKIPS when the authorized disposable PostgreSQL is not configured.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px-evidence-pg")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402
import _pgtest  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)


def _campaign():
    return {"manifest": {"kind": "trial", "backend": {"is_real": False, "model_id": "stub-x",
            "runtime": "n/a", "backend": "deterministic_stub"}, "n_records": 1},
            "metrics": {"kind": "trial", "record": {"condition": "baseline_benign",
            "model": {"id": "stub-x"}, "observed_behavior": "hello world",
            "evaluation": {"canary": False, "task_ok": True}, "outcome": "boundary_preserved"}}}


def test_pg_admin_verify_readonly_and_tamper_detected():
    with _pgtest.isolated_pg_database():
        import importlib
        import app as appmod
        importlib.reload(appmod)
        from models import db, ParallaxResearchRun
        from parallax.research import store as rstore
        application = appmod.create_app()
        with application.app_context():
            assert db.engine.dialect.name == "postgresql"
            db.create_all()
            row = rstore.persist_run(db, researcher_id="gh-res", campaign=_campaign())
            db.session.commit()
            rid = row.run_id

            # valid record verifies, integrity checks pass, read-only
            before = ParallaxResearchRun.query.filter_by(run_id=rid).first()
            snap = (before.run_record, before.signature, before.record_hash, before.signing_kid)
            res = rstore.admin_verify_run(db, run_id=rid)
            assert res["exists"] and res["hash_match"] and res["signature_valid"]
            assert res["kid_trusted"] and res["signed_run_id_matches"]
            assert res["tamper_negative_control_fails"] is True and res["all_checks_pass"] is True
            after = ParallaxResearchRun.query.filter_by(run_id=rid).first()
            assert (after.run_record, after.signature, after.record_hash, after.signing_kid) == snap

            # DB-level tamper (bytes changed, signature not regenerated) is detected
            rec = json.loads(after.run_record)
            rec["metrics"]["record"]["observed_behavior"] = "ALTERED"
            after.run_record = json.dumps(rec)
            db.session.commit()
            res2 = rstore.admin_verify_run(db, run_id=rid)
            assert res2["signature_valid"] is False and res2["all_checks_pass"] is False

            # unknown id reports absent
            assert rstore.admin_verify_run(db, run_id="run-nope")["exists"] is False
