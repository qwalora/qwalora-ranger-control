"""PARALLAX Phase 1D Workstream C - audit-checkpoint trust-boundary tests.

Each mitigated threat in audit_integrity.THREAT_MODEL is demonstrated; the one UNMITIGATED threat
(simultaneous DB + signing-key compromise) is asserted to be honestly labeled, and the external-anchor
detection path is demonstrated for the truncation-plus-checkpoint-deletion case.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1d-trust")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

from parallax import auditlog, audit_integrity as AI  # noqa: E402


@pytest.fixture()
def appctx():
    import app as appmod
    from models import db
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.drop_all(); db.create_all()
    from models import AdminUser
    db.session.add(AdminUser(github_id="admin-1", login="admin-1", role="reviewer"))
    db.session.commit()
    yield appmod, db
    ctx.pop()


def _admin(db):
    from models import AdminUser
    return AdminUser.query.filter_by(github_id="admin-1").first()


def _append(db, n, start=0):
    for i in range(start, start + n):
        auditlog.append(db, action="a%d" % i, actor_id="admin-1", subject_kind="x",
                        subject_ref="r%d" % i, detail={"i": i})
    db.session.commit()


def _events(db):
    from models import ParallaxAuditEvent
    return ParallaxAuditEvent.query.order_by(ParallaxAuditEvent.seq.asc()).all()


def test_threat_model_declares_both_compromise_unmitigated():
    tm = AI.THREAT_MODEL
    assert tm["simultaneous_db_and_signing_key_compromise"][0] is False   # honestly NOT mitigated
    assert tm["accidental_corruption"][0] is True
    assert tm["unauthorized_db_modification_without_signing_key"][0] is True
    assert tm["tail_truncation_without_signing_key"][0] is True
    # the in-DB anchor must never be labeled independent
    assert AI.ANCHOR_INDEPENDENCE == "not_independent_same_store_same_key"


def test_accidental_corruption_detected(appctx):
    _a, db = appctx
    _append(db, 4)
    ev = _events(db)[1]; ev.record_hash = "0" * 64; db.session.commit()
    assert auditlog.verify_chain(db) is False


def test_unauthorized_db_modification_without_key_detected(appctx):
    _a, db = appctx
    _append(db, 4)
    import json
    ev = _events(db)[2]
    rec = json.loads(ev.detail_json); rec["actor_id"] = "attacker"
    ev.detail_json = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    db.session.commit()
    # attacker lacks the signing key: the edit breaks the record-hash / signature
    assert AI.verify_events(db)["ok"] is False


def test_tail_truncation_without_key_detected_by_checkpoint(appctx):
    _a, db = appctx
    _append(db, 5)
    AI.write_checkpoint(db, principal=_admin(db))
    for e in _events(db)[-2:]:
        db.session.delete(e)
    db.session.commit()
    assert AI.assess(db)["status"] == AI.TRUNCATED


def test_external_anchor_catches_truncation_even_if_checkpoints_deleted(appctx):
    _a, db = appctx
    _append(db, 5)
    AI.write_checkpoint(db, principal=_admin(db))
    # emit an EXTERNAL anchor to a sink outside the DB (here an in-test list standing in for an
    # independent store); then the attacker truncates the chain AND deletes every in-DB checkpoint
    external = []
    AI.export_anchor(db, sink=external.append)
    from models import ParallaxAuditCheckpoint
    ParallaxAuditCheckpoint.query.delete()
    for e in _events(db)[-2:]:
        db.session.delete(e)
    db.session.commit()
    # in-DB assessment now cannot prove truncation (no checkpoint left)...
    assert AI.assess(db)["status"] == AI.NO_CHECKPOINT
    # ...but the externally-held anchor still detects it
    assert AI.verify_against_external_anchor(db, external[-1])["status"] == AI.TRUNCATED


def test_both_compromise_can_forge_consistent_in_db_state(appctx):
    """Demonstrates the UNMITIGATED case: with the signing key AND db write, a forged shorter chain
    plus a fresh matching checkpoint assess as OK in-DB - which is exactly why an INDEPENDENT external
    anchor is required (and why the in-DB anchor is never called independent)."""
    _a, db = appctx
    _append(db, 5)
    external = []
    AI.write_checkpoint(db, principal=_admin(db))
    AI.export_anchor(db, sink=external.append)        # an honest external anchor at count=5
    # attacker (holds key + db): truncate to 3 and re-checkpoint to match
    from models import ParallaxAuditCheckpoint
    for e in _events(db)[-2:]:
        db.session.delete(e)
    ParallaxAuditCheckpoint.query.delete(); db.session.commit()
    AI.write_checkpoint(db, principal=_admin(db))      # forged consistent checkpoint at count=3
    assert AI.assess(db)["status"] == AI.OK            # in-DB view is fooled (the documented gap)
    # only the pre-existing EXTERNAL anchor exposes the truncation
    assert AI.verify_against_external_anchor(db, external[-1])["status"] == AI.TRUNCATED
