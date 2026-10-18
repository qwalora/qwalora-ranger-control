"""PARALLAX Phase 1C Workstream C - audit-chain resilience, truncation detection, admin verifier.

In-process (SQLite) tests of the deterministic integrity properties. Concurrent real-PostgreSQL appends
are covered in test_parallax_audit_pg.py. Demonstrates that the hash chain alone does NOT detect tail
truncation, while the separately-anchored checkpoint does.
"""
import base64
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1c-audit")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402

import signing  # noqa: E402
from parallax import auditlog, audit_integrity as AI, registry  # noqa: E402


def _seed_b64():
    k = Ed25519PrivateKey.generate()
    return base64.b64encode(
        k.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption())).decode()


@pytest.fixture(autouse=True)
def _reset_keys():
    yield
    signing._reset_registry()


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
        auditlog.append(db, action="act%d" % i, actor_id="admin-1", subject_kind="x",
                        subject_ref="r%d" % i, detail={"i": i})
    db.session.commit()


def _events(db):
    from models import ParallaxAuditEvent
    return ParallaxAuditEvent.query.order_by(ParallaxAuditEvent.seq.asc()).all()


# --- full verification and each corruption class --------------------------------------------------
def test_full_chain_verifies(appctx):
    _a, db = appctx
    _append(db, 5)
    assert auditlog.verify_chain(db) is True
    v = AI.verify_events(db)
    assert v["ok"] and v["count"] == 5 and v["head_seq"] == 4


def test_detect_altered_payload(appctx):
    _a, db = appctx
    _append(db, 4)
    ev = _events(db)[2]
    rec = json.loads(ev.detail_json); rec["detail"] = {"i": 999}
    ev.detail_json = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    db.session.commit()
    assert auditlog.verify_chain(db) is False
    assert AI.verify_events(db)["ok"] is False


def test_detect_invalid_signature(appctx):
    _a, db = appctx
    _append(db, 3)
    ev = _events(db)[1]
    ev.signature = base64.b64encode(b"\x00" * 64).decode()
    db.session.commit()
    assert AI.verify_events(db)["reason"].startswith("bad_signature")


def test_detect_removed_middle_event_breaks_link(appctx):
    _a, db = appctx
    _append(db, 5)
    db.session.delete(_events(db)[2]); db.session.commit()
    assert auditlog.verify_chain(db) is False            # seq gap / broken link


def test_duplicate_seq_rejected_by_db_and_noncontiguous_detected(appctx):
    from sqlalchemy.exc import IntegrityError
    _a, db = appctx
    _append(db, 4)                                        # seq 0,1,2,3
    # duplicate sequence numbers are rejected at the STORAGE layer by UNIQUE(stream, seq)
    _events(db)[0].seq = 1
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    # a non-contiguous / out-of-order seq is caught by the verifier (seq must equal position)
    _events(db)[3].seq = 7
    db.session.commit()
    assert auditlog.verify_chain(db) is False
    assert AI.verify_events(db)["ok"] is False


# --- truncation: hash chain misses it, the checkpoint catches it ---------------------------------
def test_tail_truncation_missed_by_chain_caught_by_checkpoint(appctx):
    _a, db = appctx
    _append(db, 5)
    AI.write_checkpoint(db, principal=_admin(db))        # anchor count=5, head@seq4
    # truncate the tail: remove the last 2 events
    for e in _events(db)[-2:]:
        db.session.delete(e)
    db.session.commit()
    # the surviving prefix is a perfectly valid chain...
    assert auditlog.verify_chain(db) is True
    assert AI.verify_events(db)["ok"] is True and AI.verify_events(db)["count"] == 3
    # ...but the checkpoint anchor detects the truncation
    rep = AI.integrity_report(db)
    assert rep["status"] == AI.TRUNCATED
    assert rep["checkpoint"]["event_count"] == 5 and rep["event_count"] == 3
    assert rep["anchor_independence"] == AI.ANCHOR_INDEPENDENCE


def test_no_checkpoint_cannot_rule_out_truncation(appctx):
    _a, db = appctx
    _append(db, 3)
    assert AI.integrity_report(db)["status"] == AI.NO_CHECKPOINT


def test_growth_since_checkpoint_is_ok(appctx):
    _a, db = appctx
    _append(db, 3)
    AI.write_checkpoint(db, principal=_admin(db))
    _append(db, 2, start=3)
    assert AI.assess(db)["status"] == AI.OK


def test_head_rewrite_same_count_detected(appctx):
    _a, db = appctx
    _append(db, 5)
    AI.write_checkpoint(db, principal=_admin(db))
    db.session.delete(_events(db)[-1]); db.session.commit()   # drop head
    _append(db, 1, start=99)                                  # re-add a DIFFERENT head at seq 4
    assert AI.assess(db)["status"] == AI.REWRITTEN


def test_forged_or_invalid_checkpoint_detected(appctx):
    _a, db = appctx
    _append(db, 4)
    cp = AI.write_checkpoint(db, principal=_admin(db))
    cp.head_hash = "deadbeef" * 8                             # tamper the anchor
    db.session.commit()
    assert AI.verify_checkpoint(AI.latest_checkpoint(db)) is False
    assert AI.assess(db)["status"] == AI.FORGED_CHECKPOINT


def test_write_checkpoint_requires_authority_and_valid_chain(appctx):
    _a, db = appctx
    _append(db, 3)
    with pytest.raises(registry.RegistryAuthError):
        AI.write_checkpoint(db, principal={"login": "nobody"})
    # a broken chain cannot be checkpointed
    ev = _events(db)[1]; ev.signature = base64.b64encode(b"\x00" * 64).decode(); db.session.commit()
    with pytest.raises(ValueError):
        AI.write_checkpoint(db, principal=_admin(db))


def test_restart_continuity(appctx):
    _a, db = appctx
    _append(db, 4)
    AI.write_checkpoint(db, principal=_admin(db))
    db.session.remove()                                      # simulate process restart
    assert auditlog.verify_chain(db) is True
    assert AI.assess(db)["status"] == AI.OK


def test_checkpoint_verifies_across_authorized_key_rotation(appctx):
    _a, db = appctx
    A, B = _seed_b64(), _seed_b64()
    signing._install_registry([{"kid": "A", "state": "active", "seed_b64": A}], "A")
    _append(db, 4)
    AI.write_checkpoint(db, principal=_admin(db))
    # rotate: A verify-only, B active
    signing._install_registry([{"kid": "A", "state": "verify_only", "seed_b64": A},
                               {"kid": "B", "state": "active", "seed_b64": B}], "B")
    db.session.remove()
    assert AI.verify_events(db)["ok"] is True                # historical A events still verify
    assert AI.assess(db)["status"] == AI.OK                  # A-signed checkpoint still verifies
    # a new checkpoint is signed by B and still assesses OK
    _append(db, 1, start=50)
    AI.write_checkpoint(db, principal=_admin(db))
    assert AI.assess(db)["status"] == AI.OK


def test_integrity_report_leaks_no_payload(appctx):
    _a, db = appctx
    _append(db, 3)
    AI.write_checkpoint(db, principal=_admin(db))
    rep = AI.integrity_report(db)
    blob = json.dumps(rep)
    assert "detail_json" not in blob and "act0" not in blob   # no event payloads/actions in the report
