"""STRATA S6 §1 (post-closure) - suspended-range retention cleanup.

A suspended range frees its RAM slot but keeps its disks. These tests prove the disks are reclaimed
once the range is past retention, WITHOUT ever discarding evidence or deleting during an open hold,
and only after the broker confirms remote destruction. Offline (mock broker + fault-injecting double).
"""
import datetime as _dt
import json as _json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "s6ret")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("LUDUS_API_URL", None)

import pytest  # noqa: E402

from _s6util import expiring_client  # noqa: E402
import broker  # noqa: E402
import strata_assignment as asn  # noqa: E402
from siem import board_variants as bv  # noqa: E402

_ADMIN = {"Authorization": "Bearer s6-ret-admin", "Accept": "application/json"}


@pytest.fixture(autouse=True)
def _guard():
    keys = ("RANGER_STRATA_PORTFOLIOS", "RANGER_ENV", "RANGER_S6_ATTEST_TEST", "ADMIN_TOKEN",
            "LUDUS_API_URL", "LUDUS_ADAPTER_VERIFIED")
    saved = {k: os.environ.get(k) for k in keys}
    import app as _a
    gkeys = ("MAX_CONCURRENT", "RANGE_IDLE_HOURS", "RANGE_MAX_AGE_HOURS",
             "RANGE_EVIDENCE_HOLD_HOURS", "RANGE_SUSPENDED_RETENTION_HOURS")
    gsaved = {k: getattr(_a, k) for k in gkeys}
    try:
        yield
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        for k, v in gsaved.items():
            setattr(_a, k, v)


def _app():
    import app as appmod
    from models import db, Cohort, AdminUser
    os.environ["ADMIN_TOKEN"] = "s6-ret-admin"
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.drop_all(); db.create_all()
    if not Cohort.query.filter_by(name="2026-A").first():
        db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
    if AdminUser.query.filter_by(github_id="gid-admin").first() is None:
        db.session.add(AdminUser(github_id="gid-admin", login="alice", role="reviewer"))
    db.session.commit()
    return appmod, application, db, ctx


def _cand(db, handle, board=5):
    from models import Candidate
    c = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort="2026-A",
                  github_id=f"g-{handle}", status="active", current_board=board, token=f"tok-{handle}")
    db.session.add(c); db.session.commit()
    return c


def _ensure_catalog(db, application, board):
    import strata_catalog as cat
    from models import ScenarioCatalogEntry
    if [e for e in ScenarioCatalogEntry.query.filter_by(status="catalog_eligible").all()
            if _json.loads(e.board_compat)[0] == board]:
        return
    for e in cat.register_all(db, boards=(board,)):
        with application.test_request_context():
            from flask import session
            session["admin"] = True; session["admin_login"] = "alice"; session["admin_gid"] = "gid-admin"
            cat.approve(db, e, None)
    db.session.commit()


def _start_and_submit(appmod, application, db, c):
    """Deploy board 5 governed, submit correct flags (opens the evidence hold + persists a signed
    attestation), and return the (client, RangeRequest)."""
    from models import AdminUser, RangeRequest, ScenarioBinding
    _ensure_catalog(db, application, 5)
    asn.set_cohort_portfolio(db, "2026-A", 5, bv.variants_for(5)[:2],
                             admin=AdminUser.query.filter_by(github_id="gid-admin").first())
    client = expiring_client(application, db)
    hdr = {"X-Candidate-Token": c.token}
    assert client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr).status_code == 200
    assert client.post("/labs/start", json={"handle": c.handle}, headers=hdr).get_json()["range_status"] == "deployed"
    b = ScenarioBinding.query.filter_by(candidate_id=c.id, board=5).first()
    world = asn.generate(b)
    client.post("/grade/submit", json={"handle": c.handle,
                "submission": {"flags": dict(world["_flags"])}}, headers=hdr)
    rr = RangeRequest.query.filter_by(candidate_id=c.id, board=5).first()
    return client, rr


def _suspend_via_idle_reclaim(appmod, db, client, rr):
    """Drive the range to 'suspended' through the real idle-reclaim path (hold still open)."""
    appmod.RANGE_IDLE_HOURS = 0.0001
    appmod.RANGE_MAX_AGE_HOURS = 0
    rr.last_active_at = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=1)
    db.session.commit()
    client.post("/admin/reconcile", headers=_ADMIN)
    from models import RangeRequest
    return RangeRequest.query.get(rr.id)


def test_suspended_under_open_hold_is_preserved():
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest
        c = _cand(db, "ret1")
        client, rr = _start_and_submit(appmod, application, db, c)
        rr = _suspend_via_idle_reclaim(appmod, db, client, rr)
        assert rr.status == "suspended" and rr.evidence_hold_until is not None
        # hold still open; retention cleanup must NOT delete it
        appmod.RANGE_SUSPENDED_RETENTION_HOURS = 0.0001
        client.post("/admin/reconcile", headers=_ADMIN)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "suspended", "must never delete a suspended range while its hold is open"
    finally:
        ctx.pop()


def test_suspended_past_retention_with_evidence_is_destroyed():
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest, BoardResult
        c = _cand(db, "ret2")
        client, rr = _start_and_submit(appmod, application, db, c)
        rr = _suspend_via_idle_reclaim(appmod, db, client, rr)
        assert rr.status == "suspended"
        assert BoardResult.query.filter_by(candidate_id=c.id, board=5).first().range_attestation
        # end the hold and pass the retention grace
        appmod.RANGE_SUSPENDED_RETENTION_HOURS = 0.0001
        rr.evidence_hold_until = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)
        db.session.commit()
        client.post("/admin/reconcile", headers=_ADMIN)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "destroyed", "a suspended range past retention with evidence must be reclaimed"
    finally:
        ctx.pop()


def test_suspended_past_retention_without_evidence_is_not_destroyed():
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest, BoardResult
        c = _cand(db, "ret3")
        client, rr = _start_and_submit(appmod, application, db, c)
        rr = _suspend_via_idle_reclaim(appmod, db, client, rr)
        # wipe the persisted signed record to simulate evidence not durably preserved
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        br.range_attestation = None
        appmod.RANGE_SUSPENDED_RETENTION_HOURS = 0.0001
        rr.evidence_hold_until = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)
        db.session.commit()
        client.post("/admin/reconcile", headers=_ADMIN)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "suspended", "must NOT destroy disks when the signed record is not preserved"
        assert "no persisted signed record" in (rr.detail or "")
    finally:
        ctx.pop()


def test_interrupted_cleanup_retries_then_confirms(monkeypatch):
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest
        c = _cand(db, "ret4")
        client, rr = _start_and_submit(appmod, application, db, c)
        rr = _suspend_via_idle_reclaim(appmod, db, client, rr)
        appmod.RANGE_SUSPENDED_RETENTION_HOURS = 0.0001
        rr.evidence_hold_until = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)
        db.session.commit()
        # first pass: broker destroy accepted but NOT confirmed -> range stays suspended (retry)
        monkeypatch.setattr(broker, "destroy_range",
                            lambda *a, **k: (False, "accepted, not confirmed", broker.OP_PENDING))
        client.post("/admin/reconcile", headers=_ADMIN)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "suspended", "an unconfirmed destroy must leave the range suspended"
        # second pass: destruction now confirmed -> reclaimed
        monkeypatch.setattr(broker, "destroy_range",
                            lambda *a, **k: (True, "confirmed absent", broker.OP_CONFIRMED))
        client.post("/admin/reconcile", headers=_ADMIN)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "destroyed", "a later confirmed pass reclaims the disks"
    finally:
        ctx.pop()


def test_candidate_exit_then_retention_cleanup():
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest
        c = _cand(db, "ret5")
        client, rr = _start_and_submit(appmod, application, db, c)
        # admin removes the candidate while the hold is open -> range SUSPENDED (evidence preserved)
        client.post(f"/admin/candidates/{c.id}/exit", data={"kind": "withdrawn", "reason": "t"},
                    headers=_ADMIN)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "suspended", "exit under hold suspends, not destroys"
        # later, past hold + retention, the suspended-cleanup reclaims the disks
        appmod.RANGE_SUSPENDED_RETENTION_HOURS = 0.0001
        rr.evidence_hold_until = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)
        db.session.commit()
        client.post("/admin/reconcile", headers=_ADMIN)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "destroyed"
    finally:
        ctx.pop()


def test_repeated_maintenance_is_idempotent():
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest
        c = _cand(db, "ret6")
        client, rr = _start_and_submit(appmod, application, db, c)
        rr = _suspend_via_idle_reclaim(appmod, db, client, rr)
        appmod.RANGE_SUSPENDED_RETENTION_HOURS = 0.0001
        rr.evidence_hold_until = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)
        db.session.commit()
        for _ in range(3):
            client.post("/admin/reconcile", headers=_ADMIN)
        rows = RangeRequest.query.filter_by(candidate_id=c.id, board=5).all()
        assert len(rows) == 1 and rows[0].status == "destroyed", "repeated maintenance is stable"
    finally:
        ctx.pop()


def test_retention_disabled_keeps_disks():
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest
        c = _cand(db, "ret7")
        client, rr = _start_and_submit(appmod, application, db, c)
        rr = _suspend_via_idle_reclaim(appmod, db, client, rr)
        appmod.RANGE_SUSPENDED_RETENTION_HOURS = 0  # disabled
        rr.evidence_hold_until = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=100)
        db.session.commit()
        client.post("/admin/reconcile", headers=_ADMIN)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "suspended", "with retention disabled, suspended disks are kept"
    finally:
        ctx.pop()
