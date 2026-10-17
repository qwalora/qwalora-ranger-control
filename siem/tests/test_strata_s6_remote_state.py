"""STRATA S6 R3 (final correction) - remote-state safety: tri-state VM power, accepted-vs-confirmed
transitions that keep counting capacity until definitively resolved, and reconciliation recovery of
accepted-but-unconfirmed operations. Offline: mock broker + a fault-injecting double (no live Ludus).
"""
import datetime as _dt
import json as _json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "s6rs")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("LUDUS_API_URL", None)

import pytest  # noqa: E402

from _s6util import expiring_client  # noqa: E402
import broker  # noqa: E402


@pytest.fixture(autouse=True)
def _guard():
    keys = ("RANGER_STRATA_PORTFOLIOS", "LUDUS_API_URL", "LUDUS_ADAPTER_VERIFIED", "ADMIN_TOKEN")
    saved = {k: os.environ.get(k) for k in keys}
    import app as _a
    gkeys = ("MAX_CONCURRENT", "RAIDER_RAM_UNITS", "CAPSTONE_RAM_UNITS", "RANGE_IDLE_HOURS",
             "RANGE_MAX_AGE_HOURS", "RANGE_EVIDENCE_HOLD_HOURS", "RANGE_SUSPENDED_RETENTION_HOURS")
    gsaved = {k: getattr(_a, k) for k in gkeys}
    try:
        yield
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        for k, v in gsaved.items():
            setattr(_a, k, v)


# ============================================================ R3-3: tri-state VM power =============
def test_power_off_not_confirmed_when_any_vm_unknown(monkeypatch):
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    monkeypatch.setattr(broker, "_req", lambda *a, **k: {})  # POST accepted
    # one VM explicitly stopped, one with NO power field (unknown) -> power-off NOT confirmed
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "poweredOn": False}, {"name": "SRV02"}]})

    class C:
        ludus_user_id = "U"
    confirmed, _d, outcome = broker.power_off(C())
    assert confirmed is False and outcome in (broker.OP_PENDING, broker.OP_UNKNOWN)


def test_power_on_not_confirmed_when_any_vm_unknown_or_unrecognized(monkeypatch):
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    monkeypatch.setattr(broker, "_req", lambda *a, **k: {})

    class C:
        ludus_user_id = "U"
    # one running, one with an UNRECOGNIZED state string -> not all-running -> not confirmed
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "powerState": "running"}, {"name": "SRV02", "powerState": "weird"}]})
    confirmed, _d, outcome = broker.power_on(C())
    assert confirmed is False


def test_confirm_power_is_read_only_and_tri_state(monkeypatch):
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"

    class C:
        ludus_user_id = "U"
    # confirm_power must NOT issue any request (no power command); only range_detail is read
    def _no_req(*a, **k):
        raise AssertionError("confirm_power must not issue any API request")
    monkeypatch.setattr(broker, "_req", _no_req)
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "poweredOn": True}, {"name": "SRV02", "poweredOn": True}]})
    assert broker.confirm_power(C(), "running") == (True, broker.OP_CONFIRMED)
    # all stopped while we wanted running -> definitive failure
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "poweredOn": False}, {"name": "SRV02", "poweredOn": False}]})
    assert broker.confirm_power(C(), "running") == (False, broker.OP_FAILED)
    # mixed / unknown -> pending (hold)
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "poweredOn": True}, {"name": "SRV02"}]})
    assert broker.confirm_power(C(), "running") == (False, broker.OP_PENDING)


# ============================================================ R3-2 / R3-5: app integration =========
def _app():
    import app as appmod
    from models import db, Cohort, AdminUser
    os.environ["ADMIN_TOKEN"] = "s6-rs-admin"
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.drop_all(); db.create_all()
    if not Cohort.query.filter_by(name="2026-A").first():
        db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
    if AdminUser.query.filter_by(github_id="gid-admin").first() is None:
        db.session.add(AdminUser(github_id="gid-admin", login="alice", role="reviewer"))
    db.session.commit()
    return appmod, application, db, ctx


def _cand(db, handle, board=5, status="active"):
    from models import Candidate
    c = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort="2026-A",
                  github_id=f"g-{handle}", status=status, current_board=board, token=f"tok-{handle}")
    db.session.add(c); db.session.commit()
    return c


def _suspended_range(db, c, host="primary", board=5):
    from models import RangeRequest
    rr = RangeRequest(candidate_id=c.id, board=board, host=host, status="suspended",
                      ludus_range_id="RID-%s" % c.handle, template="goad",
                      deployed_at=_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=1))
    db.session.add(rr); db.session.commit()
    return rr


def test_uncertain_resume_holds_capacity_then_recovers(monkeypatch):
    """A power-on accepted but not yet confirmed keeps the range in 'resuming' (slot held); repeated
    maintenance (read-only) resolves it to deployed once VMs are confirmed running - no undercount, no
    duplicate power-on."""
    appmod, application, db, ctx = _app()
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    try:
        from models import RangeRequest
        c = _cand(db, "rs_resume", 5)
        rr = _suspended_range(db, c)
        # power_on POST is accepted; count how many times it is issued (must be exactly once)
        posts = {"poweron": 0}
        real_req = broker._req
        def _req(method, path, *a, **k):
            if path == "/range/poweron":
                posts["poweron"] += 1
                return {}
            if path.startswith("/range"):
                return {}
            return {}
        monkeypatch.setattr(broker, "_req", _req)
        # VMs in an UNKNOWN (still-transitioning) state at resume time -> PENDING -> 'resuming'
        # (not all-stopped, which would be a definitive failure).
        monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
            "VMs": [{"name": "DC01"}, {"name": "SRV02", "powerState": "starting"}]})
        client = expiring_client(application, db)
        r = client.post("/labs/start", json={"handle": c.handle}, headers={"X-Candidate-Token": c.token})
        assert r.status_code == 200
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "resuming", "an unconfirmed resume must hold a 'resuming' (slot-counted) state"
        assert posts["poweron"] == 1

        # repeated maintenance while still unconfirmed (unknown) -> stays resuming, no 2nd power-on
        admin = {"Authorization": "Bearer s6-rs-admin", "Accept": "application/json"}
        client.post("/admin/reconcile", headers=admin)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "resuming" and posts["poweron"] == 1

        # VMs now confirmed running -> next maintenance resolves to deployed (still no new power-on)
        monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
            "VMs": [{"name": "DC01", "poweredOn": True}, {"name": "SRV02", "poweredOn": True}]})
        client.post("/admin/reconcile", headers=admin)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "deployed" and posts["poweron"] == 1, "resume confirmed read-only, once"
    finally:
        ctx.pop()


def test_resuming_range_counts_against_capacity(monkeypatch):
    """A 'resuming' range holds its RAM slot, so a second range cannot deploy onto a full host - the
    reservation is never undercounted while the transition is unresolved."""
    appmod, application, db, ctx = _app()
    appmod.MAX_CONCURRENT = 1
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    try:
        from models import RangeRequest
        c = _cand(db, "rs_hold", 5)
        rr = _suspended_range(db, c)
        monkeypatch.setattr(broker, "_req", lambda *a, **k: {})
        monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
            "VMs": [{"name": "DC01", "powerState": "starting"}]})  # unknown/transitioning -> pending
        client = expiring_client(application, db)
        client.post("/labs/start", json={"handle": c.handle}, headers={"X-Candidate-Token": c.token})
        assert RangeRequest.query.get(rr.id).status == "resuming"
        # the resuming range occupies the single unit, so capacity is used up
        import app as a
        assert a is appmod
        # a direct capacity check: used >= capacity (1), so a new admit for board 5 must be refused
        used = (RangeRequest.query.filter(RangeRequest.host == "primary",
                RangeRequest.status.in_(RangeRequest.OCCUPIES_SLOT)).count())
        assert used == 1, "the resuming range counts against the host's slots"
    finally:
        ctx.pop()


def test_definitive_resume_failure_releases_slot(monkeypatch):
    appmod, application, db, ctx = _app()
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    try:
        from models import RangeRequest
        c = _cand(db, "rs_fail", 5)
        rr = _suspended_range(db, c)
        monkeypatch.setattr(broker, "_req", lambda *a, **k: {})
        # VMs confirmed STOPPED after a power-on attempt = definitive failure -> back to suspended
        monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
            "VMs": [{"name": "DC01", "poweredOn": False}, {"name": "SRV02", "poweredOn": False}]})
        # power_on confirm sees all-stopped -> OP_FAILED
        client = expiring_client(application, db)
        client.post("/labs/start", json={"handle": c.handle}, headers={"X-Candidate-Token": c.token})
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "suspended", "a definitive resume failure releases the reservation"
    finally:
        ctx.pop()


def test_interrupted_deploy_stays_counted_on_unknown(monkeypatch):
    """An accepted deploy whose status probe is UNKNOWN keeps the range 'deploying' (counted), not
    dropped to failed - no undercount, no premature free, recovered on a later poll."""
    appmod, application, db, ctx = _app()
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    try:
        from models import RangeRequest
        c = _cand(db, "rs_depl", 5)
        # deploy accepted, but the status probe errors -> range_status returns 'unknown'
        monkeypatch.setattr(broker, "ensure_user", lambda *a, **k: ("U", "k", "ok"))
        monkeypatch.setattr(broker, "set_range_config", lambda *a, **k: (True, "cfg"))
        monkeypatch.setattr(broker, "deploy_range", lambda *a, **k: ("deploying", "RID", "accepted"))
        monkeypatch.setattr(broker, "wireguard_config", lambda *a, **k: "wg")
        monkeypatch.setattr(broker, "range_status", lambda *a, **k: ("unknown", "probe error (transient)"))
        from models import RangeRequest as RR
        rr = RR(candidate_id=c.id, board=5, host="primary", status="configured", template="goad")
        db.session.add(rr); db.session.commit()
        client = expiring_client(application, db)
        client.post("/labs/start", json={"handle": c.handle}, headers={"X-Candidate-Token": c.token})
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "deploying", "an unknown deploy probe keeps the range reserved (counted)"
    finally:
        ctx.pop()
