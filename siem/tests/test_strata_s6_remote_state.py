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


def test_confirm_power_read_only_complete_inventory_and_async_safe(monkeypatch):
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"

    class C:
        ludus_user_id = "U"
    exp = ["DC01", "SRV02"]
    # confirm_power must NOT issue any request (no power command); only range_detail is read
    monkeypatch.setattr(broker, "_req",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no API request allowed")))
    # all expected VMs explicitly running -> CONFIRMED
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "poweredOn": True}, {"name": "SRV02", "poweredOn": True}]})
    assert broker.confirm_power(C(), "running", expected_vms=exp) == (True, broker.OP_CONFIRMED)
    # R4-2: all stopped after an accepted power-on is PENDING (may be queued), NOT a failure
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "poweredOn": False}, {"name": "SRV02", "poweredOn": False}]})
    assert broker.confirm_power(C(), "running", expected_vms=exp) == (False, broker.OP_PENDING)
    # terminal failure ONLY from an authoritative Ludus error -> FAILED
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "rangeState": "FAILURE", "VMs": [{"name": "DC01", "poweredOn": False}]})
    assert broker.confirm_power(C(), "running", expected_vms=exp) == (False, broker.OP_FAILED)
    # R4-3: an expected VM MISSING from the response -> never confirmed (no success from a subset)
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "poweredOn": True}]})  # SRV02 omitted
    assert broker.confirm_power(C(), "running", expected_vms=exp) == (False, broker.OP_PENDING)
    # R4-3: a DUPLICATE VM name -> inventory mismatch -> never confirmed
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "poweredOn": True}, {"name": "DC01", "poweredOn": True},
                {"name": "SRV02", "poweredOn": True}]})
    assert broker.confirm_power(C(), "running", expected_vms=exp) == (False, broker.OP_PENDING)
    # R4-3: a MALFORMED entry -> inventory mismatch -> never confirmed
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "poweredOn": True}, {"poweredOn": True}]})  # entry with no name
    assert broker.confirm_power(C(), "running", expected_vms=exp) == (False, broker.OP_PENDING)
    # unknown expected inventory -> cannot positively confirm even if observed look running
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "poweredOn": True}]})
    assert broker.confirm_power(C(), "running", expected_vms=None) == (False, broker.OP_PENDING)


def test_delayed_power_on_holds_capacity_until_running(monkeypatch):
    """R4-2: a delayed power-on sequence stopped -> stopped -> starting -> running must keep the
    reservation (PENDING) until positively running, never flipping to failure on an interim state."""
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"

    class C:
        ludus_user_id = "U"
    exp = ["DC01"]
    seq = iter([
        {"VMs": [{"name": "DC01", "poweredOn": False}]},                 # stopped
        {"VMs": [{"name": "DC01", "poweredOn": False}]},                 # still stopped
        {"VMs": [{"name": "DC01", "powerState": "starting"}]},           # starting (unknown)
        {"VMs": [{"name": "DC01", "poweredOn": True}]},                  # running
    ])
    cur = {"d": None}
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: cur["d"])
    for _ in range(3):
        cur["d"] = next(seq)
        confirmed, outcome = broker.confirm_power(C(), "running", expected_vms=exp)
        assert confirmed is False and outcome == broker.OP_PENDING, "interim states must hold, not fail"
    cur["d"] = next(seq)
    assert broker.confirm_power(C(), "running", expected_vms=exp) == (True, broker.OP_CONFIRMED)


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
        # The authoritative expected inventory for this range (every confirmation must account for it).
        monkeypatch.setattr(broker, "expected_inventory", lambda *a, **k: ["DC01", "SRV02"])
        # VMs in an UNKNOWN (still-transitioning) state at resume time -> PENDING -> 'resuming'.
        # all-stopped would ALSO be PENDING now (async-safe, R4-2); only an authoritative terminal
        # Ludus signal is a definitive failure. Here SRV02 is still 'starting' (unknown).
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
        monkeypatch.setattr(broker, "expected_inventory", lambda *a, **k: ["DC01"])
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


def test_all_stopped_after_resume_holds_not_releases(monkeypatch):
    """R4-2: observing all VMs still STOPPED right after an accepted power-on is NOT a definitive
    failure (the op may be queued). The reservation is HELD ('resuming'), never released on that
    observation alone - only an authoritative terminal Ludus signal releases it."""
    appmod, application, db, ctx = _app()
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    try:
        from models import RangeRequest
        c = _cand(db, "rs_hold2", 5)
        rr = _suspended_range(db, c)
        monkeypatch.setattr(broker, "_req", lambda *a, **k: {})
        monkeypatch.setattr(broker, "expected_inventory", lambda *a, **k: ["DC01", "SRV02"])
        # all-stopped immediately after an accepted power-on -> PENDING (async-safe), slot held
        monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
            "VMs": [{"name": "DC01", "poweredOn": False}, {"name": "SRV02", "poweredOn": False}]})
        client = expiring_client(application, db)
        client.post("/labs/start", json={"handle": c.handle}, headers={"X-Candidate-Token": c.token})
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "resuming", "all-stopped alone must NOT release; the reservation is held"
    finally:
        ctx.pop()


def test_definitive_resume_failure_releases_slot(monkeypatch):
    """Only an AUTHORITATIVE terminal failure from Ludus (an error range-state) releases a resuming
    reservation back to 'suspended'. A mere non-target power observation never does (see R4-2)."""
    appmod, application, db, ctx = _app()
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    try:
        from models import RangeRequest
        c = _cand(db, "rs_fail", 5)
        rr = _suspended_range(db, c)
        monkeypatch.setattr(broker, "_req", lambda *a, **k: {})
        monkeypatch.setattr(broker, "expected_inventory", lambda *a, **k: ["DC01", "SRV02"])
        # Ludus authoritatively reports the range in an error state -> OP_FAILED -> suspended
        monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
            "rangeState": "FAILURE",
            "VMs": [{"name": "DC01", "poweredOn": False}, {"name": "SRV02", "poweredOn": False}]})
        client = expiring_client(application, db)
        client.post("/labs/start", json={"handle": c.handle}, headers={"X-Candidate-Token": c.token})
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "suspended", "an authoritative terminal failure releases the reservation"
    finally:
        ctx.pop()


# ============================================================ R4-1: status-write-path integrity =====
def _deployed_range(db, c, host="primary", board=5, status="deployed"):
    from models import RangeRequest
    rr = RangeRequest(candidate_id=c.id, board=board, host=host, status=status,
                      ludus_range_id="RID-%s" % c.handle, template="goad",
                      deployed_at=_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=5))
    db.session.add(rr); db.session.commit()
    return rr


def test_candidate_status_poll_unknown_preserves_reservation(monkeypatch):
    """R4-1: a candidate /labs/status poll that observes an UNKNOWN (transient) probe must NOT free a
    slot-occupying range - the reservation (and weighted capacity) is held. Repeated unknowns never
    erode it."""
    appmod, application, db, ctx = _app()
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    try:
        from models import RangeRequest
        c = _cand(db, "rs_poll", 5)
        rr = _deployed_range(db, c, status="deploying")
        monkeypatch.setattr(broker, "range_status", lambda *a, **k: ("unknown", "probe timeout (transient)"))
        client = expiring_client(application, db)
        hdr = {"X-Candidate-Token": c.token}
        for _ in range(4):  # repeated unknown polls must not erode the reservation
            r = client.post("/labs/status", json={"handle": c.handle}, headers=hdr)
            assert r.status_code == 200
            rr = RangeRequest.query.get(rr.id)
            assert rr.status == "deploying", "an unknown candidate poll must keep the slot reserved"
        assert rr.status in RangeRequest.OCCUPIES_SLOT
    finally:
        ctx.pop()


def test_admin_refresh_unknown_preserves_reservation(monkeypatch):
    """R4-1: an administrator /admin/ranges/<id> action=refresh observing UNKNOWN must go through the
    same fail-closed policy - it cannot drop a deployed range to a non-occupying state."""
    appmod, application, db, ctx = _app()
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    try:
        from models import RangeRequest
        c = _cand(db, "rs_adm", 5)
        rr = _deployed_range(db, c, status="deployed")
        monkeypatch.setattr(broker, "range_status", lambda *a, **k: ("unknown", "probe error (transient)"))
        client = expiring_client(application, db)
        admin = {"Authorization": "Bearer s6-rs-admin"}
        r = client.post("/admin/ranges/%d" % c.id, data={"action": "refresh"}, headers=admin)
        assert r.status_code in (200, 302)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "deployed", "an unknown admin refresh must not free the reservation"
        assert rr.status in RangeRequest.OCCUPIES_SLOT
    finally:
        ctx.pop()


def test_status_paths_never_resolve_resuming_without_power_confirmation(monkeypatch):
    """R4-1: neither a candidate poll nor an admin refresh may resolve a 'resuming' range to
    'deployed' on a bare status probe - only the power-confirmation poll (_poll_resuming) may. Even a
    probe that reports 'deployed' must leave a resuming range resuming (slot still held)."""
    appmod, application, db, ctx = _app()
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    try:
        from models import RangeRequest
        c = _cand(db, "rs_resv", 5)
        rr = _deployed_range(db, c, status="resuming")
        # a bare status probe that even claims 'deployed' must NOT resolve a resuming range
        monkeypatch.setattr(broker, "range_status", lambda *a, **k: ("deployed", "range reports up"))
        client = expiring_client(application, db)
        hdr = {"X-Candidate-Token": c.token}
        r = client.post("/labs/status", json={"handle": c.handle}, headers=hdr)
        assert r.status_code == 200
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "resuming", "a candidate poll must not resolve resuming without power confirmation"
        # same guarantee on the admin refresh path
        admin = {"Authorization": "Bearer s6-rs-admin"}
        client.post("/admin/ranges/%d" % c.id, data={"action": "refresh"}, headers=admin)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "resuming", "an admin refresh must not resolve resuming without power confirmation"
        assert rr.status in RangeRequest.OCCUPIES_SLOT
    finally:
        ctx.pop()


def test_status_probe_illegal_transition_holds(monkeypatch):
    """R4-1: a probe reporting a status that is not a LEGAL lifecycle transition from the current
    slot-occupying state is rejected (held), never written blindly - the reservation stands."""
    appmod, application, db, ctx = _app()
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    try:
        from models import RangeRequest
        c = _cand(db, "rs_illegal", 5)
        rr = _deployed_range(db, c, status="deploying")
        # 'resuming' is not a legal transition from 'deploying' via a bare probe -> hold
        monkeypatch.setattr(broker, "range_status", lambda *a, **k: ("resuming", "probe confusion"))
        client = expiring_client(application, db)
        hdr = {"X-Candidate-Token": c.token}
        client.post("/labs/status", json={"handle": c.handle}, headers=hdr)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "deploying", "an illegal probe transition must hold, not be written blindly"
        assert rr.status in RangeRequest.OCCUPIES_SLOT
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
        monkeypatch.setattr(broker, "set_range_config", lambda *a, **k: (True, "cfg", broker.OP_CONFIRMED))
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


# ============================================================ A: ambiguous Ludus command dispatch ===
class _Cand:
    ludus_user_id = "U"


def _raiser(exc, counter=None):
    def _fn(*a, **k):
        if counter is not None:
            counter["n"] += 1
        raise exc
    return _fn


def test_power_on_ambiguous_dispatch_is_unknown_not_failed(monkeypatch):
    """A: a timeout / transport / TLS error raised while SENDING power-on is AMBIGUOUS (the node may
    have accepted it). It must be OP_UNKNOWN (hold + reconcile), never OP_FAILED, and the non-idempotent
    command must NOT be resent (exactly one dispatch attempt)."""
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    for exc in (broker.LudusTimeout("timed out after 30s"),
                broker.LudusUnavailable("transport error: connection reset", status=503),
                broker.LudusProtocolError("TLS error talking to Ludus")):
        n = {"n": 0}
        monkeypatch.setattr(broker, "_req", _raiser(exc, n))
        confirmed, detail, outcome = broker.power_on(_Cand())
        assert confirmed is False and outcome == broker.OP_UNKNOWN, (
            "ambiguous power-on dispatch must be UNKNOWN (held), got %r (%s)" % (outcome, exc))
        assert n["n"] == 1, "a non-idempotent power-on must never be auto-resent on ambiguity"


def test_power_on_definitive_rejection_is_failed(monkeypatch):
    """A: an authoritative server-side rejection (401/403/404) means the command did NOT execute ->
    OP_FAILED (the only case that may release the reservation)."""
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    for exc in (broker.LudusAuthError("forbidden", status=403),
                broker.LudusNotFound("no such range", status=404)):
        monkeypatch.setattr(broker, "_req", _raiser(exc))
        confirmed, detail, outcome = broker.power_on(_Cand())
        assert confirmed is False and outcome == broker.OP_FAILED, (
            "a definitive rejection must be FAILED, got %r (%s)" % (outcome, exc))


def test_power_off_ambiguous_dispatch_is_unknown_not_failed(monkeypatch):
    """A: symmetric to power-on - an ambiguous power-off dispatch holds (UNKNOWN), never a false
    failure, and is never auto-resent."""
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    n = {"n": 0}
    monkeypatch.setattr(broker, "_req", _raiser(broker.LudusTimeout("timed out"), n))
    confirmed, detail, outcome = broker.power_off(_Cand())
    assert confirmed is False and outcome == broker.OP_UNKNOWN
    assert n["n"] == 1, "a non-idempotent power-off must never be auto-resent on ambiguity"
    # definitive rejection still fails
    monkeypatch.setattr(broker, "_req", _raiser(broker.LudusAuthError("401", status=401)))
    assert broker.power_off(_Cand())[2] == broker.OP_FAILED


def test_deploy_dispatch_ambiguous_holds_deploying_not_failed(monkeypatch):
    """A: a deploy POST that fails ambiguously (timeout/5xx after send) may have started a build. It is
    reported 'deploying' with NO range id (hold + read-only reconcile), never 'failed', and is not
    resent. A definitive rejection is 'failed'."""
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    n = {"n": 0}
    monkeypatch.setattr(broker, "_req", _raiser(broker.LudusUnavailable("5xx", status=502), n))
    status, rid, detail = broker.deploy_range(_Cand())
    assert status == "deploying" and rid is None, "ambiguous deploy must HOLD as deploying, not fail"
    assert n["n"] == 1, "a non-idempotent deploy must never be auto-resent on ambiguity"
    monkeypatch.setattr(broker, "_req", _raiser(broker.LudusConflict("409", status=409)))
    status2, _rid2, _d2 = broker.deploy_range(_Cand())
    assert status2 == "failed", "a definitive rejection (409) is a deploy failure"


def test_set_range_config_tri_state(monkeypatch):
    """A/B: config apply distinguishes CONFIRMED / FAILED (definitive) / UNKNOWN (ambiguous)."""
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    monkeypatch.setattr(broker, "_req", lambda *a, **k: {})
    assert broker.set_range_config(_Cand())[2] == broker.OP_CONFIRMED
    monkeypatch.setattr(broker, "_req", _raiser(broker.LudusTimeout("t")))
    assert broker.set_range_config(_Cand())[2] == broker.OP_UNKNOWN
    monkeypatch.setattr(broker, "_req", _raiser(broker.LudusAuthError("401", status=401)))
    assert broker.set_range_config(_Cand())[2] == broker.OP_FAILED


def test_timeout_after_send_then_reconciles_running(monkeypatch):
    """A (delayed completion / interrupted response): a power-on whose response was lost (timeout)
    returns UNKNOWN; the operation actually landed, so a later READ-ONLY confirm_power sees every VM
    running and resolves CONFIRMED - no resend needed, capacity held across the gap."""
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    # dispatch: the POST response is lost
    monkeypatch.setattr(broker, "_req", _raiser(broker.LudusTimeout("response lost")))
    assert broker.power_on(_Cand())[2] == broker.OP_UNKNOWN
    # reconcile: the op had in fact been accepted; VMs are now confirmed running
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "VMs": [{"name": "DC01", "poweredOn": True}, {"name": "SRV02", "poweredOn": True}]})
    ok, outcome = broker.confirm_power(_Cand(), "running", expected_vms=["DC01", "SRV02"])
    assert ok is True and outcome == broker.OP_CONFIRMED, "read-only reconcile resolves the real state"


def test_resume_timeout_after_send_holds_then_reconciles(monkeypatch):
    """A integration: a suspended range whose resume power-on times out stays 'resuming' (slot held,
    power-on issued exactly once); a later read-only maintenance pass, once VMs are confirmed running,
    resolves it to 'deployed' with NO second power-on."""
    appmod, application, db, ctx = _app()
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    try:
        from models import RangeRequest
        c = _cand(db, "rs_to", 5)
        rr = _suspended_range(db, c)
        posts = {"poweron": 0}
        timed_out = {"v": True}

        def _req(method, path, *a, **k):
            if path == "/range/poweron":
                posts["poweron"] += 1
                if timed_out["v"]:
                    raise broker.LudusTimeout("power-on response lost")
                return {}
            return {}
        monkeypatch.setattr(broker, "_req", _req)
        monkeypatch.setattr(broker, "expected_inventory", lambda *a, **k: ["DC01", "SRV02"])
        # VMs not yet observed running at resume time
        monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
            "VMs": [{"name": "DC01", "powerState": "starting"}, {"name": "SRV02", "powerState": "starting"}]})
        client = expiring_client(application, db)
        r = client.post("/labs/start", json={"handle": c.handle}, headers={"X-Candidate-Token": c.token})
        assert r.status_code == 200
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "resuming", "a timed-out resume dispatch holds the slot (resuming)"
        assert posts["poweron"] == 1

        # the power-on had in fact landed; VMs now confirmed running. A read-only reconcile resolves it.
        monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
            "VMs": [{"name": "DC01", "poweredOn": True}, {"name": "SRV02", "poweredOn": True}]})
        admin = {"Authorization": "Bearer s6-rs-admin", "Accept": "application/json"}
        client.post("/admin/reconcile", headers=admin)
        rr = RangeRequest.query.get(rr.id)
        assert rr.status == "deployed", "read-only reconcile resolves the held resume to deployed"
        assert posts["poweron"] == 1, "the non-idempotent power-on must never be resent"
    finally:
        ctx.pop()


# ============================================================ B: config must apply before deploy ====
def _deploy_setup(monkeypatch, cfg_outcome):
    """Wire a board-5 candidate for a /labs/start deploy with set_range_config returning the given
    outcome, and a deploy_range SPY that records whether it was called."""
    appmod, application, db, ctx = _app()
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    from models import RangeRequest
    c = _cand(db, "cfg_%s" % cfg_outcome, 5)
    rr = RangeRequest(candidate_id=c.id, board=5, host="primary", status="configured", template="goad")
    db.session.add(rr); db.session.commit()
    spy = {"deploy_calls": 0}
    monkeypatch.setattr(broker, "ensure_user", lambda *a, **k: ("U", "k", "ok"))
    monkeypatch.setattr(broker, "set_range_config",
                        lambda *a, **k: (cfg_outcome == broker.OP_CONFIRMED, "cfg:%s" % cfg_outcome, cfg_outcome))

    def _deploy(*a, **k):
        spy["deploy_calls"] += 1
        return ("deploying", "RID", "accepted")
    monkeypatch.setattr(broker, "deploy_range", _deploy)
    monkeypatch.setattr(broker, "wireguard_config", lambda *a, **k: "wg")
    monkeypatch.setattr(broker, "range_status", lambda *a, **k: ("deployed", "up"))
    return appmod, application, db, ctx, c, rr, spy


def test_deploy_refused_when_config_definitively_rejected(monkeypatch):
    """B: a definitively rejected pinned config must STOP the deploy - deploy_range is never called and
    the reserved slot is released (failed), so no range is built on a non-approved config."""
    appmod, application, db, ctx, c, rr, spy = _deploy_setup(monkeypatch, broker.OP_FAILED)
    try:
        from models import RangeRequest
        client = expiring_client(application, db)
        client.post("/labs/start", json={"handle": c.handle}, headers={"X-Candidate-Token": c.token})
        rr = RangeRequest.query.get(rr.id)
        assert spy["deploy_calls"] == 0, "deploy must NOT run when the pinned config was rejected"
        assert rr.status == "failed" and rr.status not in RangeRequest.OCCUPIES_SLOT
        assert "config" in (rr.detail or "").lower() and "refusing to deploy" in (rr.detail or "")
    finally:
        ctx.pop()


def test_deploy_refused_when_config_apply_ambiguous(monkeypatch):
    """B: an ambiguous (unconfirmed) config apply must ALSO stop the deploy - building on a config we
    cannot prove landed could provision a stale scenario. Fail closed; deploy_range never runs."""
    appmod, application, db, ctx, c, rr, spy = _deploy_setup(monkeypatch, broker.OP_UNKNOWN)
    try:
        from models import RangeRequest
        client = expiring_client(application, db)
        client.post("/labs/start", json={"handle": c.handle}, headers={"X-Candidate-Token": c.token})
        rr = RangeRequest.query.get(rr.id)
        assert spy["deploy_calls"] == 0, "deploy must NOT run on an unconfirmed config"
        assert rr.status == "failed"
        assert "unconfirmed" in (rr.detail or "").lower() or "unverified" in (rr.detail or "").lower()
    finally:
        ctx.pop()


def test_confirmed_config_allows_deploy(monkeypatch):
    """B control: a demonstrably applied config DOES proceed to deploy (the gate is not over-broad)."""
    appmod, application, db, ctx, c, rr, spy = _deploy_setup(monkeypatch, broker.OP_CONFIRMED)
    try:
        from models import RangeRequest
        client = expiring_client(application, db)
        client.post("/labs/start", json={"handle": c.handle}, headers={"X-Candidate-Token": c.token})
        rr = RangeRequest.query.get(rr.id)
        assert spy["deploy_calls"] == 1, "a confirmed config must proceed to exactly one deploy"
        assert rr.status == "deployed"
    finally:
        ctx.pop()


def test_stale_config_cannot_silently_provision_mismatched_scenario(monkeypatch):
    """B (proof): if the approved pinned config does not demonstrably apply, the range is NEVER built.
    deploy_range is never reached and no range id is assigned, so a stale/previous config can never
    silently provision a scenario different from the approved ScenarioBinding."""
    for outcome in (broker.OP_FAILED, broker.OP_UNKNOWN):
        appmod, application, db, ctx, c, rr, spy = _deploy_setup(monkeypatch, outcome)
        try:
            from models import RangeRequest
            client = expiring_client(application, db)
            client.post("/labs/start", json={"handle": c.handle},
                        headers={"X-Candidate-Token": c.token})
            rr = RangeRequest.query.get(rr.id)
            assert spy["deploy_calls"] == 0
            assert rr.ludus_range_id is None, "no range may be built on an unverified config"
            assert rr.status not in RangeRequest.OCCUPIES_SLOT
        finally:
            ctx.pop()
