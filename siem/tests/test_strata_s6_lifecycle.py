"""STRATA S6 sections 15-16 - the hardened Ludus adapter and the range lifecycle
state machine with evidence-preservation guards.

Three layers, all offline:
  * broker (section 15): typed errors, bounded retry/backoff for idempotent calls,
    TLS verification policy, idempotent 404/409 handling, power off/on, and the
    technical-validation probe that NEVER passes a mock or unverified-adapter range.
  * range_lifecycle (section 16): a pure state machine - legal/illegal transitions,
    slot accounting (suspended frees the slot), and the reclaim/teardown evidence guard.
  * integration (app, mock broker, in-memory sqlite): submitting an isolated objective
    opens an evidence hold; reclamation then SUSPENDS (power-off) instead of destroying;
    re-entry RESUMES (power-on) rather than rebuilding; a suspended range frees capacity.

Category D (actual Ludus/Proxmox timing + REST paths) stays UNVERIFIED without a live
host: these tests prove the control-plane logic, never a live range.
"""
import datetime as _dt
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "s6life")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("LUDUS_API_URL", None)
os.environ.setdefault("ADMIN_TOKEN", "s6-admin-tok")

import pytest  # noqa: E402

import broker  # noqa: E402
import range_lifecycle as L  # noqa: E402


@pytest.fixture(autouse=True)
def _env_guard():
    keys = ("LUDUS_API_URL", "LUDUS_API_KEY", "LUDUS_VERIFY_TLS", "LUDUS_CA_BUNDLE",
            "LUDUS_ADAPTER_VERIFIED", "LUDUS_RETRIES", "LUDUS_TIMEOUT",
            "RANGER_STRATA_PORTFOLIOS", "RANGER_ENV", "RANGER_S6_ATTEST_TEST")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        yield
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


class _C:
    def __init__(self, handle="ranger", cohort="2026-A"):
        self.handle = handle
        self.name = handle
        self.cohort = cohort
        self.ludus_user_id = "026A-RANGER-ABCD"


# =====================================================================================
# section 15 - broker hardening (no network: _do_once is patched)
# =====================================================================================
def test_http_error_classification_is_typed():
    import urllib.error

    def mk(code):
        e = urllib.error.HTTPError("http://x", code, "msg", {}, None)
        return broker._classify_http_error(e)

    assert isinstance(mk(401), broker.LudusAuthError)
    assert isinstance(mk(403), broker.LudusAuthError)
    assert isinstance(mk(404), broker.LudusNotFound)
    assert isinstance(mk(409), broker.LudusConflict)
    assert isinstance(mk(503), broker.LudusUnavailable) and mk(503).retryable
    # a generic 4xx is a definite client error, never retried
    assert mk(418).retryable is False
    # auth/not-found/conflict are not retryable
    assert mk(401).retryable is False and mk(404).retryable is False


def test_idempotent_call_retries_then_raises(monkeypatch):
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_RETRIES"] = "3"
    calls = {"n": 0}

    def boom(*a, **k):
        calls["n"] += 1
        raise broker.LudusUnavailable("503", status=503)

    monkeypatch.setattr(broker, "_do_once", boom)
    monkeypatch.setattr(broker.time, "sleep", lambda *_a, **_k: None)
    with pytest.raises(broker.LudusUnavailable):
        broker._req("GET", "/range", idempotent=True)
    assert calls["n"] == 3, "idempotent call must retry up to the configured attempts"


def test_non_idempotent_call_is_not_retried(monkeypatch):
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_RETRIES"] = "3"
    calls = {"n": 0}

    def boom(*a, **k):
        calls["n"] += 1
        raise broker.LudusUnavailable("503", status=503)

    monkeypatch.setattr(broker, "_do_once", boom)
    monkeypatch.setattr(broker.time, "sleep", lambda *_a, **_k: None)
    with pytest.raises(broker.LudusUnavailable):
        broker._req("POST", "/range/deploy", {"x": 1})  # idempotent defaults False
    assert calls["n"] == 1, "a write must never be silently retried (double-provision risk)"


def test_non_retryable_error_is_not_retried_even_if_idempotent(monkeypatch):
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_RETRIES"] = "4"
    calls = {"n": 0}

    def boom(*a, **k):
        calls["n"] += 1
        raise broker.LudusAuthError("401", status=401)

    monkeypatch.setattr(broker, "_do_once", boom)
    monkeypatch.setattr(broker.time, "sleep", lambda *_a, **_k: None)
    with pytest.raises(broker.LudusAuthError):
        broker._req("GET", "/range", idempotent=True)
    assert calls["n"] == 1, "a non-retryable auth error must not be retried"


def test_tls_verification_is_on_by_default():
    os.environ.pop("LUDUS_VERIFY_TLS", None)
    assert broker._verify_tls() is True
    ctx = broker._ssl_context()
    import ssl as _ssl
    assert ctx.verify_mode == _ssl.CERT_REQUIRED and ctx.check_hostname is True
    # explicit opt-out yields an unverified context and is surfaced in status
    os.environ["LUDUS_VERIFY_TLS"] = "0"
    assert broker._verify_tls() is False
    ctx2 = broker._ssl_context()
    assert ctx2.verify_mode == _ssl.CERT_NONE
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    assert "TLS verification DISABLED" in broker.broker_status()


def test_destroy_treats_404_as_idempotent_success(monkeypatch):
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"

    def nf(*a, **k):
        raise broker.LudusNotFound("404", status=404)

    monkeypatch.setattr(broker, "_req", nf)
    ok, detail = broker.destroy_range(_C())
    assert ok is True and "absent" in detail


def test_ensure_user_treats_409_as_reuse(monkeypatch):
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"

    def conflict(*a, **k):
        raise broker.LudusConflict("409", status=409)

    monkeypatch.setattr(broker, "_req", conflict)
    uid, key, detail = broker.ensure_user(_C())
    assert key is None and "already existed" in detail


def test_verify_range_fails_closed_mock_and_unverified():
    c = _C()
    # mock: no live range -> never validated
    r = broker.verify_range(c, {"expected_vm_count": 5})
    assert r["ok"] is False and "mock" in r["reason"]
    # live but adapter unverified -> fail closed even though the probe code exists
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    r2 = broker.verify_range(c, {"expected_vm_count": 5})
    assert r2["ok"] is False and "UNVERIFIED" in r2["reason"]


def test_verify_range_passes_only_when_live_verified_and_detail_matches(monkeypatch):
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    c = _C()
    good = {"rangeState": "SUCCESS",
            "VMs": [{"name": "DC01", "poweredOn": True}, {"name": "SRV02", "poweredOn": True}]}
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: good)
    r = broker.verify_range(c, {"vms": ["DC01", "SRV02"], "expected_vm_count": 2,
                                "require_powered_on": True})
    assert r["ok"] is True and set(r["observed_vms"]) == {"DC01", "SRV02"}
    # a powered-off VM fails the probe
    bad = {"rangeState": "SUCCESS",
           "VMs": [{"name": "DC01", "poweredOn": True}, {"name": "SRV02", "poweredOn": False}]}
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: bad)
    r2 = broker.verify_range(c, {"vms": ["DC01", "SRV02"], "require_powered_on": True})
    assert r2["ok"] is False


def test_power_off_on_are_power_toggles_not_snapshots():
    ok1, d1 = broker.power_off(_C())
    ok2, d2 = broker.power_on(_C())
    assert ok1 and ok2
    assert "disks preserved" in d1 and "snapshot" not in d1.lower()


# =====================================================================================
# section 16 - lifecycle state machine (pure)
# =====================================================================================
def test_legal_and_illegal_transitions():
    assert L.can_transition(L.DEPLOYED, L.SUSPENDED)
    assert L.can_transition(L.SUSPENDED, L.DEPLOYED)
    assert L.can_transition(L.DESTROYED, L.CONFIGURED)  # rebuild
    assert L.can_transition(L.DEPLOYED, L.DEPLOYED)     # idempotent re-poll
    assert not L.can_transition(L.DEPLOYED, L.CONFIGURED)
    assert not L.can_transition(L.DESTROYED, L.SUSPENDED)
    with pytest.raises(L.IllegalTransition):
        L.assert_transition(L.DEPLOYED, L.CONFIGURED)


def test_slot_accounting_suspended_frees_slot():
    assert L.is_slot_occupying(L.DEPLOYED) and L.is_slot_occupying(L.DEPLOYING)
    assert not L.is_slot_occupying(L.SUSPENDED)
    assert L.is_active(L.SUSPENDED) and not L.is_terminal(L.SUSPENDED)
    assert L.is_terminal(L.DESTROYED)


def test_reclaim_decision_evidence_guard():
    now = _dt.datetime.now(_dt.timezone.utc)
    future = now + _dt.timedelta(hours=10)
    past = now - _dt.timedelta(hours=1)
    # no hold -> destroy
    assert L.reclaim_decision(state=L.DEPLOYED, now=now, evidence_hold_until=None,
                              reason="idle")["action"] == "destroy"
    # hold open -> suspend, even for a max_age reclaim (evidence outranks cost in-window)
    d = L.reclaim_decision(state=L.DEPLOYED, now=now, evidence_hold_until=future, reason="max_age")
    assert d["action"] == "suspend" and d["to_state"] == L.SUSPENDED
    # hold expired -> destroy
    assert L.reclaim_decision(state=L.DEPLOYED, now=now, evidence_hold_until=past,
                              reason="idle")["action"] == "destroy"
    # a non-slot state needs no reclamation
    assert L.reclaim_decision(state=L.SUSPENDED, now=now, evidence_hold_until=None,
                              reason="idle")["action"] == "hold"


def test_teardown_guard_blocks_destroy_during_evidence_window():
    now = _dt.datetime.now(_dt.timezone.utc)
    allowed, _ = L.teardown_allowed(state=L.DEPLOYED, now=now,
                                    evidence_hold_until=now + _dt.timedelta(hours=5))
    assert allowed is False
    allowed2, _ = L.teardown_allowed(state=L.DEPLOYED, now=now,
                                     evidence_hold_until=now - _dt.timedelta(hours=1))
    assert allowed2 is True


def test_action_plans_describe_reality():
    assert L.suspend_plan()["broker_op"] == "power_off" and L.suspend_plan()["to_state"] == L.SUSPENDED
    assert L.resume_plan()["broker_op"] == "power_on" and L.resume_plan()["to_state"] == L.DEPLOYED
    rb = L.rebuild_plan()
    assert rb["broker_ops"] == ["destroy_range", "deploy_range"]
    assert "NOT preserved" in rb["note"] or "NOT a resume" in rb["note"] or "not preserved" in rb["note"].lower()


# =====================================================================================
# integration (app, mock broker)
# =====================================================================================
def _app():
    import app as appmod
    from models import db, AdminUser, Cohort
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.create_all()
    for nm in ("2026-A",):
        if not Cohort.query.filter_by(name=nm).first():
            db.session.add(Cohort(name=nm, pathway="strata", status="active"))
    if AdminUser.query.filter_by(github_id="gid-admin").first() is None:
        db.session.add(AdminUser(github_id="gid-admin", login="alice", role="reviewer"))
    db.session.commit()
    import strata_catalog as cat
    for e in cat.register_all(db, boards=(5,)):
        with application.test_request_context():
            from flask import session
            session["admin"] = True
            session["admin_login"] = "alice"
            session["admin_gid"] = "gid-admin"
            cat.approve(db, e, None)
    db.session.commit()
    return appmod, application, db, ctx


def _cand(db, handle, board=5):
    from models import Candidate
    c = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort="2026-A",
                  github_id=f"g-{handle}", status="active", current_board=board, token=f"tok-{handle}")
    db.session.add(c); db.session.commit()
    return c


def _admin_row(db):
    from models import AdminUser
    return AdminUser.query.filter_by(github_id="gid-admin").first()


def _start_board5(appmod, application, db, c):
    import strata_assignment as asn
    from siem import board_variants as bv
    asn.set_cohort_portfolio(db, "2026-A", 5, bv.variants_for(5)[:2], admin=_admin_row(db))
    client = application.test_client()
    hdr = {"X-Candidate-Token": c.token}
    assert client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr).status_code == 200
    r = client.post("/labs/start", json={"handle": c.handle}, headers=hdr)
    assert r.status_code == 200, r.data
    return client, hdr, r.get_json()


def test_submitting_isolated_objective_opens_evidence_hold():
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest, ScenarioBinding
        import strata_assignment as asn
        c = _cand(db, "g5hold")
        client, hdr, started = _start_board5(appmod, application, db, c)
        assert started["range_status"] == "deployed"
        b = ScenarioBinding.query.filter_by(candidate_id=c.id, board=5).first()
        world = asn.generate(b)
        g = client.post("/grade/submit", json={"handle": c.handle,
                        "submission": {"flags": dict(world["_flags"])}}, headers=hdr)
        assert g.status_code == 200
        rr = RangeRequest.query.filter_by(candidate_id=c.id, board=5).first()
        assert rr.evidence_hold_until is not None
        hold = rr.evidence_hold_until
        if hold.tzinfo is None:
            hold = hold.replace(tzinfo=_dt.timezone.utc)
        assert hold > _dt.datetime.now(_dt.timezone.utc), "submission must open a future evidence hold"
    finally:
        ctx.pop()


def test_reclaim_suspends_under_evidence_hold_then_destroys_after():
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest, ScenarioBinding
        import strata_assignment as asn
        c = _cand(db, "g5susp")
        client, hdr, _ = _start_board5(appmod, application, db, c)
        b = ScenarioBinding.query.filter_by(candidate_id=c.id, board=5).first()
        world = asn.generate(b)
        client.post("/grade/submit", json={"handle": c.handle,
                    "submission": {"flags": dict(world["_flags"])}}, headers=hdr)
        rr = RangeRequest.query.filter_by(candidate_id=c.id, board=5).first()
        assert rr.status == "deployed" and rr.evidence_hold_until is not None

        # force idle reclamation now: backdate activity and lower the idle threshold
        appmod.RANGE_IDLE_HOURS = 0.0001
        appmod.RANGE_MAX_AGE_HOURS = 0  # isolate the idle path
        rr.last_active_at = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=1)
        rr.deployed_at = rr.last_active_at
        db.session.commit()

        admin = {"Authorization": "Bearer s6-admin-tok", "Accept": "application/json"}
        client.post("/admin/reconcile", headers=admin)
        rr = RangeRequest.query.filter_by(candidate_id=c.id, board=5).first()
        assert rr.status == "suspended", "an open evidence window must SUSPEND, never destroy"

        # once the evidence window closes, reclamation may destroy
        rr.status = "deployed"   # pretend it was resumed and went idle again
        rr.evidence_hold_until = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=1)
        rr.last_active_at = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=1)
        db.session.commit()
        client.post("/admin/reconcile", headers=admin)
        rr = RangeRequest.query.filter_by(candidate_id=c.id, board=5).first()
        assert rr.status == "destroyed", "after the evidence window closes, idle reclaim destroys"
    finally:
        ctx.pop()


def test_reentering_suspended_board_resumes_not_rebuilds():
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest
        c = _cand(db, "g5resume")
        client, hdr, _ = _start_board5(appmod, application, db, c)
        rr = RangeRequest.query.filter_by(candidate_id=c.id, board=5).first()
        rid = rr.ludus_range_id
        # suspend it directly (as reclamation under hold would)
        rr.status = "suspended"
        db.session.commit()
        # re-entry starts the lab again -> must resume (power-on), not rebuild
        r = client.post("/labs/start", json={"handle": c.handle}, headers=hdr)
        assert r.status_code == 200
        rr = RangeRequest.query.filter_by(candidate_id=c.id, board=5).first()
        assert rr.status == "deployed" and "resumed" in (rr.detail or "")
        assert rr.ludus_range_id == rid, "resume keeps the same range (evidence intact), not a fresh id"
    finally:
        ctx.pop()


def test_suspended_range_frees_a_concurrency_slot():
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest
        appmod.MAX_CONCURRENT = 1
        ca = _cand(db, "g5a")
        cb = _cand(db, "g5b")
        client_a, hdr_a, started_a = _start_board5(appmod, application, db, ca)
        assert started_a["range_status"] == "deployed"
        # second candidate at cap -> queued
        import strata_assignment as asn
        from siem import board_variants as bv
        asn.set_cohort_portfolio(db, "2026-A", 5, bv.variants_for(5)[:2], admin=_admin_row(db))
        client_b = application.test_client()
        hdr_b = {"X-Candidate-Token": cb.token}
        client_b.post("/labs/dataset", json={"handle": cb.handle}, headers=hdr_b)
        rb = client_b.post("/labs/start", json={"handle": cb.handle}, headers=hdr_b).get_json()
        assert rb["range_status"] == "queued_slot", "at cap, the second range must queue"
        # suspend A -> frees the slot; reconcile promotes B
        rra = RangeRequest.query.filter_by(candidate_id=ca.id, board=5).first()
        rra.status = "suspended"
        db.session.commit()
        admin = {"Authorization": "Bearer s6-admin-tok", "Accept": "application/json"}
        client_b.post("/admin/reconcile", headers=admin)
        rrb = RangeRequest.query.filter_by(candidate_id=cb.id, board=5).first()
        assert rrb.status == "deployed", "a suspended range frees its slot for a queued range"
    finally:
        ctx.pop()
