"""STRATA S6 - ENGINEERING ACCEPTANCE SUITE (section 21).

A single, high-signal gate over the whole S6 contract for boards 5 (Raider) and 6 (Vanguard). Each
test is labeled NEGATIVE (a thing that MUST be refused / MUST fail) or POSITIVE (a thing that MUST
work). The per-feature suites (attestation, families, governance, lifecycle, capstone) carry the
exhaustive coverage; this suite asserts the headline guarantees together so acceptance is one run.

Offline only: the mock broker is the default; a deterministic test override simulates an ATTESTED
real range for the allow-path, exactly as S5 does for activation. No Ludus host is contacted, so
evidence categories D (actual Ludus/Proxmox) and E (candidate acceptance) are NOT covered here and
remain unverified until a live host exists.
"""
import datetime as _dt
import json as _json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "s6acc")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("LUDUS_API_URL", None)

import pytest  # noqa: E402

from _s6util import expiring_client  # noqa: E402

import scenarios as sc  # noqa: E402
import broker  # noqa: E402
import range_lifecycle as L  # noqa: E402
import strata_range_attestation as ra  # noqa: E402


@pytest.fixture(autouse=True)
def _env_guard():
    keys = ("RANGER_ENV", "RANGER_S6_ATTEST_TEST", "CI_TOKEN", "RANGER_STRATA_PORTFOLIOS",
            "LUDUS_API_URL", "LUDUS_ADAPTER_VERIFIED", "LUDUS_VERIFY_TLS")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        yield
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _app():
    import app as appmod
    from models import db, Cohort, AdminUser
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.drop_all(); db.create_all()  # per-test schema reset: StaticPool shares one in-memory DB in a process
    if not Cohort.query.filter_by(name="2026-A").first():
        db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
    if not Cohort.query.filter_by(name="2026-B").first():
        db.session.add(Cohort(name="2026-B", pathway="strata", status="active"))
    if AdminUser.query.filter_by(github_id="gid-admin").first() is None:
        db.session.add(AdminUser(github_id="gid-admin", login="alice", role="reviewer"))
    db.session.commit()
    return appmod, application, db, ctx


def _cand(db, handle, board, cohort="2026-A"):
    from models import Candidate
    c = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort=cohort,
                  github_id=f"g-{handle}", status="active", current_board=board, token=f"tok-{handle}")
    db.session.add(c); db.session.commit()
    return c


def _seed_for(c, board):
    from models import ScenarioAssignment
    a = (ScenarioAssignment.query.filter_by(github_id=c.github_id, board=board, cohort=c.cohort)
         .order_by(ScenarioAssignment.id.desc()).first())
    return a.seed if a else None


def _correct_flags_legacy(c, client, board):
    hdr = {"X-Candidate-Token": c.token}
    assert client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr).status_code == 200
    seed = _seed_for(c, board)
    assert seed
    return {"flags": sc.flags_for_board(board, seed)}


def _ensure_board_catalog(db, application, board):
    """Register + approve the board's scenario families ONCE (idempotent). Registering twice would
    collide on material diversity, so guard on existing approved entries."""
    import json as _j
    import strata_catalog as cat
    from models import ScenarioCatalogEntry
    existing = [e for e in ScenarioCatalogEntry.query.filter_by(status="catalog_eligible").all()
                if _j.loads(e.board_compat)[0] == board]
    if existing:
        return
    for e in cat.register_all(db, boards=(board,)):
        with application.test_request_context():
            from flask import session
            session["admin"] = True; session["admin_login"] = "alice"; session["admin_gid"] = "gid-admin"
            cat.approve(db, e, None)
    db.session.commit()


def _approve_portfolio(db, application, cohort, board, n=2):
    import strata_assignment as asn
    from siem import board_variants as bv
    from models import AdminUser
    _ensure_board_catalog(db, application, board)
    admin = AdminUser.query.filter_by(github_id="gid-admin").first()
    asn.set_cohort_portfolio(db, cohort, board, bv.variants_for(board)[:n], admin=admin)


# =====================================================================================
# NEGATIVE - must be refused / must fail
# =====================================================================================
def test_NEG_mock_range_earns_no_isolated_credit_and_no_promotion():
    appmod, application, db, ctx = _app()
    try:
        from models import BoardResult, Candidate
        client = expiring_client(application, db)
        c = _cand(db, "accN1", 5)
        hdr = {"X-Candidate-Token": c.token}
        g = client.post("/grade/submit", json={"handle": c.handle,
                        "submission": _correct_flags_legacy(c, client, 5)}, headers=hdr).get_json()
        assert g["score"] >= 95.0 and g["passed"] is False and g["promoted"] is False
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        assert br.objective_passed is False
        assert _json.loads(br.range_attestation)["real"] is False
        assert Candidate.query.get(c.id).current_board == 5
    finally:
        ctx.pop()


def test_NEG_ci_callback_refuses_isolated_boards():
    os.environ["CI_TOKEN"] = "acc-ci-tok"
    appmod, application, db, ctx = _app()
    try:
        client = expiring_client(application, db)
        hdr = {"X-CI-Token": "acc-ci-tok"}  # authenticate past the token gate to reach the refusal
        for board in (5, 6):
            c = _cand(db, f"accN2b{board}", board)
            r = client.post("/grade", json={"handle": c.handle, "board": board, "score": 100}, headers=hdr)
            assert r.status_code == 409, f"board {board} CI callback must be refused, got {r.status_code}"
    finally:
        ctx.pop()


def test_NEG_attestation_rejects_forged_foreign_and_expired():
    _saved = {k: os.environ.get(k) for k in ("RANGER_ENV", "RANGER_S6_ATTEST_TEST")}
    os.environ["RANGER_ENV"] = "test"; os.environ["RANGER_S6_ATTEST_TEST"] = "1"
    try:
        class _RR:
            status = "deployed"; ludus_range_id = "RID-1"; template = "goad"
        rec = ra.attest(type("C", (), {"handle": "h", "cohort": "2026-A"})(), 5, _RR(), broker,
                        cohort="2026-A", attempt=1, scenario={"scenario_ref": "ref-5"})[1]
        ok, _ = ra.verify_stored(rec, handle="h", board=5, cohort="2026-A", attempt=1, scenario_ref="ref-5")
        assert ok is True
        tampered = dict(rec); tampered["board"] = 6
        assert ra.verify_stored(tampered, handle="h", board=6, cohort="2026-A", attempt=1)[0] is False
        assert ra.verify_stored(rec, handle="other", board=5, cohort="2026-A", attempt=1)[0] is False
        assert ra.verify_stored(rec, handle="h", board=5, cohort="2026-Z", attempt=1)[0] is False
        expired = dict(rec)
        assert ra.verify_stored(expired, handle="h", board=5, cohort="2026-A", attempt=1,
                                now=_dt.datetime(2099, 1, 1, tzinfo=_dt.timezone.utc))[0] is False
    finally:
        for k, v in _saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def test_NEG_one_candidate_flags_do_not_grade_anothers_world():
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        import strata_assignment as asn
        _approve_portfolio(db, application, "2026-A", 5, n=2)
        _approve_portfolio(db, application, "2026-B", 5, n=2)
        ca = _cand(db, "accN4a", 5, "2026-A")
        cb = _cand(db, "accN4b", 5, "2026-B")
        ba = asn.assign(db, ca, 5, cohort="2026-A",
                        portfolio=asn.resolve_portfolio(db, "2026-A", 5, required=True), require_portfolio=True)
        bb = asn.assign(db, cb, 5, cohort="2026-B",
                        portfolio=asn.resolve_portfolio(db, "2026-B", 5, required=True), require_portfolio=True)
        assert ba.seed != bb.seed
        wa = asn.generate(ba)
        cross, _ = asn.grade(bb, {"flags": dict(wa["_flags"])})
        assert cross < 95.0, "A's flags must not satisfy B's pinned world"
    finally:
        ctx.pop()


def test_NEG_capstone_missing_mandatory_milestone_fails():
    w = sc.generate_board6("acc-cap")
    flags = dict(w["_flags"])
    no_crown = {k: v for k, v in flags.items() if k != "crown"}
    assert sum(o["points"] for o in w["objectives"] if o["id"] != "crown") >= 95
    score, fb = sc.score_board6(w, {"flags": no_crown})
    assert score < 95.0 and fb[0]["capstone_complete"] is False and "crown" in fb[0]["mandatory_missing"]


def test_NEG_verify_range_fails_closed_mock_and_unverified():
    class C:
        handle = "r"; cohort = "2026-A"; ludus_user_id = "U-1"
    assert broker.verify_range(C(), {"expected_vm_count": 5})["ok"] is False  # mock
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    assert broker.verify_range(C(), {"expected_vm_count": 5})["ok"] is False  # live but unverified


def test_NEG_lifecycle_illegal_transition_and_teardown_guard():
    with pytest.raises(L.IllegalTransition):
        L.assert_transition(L.DEPLOYED, L.CONFIGURED)
    now = _dt.datetime.now(_dt.timezone.utc)
    allowed, _ = L.teardown_allowed(state=L.DEPLOYED, now=now,
                                    evidence_hold_until=now + _dt.timedelta(hours=5))
    assert allowed is False
    # a suspended range frees its concurrency slot
    assert L.is_slot_occupying(L.SUSPENDED) is False


def test_NEG_candidate_projection_never_leaks_flags():
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        import strata_assignment as asn
        _approve_portfolio(db, application, "2026-A", 6, n=2)
        c = _cand(db, "accN8", 6)
        b = asn.assign(db, c, 6, cohort="2026-A",
                       portfolio=asn.resolve_portfolio(db, "2026-A", 6, required=True), require_portfolio=True)
        view = asn.candidate_view(b, asn.generate(b))
        assert "_flags" not in view and "_flags" not in str(view) and "QR6" not in str(view)
    finally:
        ctx.pop()


# =====================================================================================
# POSITIVE - must work
# =====================================================================================
def test_POS_attested_real_range_awards_and_promotes_once():
    _saved = {k: os.environ.get(k) for k in ("RANGER_ENV", "RANGER_S6_ATTEST_TEST")}
    os.environ["RANGER_ENV"] = "test"; os.environ["RANGER_S6_ATTEST_TEST"] = "1"
    appmod, application, db, ctx = _app()
    try:
        from models import BoardResult, Candidate
        client = expiring_client(application, db)
        c = _cand(db, "accP1", 5)
        hdr = {"X-Candidate-Token": c.token}
        sub = _correct_flags_legacy(c, client, 5)
        g = client.post("/grade/submit", json={"handle": c.handle, "submission": sub}, headers=hdr).get_json()
        assert g["passed"] is True
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        att = _json.loads(br.range_attestation)
        assert att["mode"] == "test_fixture" and att["real"] is False  # creditable but never claimed real
        assert Candidate.query.get(c.id).current_board == 5            # no promotion without report
        br.report_status = "approved"; db.session.add(br); db.session.commit()
        g2 = client.post("/grade/submit", json={"handle": c.handle, "submission": sub}, headers=hdr).get_json()
        assert g2["promoted"] is True and Candidate.query.get(c.id).current_board == 6
    finally:
        for k, v in _saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        ctx.pop()


def test_POS_governed_assignment_pins_immutably_and_replays():
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        import strata_assignment as asn
        _approve_portfolio(db, application, "2026-A", 5, n=2)
        c = _cand(db, "accP2", 5)
        b = asn.assign(db, c, 5, cohort="2026-A",
                       portfolio=asn.resolve_portfolio(db, "2026-A", 5, required=True), require_portfolio=True)
        w = asn.generate(b)
        assert asn.generate(b) == w  # reproducible replay
        # re-assigning the same attempt does not repin a different world
        b2 = asn.assign(db, c, 5, cohort="2026-A",
                        portfolio=asn.resolve_portfolio(db, "2026-A", 5, required=True), require_portfolio=True)
        assert b2.seed == b.seed and b2.variant_id == b.variant_id
        score, _ = asn.grade(b, {"flags": dict(w["_flags"])})
        assert score >= 95.0
    finally:
        ctx.pop()


def test_POS_full_capstone_passes():
    w = sc.generate_board6("acc-full")
    score, fb = sc.score_board6(w, {"flags": dict(w["_flags"])})
    assert score == 100.0 and fb[0]["capstone_complete"] is True
    assert fb[0]["rubric_version"] == sc.CAPSTONE_RUBRIC_VERSION


def test_POS_broker_tls_on_by_default_and_errors_typed():
    os.environ.pop("LUDUS_VERIFY_TLS", None)
    import ssl as _ssl
    assert broker._verify_tls() is True
    assert broker._ssl_context().verify_mode == _ssl.CERT_REQUIRED
    import urllib.error
    e = urllib.error.HTTPError("http://x", 503, "m", {}, None)
    assert isinstance(broker._classify_http_error(e), broker.LudusUnavailable)
    assert broker._classify_http_error(e).retryable is True


def test_POS_reclaim_suspends_under_hold_then_destroys_after():
    now = _dt.datetime.now(_dt.timezone.utc)
    d1 = L.reclaim_decision(state=L.DEPLOYED, now=now,
                            evidence_hold_until=now + _dt.timedelta(hours=5), reason="idle")
    assert d1["action"] == "suspend" and d1["to_state"] == L.SUSPENDED
    d2 = L.reclaim_decision(state=L.DEPLOYED, now=now,
                            evidence_hold_until=now - _dt.timedelta(hours=1), reason="idle")
    assert d2["action"] == "destroy" and d2["to_state"] == L.DESTROYED
