"""STRATA S6 - FINAL INTEGRITY CLOSURE acceptance (reviewer items 1-5), proven through the actual
integrated code paths (Flask routes + broker + strata_assignment), not only pure functions.

NEGATIVE = must be refused / must fail closed; POSITIVE = must work.

Categories (per the closure request):
  A pure unit, B Flask/SQLite integration, D mock-Ludus adapter. PostgreSQL concurrency (C) and real
  Ludus/Proxmox (E) are out of scope offline and remain pending. The test_fixture path is an OFFLINE
  qualification simulation, never live-range validation.
"""
import datetime as _dt
import json as _json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "s6clo")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("LUDUS_API_URL", None)
os.environ.setdefault("ADMIN_TOKEN", "s6-clo-admin")

import pytest  # noqa: E402

from _s6util import expiring_client  # noqa: E402

import scenarios as sc  # noqa: E402
import broker  # noqa: E402
import strata_assignment as asn  # noqa: E402
from siem import board_variants as bv  # noqa: E402


@pytest.fixture(autouse=True)
def _env_guard():
    keys = ("RANGER_STRATA_PORTFOLIOS", "RANGER_ENV", "RANGER_S6_ATTEST_TEST",
            "LUDUS_API_URL", "LUDUS_ADAPTER_VERIFIED", "CI_TOKEN", "ADMIN_TOKEN")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        yield
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _app():
    import app as appmod
    from models import db, Cohort, AdminUser
    # Explicit per-app admin token (not setdefault): immune to cross-suite import order so the admin
    # Bearer header matches the app's configured token instead of 401-ing.
    os.environ["ADMIN_TOKEN"] = "s6-clo-admin"
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.drop_all(); db.create_all()  # per-test schema reset: StaticPool shares one in-memory DB in a process
    for nm in ("2026-A", "2026-B"):
        if not Cohort.query.filter_by(name=nm).first():
            db.session.add(Cohort(name=nm, pathway="strata", status="active"))
    if AdminUser.query.filter_by(github_id="gid-admin").first() is None:
        db.session.add(AdminUser(github_id="gid-admin", login="alice", role="reviewer"))
    db.session.commit()
    return appmod, application, db, ctx


def _admin(db):
    from models import AdminUser
    return AdminUser.query.filter_by(github_id="gid-admin").first()


def _ensure_catalog(db, application, board):
    import strata_catalog as cat
    from models import ScenarioCatalogEntry
    existing = [e for e in ScenarioCatalogEntry.query.filter_by(status="catalog_eligible").all()
                if _json.loads(e.board_compat)[0] == board]
    if existing:
        return
    for e in cat.register_all(db, boards=(board,)):
        with application.test_request_context():
            from flask import session
            session["admin"] = True; session["admin_login"] = "alice"; session["admin_gid"] = "gid-admin"
            cat.approve(db, e, None)
    db.session.commit()


def _portfolio(db, application, cohort, board, n=2):
    _ensure_catalog(db, application, board)
    asn.set_cohort_portfolio(db, cohort, board, bv.variants_for(board)[:n], admin=_admin(db))


def _cand(db, handle, board, cohort="2026-A"):
    from models import Candidate
    c = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort=cohort,
                  github_id=f"g-{handle}", status="active", current_board=board, token=f"tok-{handle}")
    db.session.add(c); db.session.commit()
    return c


# ============================================================ §1: pinned generation contract =======
def test_1_POS_variant_revision_after_assignment_still_agrees(monkeypatch):
    """The headline §1 test: after a candidate is assigned, REVISE the live variant library. The
    pinned generation contract must still reproduce the ORIGINAL world, so range placement and the
    grader continue to agree with the scenario the candidate was actually assigned."""
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        _portfolio(db, application, "2026-A", 5, n=2)
        c = _cand(db, "clo1", 5)
        b = asn.assign(db, c, 5, cohort="2026-A",
                       portfolio=asn.resolve_portfolio(db, "2026-A", 5, required=True),
                       require_portfolio=True)
        original = asn.generate(b)
        correct = {"flags": dict(original["_flags"])}
        assert asn.grade(b, correct)[0] >= 95.0

        # Simulate a variant REVISION in the live library: gen_params now returns different material.
        real_gen = bv.gen_params
        def revised(board, variant_id):
            gp = dict(real_gen(board, variant_id) or {})
            gp["svc_pool"] = ["revised_svc_acct"]
            gp["escalation_edge"] = "WriteOwner"
            return gp
        monkeypatch.setattr(bv, "gen_params", revised)
        # The live world WOULD now differ (prove the revision is material)...
        live_board, live_vid = b.board, b.variant_id
        assert revised(live_board, live_vid) != (real_gen(live_board, live_vid) or {})
        # ...but the PINNED binding still reproduces the original world and still grades correctly.
        assert asn.generate(b) == original, "pinned contract must survive a live variant revision"
        assert asn.grade(b, correct)[0] >= 95.0, "grader must still agree with the pinned scenario"
    finally:
        ctx.pop()


def test_1_NEG_governed_deploy_without_binding_fails_closed():
    """A governed isolated board started WITHOUT a bound scenario must not provision from a legacy
    seed; _try_deploy fails closed (range ends 'failed', no mock range stood up)."""
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest
        _portfolio(db, application, "2026-A", 5, n=2)
        c = _cand(db, "clo1b", 5)
        client = expiring_client(application, db)
        hdr = {"X-Candidate-Token": c.token}
        # start the lab WITHOUT opening the dataset first -> no ScenarioBinding exists
        r = client.post("/labs/start", json={"handle": c.handle}, headers=hdr)
        assert r.status_code == 200
        rr = RangeRequest.query.filter_by(candidate_id=c.id, board=5).first()
        assert rr.status == "failed", "governed deploy with no binding must fail closed"
        assert "bound scenario" in (rr.detail or "")
    finally:
        ctx.pop()


# ============================================================ §2: complete probe contract ==========
def test_2_NEG_mode_real_noncreditable_until_full_probe(monkeypatch):
    """Even with a live, adapter-verified range whose Ludus-direct checks all pass, MODE_REAL is
    non-creditable while the guest/scenario probe results are unknown (fail closed)."""
    import strata_range_attestation as ra
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"

    class _C:
        handle = "r"; cohort = "2026-A"; ludus_user_id = "U-9"; github_id = "g-r"

    class _RR:
        status = "deployed"; ludus_range_id = "RID-9"; template = "goad"
    monkeypatch.setattr(broker, "range_detail", lambda *a, **k: {
        "userID": "U-9", "rangeState": "SUCCESS", "VMs": [{"name": "DC01", "poweredOn": True}]})
    creditable, rec = ra.attest(_C(), 6, _RR(), broker, cohort="2026-A", attempt=1,
                                scenario={"scenario_ref": "r6"}, expected_vms=["DC01"])
    assert creditable is False
    assert rec["mode"] in (ra.MODE_UNAVAILABLE,)
    assert rec["technical_validation"]["passed"] is False


# ============================================================ §3 + §4: destructive paths ===========
def _start_governed(appmod, application, db, c, board=5):
    _portfolio(db, application, "2026-A", board, n=2)
    client = expiring_client(application, db)
    hdr = {"X-Candidate-Token": c.token}
    assert client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr).status_code == 200
    r = client.post("/labs/start", json={"handle": c.handle}, headers=hdr)
    assert r.status_code == 200 and r.get_json()["range_status"] == "deployed"
    return client, hdr


def test_3_POS_exit_under_evidence_hold_suspends_not_destroys():
    """A candidate exit (withdraw/remove) must NOT destroy a range holding evidence: with an open
    evidence window the range is SUSPENDED (disks + signed record preserved), and the signed
    qualification record survives in the DB independently of the VM disks."""
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest, BoardResult
        c = _cand(db, "clo3", 5)
        client, hdr = _start_governed(appmod, application, db, c)
        # submit to open the evidence window and persist a signed attestation record
        from models import ScenarioBinding
        b = ScenarioBinding.query.filter_by(candidate_id=c.id, board=5).first()
        world = asn.generate(b)
        client.post("/grade/submit", json={"handle": c.handle,
                    "submission": {"flags": dict(world["_flags"])}}, headers=hdr)
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        assert br.range_attestation, "a signed record must be persisted before teardown"
        # admin removes the candidate
        admin = {"Authorization": "Bearer s6-clo-admin", "Accept": "application/json"}
        client.post(f"/admin/candidates/{c.id}/exit", data={"kind": "withdrawn", "reason": "test"},
                    headers=admin)
        rr = RangeRequest.query.filter_by(candidate_id=c.id, board=5).first()
        assert rr.status == "suspended", "exit under evidence hold must suspend, not destroy"
        # the signed qualification record still exists, independent of the (preserved) VM disks
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        assert br.range_attestation
    finally:
        ctx.pop()


def test_4_NEG_failed_broker_teardown_does_not_change_state_or_free_slot(monkeypatch):
    """A failed/unconfirmed broker destroy must leave the range in its slot-holding state: the DB is
    not flipped to destroyed and the slot is not released (no oversubscription / phantom capacity)."""
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        from models import RangeRequest
        c = _cand(db, "clo4", 5)
        client, hdr = _start_governed(appmod, application, db, c)
        rr = RangeRequest.query.filter_by(candidate_id=c.id, board=5).first()
        assert rr.status == "deployed"
        # fault-inject: the broker destroy is accepted but remote absence is NOT confirmed (§2/§4)
        monkeypatch.setattr(broker, "destroy_range",
                            lambda *a, **k: (False, "destroy accepted but not confirmed absent",
                                             broker.OP_PENDING))
        admin = {"Authorization": "Bearer s6-clo-admin", "Accept": "application/json"}
        client.post(f"/admin/ranges/{c.id}", data={"action": "force_destroy"}, headers=admin)
        rr = RangeRequest.query.filter_by(candidate_id=c.id, board=5).first()
        assert rr.status == "deployed", "an unconfirmed teardown must not mark the range destroyed"
        assert "pending" in (rr.detail or "") or "not confirmed" in (rr.detail or "")
    finally:
        ctx.pop()


# ============================================================ §5: full attestation binding =========
def test_5_POS_governed_attested_real_promotes_with_full_binding():
    """With governance ON and the offline attested-real override, a board-5 submission against a
    deployed range earns credit and (with report approval) promotes - the gate re-verifies the FULL
    binding (candidate github id, binding id, spec id, content hash, gen-contract hash, rubric)."""
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    os.environ["RANGER_ENV"] = "test"; os.environ["RANGER_S6_ATTEST_TEST"] = "1"
    appmod, application, db, ctx = _app()
    try:
        from models import BoardResult, Candidate, ScenarioBinding
        c = _cand(db, "clo5", 5)
        client, hdr = _start_governed(appmod, application, db, c)
        b = ScenarioBinding.query.filter_by(candidate_id=c.id, board=5).first()
        world = asn.generate(b)
        sub = {"flags": dict(world["_flags"])}
        g = client.post("/grade/submit", json={"handle": c.handle, "submission": sub}, headers=hdr).get_json()
        assert g["passed"] is True
        att = _json.loads(BoardResult.query.filter_by(candidate_id=c.id, board=5).first().range_attestation)
        # the attestation carries the full governed binding identity
        assert att["binding_id"] == b.id and att["spec_id"] == b.spec_id
        assert att["scenario_content_hash"] == b.content_hash and att["gen_contract_hash"] == b.gen_hash
        assert att["candidate_github_id"] == c.github_id and att["rubric_version"] == sc.rubric_version(5)
        # approve the report -> promotes once (gate re-verifies the full binding)
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        br.report_status = "approved"; db.session.add(br); db.session.commit()
        client.post("/grade/submit", json={"handle": c.handle, "submission": sub}, headers=hdr)
        assert Candidate.query.get(c.id).current_board == 6
    finally:
        ctx.pop()


def test_5_NEG_unrelated_signed_attestation_cannot_qualify_another_attempt():
    """A genuine, correctly-signed attestation minted for one candidate/binding must NOT qualify a
    different candidate's attempt: the governed gate rejects the foreign binding identity."""
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    os.environ["RANGER_ENV"] = "test"; os.environ["RANGER_S6_ATTEST_TEST"] = "1"
    appmod, application, db, ctx = _app()
    try:
        import strata_range_attestation as ra
        from models import BoardResult, Candidate, ScenarioBinding
        # victim candidate with a real, deployed, governed, attested board 5 and report approved
        cv = _cand(db, "clo5v", 5)
        client_v, hdr_v = _start_governed(appmod, application, db, cv)
        bv_bind = ScenarioBinding.query.filter_by(candidate_id=cv.id, board=5).first()
        wv = asn.generate(bv_bind)
        subv = {"flags": dict(wv["_flags"])}
        client_v.post("/grade/submit", json={"handle": cv.handle, "submission": subv}, headers=hdr_v)
        brv = BoardResult.query.filter_by(candidate_id=cv.id, board=5).first()
        genuine = brv.range_attestation
        assert genuine

        # attacker candidate: score their OWN world, then graft the victim's genuine signed
        # attestation onto their board result by a direct DB tamper (the grading path always re-mints
        # the submitter's own attestation, so the graft is only reachable by tampering the stored row).
        from models import Report
        ca = _cand(db, "clo5a", 5)
        client_a, hdr_a = _start_governed(appmod, application, db, ca)
        ba = ScenarioBinding.query.filter_by(candidate_id=ca.id, board=5).first()
        wa = asn.generate(ba)
        client_a.post("/grade/submit", json={"handle": ca.handle,
                      "submission": {"flags": dict(wa["_flags"])}}, headers=hdr_a)
        bra = BoardResult.query.filter_by(candidate_id=ca.id, board=5).first()
        bra.range_attestation = genuine            # graft the foreign (victim) attestation
        db.session.add(bra)
        rep = Report(candidate_id=ca.id, board="board5", role="red-teamer",
                     body="analysis", status="pending")
        db.session.add(rep); db.session.commit()
        # approve the report -> the promotion gate re-verifies the STORED (grafted) attestation, whose
        # handle/github/binding are foreign, and must refuse. No re-mint happens on this path.
        admin = {"Authorization": "Bearer s6-clo-admin", "Accept": "application/json"}
        client_a.post(f"/admin/reports/{rep.id}", data={"action": "approve"}, headers=admin)
        assert Candidate.query.get(ca.id).current_board == 5, \
            "a foreign signed attestation must not qualify another candidate's attempt"
    finally:
        ctx.pop()
