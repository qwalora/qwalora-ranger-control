"""STRATA S6 - range attestation boundary (sections 9 + 13), exercised through the real routes and
at the unit level. A simulated/unvalidated/foreign/expired/forged range must never produce an
isolated-board (5/6) objective award or promotion. Offline: the mock broker is the default; a
deterministic test override simulates an ATTESTED real range (labeled test_fixture) for the
allow-path only, exactly as S5 does for activation. No Ludus host is contacted.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "s6")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("LUDUS_API_URL", None)   # broker stays in mock mode

import json as _json  # noqa: E402

import pytest  # noqa: E402

import scenarios as sc  # noqa: E402
import broker  # noqa: E402
import strata_range_attestation as ra  # noqa: E402


@pytest.fixture(autouse=True)
def _env_guard():
    """Snapshot and restore the env vars this module mutates, so a test override never leaks into
    other test modules that set these at import time (e.g. the board-2 suite's RANGER_ENV=test)."""
    keys = ("RANGER_ENV", "RANGER_S6_ATTEST_TEST", "CI_TOKEN")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        yield
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _app():
    import app as appmod
    from models import db, Cohort
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.create_all()
    if not Cohort.query.filter_by(name="2026-A").first():
        db.session.add(Cohort(name="2026-A", pathway="strata", status="active")); db.session.commit()
    return application, db, ctx


def _cand(db, handle, board):
    from models import Candidate
    c = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort="2026-A",
                  github_id=f"g-{handle}", status="active", current_board=board, token=f"tok-{handle}")
    db.session.add(c); db.session.commit()
    return c


def _seed_for(c, board):
    from models import ScenarioAssignment
    a = (ScenarioAssignment.query.filter_by(github_id=c.github_id, board=board, cohort=c.cohort)
         .order_by(ScenarioAssignment.id.desc()).first())
    return a.seed if a else None


def _correct_flags(c, client, board):
    hdr = {"X-Candidate-Token": c.token}
    r = client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr)
    assert r.status_code == 200, r.data
    seed = _seed_for(c, board)
    assert seed
    return {"flags": sc.flags_for_board(board, seed)}


# ---------------------------------------------------------------------- end-to-end (HTTP) ----------
def test_board5_mock_range_refuses_objective_award():
    assert broker.is_live() is False
    application, db, ctx = _app()
    try:
        from models import BoardResult, Candidate
        client = application.test_client()
        c = _cand(db, "b5mock", 5)
        hdr = {"X-Candidate-Token": c.token}
        g = client.post("/grade/submit", json={"handle": c.handle,
                        "submission": _correct_flags(c, client, 5)}, headers=hdr)
        gb = g.get_json()
        assert gb["score"] >= 95.0 and gb["passed"] is False and gb["promoted"] is False
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        assert br.objective_passed is False
        att = _json.loads(br.range_attestation)
        assert att["real"] is False and att["mode"] == "mock"
        assert Candidate.query.get(c.id).current_board == 5
    finally:
        ctx.pop()


def test_board5_attested_real_range_awards_and_promotes():
    application, db, ctx = _app()
    _saved = {k: os.environ.get(k) for k in ("RANGER_ENV", "RANGER_S6_ATTEST_TEST")}
    os.environ["RANGER_ENV"] = "test"; os.environ["RANGER_S6_ATTEST_TEST"] = "1"
    try:
        from models import BoardResult, Candidate
        client = application.test_client()
        c = _cand(db, "b5real", 5)
        hdr = {"X-Candidate-Token": c.token}
        submission = _correct_flags(c, client, 5)
        g = client.post("/grade/submit", json={"handle": c.handle, "submission": submission}, headers=hdr)
        assert g.get_json()["passed"] is True
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        att = _json.loads(br.range_attestation)
        assert att["mode"] == "test_fixture" and att["real"] is False  # creditable, but never 'real'
        assert Candidate.query.get(c.id).current_board == 5            # not promoted without report
        br.report_status = "approved"; db.session.add(br); db.session.commit()
        g2 = client.post("/grade/submit", json={"handle": c.handle, "submission": submission}, headers=hdr)
        assert g2.get_json()["promoted"] is True
        assert Candidate.query.get(c.id).current_board == 6
    finally:
        for k, v in _saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        ctx.pop()


def test_board6_mock_range_refuses_award():
    application, db, ctx = _app()
    try:
        from models import BoardResult
        client = application.test_client()
        c = _cand(db, "b6mock", 6)
        hdr = {"X-Candidate-Token": c.token}
        g = client.post("/grade/submit", json={"handle": c.handle,
                        "submission": _correct_flags(c, client, 6)}, headers=hdr)
        gb = g.get_json()
        assert gb["score"] >= 95.0 and gb["passed"] is False
        br = BoardResult.query.filter_by(candidate_id=c.id, board=6).first()
        assert br.objective_passed is False and _json.loads(br.range_attestation)["real"] is False
    finally:
        ctx.pop()


def test_grade_ci_callback_refuses_isolated_boards():
    application, db, ctx = _app()
    _saved_ci = os.environ.get("CI_TOKEN"); os.environ["CI_TOKEN"] = "ci-secret"
    try:
        from models import BoardResult
        client = application.test_client()
        c = _cand(db, "cici", 5)
        for board in (5, 6):
            r = client.post("/grade", json={"handle": c.handle, "board": board, "score": 100},
                            headers={"X-CI-Token": "ci-secret"})
            assert r.status_code == 409, (board, r.data)
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        assert br is None or br.objective_passed is False
    finally:
        os.environ.pop("CI_TOKEN", None) if _saved_ci is None else os.environ.__setitem__("CI_TOKEN", _saved_ci)
        ctx.pop()


# ---------------------------------------------------------------------- unit: verify_stored --------
class _RR:
    def __init__(self, deployed=False, rid=None, status="configured"):
        self.is_deployed = deployed; self.ludus_range_id = rid; self.status = status; self.template = "goad"


class _C:
    def __init__(self, handle="h", cohort="2026-A"):
        self.handle = handle; self.cohort = cohort; self.ludus_user_id = "QR-h"


def _real_fixture_record():
    """A creditable attestation under the active test override (mode test_fixture)."""
    os.environ["RANGER_ENV"] = "test"; os.environ["RANGER_S6_ATTEST_TEST"] = "1"
    creditable, rec = ra.attest(_C(), 5, _RR(), broker, cohort="2026-A", attempt=1,
                                scenario={"scenario_ref": "ref-5"})
    assert creditable and rec["mode"] == "test_fixture"
    return rec


def _clear_override():
    os.environ.pop("RANGER_ENV", None); os.environ.pop("RANGER_S6_ATTEST_TEST", None)


def test_mock_and_urlonly_and_deployedonly_are_not_creditable():
    _clear_override()
    # mock broker -> not creditable
    creditable, rec = ra.attest(_C(), 5, _RR(), broker, cohort="2026-A")
    assert not creditable and rec["mode"] == "mock"
    # a configured URL alone (live broker) with NO validated range -> unavailable, not creditable,
    # even when the stored status says 'deployed' (deployed status alone does not attest validation).
    saved = broker.is_live
    broker.is_live = lambda: True
    try:
        creditable2, rec2 = ra.attest(_C(), 5, _RR(deployed=True, status="deployed"), broker, cohort="2026-A")
        assert not creditable2 and rec2["mode"] == "unavailable"
        assert rec2["technical_validation"]["passed"] is False
    finally:
        broker.is_live = saved


def test_forged_foreign_expired_and_testfixture_without_override_fail_closed():
    rec = _real_fixture_record()
    # baseline: valid under override + matching identity
    ok, _ = ra.verify_stored(rec, handle="h", board=5, cohort="2026-A", attempt=1, scenario_ref="ref-5")
    assert ok
    # forged/altered: flip a field without re-signing
    tampered = dict(rec); tampered["board"] = 6
    assert ra.verify_stored(tampered, handle="h", board=6, cohort="2026-A", attempt=1)[0] is False
    # foreign candidate / cohort
    assert ra.verify_stored(rec, handle="other", board=5, cohort="2026-A", attempt=1)[0] is False
    assert ra.verify_stored(rec, handle="h", board=5, cohort="2026-Z", attempt=1)[0] is False
    # scenario mismatch
    assert ra.verify_stored(rec, handle="h", board=5, cohort="2026-A", attempt=1, scenario_ref="ref-X")[0] is False
    # expired assessment window
    expired = dict(rec); expired["assessment_window"] = {"expires_at": "2000-01-01T00:00:00+00:00"}
    import signing
    expired["signature"] = signing.sign({k: expired[k] for k in expired if k != "signature"})
    assert ra.verify_stored(expired, handle="h", board=5, cohort="2026-A", attempt=1)[0] is False
    # a test-fixture attestation is NOT real-production proof once the override is gone
    _clear_override()
    assert ra.verify_stored(rec, handle="h", board=5, cohort="2026-A", attempt=1)[0] is False


def test_gate_verifies_stored_not_reminted():
    _clear_override()
    rec = _real_fixture_record()
    _clear_override()
    # outside the override, even a well-signed test-fixture attestation is refused at the gate
    ok, reason = ra.verify_stored(rec, handle="h", board=5, cohort="2026-A", attempt=1)
    assert ok is False and "real-production" in reason
