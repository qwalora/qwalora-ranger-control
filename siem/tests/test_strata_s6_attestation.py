"""STRATA S6 - the real-vs-mock range attestation boundary (section 9), exercised through the real
candidate/CI routes. A simulated range must never produce an isolated-board (5/6) objective award or
promotion. These tests run offline (no Ludus host): the mock broker is the default, and a deterministic
test override simulates an ATTESTED real range for the allow-path, exactly as S5 does for activation.
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

import scenarios as sc  # noqa: E402
import broker  # noqa: E402


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


def _correct_flags(c, db, client, board):
    """Open the board dataset (assigns the seed), then derive the correct seed-bound flags."""
    hdr = {"X-Candidate-Token": c.token}
    r = client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr)
    assert r.status_code == 200, r.data
    seed = _seed_for(c, board)
    assert seed, "seed must be assigned after opening the dataset"
    return {"flags": sc.flags_for_board(board, seed)}


def test_board5_mock_range_refuses_objective_award():
    assert broker.is_live() is False, "broker must be mock in this suite"
    application, db, ctx = _app()
    try:
        from models import BoardResult, Candidate
        client = application.test_client()
        c = _cand(db, "b5mock", 5)
        hdr = {"X-Candidate-Token": c.token}
        submission = _correct_flags(c, db, client, 5)
        g = client.post("/grade/submit", json={"handle": c.handle, "submission": submission}, headers=hdr)
        assert g.status_code == 200, g.data
        gb = g.get_json()
        # the flags are correct (score at/above the bar) but the range is SIMULATED, so no award
        assert gb["score"] >= 95.0, gb
        assert gb["passed"] is False, "a mock/simulated range must not award an isolated-board objective"
        assert gb["promoted"] is False
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        assert br.objective_passed is False
        att = _json.loads(br.range_attestation)
        assert att["real"] is False and att["mode"] == "mock_simulation"
        assert Candidate.query.get(c.id).current_board == 5  # not promoted
    finally:
        ctx.pop()


def test_board5_attested_real_range_awards_and_promotes():
    application, db, ctx = _app()
    _saved = {k: os.environ.get(k) for k in ("RANGER_ENV", "RANGER_S6_ATTEST_TEST")}
    os.environ["RANGER_ENV"] = "test"
    os.environ["RANGER_S6_ATTEST_TEST"] = "1"   # deterministic attested-real-range override (test only)
    try:
        from models import BoardResult, Candidate
        client = application.test_client()
        c = _cand(db, "b5real", 5)
        hdr = {"X-Candidate-Token": c.token}
        submission = _correct_flags(c, db, client, 5)
        g = client.post("/grade/submit", json={"handle": c.handle, "submission": submission}, headers=hdr)
        gb = g.get_json()
        assert gb["passed"] is True, "an attested real range with correct flags must award the objective"
        # objective passed but report not yet approved -> not promoted
        assert gb["promoted"] is False and Candidate.query.get(c.id).current_board == 5
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        att = _json.loads(br.range_attestation)
        assert att["real"] is True
        # approve the human technical report, then the gate promotes to board 6 (exactly once)
        br.report_status = "approved"; db.session.add(br); db.session.commit()
        g2 = client.post("/grade/submit", json={"handle": c.handle, "submission": submission}, headers=hdr)
        assert g2.get_json()["promoted"] is True
        assert Candidate.query.get(c.id).current_board == 6
    finally:
        for k, v in _saved.items():   # restore (do not clobber other suites' module-level env)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        ctx.pop()


def test_board6_mock_range_refuses_award():
    application, db, ctx = _app()
    try:
        from models import BoardResult
        client = application.test_client()
        c = _cand(db, "b6mock", 6)
        hdr = {"X-Candidate-Token": c.token}
        submission = _correct_flags(c, db, client, 6)
        g = client.post("/grade/submit", json={"handle": c.handle, "submission": submission}, headers=hdr)
        gb = g.get_json()
        assert gb["score"] >= 95.0 and gb["passed"] is False
        br = BoardResult.query.filter_by(candidate_id=c.id, board=6).first()
        assert br.objective_passed is False
        assert _json.loads(br.range_attestation)["real"] is False
    finally:
        ctx.pop()


def test_grade_ci_callback_refuses_isolated_boards():
    application, db, ctx = _app()
    _saved_ci = os.environ.get("CI_TOKEN")
    os.environ["CI_TOKEN"] = "ci-secret"
    try:
        from models import BoardResult
        client = application.test_client()
        c = _cand(db, "cici", 5)
        for board in (5, 6):
            r = client.post("/grade", json={"handle": c.handle, "board": board, "score": 100},
                            headers={"X-CI-Token": "ci-secret"})
            assert r.status_code == 409, (board, r.data)
        # no objective was recorded via the CI callback for the isolated board
        assert BoardResult.query.filter_by(candidate_id=c.id, board=5).first() is None or \
            BoardResult.query.filter_by(candidate_id=c.id, board=5).first().objective_passed is False
    finally:
        if _saved_ci is None:
            os.environ.pop("CI_TOKEN", None)
        else:
            os.environ["CI_TOKEN"] = _saved_ci
        ctx.pop()


def test_attestation_record_is_signed_and_tamper_evident():
    import strata_range_attestation as ra

    class _RR:
        is_deployed = False; status = "configured"; ludus_range_id = "r1"

    class _C:
        handle = "x"; cohort = "2026-A"
    real, rec = ra.attest(_C(), 5, _RR(), broker, cohort="2026-A")
    assert real is False and ra.verify(rec) is False      # mock posture: not a valid real attestation
    tampered = dict(rec); tampered["real"] = True
    assert ra.verify(tampered) is False                    # signature no longer matches
