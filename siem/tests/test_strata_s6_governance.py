"""STRATA S6 section 14 (part 2) - boards 5/6 under the S3/S4 cohort scenario governance: catalog
registration + approval, cohort portfolios, randomized assignment, immutable pinning, materially
different worlds across two cohorts, reproducible replay, non-transfer of protected answers,
exhaustion, cross-candidate isolation, candidate-safe projection, and the governed grade path still
honoring the S6 real-range attestation gate. Offline (mock broker)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "s6gov")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("LUDUS_API_URL", None)

import pytest  # noqa: E402

import strata_catalog as cat  # noqa: E402
import strata_assignment as asn  # noqa: E402
from siem import board_variants as bv  # noqa: E402


@pytest.fixture(autouse=True)
def _env_guard():
    keys = ("RANGER_STRATA_PORTFOLIOS", "RANGER_ENV", "RANGER_S6_ATTEST_TEST")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        yield
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _app():
    import app as appmod
    from models import db, AdminUser, Cohort
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.create_all()
    for nm in ("2026-A", "2026-B"):
        if not Cohort.query.filter_by(name=nm).first():
            db.session.add(Cohort(name=nm, pathway="strata", status="active"))
    admin = AdminUser.query.filter_by(github_id="gid-admin").first()
    if admin is None:
        admin = AdminUser(github_id="gid-admin", login="alice", role="reviewer")
        db.session.add(admin)
    db.session.commit()
    for e in cat.register_all(db, boards=(5, 6)):
        cat.approve(db, e, admin)
    db.session.commit()
    return application, db, ctx, admin


def _cand(db, handle, cohort, board):
    from models import Candidate
    c = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort=cohort,
                  github_id=f"g-{handle}", status="active", current_board=board, token=f"tok-{handle}")
    db.session.add(c); db.session.commit()
    return c


def test_board5_two_cohorts_materially_diverse_and_non_transfer():
    application, db, ctx, admin = _app()
    try:
        fams5 = bv.variants_for(5)
        # two cohorts with different (overlapping) board-5 portfolios
        asn.set_cohort_portfolio(db, "2026-A", 5, fams5[:2], admin=admin)
        asn.set_cohort_portfolio(db, "2026-B", 5, fams5[1:], admin=admin)
        ca = _cand(db, "g5a", "2026-A", 5)
        cb = _cand(db, "g5b", "2026-B", 5)
        ba = asn.assign(db, ca, 5, cohort="2026-A",
                        portfolio=asn.resolve_portfolio(db, "2026-A", 5, required=True),
                        require_portfolio=True)
        bb = asn.assign(db, cb, 5, cohort="2026-B",
                        portfolio=asn.resolve_portfolio(db, "2026-B", 5, required=True),
                        require_portfolio=True)
        # cross-candidate isolation: distinct pinned seeds
        assert ba.seed != bb.seed
        wa = asn.generate(ba)
        wb = asn.generate(bb)
        # candidate-safe projection carries no protected flags
        va = asn.candidate_view(ba, wa)
        assert "_flags" not in va and "_flags" not in str(va)
        # reproducible replay: regenerating the binding yields the identical world
        assert asn.generate(ba) == wa
        # the reference-correct submission grades at/above the bar
        sa, _ = asn.grade(ba, {"flags": dict(wa["_flags"])})
        assert sa >= 95.0
        # non-transfer: candidate A's captured flags do not grade candidate B's world
        cross, _ = asn.grade(bb, {"flags": dict(wa["_flags"])})
        assert cross < 95.0, "one candidate's flags must not satisfy another's pinned world"
    finally:
        ctx.pop()


def test_board6_capstone_governed_and_distinct_from_board5():
    application, db, ctx, admin = _app()
    try:
        asn.set_cohort_portfolio(db, "2026-A", 6, bv.variants_for(6)[:2], admin=admin)
        c = _cand(db, "g6a", "2026-A", 6)
        b = asn.assign(db, c, 6, cohort="2026-A",
                       portfolio=asn.resolve_portfolio(db, "2026-A", 6, required=True),
                       require_portfolio=True)
        w = asn.generate(b)
        assert w["board"] == 6 and w["targets"]["trust_topology"] is not None
        full, _ = asn.grade(b, {"flags": dict(w["_flags"])})
        assert full >= 95.0
        # a board-6 world is structurally a capstone (multi-forest objectives), not board 5
        assert any(o["id"] in ("trust_abuse", "cross_forest", "forest_persist") for o in w["objectives"])
    finally:
        ctx.pop()


def test_assignment_exhaustion_fails_closed():
    application, db, ctx, admin = _app()
    try:
        # a one-family portfolio: a second attempt cannot repeat the only variant -> exhausted
        asn.set_cohort_portfolio(db, "2026-A", 5, [bv.variants_for(5)[0]], admin=admin)
        c = _cand(db, "g5x", "2026-A", 5)
        pf = asn.resolve_portfolio(db, "2026-A", 5, required=True)
        asn.assign(db, c, 5, cohort="2026-A", attempt=1, portfolio=pf, require_portfolio=True)
        with pytest.raises(asn.AssignmentExhausted):
            asn.assign(db, c, 5, cohort="2026-A", attempt=2, portfolio=pf, require_portfolio=True)
    finally:
        ctx.pop()


def test_governed_grade_submit_still_honors_attestation_gate():
    # Portfolios ON routes board 5 through the binding grader, which must STILL pass through the S6
    # attestation gate: a correct submission against a mock range earns no objective.
    application, db, ctx, admin = _app()
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    try:
        from models import BoardResult, Candidate
        asn.set_cohort_portfolio(db, "2026-A", 5, bv.variants_for(5)[:2], admin=admin)
        c = _cand(db, "g5http", "2026-A", 5)
        client = application.test_client()
        hdr = {"X-Candidate-Token": c.token}
        # opening the dataset binds the attempt
        r = client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr)
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert "_flags" not in str(body) and body.get("case_ref")
        from models import ScenarioBinding
        b = ScenarioBinding.query.filter_by(candidate_id=c.id, board=5).first()
        world = asn.generate(b)
        g = client.post("/grade/submit", json={"handle": c.handle,
                        "submission": {"flags": dict(world["_flags"])}}, headers=hdr)
        gb = g.get_json()
        assert gb["score"] >= 95.0 and gb["passed"] is False and gb["promoted"] is False
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        assert br.objective_passed is False   # mock range -> no credit even with correct flags
        assert Candidate.query.get(c.id).current_board == 5
    finally:
        ctx.pop()
