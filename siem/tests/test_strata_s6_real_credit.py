"""STRATA S6 §4 (post-closure) - a REAL (production) isolated-range objective credits ONLY under
scenario governance with a valid, approved binding.

MODE_REAL is unreachable offline by design (the §2 probe fails closed without a live, adapter-verified
host and a guest probe). To exercise the governance gate itself, these tests FORCE a real posture by
pointing the broker at a live URL and monkeypatching technical_validation to pass - a test double, not
a live range - and then assert that credit is granted ONLY when governance + an approved binding are
present. The offline test_fixture path is covered elsewhere and is inert outside test/ci, so it is
never a production bypass.
"""
import json as _json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "s6rc")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

import pytest  # noqa: E402

from _s6util import expiring_client  # noqa: E402
import strata_range_attestation as ra  # noqa: E402
import strata_assignment as asn  # noqa: E402
from siem import board_variants as bv  # noqa: E402


@pytest.fixture(autouse=True)
def _guard(monkeypatch):
    keys = ("RANGER_STRATA_PORTFOLIOS", "LUDUS_API_URL", "LUDUS_ADAPTER_VERIFIED",
            "RANGER_ENV", "RANGER_S6_ATTEST_TEST")
    saved = {k: os.environ.get(k) for k in keys}
    # Force a REAL posture: a live broker URL + a technical_validation that passes (a test double).
    os.environ["LUDUS_API_URL"] = "https://ludus.invalid"
    os.environ["LUDUS_ADAPTER_VERIFIED"] = "1"
    os.environ.pop("RANGER_ENV", None)
    os.environ.pop("RANGER_S6_ATTEST_TEST", None)
    monkeypatch.setattr(ra, "technical_validation",
                        lambda *a, **k: {"passed": True, "simulated": False, "checks": {},
                                         "observed_vms": [], "reason": "forced-real (test double)"})
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


def _catalog(db, application, board):
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


def _bind_and_submit(appmod, application, db, c, *, portfolios):
    """Open the dataset (binds under governance) and submit correct flags. Returns the BoardResult."""
    from models import AdminUser, BoardResult, ScenarioBinding
    client = expiring_client(application, db)
    hdr = {"X-Candidate-Token": c.token}
    if portfolios:
        _catalog(db, application, 5)
        asn.set_cohort_portfolio(db, "2026-A", 5, bv.variants_for(5)[:2],
                                 admin=AdminUser.query.filter_by(github_id="gid-admin").first())
    r = client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr)
    assert r.status_code == 200, r.data
    if portfolios:
        b = ScenarioBinding.query.filter_by(candidate_id=c.id, board=5).first()
        sub = {"flags": dict(asn.generate(b)["_flags"])}
    else:
        import scenarios as sc
        from models import ScenarioAssignment
        a = (ScenarioAssignment.query.filter_by(github_id=c.github_id, board=5, cohort=c.cohort)
             .order_by(ScenarioAssignment.id.desc()).first())
        sub = {"flags": sc.flags_for_board(5, a.seed)}
    client.post("/grade/submit", json={"handle": c.handle, "submission": sub}, headers=hdr)
    return BoardResult.query.filter_by(candidate_id=c.id, board=5).first()


def test_real_credit_requires_governance_denied_without_portfolios():
    os.environ.pop("RANGER_STRATA_PORTFOLIOS", None)  # portfolios OFF -> legacy seed path
    appmod, application, db, ctx = _app()
    try:
        c = _cand(db, "rc_nogov")
        br = _bind_and_submit(appmod, application, db, c, portfolios=False)
        att = _json.loads(br.range_attestation)
        assert att["mode"] == ra.MODE_REAL, "test harness must produce a REAL posture"
        assert br.objective_passed is False, "a real range must NOT credit without governance"
    finally:
        ctx.pop()


def test_real_credit_granted_under_governance_with_approved_binding():
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        c = _cand(db, "rc_gov")
        br = _bind_and_submit(appmod, application, db, c, portfolios=True)
        att = _json.loads(br.range_attestation)
        assert att["mode"] == ra.MODE_REAL
        assert br.objective_passed is True, "a real range under governance with an approved binding credits"
    finally:
        ctx.pop()


def test_real_credit_denied_when_binding_revoked():
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod, application, db, ctx = _app()
    try:
        from models import AdminUser, ScenarioBinding, ScenarioCatalogEntry
        c = _cand(db, "rc_revoked")
        client = expiring_client(application, db)
        hdr = {"X-Candidate-Token": c.token}
        _catalog(db, application, 5)
        asn.set_cohort_portfolio(db, "2026-A", 5, bv.variants_for(5)[:2],
                                 admin=AdminUser.query.filter_by(github_id="gid-admin").first())
        assert client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr).status_code == 200
        b = ScenarioBinding.query.filter_by(candidate_id=c.id, board=5).first()
        # revoke the APPROVED catalog entry the binding points at -> no longer an approved scenario
        entry = ScenarioCatalogEntry.query.filter_by(spec_id=b.spec_id, content_hash=b.content_hash).first()
        entry.status = "revoked"
        db.session.commit()
        sub = {"flags": dict(asn.generate(b)["_flags"])}
        client.post("/grade/submit", json={"handle": c.handle, "submission": sub}, headers=hdr)
        from models import BoardResult
        br = BoardResult.query.filter_by(candidate_id=c.id, board=5).first()
        assert _json.loads(br.range_attestation)["mode"] == ra.MODE_REAL
        assert br.objective_passed is False, "a revoked/unapproved binding must not credit a real range"
    finally:
        ctx.pop()
