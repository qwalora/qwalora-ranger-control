"""Tests for the operator-run PARALLAX Research Review acceptance fixture (scripts/px_review_fixture.py)
on GENUINE PostgreSQL. Covers identity collision, duplicate execution, partial-failure recovery,
reviewer-role exclusion, signature integrity, and protected-record isolation. Disposable DB, isolated
identities. SKIPS without the authorized disposable PostgreSQL.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

os.environ.setdefault("SECRET_KEY", "px-fixture-pg")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402
import _pgtest  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)

import px_review_fixture as fx  # noqa: E402


@pytest.fixture()
def ctx():
    saved = {k: os.environ.get(k) for k in ("RANGER_PARALLAX_LABA", "RANGER_PARALLAX_LABA_ENV",
                                            "REVIEWER_GITHUB_IDS")}
    os.environ["RANGER_PARALLAX_LABA"] = "1"
    os.environ["RANGER_PARALLAX_LABA_ENV"] = "test"
    os.environ.pop("REVIEWER_GITHUB_IDS", None)
    for m in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
        os.environ.pop(m, None)
    with _pgtest.isolated_pg_database():
        import importlib
        import app as appmod
        importlib.reload(appmod)
        from models import db
        application = appmod.create_app()
        appctx = application.app_context()
        appctx.push()
        db.create_all()
        yield application, db
        appctx.pop()
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _counts(ParallaxResearchRun):
    tr = ParallaxResearchRun.query.filter(
        ParallaxResearchRun.run_record.contains('"kind":"trial"')).filter(
        ParallaxResearchRun.run_record.contains(fx.FIXTURE_LABEL)).count()
    iv = ParallaxResearchRun.query.filter(
        ParallaxResearchRun.run_record.contains('"kind":"investigation"')).filter(
        ParallaxResearchRun.run_record.contains(fx.FIXTURE_LABEL)).count()
    return tr, iv


def test_happy_path_ready_and_pending(ctx):
    _app, db = ctx
    res = fx.ensure_fixture(db)
    assert res["ready"] and res["created_investigation"] is True
    assert res["is_admin"] is False and res["is_reviewer"] is False and res["program"] == "parallax"
    assert res["evidence_provenance"] == "simulated" and res["evidence_is_empirical"] is False
    assert res["investigation_signature_verifies"] and res["evidence_signature_verifies"]
    assert res["evidence_owner_matches"] and res["status"] == "pending"
    assert res["appears_in_pending_queue"] is True
    assert res["qualification_decisions_total"] == 0
    # fixture identity is PARALLAX-only, not admin, and collision-proof (colon id)
    from models import ProgramMembership, Candidate, AdminUser
    c = Candidate.query.filter_by(github_id=fx.FIXTURE_GID).first()
    assert ":" in c.github_id
    assert {m.program for m in ProgramMembership.query.filter_by(candidate_id=c.id).all()} == {"parallax"}
    assert AdminUser.query.filter_by(github_id=fx.FIXTURE_GID).first() is None


def test_identity_collision_does_not_touch_real_account(ctx):
    _app, db = ctx
    from models import Candidate
    real = Candidate(handle="realuser", name="Real", email="r@e", cohort="2026-A",
                     github_id="realuser", status="active", current_board=2)
    db.session.add(real); db.session.commit()
    res = fx.ensure_fixture(db)
    assert res["fixture_researcher_github_id"] == fx.FIXTURE_GID
    after = Candidate.query.filter_by(github_id="realuser").first()
    assert after.current_board == 2 and after.status == "active"  # untouched


def test_duplicate_execution_is_idempotent(ctx):
    _app, db = ctx
    from models import ParallaxResearchRun
    r1 = fx.ensure_fixture(db)
    r2 = fx.ensure_fixture(db)
    assert r2["created_investigation"] is False
    assert r1["investigation_id"] == r2["investigation_id"]
    assert _counts(ParallaxResearchRun) == (1, 1)   # exactly one trial + one investigation


def test_partial_failure_recovers_orphan_trial(ctx):
    _app, db = ctx
    from models import ParallaxResearchRun, Candidate, ProgramMembership
    from parallax.research import store as rstore
    # simulate an interrupted prior run: fixture candidate + a fixture TRIAL only (no investigation)
    c = Candidate(handle=fx.FIXTURE_HANDLE, name=fx.FIXTURE_NAME, email="x@nonprod.invalid",
                  cohort="2026-A", github_id=fx.FIXTURE_GID, status="active", current_board=1)
    db.session.add(c); db.session.commit()
    db.session.add(ProgramMembership(candidate_id=c.id, program="parallax", status="active",
                                     cohort="2026-A")); db.session.commit()
    orphan = rstore.persist_run(db, researcher_id=fx.FIXTURE_GID, campaign={
        "manifest": {"kind": "trial", "backend": {"is_real": False, "model_id": "stub"},
                     "n_records": 1, "fixture": fx.FIXTURE_LABEL},
        "metrics": {"kind": "trial", "record": {"condition": "experimental_attack",
                    "model": {"id": "stub"}, "observed_behavior": "INJECTION-OK",
                    "evaluation": {"canary": True, "task_ok": False},
                    "outcome": "successful_unauthorized_behavior"}, "fixture": fx.FIXTURE_LABEL}})
    db.session.commit()
    res = fx.ensure_fixture(db)
    assert res["created_investigation"] is True
    assert res["evidence_run_id"] == orphan.run_id       # reused the orphan, did NOT make a new trial
    assert _counts(ParallaxResearchRun) == (1, 1)


def test_reviewer_role_exclusion(ctx):
    _app, db = ctx
    with pytest.raises(fx.FixtureError) as ei:
        fx.ensure_fixture(db, reviewer_ids={fx.FIXTURE_GID})
    assert ei.value.code == "is_reviewer"


def test_inactive_fixture_is_not_reactivated(ctx):
    _app, db = ctx
    from models import Candidate
    c = Candidate(handle=fx.FIXTURE_HANDLE, name=fx.FIXTURE_NAME, email="x@nonprod.invalid",
                  cohort="2026-A", github_id=fx.FIXTURE_GID, status="suspended", current_board=1)
    db.session.add(c); db.session.commit()
    with pytest.raises(fx.FixtureError) as ei:
        fx.ensure_fixture(db)
    assert ei.value.code == "fixture_inactive"
    assert Candidate.query.filter_by(github_id=fx.FIXTURE_GID).first().status == "suspended"  # untouched


def test_signature_integrity_ready_gate(ctx):
    _app, db = ctx
    from models import ParallaxResearchRun
    res = fx.ensure_fixture(db)
    inv_id = res["investigation_id"]
    # tamper the fixture investigation bytes (signature no longer valid)
    row = ParallaxResearchRun.query.filter_by(run_id=inv_id).first()
    rec = json.loads(row.run_record)
    rec["metrics"]["analysis"] = rec["metrics"]["analysis"] + " [TAMPERED]"
    row.run_record = json.dumps(rec, separators=(",", ":"))  # compact, so idempotency still finds it
    db.session.commit()
    # a re-run reuses the (now-tampered) investigation; the ready-gate must refuse
    with pytest.raises(fx.FixtureError) as ei:
        fx.ensure_fixture(db)
    assert ei.value.code == "sig_investigation"


def test_protected_records_isolation(ctx):
    _app, db = ctx
    from models import ParallaxResearchRun
    from parallax.research import store as rstore
    # pre-seed two records with the PROTECTED ids (distinct owner) and snapshot them
    for pid in fx.PROTECTED_RECORDS:
        rstore.persist_run(db, researcher_id="gh-live-owner", campaign={
            "manifest": {"kind": "trial", "backend": {"is_real": True, "model_id": "qwen"},
                         "n_records": 1},
            "metrics": {"kind": "trial", "record": {"condition": "baseline_benign",
                        "observed_behavior": "benign"}}})
    # rename two arbitrary rows to the protected ids to simulate their presence
    rows = ParallaxResearchRun.query.order_by(ParallaxResearchRun.id).limit(2).all()
    for row, pid in zip(rows, fx.PROTECTED_RECORDS):
        row.run_id = pid
    db.session.commit()
    before = {pid: (r.run_record, r.signature, r.record_hash)
              for pid in fx.PROTECTED_RECORDS
              for r in [ParallaxResearchRun.query.filter_by(run_id=pid).first()]}
    res = fx.ensure_fixture(db)
    assert res["protected_records_unchanged"] is True
    for pid in fx.PROTECTED_RECORDS:
        r = ParallaxResearchRun.query.filter_by(run_id=pid).first()
        assert (r.run_record, r.signature, r.record_hash) == before[pid]
