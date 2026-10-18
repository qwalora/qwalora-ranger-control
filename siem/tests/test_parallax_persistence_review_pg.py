"""PARALLAX Phase 1D Workstream E - persistence integrity review on GENUINE PostgreSQL.

Complements the 1B/1C PG suites (single-operation races, restart, rollback, recovery) with the
cross-operation concern the review calls out: the subject->stream advisory-lock ORDERING must be
deadlock-free when DIFFERENT governance operations run concurrently, and consequential verification
must never return a torn/revoked artifact as active. Gated by _pgtest (skips fail-closed).
"""
import importlib
import os
import sys
import threading
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1d-persist-review")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

import _pgtest  # noqa: E402
from parallax import registry, reviewer_store, assessment_store, auditlog  # noqa: E402
from parallax import laba_assessment as LA, laba_blueprint as BP, laba_sim as sim  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)
COHORT = "2026-A"


def _fresh_app():
    import app as appmod
    importlib.reload(appmod)
    from models import db
    return appmod, appmod.create_app(), db


def _seed(db):
    from models import AdminUser, Candidate
    db.session.add_all([
        AdminUser(github_id="admin-1", login="admin-1", role="reviewer"),
        AdminUser(github_id="rev-1", login="rev-1", role="reviewer"),
        AdminUser(github_id="rev-2", login="rev-2", role="reviewer"),
        Candidate(handle="gh-alice", name="A", email="a@e", cohort=COHORT, github_id="gh-alice",
                  status="active", current_board=1),
        Candidate(handle="gh-bob", name="B", email="b@e", cohort=COHORT, github_id="gh-bob",
                  status="active", current_board=1)])
    db.session.commit()


def _admin(db, gid="admin-1"):
    from models import AdminUser
    return AdminUser.query.filter_by(github_id=gid).first()


def _run(application, fns):
    """Run fns concurrently (each in its own app context); return list of per-thread exceptions."""
    n = len(fns)
    barrier = threading.Barrier(n)
    errs = [None] * n

    def work(i, fn):
        try:
            with application.app_context():
                barrier.wait()
                fn()
        except BaseException:  # noqa: BLE001
            errs[i] = traceback.format_exc()
    ts = [threading.Thread(target=work, args=(i, fn)) for i, fn in enumerate(fns)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=60)
    assert not any(t.is_alive() for t in ts), "a worker did not finish (possible deadlock)"
    return errs


def _envelope(db, approval, candidate_key):
    binding = {"candidate_key": candidate_key, "cohort": COHORT, "assessment_id": "LAB-A", "attempt": 1}
    directory = reviewer_store.directory_for(db, binding)
    reviewer = {"reviewer_id": "rev-1", "directory": directory, "decision": "pass", "note": "ok",
                "rubric_scores": {"rootcause_analysis_quality": 85}}
    spec, contract, inst = LA.bind_instance(cohort=COHORT, candidate_key=candidate_key, approval=approval,
                                            authorized_admins=registry.authorized_admins(db))
    t = sim.truth(inst)
    findings = {"findings": [{"event_id": b, "classification": "unauthorized_access", "evidence": [b]}
                            for b in sorted(t["breaches"])], "analysis": "rc"}
    return LA.run_assessment(findings, cohort=COHORT, candidate_key=candidate_key, approval=approval,
                             authorized_admins=registry.authorized_admins(db), reviewer=reviewer)


def test_mixed_operation_concurrency_is_deadlock_free_and_invariants_hold():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            assert db.engine.dialect.name == "postgresql"
            db.create_all(); _seed(db)
            approval, _ = registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(),
                                                       principal=_admin(db))
            reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                           candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")
            reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                           candidate_key="gh-bob", cohort=COHORT, assessment_id="LAB-A")
            env_alice = _envelope(db, approval, "gh-alice")
            env_bob = _envelope(db, approval, "gh-bob")

        # Different operation types, different subject locks, all contending for the one audit-stream
        # lock - exercises the subject->stream ordering for deadlock freedom.
        fns = [
            lambda: registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db)),
            lambda: registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db)),
            lambda: assessment_store.record_assessment(db, env_alice, candidate_key="gh-alice"),
            lambda: assessment_store.record_assessment(db, env_bob, candidate_key="gh-bob"),
            lambda: _assign_safe(db, "rev-1", "LAB-B"),
            lambda: _assign_safe(db, "rev-2", "LAB-B"),
        ]
        errs = _run(application, fns)
        assert all(e is None for e in errs), [e for e in errs if e]
        with application.app_context():
            from models import ParallaxApproval, ParallaxReviewerAssignment, UnitResult
            assert ParallaxApproval.query.filter_by(kind="scoring_spec").count() == 1
            assert UnitResult.query.filter_by(kind="qualification_decision").count() == 2  # alice + bob
            assert ParallaxReviewerAssignment.query.filter_by(assessment_id="LAB-B",
                                                              status="active").count() == 1
            assert auditlog.verify_chain(db) is True


def _assign_safe(db, reviewer_id, assessment_id):
    try:
        reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id=reviewer_id,
                                       candidate_key="gh-alice", cohort=COHORT, assessment_id=assessment_id)
    except reviewer_store.AssignmentError:
        pass   # losing the one-active-per-attempt race is a correct outcome, not an error


def test_concurrent_revoke_and_verify_never_returns_torn_artifact():
    with _pgtest.isolated_pg_database():
        _appmod, application, db = _fresh_app()
        with application.app_context():
            db.create_all(); _seed(db)
            _, row = registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
            content_hash = row.content_hash
        results = []

        def revoker():
            with application.app_context():
                registry.revoke_spec_approval(db, principal=_admin(db), content_hash=content_hash,
                                              reason="race")

        def verifier():
            with application.app_context():
                for _ in range(20):
                    a = registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint())
                    # must be EITHER a signature-valid active approval OR None - never a torn record
                    if a is not None:
                        import signing
                        results.append(signing.verify(a["record"], a["signature"]))
        ts = [threading.Thread(target=verifier) for _ in range(3)] + [threading.Thread(target=revoker)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=60)
        assert all(results) if results else True            # every non-None read verified
        with application.app_context():
            assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is None  # ends revoked
            assert auditlog.verify_chain(db) is True
