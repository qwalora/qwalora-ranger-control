"""PARALLAX Phase 1B - GENUINE PostgreSQL transaction/concurrency validation.

Runs only against an explicitly authorized, disposable local PostgreSQL (via siem/tests/_pgtest.py):
it creates a throwaway database, exercises the real ORM + transactions + advisory locks under
concurrent threads, and drops the database afterward. SKIPS (never touches production) when the
authorized disposable server is not configured - that skip is reported, not silently mocked.
"""
import os
import sys
import threading
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1b-pg")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

import _pgtest  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)

COHORT = "2026-A"


def _seed(db):
    from models import AdminUser, Candidate
    db.session.add_all([
        AdminUser(github_id="admin-1", login="admin-1", role="reviewer"),
        AdminUser(github_id="rev-1", login="rev-1", role="reviewer"),
        AdminUser(github_id="rev-2", login="rev-2", role="reviewer"),
        Candidate(handle="gh-alice", name="A", email="a@e", cohort=COHORT, github_id="gh-alice",
                  status="active", current_board=1),
    ])
    db.session.commit()


def _admin(db):
    from models import AdminUser
    return AdminUser.query.filter_by(github_id="admin-1").first()


def _race(application, fn, n=6):
    barrier = threading.Barrier(n)
    results = [None] * n

    def work(i):
        rec = {"error": None, "val": None}
        try:
            with application.app_context():
                barrier.wait()
                rec["val"] = fn()
        except BaseException:  # noqa: BLE001
            rec["error"] = traceback.format_exc()
        results[i] = rec

    ts = [threading.Thread(target=work, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return results


def test_pg_persistence_transactions_and_concurrency():
    from parallax import registry, reviewer_store, assessment_store, pathway_persistent, auditlog
    from parallax import laba_assessment as LA, laba_blueprint as BP, laba_sim as sim
    from siem import assessment_contract as ac

    with _pgtest.isolated_pg_database():
        import importlib
        import app as appmod
        importlib.reload(appmod)  # rebind the engine to the freshly-set disposable DATABASE_URL
        from models import db, ParallaxApproval, ParallaxReviewerAssignment, UnitResult
        application = appmod.create_app()
        with application.app_context():
            assert db.engine.dialect.name == "postgresql"   # prove this is REAL PostgreSQL
            db.create_all()
            _seed(db)

        # --- governance idempotency under concurrency: many racers, exactly one approval row ------
        res = _race(application, lambda: registry.store_spec_approval(
            db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))[1].content_hash)
        assert all(r["error"] is None for r in res), [r["error"] for r in res if r["error"]]
        with application.app_context():
            assert ParallaxApproval.query.filter_by(kind="scoring_spec").count() == 1
            approval = registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint())
            assert approval is not None
            reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                           candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")

        # build ONE signed assessment envelope single-threaded
        with application.app_context():
            binding = {"candidate_key": "gh-alice", "cohort": COHORT, "assessment_id": "LAB-A", "attempt": 1}
            directory = reviewer_store.directory_for(db, binding)
            reviewer = {"reviewer_id": "rev-1", "directory": directory, "decision": "pass", "note": "ok",
                        "rubric_scores": {"rootcause_analysis_quality": 85}}
            spec, contract, inst = LA.bind_instance(cohort=COHORT, candidate_key="gh-alice",
                                                    approval=approval,
                                                    authorized_admins=registry.authorized_admins(db))
            t = sim.truth(inst)
            findings = {"findings": [{"event_id": b, "classification": "unauthorized_access",
                                      "evidence": [b]} for b in sorted(t["breaches"])], "analysis": "rc"}
            env = LA.run_assessment(findings, cohort=COHORT, candidate_key="gh-alice", approval=approval,
                                    authorized_admins=registry.authorized_admins(db), reviewer=reviewer)

        # --- assessment-record idempotency under concurrency: exactly one decision row ------------
        res2 = _race(application, lambda: assessment_store.record_assessment(
            db, env, candidate_key="gh-alice")["decision_row"].record_hash)
        assert all(r["error"] is None for r in res2), [r["error"] for r in res2 if r["error"]]
        with application.app_context():
            assert UnitResult.query.filter_by(kind="qualification_decision").count() == 1

        # --- reviewer-assignment race: two different reviewers, exactly one active assignment -----
        def _assign(rid):
            def fn():
                try:
                    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id=rid,
                                                   candidate_key="gh-alice", cohort=COHORT,
                                                   assessment_id="LAB-B")
                    return "ok"
                except reviewer_store.AssignmentError:
                    return "refused"
            return fn
        # revoke-free fresh attempt LAB-B; race rev-1 vs rev-2
        barrier = threading.Barrier(2)
        out = {}

        def w(rid):
            with application.app_context():
                barrier.wait()
                try:
                    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id=rid,
                                                   candidate_key="gh-alice", cohort=COHORT,
                                                   assessment_id="LAB-B")
                    out[rid] = "ok"
                except Exception as e:  # noqa: BLE001
                    out[rid] = type(e).__name__
        th = [threading.Thread(target=w, args=(r,)) for r in ("rev-1", "rev-2")]
        for x in th:
            x.start()
        for x in th:
            x.join()
        with application.app_context():
            active = ParallaxReviewerAssignment.query.filter_by(assessment_id="LAB-B",
                                                                status="active").count()
            assert active == 1, (active, out)

        # --- restart-after-commit: reconnect and re-verify persisted signatures -------------------
        with application.app_context():
            db.session.remove()
            assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is not None
            rec = assessment_store.assessment_record_for(db, candidate_key="gh-alice",
                                                         assessment_id="LAB-A")
            assert rec is not None and ac.verify_decision(rec["signed_decision"])
            assert auditlog.verify_chain(db) is True
            # no approved portfolio -> pathway impossible even here
            d = pathway_persistent.decide_pathway_persistent(db, candidate_key="gh-alice", cohort=COHORT)
            assert d["qualified"] is False and d["reason"] == "no_approved_portfolio_policy"
