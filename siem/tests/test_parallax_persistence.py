"""PARALLAX Phase 1B - durable governance / reviewer / assessment persistence (DB-backed integration).

In-process DB-backed integration tests (SQLite in-memory via the app's StaticPool). They exercise the
real ORM models, transactions, and cross-session (restart-simulated) verification. Genuine PostgreSQL
transaction/concurrency validation lives in test_parallax_persistence_pg.py (disposable PG, gated).

Covers governance, reviewer, evidence, availability, and qualification-boundary attack classes, plus
the independent flag matrix. Env vars changed by a test are restored.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1b-persist")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

from siem import assessment_contract as ac  # noqa: E402
from parallax import registry, reviewer_store, assessment_store, pathway_persistent, auditlog  # noqa: E402
from parallax import laba_assessment as LA, laba_blueprint as BP, laba_sim as sim  # noqa: E402
from parallax import pathway_qualification as PQ, governance  # noqa: E402

COHORT = "2026-A"
_FLAGS = ("RANGER_PARALLAX_QUALIFICATION_ACTIVE", "RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE",
          "REVIEWER_GITHUB_IDS")


@pytest.fixture()
def appctx():
    saved = {k: os.environ.get(k) for k in _FLAGS}
    for k in _FLAGS:
        os.environ.pop(k, None)
    import app as appmod
    from models import db
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.drop_all(); db.create_all()
    yield appmod, db
    try:
        ctx.pop()
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _seed(db):
    from models import AdminUser, Candidate
    db.session.add_all([
        AdminUser(github_id="admin-1", login="admin-1", role="reviewer"),
        AdminUser(github_id="rev-1", login="rev-1", role="reviewer"),
        AdminUser(github_id="rev-2", login="rev-2", role="reviewer"),
        AdminUser(github_id="sponsor-1", login="sponsor-1", role="sponsor"),
        Candidate(handle="gh-alice", name="A", email="a@e", cohort=COHORT, github_id="gh-alice",
                  status="active", current_board=1),
        Candidate(handle="gh-bob", name="B", email="b@e", cohort=COHORT, github_id="gh-bob",
                  status="active", current_board=1),
    ])
    db.session.commit()


def _admin(db, gid="admin-1"):
    from models import AdminUser
    return AdminUser.query.filter_by(github_id=gid).first()


def _approve(db):
    approval, _ = registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
    return approval


def _run_and_persist(db, approval, candidate_key="gh-alice", reviewer_id="rev-1", decision="pass"):
    binding = {"candidate_key": candidate_key, "cohort": COHORT, "assessment_id": "LAB-A", "attempt": 1}
    directory = reviewer_store.directory_for(db, binding)
    reviewer = {"reviewer_id": reviewer_id, "directory": directory, "decision": decision, "note": "ok",
                "rubric_scores": {"rootcause_analysis_quality": 85}}
    spec, contract, inst = LA.bind_instance(cohort=COHORT, candidate_key=candidate_key, approval=approval,
                                            authorized_admins=registry.authorized_admins(db))
    t = sim.truth(inst)
    findings = {"findings": [{"event_id": b, "classification": "unauthorized_access", "evidence": [b]}
                            for b in sorted(t["breaches"])], "analysis": "rc"}
    env = LA.run_assessment(findings, cohort=COHORT, candidate_key=candidate_key, approval=approval,
                            authorized_admins=registry.authorized_admins(db), reviewer=reviewer)
    res = assessment_store.record_assessment(db, env, candidate_key=candidate_key)
    return env, res


# --- governance ----------------------------------------------------------------------------------
def test_spec_approval_requires_authorized_admin(appctx):
    _appmod, db = appctx
    _seed(db)
    from models import AdminUser
    with pytest.raises(registry.RegistryAuthError):
        registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(),
                                     principal=AdminUser.query.filter_by(github_id="sponsor-1").first())


def test_spec_approval_idempotent_and_persists_across_restart(appctx):
    _appmod, db = appctx
    _seed(db)
    approval = _approve(db)
    from models import ParallaxApproval
    assert ParallaxApproval.query.filter_by(kind="scoring_spec").count() == 1
    registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))  # idempotent
    assert ParallaxApproval.query.filter_by(kind="scoring_spec").count() == 1
    db.session.remove()   # simulate restart: fresh session, re-read from DB
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is not None


def test_modified_blueprint_not_covered_by_prior_approval(appctx):
    _appmod, db = appctx
    _seed(db)
    _approve(db)
    bp = BP.blueprint()
    bp["decision_policy"]["rubric_threshold"] = 1.0   # material change
    assert registry.active_spec_approval(db, BP.LABA_SPEC, bp) is None


def test_revoked_approval_not_active(appctx):
    _appmod, db = appctx
    _seed(db)
    _approve(db)
    ch = governance.scoring_spec_hash(BP.LABA_SPEC, BP.blueprint())
    assert registry.revoke_spec_approval(db, principal=_admin(db), content_hash=ch, reason="t") is True
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is None
    # re-approving the identical, previously-revoked content is refused (reauthorization required)
    with pytest.raises(registry.RegistryError):
        registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))


def test_approver_authority_lapse_invalidates_active_approval(appctx):
    _appmod, db = appctx
    _seed(db)
    _approve(db)
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is not None
    from models import AdminUser
    AdminUser.query.filter_by(github_id="admin-1").delete()  # approver loses governing authority
    db.session.commit()
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is None


def test_audit_chain_records_and_verifies_and_tamper_detected(appctx):
    _appmod, db = appctx
    _seed(db)
    _approve(db)
    from models import ParallaxAuditEvent
    assert ParallaxAuditEvent.query.count() >= 1
    assert auditlog.verify_chain(db) is True
    ev = ParallaxAuditEvent.query.first()
    rec = json.loads(ev.detail_json); rec["action"] = "tampered"
    ev.detail_json = json.dumps(rec); db.session.commit()
    assert auditlog.verify_chain(db) is False


# --- reviewer ------------------------------------------------------------------------------------
def test_assign_requires_authorized_admin(appctx):
    _appmod, db = appctx
    _seed(db)
    from models import AdminUser
    with pytest.raises(registry.RegistryAuthError):
        reviewer_store.assign_reviewer(db, principal=AdminUser.query.filter_by(github_id="sponsor-1").first(),
                                       reviewer_id="rev-1", candidate_key="gh-alice", cohort=COHORT,
                                       assessment_id="LAB-A", attempt=1)


def test_ineligible_reviewer_refused(appctx):
    _appmod, db = appctx
    _seed(db)
    with pytest.raises(reviewer_store.AssignmentError):
        reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="not-a-reviewer",
                                       candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")


def test_self_review_conflict_refused(appctx):
    _appmod, db = appctx
    _seed(db)
    # make gh-alice an eligible reviewer, then try to assign them to their own assessment
    from models import AdminUser
    db.session.add(AdminUser(github_id="gh-alice", login="gh-alice", role="reviewer")); db.session.commit()
    with pytest.raises(reviewer_store.AssignmentError):
        reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="gh-alice",
                                       candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")


def test_one_active_reviewer_per_attempt(appctx):
    _appmod, db = appctx
    _seed(db)
    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                   candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")
    with pytest.raises(reviewer_store.AssignmentError):
        reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-2",
                                       candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")


def test_revoked_assignment_does_not_authorize(appctx):
    _appmod, db = appctx
    _seed(db)
    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                   candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")
    assert reviewer_store.revoke_assignment(db, principal=_admin(db), reviewer_id="rev-1",
                                            candidate_key="gh-alice", cohort=COHORT,
                                            assessment_id="LAB-A") is True
    d = reviewer_store.directory_for(db, {"candidate_key": "gh-alice", "cohort": COHORT,
                                          "assessment_id": "LAB-A", "attempt": 1})
    assert d.assigned_reviewer({"candidate_key": "gh-alice", "cohort": COHORT,
                                "assessment_id": "LAB-A", "attempt": 1}) is None


def test_reviewer_scope_isolation(appctx):
    _appmod, db = appctx
    _seed(db)
    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                   candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")
    # not authorized for a different assessment id
    d = reviewer_store.directory_for(db, {"candidate_key": "gh-alice", "cohort": COHORT,
                                          "assessment_id": "LAB-OTHER", "attempt": 1})
    assert d.assigned_reviewer({"candidate_key": "gh-alice", "cohort": COHORT,
                                "assessment_id": "LAB-OTHER", "attempt": 1}) is None


# --- evidence / assessment records ---------------------------------------------------------------
def test_record_persists_and_survives_restart(appctx):
    _appmod, db = appctx
    _seed(db)
    approval = _approve(db)
    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                   candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")
    env, res = _run_and_persist(db, approval)
    assert env["assessment_passed"] is True and env["pathway_qualified"] is False
    db.session.remove()
    rec = assessment_store.assessment_record_for(db, candidate_key="gh-alice", assessment_id="LAB-A")
    assert rec is not None and ac.verify_decision(rec["signed_decision"]) and rec["adjudication"]


def test_idempotent_record(appctx):
    _appmod, db = appctx
    _seed(db)
    approval = _approve(db)
    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                   candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")
    env, _ = _run_and_persist(db, approval)
    from models import UnitResult
    n = UnitResult.query.count()
    assessment_store.record_assessment(db, env, candidate_key="gh-alice")  # retry
    assert UnitResult.query.count() == n


def test_substitution_rejected(appctx):
    _appmod, db = appctx
    _seed(db)
    approval = _approve(db)
    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                   candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")
    env, _ = _run_and_persist(db, approval)
    with pytest.raises(assessment_store.AssessmentPersistError):
        assessment_store.record_assessment(db, env, candidate_key="gh-bob")


def test_candidate_access_control(appctx):
    _appmod, db = appctx
    _seed(db)
    with pytest.raises(assessment_store.AssessmentPersistError):
        assessment_store.records_for_candidate(db, authenticated_candidate_key="gh-bob",
                                                target_candidate_key="gh-alice")


def test_tampered_stored_decision_fails_verify(appctx):
    _appmod, db = appctx
    _seed(db)
    approval = _approve(db)
    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                   candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")
    _run_and_persist(db, approval)
    from models import UnitResult
    row = UnitResult.query.filter_by(kind="qualification_decision").first()
    rec = json.loads(row.decision_json); rec["qualified"] = True   # tamper
    row.decision_json = json.dumps(rec); db.session.commit()
    db.session.remove()
    recov = assessment_store.assessment_record_for(db, candidate_key="gh-alice", assessment_id="LAB-A")
    assert ac.verify_decision(recov["signed_decision"]) is False


# --- pathway boundary over persisted records -----------------------------------------------------
def test_no_approved_portfolio_makes_pathway_impossible_even_with_flags_on(appctx):
    _appmod, db = appctx
    _seed(db)
    approval = _approve(db)
    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                   candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")
    _run_and_persist(db, approval)
    os.environ["RANGER_PARALLAX_QUALIFICATION_ACTIVE"] = "1"
    os.environ["RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"] = "1"
    d = pathway_persistent.decide_pathway_persistent(db, candidate_key="gh-alice", cohort=COHORT)
    assert d["qualified"] is False and d["reason"] == "no_approved_portfolio_policy"


@pytest.mark.parametrize("a,b", [("0", "0"), ("1", "0"), ("0", "1"), ("1", "1")])
def test_flag_matrix_single_assessment_never_pathway(appctx, a, b):
    _appmod, db = appctx
    _seed(db)
    approval = _approve(db)
    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                   candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")
    os.environ["RANGER_PARALLAX_QUALIFICATION_ACTIVE"] = a
    os.environ["RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"] = b
    env, _ = _run_and_persist(db, approval)
    assert env["assessment_passed"] is True and env["pathway_qualified"] is False
    assert env["assessment_decision"]["qualified"] is False
    d = pathway_persistent.decide_pathway_persistent(db, candidate_key="gh-alice", cohort=COHORT)
    assert d["qualified"] is False


def test_infrastructure_unavailable_fails_closed(appctx, monkeypatch):
    _appmod, db = appctx
    _seed(db)
    monkeypatch.setattr(pathway_persistent, "active_portfolio",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))
    d = pathway_persistent.decide_pathway_persistent(db, candidate_key="gh-alice", cohort=COHORT)
    assert d["qualified"] is False and d["reason"] == "infrastructure_unavailable"
