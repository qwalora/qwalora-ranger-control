"""PARALLAX Phase 1C Workstream F - adversarial checks (demonstrated findings).

Focused, in-process (SQLite) adversarial tests for attack classes not already demonstrated in
test_parallax_persistence.py / test_parallax_signing_lifecycle.py. Authority, idempotency, revocation,
authority-lapse, audit tamper, the two-flag matrix, substitution-proof writes, and kid substitution are
covered there; this file adds cross-context signature reuse, domain separation, and transplanted
adjudication rejection.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1c-secrev")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

import signing  # noqa: E402
from parallax import registry, reviewer_store, assessment_store  # noqa: E402
from parallax import laba_assessment as LA, laba_blueprint as BP, laba_sim as sim  # noqa: E402

COHORT = "2026-A"


@pytest.fixture()
def appctx():
    saved = {k: os.environ.get(k) for k in ("RANGER_PARALLAX_QUALIFICATION_ACTIVE",
                                            "RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE")}
    for k in saved:
        os.environ.pop(k, None)
    import app as appmod
    from models import db
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.drop_all(); db.create_all()
    from models import AdminUser, Candidate
    db.session.add_all([
        AdminUser(github_id="admin-1", login="admin-1", role="reviewer"),
        AdminUser(github_id="rev-1", login="rev-1", role="reviewer"),
        Candidate(handle="gh-alice", name="A", email="a@e", cohort=COHORT, github_id="gh-alice",
                  status="active", current_board=1),
        Candidate(handle="gh-bob", name="B", email="b@e", cohort=COHORT, github_id="gh-bob",
                  status="active", current_board=1)])
    db.session.commit()
    yield appmod, db
    try:
        ctx.pop()
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _admin(db, gid="admin-1"):
    from models import AdminUser
    return AdminUser.query.filter_by(github_id=gid).first()


def test_signature_is_bound_to_its_exact_content(appctx):
    """Cross-context signature reuse: a valid signature over one record must not verify any other
    record (including a record of a different type)."""
    _a, db = appctx
    approval, row = registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
    rec, sig = approval["record"], approval["signature"]
    assert signing.verify(rec, sig) is True
    # tamper any field -> fails
    tampered = json.loads(json.dumps(rec)); tampered["competency"] = "something-else"
    assert signing.verify(tampered, sig) is False
    # reuse the approval signature on an audit-event-shaped record -> fails (domain separation by content)
    audit_shaped = {"stream": "parallax-governance", "seq": 0, "action": "approve_scoring_spec",
                    "actor_id": "admin-1", "subject_kind": "scoring_spec", "subject_ref": "x",
                    "detail": {}, "parent_hash": None}
    assert signing.verify(audit_shaped, sig) is False


def test_transplanted_adjudication_and_decision_rejected(appctx):
    """A decision/adjudication signed for candidate A cannot be persisted under candidate B."""
    _a, db = appctx
    approval, _ = registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id="rev-1",
                                   candidate_key="gh-alice", cohort=COHORT, assessment_id="LAB-A")
    binding = {"candidate_key": "gh-alice", "cohort": COHORT, "assessment_id": "LAB-A", "attempt": 1}
    directory = reviewer_store.directory_for(db, binding)
    reviewer = {"reviewer_id": "rev-1", "directory": directory, "decision": "pass", "note": "ok",
                "rubric_scores": {"rootcause_analysis_quality": 85}}
    spec, contract, inst = LA.bind_instance(cohort=COHORT, candidate_key="gh-alice", approval=approval,
                                            authorized_admins=registry.authorized_admins(db))
    t = sim.truth(inst)
    findings = {"findings": [{"event_id": b, "classification": "unauthorized_access", "evidence": [b]}
                            for b in sorted(t["breaches"])], "analysis": "rc"}
    env = LA.run_assessment(findings, cohort=COHORT, candidate_key="gh-alice", approval=approval,
                            authorized_admins=registry.authorized_admins(db), reviewer=reviewer)
    # transplant: try to persist alice's signed envelope under bob
    with pytest.raises(assessment_store.AssessmentPersistError):
        assessment_store.record_assessment(db, env, candidate_key="gh-bob")
    # the legitimate owner persists fine
    assert assessment_store.record_assessment(db, env, candidate_key="gh-alice")["decision_row"] is not None


def test_revoked_or_lapsed_governance_not_returned(appctx):
    """Stale/revoked governance artifacts are never returned as active."""
    _a, db = appctx
    approval, row = registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is not None
    # revoke -> no longer active
    registry.revoke_spec_approval(db, principal=_admin(db), content_hash=row.content_hash,
                                  reason="test")
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is None


def test_approver_authority_lapse_invalidates_approval(appctx):
    """If the approver's governing authorization lapses, the approval stops verifying as active."""
    _a, db = appctx
    registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is not None
    from models import AdminUser
    AdminUser.query.filter_by(github_id="admin-1").first().role = "viewer"   # demote the approver
    db.session.commit()
    os.environ.pop("REVIEWER_GITHUB_IDS", None)
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is None
