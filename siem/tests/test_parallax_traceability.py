"""PARALLAX Phase 1E Workstream C - traceability verifier four-state verdicts and integrity cases.

Exercises VALID / INVALID / INCOMPLETE / UNAVAILABLE directly, and the integrity adversarial cases a
status route must never paper over (tampered decision, missing governance, single-assessment-qualified
guard). In-process SQLite; the HTTP lifecycle is covered in test_parallax_lifecycle_e2e.py.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1e-trace")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["DEFAULT_COHORT"] = "2026-A"

import pytest  # noqa: E402

from parallax import registry, reviewer_store, assessment_store as S, review as R, traceability as T
from parallax import laba_assessment as LA, laba_blueprint as BP, laba_sim as sim  # noqa: E402

COHORT = "2026-A"


@pytest.fixture()
def ctx():
    import app as appmod
    from models import db, AdminUser, Candidate
    application = appmod.create_app()
    c = application.app_context(); c.push()
    db.drop_all(); db.create_all()
    db.session.add_all([
        AdminUser(github_id="admin-1", login="admin-1", role="reviewer"),
        AdminUser(github_id="rev-1", login="rev-1", role="reviewer"),
        Candidate(handle="gh-alice", name="A", email="a@e", cohort=COHORT, github_id="gh-alice",
                  status="active", current_board=1)])
    db.session.commit()
    yield appmod, db
    c.pop()


def _admin(db):
    from models import AdminUser
    return AdminUser.query.filter_by(github_id="admin-1").first()


def _approve(db):
    registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
    return registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint())


def _submit(db, approval, candidate_key="gh-alice"):
    admins = registry.authorized_admins(db)
    spec, con, inst = LA.bind_instance(cohort=COHORT, candidate_key=candidate_key, approval=approval,
                                       authorized_admins=admins)
    t = sim.truth(inst)
    sub = {"findings": [{"event_id": b, "classification": "unauthorized_access", "evidence": [b]}
                        for b in sorted(t["breaches"])], "analysis": "rc"}
    env = LA.run_assessment(sub, cohort=COHORT, candidate_key=candidate_key, approval=approval,
                            authorized_admins=admins, reviewer=None)
    S.record_assessment(db, env, candidate_key=candidate_key)


def _adjudicate(db, candidate_key="gh-alice", reviewer_id="rev-1", decision="pass"):
    reviewer_store.assign_reviewer(db, principal=_admin(db), reviewer_id=reviewer_id,
                                   candidate_key=candidate_key, cohort=COHORT, assessment_id="LAB-A")
    rec = S.assessment_record_for(db, candidate_key=candidate_key, assessment_id="LAB-A")
    prov = ((rec["signed_decision"]["record"].get("decision") or {}).get("provenance") or {})
    directory = reviewer_store.directory_for(db, prov["binding"])
    adj = R.make_adjudication(reviewer_id=reviewer_id, directory=directory, binding=prov["binding"],
                              assessment_record_hash=prov["provenance_hash"], decision=decision,
                              rubric_scores={d["dimension"]: 95 for d in BP.blueprint()["rubric_dimensions"]})
    S.record_assessment(db, {"signed": rec["signed_decision"], "adjudication": adj},
                        candidate_key=candidate_key)


def test_incomplete_when_no_record(ctx):
    _a, db = ctx
    _approve(db)
    r = T.verify_assessment(db, candidate_key="gh-alice", assessment_id="LAB-A")
    assert r["verdict"] == "INCOMPLETE" and r["reason"] == "no_assessment_record"
    assert r["disposition"]["qualified"] is False


def test_incomplete_when_no_governance_approval(ctx):
    _a, db = ctx
    ap = _approve(db)
    _submit(db, ap)
    # revoke the governing approval -> no active approval -> INCOMPLETE (never silently VALID)
    from models import ParallaxApproval
    row = ParallaxApproval.query.filter_by(kind="scoring_spec").first()
    registry.revoke_spec_approval(db, principal=_admin(db), content_hash=row.content_hash, reason="t")
    r = T.verify_assessment(db, candidate_key="gh-alice", assessment_id="LAB-A")
    assert r["verdict"] == "INCOMPLETE" and r["reason"] == "no_active_governance_approval"


def test_valid_awaiting_review_then_met(ctx):
    _a, db = ctx
    ap = _approve(db)
    _submit(db, ap)
    r = T.verify_assessment(db, candidate_key="gh-alice", assessment_id="LAB-A")
    assert r["verdict"] == "VALID" and r["disposition"]["awaiting_review"] is True
    assert r["disposition"]["requirements_met"] is False and r["disposition"]["qualified"] is False
    _adjudicate(db, decision="pass")
    r = T.verify_assessment(db, candidate_key="gh-alice", assessment_id="LAB-A")
    assert r["verdict"] == "VALID" and r["disposition"]["requirements_met"] is True
    assert r["disposition"]["qualified"] is False
    # full field reconstruction present
    f = r["fields"]
    for k in ("assessment_version", "cohort", "attempt", "contract_mac", "blueprint_hash",
              "evidence_provenance", "evaluator", "scoring_result", "decision_signing_kid",
              "reviewer", "audit"):
        assert k in f, k


def test_reviewer_fail_keeps_requirements_unmet(ctx):
    _a, db = ctx
    ap = _approve(db)
    _submit(db, ap)
    _adjudicate(db, decision="fail")
    r = T.verify_assessment(db, candidate_key="gh-alice", assessment_id="LAB-A")
    assert r["verdict"] == "VALID" and r["disposition"]["requirements_met"] is False
    assert r["disposition"]["reviewer_pass"] is False and r["disposition"]["qualified"] is False


def test_invalid_on_tampered_decision(ctx):
    _a, db = ctx
    ap = _approve(db)
    _submit(db, ap)
    from models import UnitResult
    dec = UnitResult.query.filter_by(kind="qualification_decision").first()
    rec = json.loads(dec.decision_json)
    rec["decision"]["assessment_outcome"] = "met"      # tamper: flip outcome without re-signing
    dec.decision_json = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    db.session.commit()
    r = T.verify_assessment(db, candidate_key="gh-alice", assessment_id="LAB-A")
    assert r["verdict"] == "INVALID" and r["reason"] == "decision_signature_invalid"


def test_invalid_on_broken_audit_chain(ctx):
    _a, db = ctx
    ap = _approve(db); _submit(db, ap)
    from models import ParallaxAuditEvent
    ev = ParallaxAuditEvent.query.order_by(ParallaxAuditEvent.seq.asc()).first()
    ev.record_hash = "0" * 64; db.session.commit()
    r = T.verify_assessment(db, candidate_key="gh-alice", assessment_id="LAB-A")
    assert r["verdict"] == "INVALID" and r["reason"] == "audit_chain_broken"


def test_unavailable_when_records_table_missing(ctx):
    _a, db = ctx
    ap = _approve(db); _submit(db, ap)
    from sqlalchemy import text
    db.session.execute(text("DROP TABLE unit_results"))
    db.session.commit()
    r = T.verify_assessment(db, candidate_key="gh-alice", assessment_id="LAB-A")
    assert r["verdict"] == "UNAVAILABLE"
    assert r["disposition"]["qualified"] is False


def test_never_reports_qualified(ctx):
    _a, db = ctx
    ap = _approve(db); _submit(db, ap); _adjudicate(db, decision="pass")
    r = T.verify_assessment(db, candidate_key="gh-alice", assessment_id="LAB-A")
    assert r["disposition"]["qualified"] is False and r["disposition"]["assessment_only"] is True
    assert r["simulation"] is True
