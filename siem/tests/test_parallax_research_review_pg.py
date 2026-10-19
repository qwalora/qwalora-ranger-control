"""PARALLAX research REVIEWER workflow acceptance on GENUINE PostgreSQL.

Covers the hardened adjudication core + admin review API + candidate visibility + lifecycle on the
real WSGI app against a disposable database with isolated, clearly-test identities: queue visibility,
reviewer decision, candidate result visibility, invalid-target rejection, unauthorized review,
self-review denial, evidence-tampering rejection, duplicate (idempotent) handling, server-side draft
supersede, and audit integrity. Stub backend only (no model calls). Never touches the two protected
live records (runs only in a fresh disposable database). SKIPS without the authorized disposable PG.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px-review-pg")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402
import _pgtest  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)

H = {"X-CSRF-Token": "t", "Content-Type": "application/json", "Accept": "application/json"}


def _mk(db, Candidate, ProgramMembership, handle, program="parallax", status="active"):
    c = Candidate(handle=handle, name=handle, email=handle + "@e", cohort="2026-A",
                  github_id=handle, status=status, current_board=1)
    db.session.add(c); db.session.commit()
    if program:
        db.session.add(ProgramMembership(candidate_id=c.id, program=program, status="active",
                                         cohort="2026-A")); db.session.commit()
    return c.id


def _cand(app, cid):
    cl = app.test_client()
    with cl.session_transaction() as s:
        s.clear(); s["cand"] = cid; s["csrf"] = "t"
    return cl


def _admin(app, gid):
    cl = app.test_client()
    with cl.session_transaction() as s:
        s.clear(); s["admin"] = True; s["admin_gid"] = gid; s["csrf"] = "t"
    return cl


def test_parallax_research_review_workflow():
    saved = {k: os.environ.get(k) for k in ("RANGER_PARALLAX_LABA", "RANGER_PARALLAX_LABA_ENV",
                                            "REVIEWER_GITHUB_IDS", "ADMIN_TOKEN", "DISABLE_ADMIN_TOKEN")}
    os.environ["RANGER_PARALLAX_LABA"] = "1"
    os.environ["RANGER_PARALLAX_LABA_ENV"] = "test"
    os.environ["REVIEWER_GITHUB_IDS"] = "gh-rv-reviewer"
    os.environ["ADMIN_TOKEN"] = "admintoken"
    os.environ.pop("DISABLE_ADMIN_TOKEN", None)
    for m in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
        os.environ.pop(m, None)
    try:
        with _pgtest.isolated_pg_database():
            import importlib
            import app as appmod
            importlib.reload(appmod)
            from models import (db, Candidate, ProgramMembership, ParallaxResearchRun,
                                ParallaxAuditEvent, QualificationDecision)
            from parallax.research import store as rstore
            application = appmod.create_app()
            with application.app_context():
                assert db.engine.dialect.name == "postgresql"
                db.create_all()
                researcher = _mk(db, Candidate, ProgramMembership, "gh-rv-researcher")
                other = _mk(db, Candidate, ProgramMembership, "gh-rv-other")
                _mk(db, Candidate, ProgramMembership, "gh-rv-reviewer")  # reviewer identity (allow-listed)

            rc = _cand(application, researcher)

            # researcher: trial -> evidence -> draft -> submit (server supersede) -> investigation
            evid = rc.post("/parallax/research/trial", headers=H,
                           data=json.dumps({"task_id": "t-storage"})).get_json()["trial_id"]
            rc.post("/parallax/research/investigation/draft", headers=H,
                    data=json.dumps({"payload": {"evidence_run_id": evid, "analysis": "draft"},
                                     "base_version": 0}))
            sub = rc.post("/parallax/research/investigation", headers=H,
                          data=json.dumps({"evidence_run_id": evid, "analysis": "my trust-boundary analysis"}))
            assert sub.status_code == 201
            inv = sub.get_json()["investigation_id"]
            assert sub.get_json()["status"] == "pending_review" and sub.get_json()["duplicate"] is False
            # server-side supersede: the investigation draft is gone after submit
            assert rc.get("/parallax/research/draft", headers=H).get_json()["investigation"] is None

            # duplicate (idempotent): identical resubmission returns the SAME investigation, no new row
            dup = rc.post("/parallax/research/investigation", headers=H,
                          data=json.dumps({"evidence_run_id": evid, "analysis": "my trust-boundary analysis"}))
            assert dup.status_code == 200 and dup.get_json()["duplicate"] is True
            assert dup.get_json()["investigation_id"] == inv
            with application.app_context():
                assert ParallaxResearchRun.query.filter(
                    ParallaxResearchRun.run_record.contains('"kind":"investigation"')).count() == 1

            # candidate visibility: own investigation is pending_review; cross-owner is hidden (404)
            st = rc.get("/parallax/research/investigation/%s/status" % inv, headers=H).get_json()
            assert st["status"] == "pending_review" and st["decision"] is None
            assert _cand(application, other).get(
                "/parallax/research/investigation/%s/status" % inv, headers=H).status_code == 404

            # admin queue visibility
            ar = _admin(application, "gh-rv-reviewer")
            page = ar.get("/admin/research-review?status=pending").data.decode()
            assert inv in page and "gh-rv-researcher" in page

            # invalid-target rejection (non-existent + non-investigation=the trial id)
            assert ar.post("/admin/research-review/adjudicate", headers=H,
                           data=json.dumps({"investigation_id": "run-nope", "decision": "met"})
                           ).status_code == 404
            assert ar.post("/admin/research-review/adjudicate", headers=H,
                           data=json.dumps({"investigation_id": evid, "decision": "met"})
                           ).status_code == 404  # trial is not an investigation

            # unauthorized review: an admin who is NOT a reviewer is denied
            assert _admin(application, "gh-not-a-reviewer").post(
                "/admin/research-review/adjudicate", headers=H,
                data=json.dumps({"investigation_id": inv, "decision": "met"})).status_code == 403
            # a candidate/non-reviewer is denied the research adjudicate API
            assert rc.post("/parallax/research/adjudicate", headers=H,
                           data=json.dumps({"investigation_id": inv, "decision": "met"})
                           ).status_code == 403

            # authorized reviewer records a decision (valid)
            adj = ar.post("/admin/research-review/adjudicate", headers=H,
                          data=json.dumps({"investigation_id": inv, "decision": "met",
                                           "comment": "boundary violation clearly shown"}))
            assert adj.status_code == 201 and adj.get_json()["decision"] == "met"
            assert adj.get_json()["pathway_qualified"] is False

            # candidate now sees the decision + authorized feedback
            st2 = rc.get("/parallax/research/investigation/%s/status" % inv, headers=H).get_json()
            assert st2["status"] == "reviewed" and st2["decision"] == "met"
            assert st2["feedback"] == "boundary violation clearly shown"

            # self-review denial: the reviewer submits their OWN investigation, then cannot adjudicate it
            with application.app_context():
                rev_id = Candidate.query.filter_by(handle="gh-rv-reviewer").first().id
            revc = _cand(application, rev_id)
            ev2 = revc.post("/parallax/research/trial", headers=H,
                            data=json.dumps({"task_id": "t-storage"})).get_json()["trial_id"]
            inv2 = revc.post("/parallax/research/investigation", headers=H,
                             data=json.dumps({"evidence_run_id": ev2, "analysis": "own work"})
                             ).get_json()["investigation_id"]
            assert ar.post("/admin/research-review/adjudicate", headers=H,
                           data=json.dumps({"investigation_id": inv2, "decision": "met"})
                           ).status_code == 403  # self-review prohibited

            # evidence-tampering rejection: alter the investigation bytes -> signature fails -> rejected
            with application.app_context():
                row = ParallaxResearchRun.query.filter_by(run_id=inv2).first()
                rec = json.loads(row.run_record)
                rec["metrics"]["analysis"] = "TAMPERED"
                row.run_record = json.dumps(rec)
                db.session.commit()
            # a DIFFERENT (non-self) reviewer identity would still be rejected on the bad signature;
            # use the core directly with a distinct reviewer to isolate the signature failure
            with application.app_context():
                try:
                    rstore.adjudicate_investigation(db, investigation_id=inv2,
                                                    reviewer_id="gh-rv-other", decision="met")
                    assert False, "tampered investigation must be rejected"
                except rstore.ResearchStoreError as e:
                    assert getattr(e, "http", None) == 409 and "signature" in str(e)

            # CSRF rejection on the admin adjudicate (cookie-authed, no token)
            assert ar.post("/admin/research-review/adjudicate",
                           headers={"Accept": "application/json", "Content-Type": "application/json"},
                           data=json.dumps({"investigation_id": inv, "decision": "met"})
                           ).status_code == 400

            # audit integrity + no qualification anywhere
            with application.app_context():
                assert ParallaxAuditEvent.query.filter_by(
                    action="research_investigation_adjudicated", subject_ref=inv).count() >= 1
                assert ParallaxAuditEvent.query.filter_by(action="research_run_persisted").count() >= 4
                assert QualificationDecision.query.count() == 0
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
