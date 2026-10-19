"""PARALLAX research workflow END-TO-END acceptance on GENUINE PostgreSQL.

Exercises the REAL deployed routes through the WSGI app against a disposable PostgreSQL database
with isolated, clearly-test identities: trial execution -> signed evidence -> investigation draft
-> save/navigate/unsubmitted -> explicit submit -> immutable evidence -> reviewer adjudication,
plus the negative-security and research-integrity matrix. Uses the deterministic stub backend (the
approved nonproduction backend in this harness), so no real model calls and no inference spend.

This NEVER touches the two protected live records (run-f0d33a285717, run-e07852969609): it runs in a
fresh disposable database, not nonprod. SKIPS when the authorized disposable PostgreSQL is absent.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px-e2e-accept")
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


def _cl(app, cid):
    cl = app.test_client()
    with cl.session_transaction() as s:
        s.clear(); s["cand"] = cid; s["csrf"] = "t"
    return cl


def test_parallax_e2e_submission_and_review():
    saved = {k: os.environ.get(k) for k in ("RANGER_PARALLAX_LABA", "RANGER_PARALLAX_LABA_ENV",
                                            "REVIEWER_GITHUB_IDS")}
    os.environ["RANGER_PARALLAX_LABA"] = "1"
    os.environ["RANGER_PARALLAX_LABA_ENV"] = "test"
    os.environ["REVIEWER_GITHUB_IDS"] = "gh-acc-reviewer"
    for m in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
        os.environ.pop(m, None)
    try:
        with _pgtest.isolated_pg_database():
            import importlib
            import app as appmod
            importlib.reload(appmod)
            from models import (db, Candidate, ProgramMembership, ParallaxResearchRun,
                                ParallaxAuditEvent)
            application = appmod.create_app()
            with application.app_context():
                assert db.engine.dialect.name == "postgresql"
                db.create_all()
                researcher = _mk(db, Candidate, ProgramMembership, "gh-acc-researcher")
                other = _mk(db, Candidate, ProgramMembership, "gh-acc-other")
                reviewer = _mk(db, Candidate, ProgramMembership, "gh-acc-reviewer")
                strata = _mk(db, Candidate, ProgramMembership, "gh-acc-strata", program="strata")
                suspended = _mk(db, Candidate, ProgramMembership, "gh-acc-susp", status="suspended")

            rc = _cl(application, researcher)

            # (4) genuine execution via the approved stub backend -> signed evidence persisted
            tr = rc.post("/parallax/research/trial", headers=H,
                         data=json.dumps({"task_id": "t-storage"}))
            assert tr.status_code == 201, tr.get_data(as_text=True)
            tbody = tr.get_json()
            evid = tbody["trial_id"]
            assert tbody["backend_provenance"] == "simulated"      # stub => not an empirical finding
            assert tbody["pathway_qualified"] is False
            with application.app_context():
                import signing
                row = ParallaxResearchRun.query.filter_by(run_id=evid).first()
                assert row is not None
                assert signing.verify(json.loads(row.run_record), row.signature,
                                      kid=row.signing_kid) is True
                ev_snapshot = (row.run_record, row.signature, row.record_hash, row.signing_kid)

            # (5) draft the analysis, save progress, navigate away, confirm still unsubmitted
            d = rc.post("/parallax/research/investigation/draft", headers=H,
                        data=json.dumps({"payload": {"evidence_run_id": evid,
                                                     "analysis": "draft in progress"},
                                         "base_version": 0}))
            assert d.status_code == 200
            fresh = _cl(application, researcher)        # new authenticated session (navigate away/return)
            got = fresh.get("/parallax/research/draft", headers=H).get_json()
            assert got["investigation"]["payload"]["analysis"] == "draft in progress"
            with application.app_context():
                # no investigation record exists yet: a draft is not a submission
                assert ParallaxResearchRun.query.filter(
                    ParallaxResearchRun.run_record.contains('"kind":"investigation"')).count() == 0

            # (5.6) submit intentionally via the final submission action
            sub = rc.post("/parallax/research/investigation", headers=H,
                          data=json.dumps({"evidence_run_id": evid,
                                           "analysis": "final submitted analysis"}))
            assert sub.status_code == 201
            inv_id = sub.get_json()["investigation_id"]
            assert sub.get_json()["bound_to"] == evid and sub.get_json()["pathway_qualified"] is False
            with application.app_context():
                inv = ParallaxResearchRun.query.filter_by(run_id=inv_id).first()
                assert inv is not None
                # (5.9 / 8) the underlying signed trial evidence is unchanged (immutable)
                row2 = ParallaxResearchRun.query.filter_by(run_id=evid).first()
                assert (row2.run_record, row2.signature, row2.record_hash, row2.signing_kid) == ev_snapshot

            # (5 validation) negatives
            assert rc.post("/parallax/research/investigation", headers=H,
                           data=json.dumps({"analysis": "x"})).status_code == 400     # missing evidence id
            assert rc.post("/parallax/research/investigation", headers=H,
                           data=json.dumps({"evidence_run_id": evid, "analysis": ""})).status_code == 400  # empty analysis
            assert rc.post("/parallax/research/investigation", headers=H,
                           data=json.dumps({"evidence_run_id": "run-nope",
                                            "analysis": "y"})).status_code == 404     # invalid evidence id
            # unauthorized ownership: another researcher cannot bind this evidence
            assert _cl(application, other).post("/parallax/research/investigation", headers=H,
                       data=json.dumps({"evidence_run_id": evid,
                                        "analysis": "not mine"})).status_code == 404

            # (6) reviewer workflow: the research-adjudication API
            # candidate self-review / non-reviewer is denied (not on the allow-list)
            assert rc.post("/parallax/research/adjudicate", headers=H,
                           data=json.dumps({"investigation_id": inv_id,
                                            "decision": "met"})).status_code == 403
            # an authorized reviewer records a signed decision
            rvc = _cl(application, reviewer)
            adj = rvc.post("/parallax/research/adjudicate", headers=H,
                           data=json.dumps({"investigation_id": inv_id, "decision": "met",
                                            "comment": "acceptance check"}))
            assert adj.status_code == 201
            assert adj.get_json()["decision"] == "met" and adj.get_json()["pathway_qualified"] is False

            # (7) negative security
            assert _cl(application, strata).post("/parallax/research/investigation", headers=H,
                       data=json.dumps({"evidence_run_id": evid, "analysis": "z"})).status_code in (401, 403)
            assert _cl(application, suspended).post("/parallax/research/investigation", headers=H,
                       data=json.dumps({"evidence_run_id": evid, "analysis": "z"})).status_code in (401, 403)
            # CSRF rejection (cookie-authed, no token)
            assert rc.post("/parallax/research/investigation",
                           headers={"Accept": "application/json", "Content-Type": "application/json"},
                           data=json.dumps({"evidence_run_id": evid, "analysis": "z"})).status_code == 400

            # (8) audit trail: every signed run appended a signed audit event; no qualification anywhere
            with application.app_context():
                assert ParallaxAuditEvent.query.filter_by(action="research_run_persisted").count() >= 3
                from models import QualificationDecision
                assert QualificationDecision.query.count() == 0
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
