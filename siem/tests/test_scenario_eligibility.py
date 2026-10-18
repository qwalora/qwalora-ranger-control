"""F5.1 Correction 4 - fail-closed scenario assignment and eligibility.

An unavailable / unknown / unsupported-version / wrong-pathway / unapproved / revoked scenario can
NEVER become an accepted final assessment - in particular, a missing scenario must not be treated as
a scenario with no requirements. Pure-logic eligibility covers the matrix; an app-backed finalize
proves the gate actually blocks submission and leaves the draft unsubmitted.
"""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECRET_KEY", "scen-elig")
os.environ.setdefault("DEFAULT_COHORT", "2026-P")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["RANGER_EVIDENCE_DIR"] = os.path.join(ROOT, "instance", "scen_elig_evidence")
for f in ("RANGER_WORKBENCH", "RANGER_WORKBENCH_CASE_ACCESS", "RANGER_WORKBENCH_EVIDENCE_SUBMIT"):
    os.environ[f] = "1"

import json as _json  # noqa: E402
import workbench_core as wc  # noqa: E402
import workbench_scenarios as sc  # noqa: E402


class _Case:
    """Lightweight stand-in carrying only what eligibility reads."""
    def __init__(self, scenario_ref, scenario_version=1, board=1, plane="qualification",
                 workflow="qualification"):
        self.scenario_ref = scenario_ref
        self.scenario_version = scenario_version
        self.board = board
        self.plane = plane
        self.workflow = workflow


def test_eligibility_matrix():
    # 1. missing scenario reference
    assert sc.eligibility(None, 1, pathway="parallax")["status"] == "no_scenario"
    # 2. unknown scenario identifier
    assert sc.eligibility("does-not-exist", 1, pathway="parallax")["status"] == "unknown_scenario"
    # 3. unsupported scenario version
    assert sc.eligibility("parallax-agent-authz", 99, pathway="parallax")["status"] == \
        "unsupported_version"
    # 4. wrong pathway (a PARALLAX scenario requested for a STRATA candidate)
    assert sc.eligibility("parallax-agent-authz", 1, pathway="strata")["status"] == "wrong_pathway"
    # 7. valid active assignment
    assert sc.eligibility("parallax-agent-authz", 1, pathway="parallax")["ok"] is True

    # 5. unapproved scenario: inject an explicit unapproved entry (presence != approval)
    sc.SCENARIOS.setdefault("test-unapproved", {})[1] = {
        "title": "unapproved draft", "pathway": sc.pathways.PATHWAY_PARALLAX, "approved": False,
        "evidence_requirements": [{"kind": "technical_report", "required": True}],
        "submission_conditions": "x"}
    try:
        assert sc.eligibility("test-unapproved", 1, pathway="parallax")["status"] == "unapproved"
    finally:
        sc.SCENARIOS.pop("test-unapproved", None)

    # 6. revoked assignment
    sc.REVOKED.add(("parallax-agent-authz", 1))
    try:
        assert sc.eligibility("parallax-agent-authz", 1, pathway="parallax")["status"] == "revoked"
    finally:
        sc.REVOKED.discard(("parallax-agent-authz", 1))

    # 8. a pinned historical version stays valid when a newer version is added (not auto-invalidated)
    fam = sc.SCENARIOS["parallax-agent-authz"]
    fam[2] = dict(fam[1]); fam[2]["title"] = "v2 (newer)"
    try:
        assert sc.eligibility("parallax-agent-authz", 1, pathway="parallax")["ok"] is True
        assert sc.eligibility("parallax-agent-authz", 2, pathway="parallax")["ok"] is True
    finally:
        fam.pop(2, None)

    # a scenario missing its requirement set is incomplete (never "no requirements" == submittable)
    sc.SCENARIOS.setdefault("test-incomplete", {})[1] = {
        "title": "incomplete", "pathway": sc.pathways.PATHWAY_PARALLAX, "approved": True,
        "evidence_requirements": [], "submission_conditions": ""}
    try:
        assert sc.eligibility("test-incomplete", 1, pathway="parallax")["status"] == "incomplete"
    finally:
        sc.SCENARIOS.pop("test-incomplete", None)


def _app():
    import app as appmod
    from models import db, Candidate, Cohort, Case
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.create_all()
    for nm, pw in (("2026-P", "parallax"),):
        if not Cohort.query.filter_by(name=nm).first():
            db.session.add(Cohort(name=nm, pathway=pw, status="active"))
    db.session.commit()
    return application, db, Candidate, Case, ctx


def test_missing_scenario_cannot_be_finalized():
    """9/acceptance: a case whose scenario is unavailable can never be finalized, even with a finding;
    the draft stays unsubmitted (empty required-kinds set does NOT make it submittable)."""
    application, db, Candidate, Case, ctx = _app()
    try:
        c = Candidate(handle="e1", name="E", email="e1@e", cohort="2026-P", github_id="g-e1",
                      status="active", current_board=1)
        db.session.add(c); db.session.commit()
        # scenario_ref is None -> no approved scenario assigned
        case = Case(candidate_id=c.id, board=1, cohort="2026-P", plane="qualification",
                    workflow="qualification", seed="s", scenario_version=1, index_name="e1",
                    scenario_ref=None)
        db.session.add(case); db.session.commit()
        store = wc.evidence_store()
        wc.save_draft(db, case, c, {"findings": [{"claim": "something"}], "evidence_refs": [],
                                    "notes": []})
        blocked = False
        try:
            wc.finalize_submission(db, store, Case.query.get(case.id), c, "parallax")
        except wc.WorkbenchError as e:
            blocked = e.code == "SCENARIO_NOT_SUBMITTABLE" and e.http == 409
        assert blocked, "a case with no approved scenario must not finalize"
        sub = wc._submission(db, case, c)
        assert sub.submission_status == "draft", "the draft must remain unsubmitted"
    finally:
        ctx.pop()


def test_missing_required_evidence_blocks_finalize():
    """10: a scenario that REQUIRES a non-report evidence kind cannot be finalized until it is
    attached (the required set comes from the approved scenario, not a generic default)."""
    application, db, Candidate, Case, ctx = _app()
    try:
        c = Candidate(handle="e2", name="E2", email="e2@e", cohort="2026-P", github_id="g-e2",
                      status="active", current_board=1)
        db.session.add(c); db.session.commit()
        # parallax-agent-authz requires a required agent_trace + technical_report
        case = Case(candidate_id=c.id, board=1, cohort="2026-P", plane="qualification",
                    workflow="qualification", seed="s", scenario_version=1, index_name="e2",
                    scenario_ref="parallax-agent-authz")
        db.session.add(case); db.session.commit()
        store = wc.evidence_store()
        wc.save_draft(db, case, c, {"findings": [{"claim": "finding"}], "evidence_refs": [],
                                    "notes": []})
        blocked = False
        try:
            wc.finalize_submission(db, store, Case.query.get(case.id), c, "parallax")
        except wc.WorkbenchError as e:
            blocked = e.code == "MISSING_REQUIRED_EVIDENCE"
        assert blocked, "required evidence must be attached before finalize"

        # attach the required agent_trace, then finalize succeeds
        trace = _json.dumps({"schema": "ranger-agent-trace/1", "events": []}).encode()
        art = wc.submit_evidence(db, store, Case.query.get(case.id), c, "parallax",
                                 io.BytesIO(trace), evidence_type="agent_trace")
        wc.save_draft(db, case, c, {"findings": [{"claim": "finding",
                      "evidence_refs": [art["evidence_id"]]}],
                      "evidence_refs": [art["evidence_id"]], "notes": []})
        sub, _ = wc.finalize_submission(db, store, Case.query.get(case.id), c, "parallax")
        assert sub.submission_status == "submitted"
    finally:
        ctx.pop()


def test_cross_cohort_access_is_fail_closed():
    """A case from another cohort is a non-disclosing 404 on write (authorize_case_write)."""
    application, db, Candidate, Case, ctx = _app()
    try:
        from models import Cohort
        if not Cohort.query.filter_by(name="2026-Q").first():
            db.session.add(Cohort(name="2026-Q", pathway="parallax", status="active"))
        c = Candidate(handle="e3", name="E3", email="e3@e", cohort="2026-P", github_id="g-e3",
                      status="active", current_board=1)
        other = Candidate(handle="e4", name="E4", email="e4@e", cohort="2026-Q", github_id="g-e4",
                          status="active", current_board=1)
        db.session.add_all([c, other]); db.session.commit()
        case = Case(candidate_id=other.id, board=1, cohort="2026-Q", plane="qualification",
                    workflow="qualification", seed="s", scenario_version=1, index_name="e4",
                    scenario_ref="parallax-agent-authz")
        db.session.add(case); db.session.commit()
        blocked = False
        try:
            wc.authorize_case_write(db, c, case.id, action="submit")
        except wc.WorkbenchError as e:
            blocked = e.http == 404
        assert blocked, "cross-cohort/owner access must be a non-disclosing 404"
    finally:
        ctx.pop()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
