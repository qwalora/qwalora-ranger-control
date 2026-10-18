"""F5.1 Correction 3 - the actual STRATA Board 2 submission contract is preserved.

A generic workbench receipt must never finalize a STRATA Board 2 qualification case: that case keeps
its established workflow (siem/case_contract.py + case_routes.py) - candidate citation verification
against the candidate's OWN authorized index and an Ed25519-signed, snapshot-preserving citation
record. These tests drive the real Board 2 HTTP workflow with an in-memory reader, verify the signed
record, and prove the workbench refuses to finalize such a case while PARALLAX keeps its versioned
receipt.
"""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECRET_KEY", "b2-compat")
os.environ.setdefault("DEFAULT_COHORT", "2026-S")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["RANGER_EVIDENCE_DIR"] = os.path.join(ROOT, "instance", "b2_compat_evidence")
os.environ["RANGER_CASE_UI"] = "1"                      # the established Board 2 workflow
for f in ("RANGER_WORKBENCH", "RANGER_WORKBENCH_CASE_ACCESS", "RANGER_WORKBENCH_EVIDENCE_SUBMIT",
          "RANGER_WORKBENCH_ASSESSMENT_VISIBILITY"):
    os.environ[f] = "1"
os.environ.pop("RANGER_PARALLAX_QUALIFICATION_ACTIVE", None)

import json as _json  # noqa: E402
import workbench_core as wc  # noqa: E402
import pytest  # noqa: E402
import case_routes  # noqa: E402
from siem import case_contract as cc  # noqa: E402
from siem import assessment_contract as ac  # noqa: E402

# This module sets its workbench/case flags once at import, but sibling test modules mutate the same
# process os.environ at RUN time (e.g. toggling RANGER_WORKBENCH_ASSESSMENT_VISIBILITY to exercise the
# hidden state) and do not always restore it. Re-apply this module's required environment before every
# test and restore the prior values afterwards, so these tests are order-independent and do not leak.
_REQUIRED_ENV = {
    "RANGER_CASE_UI": "1",
    "RANGER_WORKBENCH": "1",
    "RANGER_WORKBENCH_CASE_ACCESS": "1",
    "RANGER_WORKBENCH_EVIDENCE_SUBMIT": "1",
    "RANGER_WORKBENCH_ASSESSMENT_VISIBILITY": "1",
    "RANGER_PARALLAX_QUALIFICATION_ACTIVE": None,  # must be OFF for this module
}


@pytest.fixture(autouse=True)
def _module_env():
    saved = {k: os.environ.get(k) for k in _REQUIRED_ENV}
    for k, v in _REQUIRED_ENV.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

IDX = "b2-idx-strata"
EVENTS = [{"_id": "evt-1", "_source": {"@timestamp": "2026-03-01T00:00:00.000Z",
                                       "event": {"action": "login"}}}]


def _valid_payload():
    return {"baseline_summary": "baseline established", "overall_conclusion": "one incident found",
            "incidents": [{"label": "susp login", "disposition": "confirmed_incident",
                           "severity": "high", "confidence": 80, "primary_identity": "u1",
                           "affected_assets": ["host-1"], "analyst_conclusion": "compromise",
                           "attack_techniques": ["T1078"],
                           "cited_evidence": [{"event_uid": "evt-1", "role": "primary",
                                               "query": {"query": {"ids": {"values": ["evt-1"]}}}}]}]}


def _foreign_payload():
    p = _valid_payload()
    # cite an event from an index that is NOT the candidate's authorized index -> out of scope
    p["incidents"][0]["cited_evidence"][0]["index"] = "someone-elses-index"
    return p


def _app():
    import app as appmod
    from models import db, Candidate, Cohort, Case
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.create_all()
    if not Cohort.query.filter_by(name="2026-S").first():
        db.session.add(Cohort(name="2026-S", pathway="strata", status="active"))
    if not Cohort.query.filter_by(name="2026-P").first():
        db.session.add(Cohort(name="2026-P", pathway="parallax", status="active"))
    db.session.commit()
    case_routes.set_reader_factory(lambda case: cc.InMemoryReader(IDX, EVENTS))
    return application, db, Candidate, Case, ctx


def _login(client, cid):
    with client.session_transaction() as s:
        s.clear(); s["cand"] = cid; s["csrf"] = "t"


def _b2_case(db, Case, cand):
    case = Case(candidate_id=cand.id, board=2, cohort="2026-S", plane="qualification",
                workflow="qualification", seed="B2SEED", scenario_version=cc.SCENARIO_VERSION,
                rubric_version=cc.RUBRIC_VERSION, index_name=IDX, status="assigned", attempt=1,
                scenario_ref="strata-soc-triage")
    db.session.add(case); db.session.commit()
    return case


def test_board2_workflow_and_workbench_cannot_bypass():
    application, db, Candidate, Case, ctx = _app()
    try:
        from models import CaseSubmission
        # a UNIQUE(candidate_id, board, attempt, plane) constraint means one Board 2 qualification
        # case per candidate; use a distinct candidate per scenario under test.
        def _cand(tag):
            c = Candidate(handle=tag, name=tag, email=f"{tag}@e", cohort="2026-S",
                          github_id=f"g-{tag}", status="active", current_board=2)
            db.session.add(c); db.session.commit()
            return c
        client = application.test_client()
        hdr = {"X-CSRF-Token": "t"}

        # 1. an actual Board 2 case reaches the established workflow; a VALID in-scope citation is
        #    accepted and 4. evidence preservation produces a signed citation record.
        cand = _cand("b2a")
        _login(client, cand.id)
        case = _b2_case(db, Case, cand)
        client.post(f"/case/{case.id}/draft", json=_valid_payload(), headers=hdr)
        r = client.post(f"/case/{case.id}/submit", json=_valid_payload(), headers=hdr)
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body["ok"] and body["submission_status"] == "submitted" and body["evidence_signed"]
        sub = (CaseSubmission.query.filter_by(case_id=case.id)
               .order_by(CaseSubmission.id.desc()).first())
        rec = _json.loads(sub.evidence_record)
        # 4/5. the signed citation record verifies (integrity/origin) and is self-consistent
        assert cc.verify_evidence_record(rec, sub.evidence_sig) is True
        assert cc.verify_record_self_consistent(rec)["ok"] is True
        # the workbench receipt columns are NOT used by the Board 2 path
        assert sub.wb_receipt is None and sub.wb_receipt_sig is None

        # 3. an invalid / foreign-index citation is rejected (does not finalize)
        cand2 = _cand("b2b")
        _login(client, cand2.id)
        case2 = _b2_case(db, Case, cand2)
        client.post(f"/case/{case2.id}/draft", json=_foreign_payload(), headers=hdr)
        r2 = client.post(f"/case/{case2.id}/submit", json=_foreign_payload(), headers=hdr)
        assert r2.status_code == 422 and r2.get_json()["stage"] == "evidence"
        assert Case.query.get(case2.id).status != "submitted"

        # 7. a generic workbench receipt CANNOT bypass the Board 2 technical verification
        cand3 = _cand("b2c")
        case3 = _b2_case(db, Case, cand3)
        store = wc.evidence_store()
        wc.save_draft(db, case3, cand3, {"findings": [{"claim": "x"}], "evidence_refs": [],
                                         "notes": []})
        refused = False
        try:
            wc.finalize_submission(db, store, Case.query.get(case3.id), cand3, "strata")
        except wc.WorkbenchError as e:
            refused = e.code == "STRATA_BOARD2_CONTRACT_REQUIRED" and e.http == 409
        assert refused, "workbench must refuse to finalize a STRATA Board 2 case"
        wsub = wc._submission(db, case3, cand3)
        # nothing finalized: no workbench receipt, no STRATA record, still a draft
        assert wsub.submission_status == "draft"
        assert wsub.wb_receipt is None and wsub.evidence_record is None

        # 6. existing STRATA grading integration remains importable + functional (unchanged contract).
        #    The dedicated grader suites (test_enterprise_grader / test_shadow_regression) prove the
        #    scoring itself; here we confirm the contract pieces the grader depends on are intact.
        from siem import enterprise_grader as eg
        assert callable(eg.score_board2_enterprise)
        assert cc.RUBRIC_VERSION == 2
        assert cc.validate_submission({"incidents": []})["ok"] is False  # mandatory-field contract
    finally:
        ctx.pop()


def test_parallax_keeps_versioned_receipt_and_qualification_inactive():
    """8/9: PARALLAX workbench submissions continue to use their distinct versioned receipt, and
    final qualification remains inactive."""
    application, db, Candidate, Case, ctx = _app()
    try:
        cand = Candidate(handle="px", name="PX", email="px@e", cohort="2026-P", github_id="g-px",
                         status="active", current_board=1)
        db.session.add(cand); db.session.commit()
        case = Case(candidate_id=cand.id, board=1, cohort="2026-P", plane="qualification",
                    workflow="qualification", seed="s", scenario_version=1, index_name="px-idx",
                    scenario_ref="parallax-agent-authz")
        db.session.add(case); db.session.commit()
        store = wc.evidence_store()
        trace = _json.dumps({"schema": "ranger-agent-trace/1", "events": []}).encode()
        art = wc.submit_evidence(db, store, case, cand, "parallax", io.BytesIO(trace),
                                 evidence_type="agent_trace")
        wc.save_draft(db, case, cand, {"findings": [{"claim": "f",
                      "evidence_refs": [art["evidence_id"]]}],
                      "evidence_refs": [art["evidence_id"]], "notes": []})
        sub, receipt = wc.finalize_submission(db, store, Case.query.get(case.id), cand, "parallax")
        assert sub.wb_receipt and sub.wb_receipt_sig
        assert sub.wb_receipt_version == wc.WB_RECEIPT_CONTRACT_VERSION
        assert sub.evidence_record is None and sub.evidence_sig is None   # STRATA columns untouched
        assert wc.verify_receipt(sub, db) is True
        # 9. PARALLAX qualification remains inactive
        assert ac.parallax_qualification_active() is False
        stv = wc.assessment_status_view(Case.query.get(case.id), sub, "parallax")
        assert stv["qualification_active"] is False and stv["qualified"] is False
    finally:
        ctx.pop()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
