"""Milestone 2 tests: Ranger-native SOC case routes + submission/evidence over the
REAL create_app (candidate session, real models, signing). Evidence reads go through
an injected in-memory reader (no live cluster). Covers authorization, cross-candidate
access, draft persistence, submission locking, evidence tampering, lifecycle, the
feature flag, truth-safety, and admin read-only oversight."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["RANGER_CASE_UI"] = "1"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import app as appmod               # noqa: E402
import case_routes                 # noqa: E402
from models import db, Candidate, Case, CaseSubmission  # noqa: E402
from siem import authz, enterprise, case_contract as cc  # noqa: E402

P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


def _reader_for(case):
    slug = case.index_name.split("-b2")[0].split("-")[-1]  # not used; rebuild from seed below
    # Rebuild the candidate slug from the stored index name: ranger-<cohort>-<slug>-b2
    parts = case.index_name.split("-")
    slug = parts[-2]
    events, _truth = enterprise.generate(slug, 2, case.seed, "A")
    return cc.InMemoryReader(case.index_name, events)


def _truth_uid(case):
    parts = case.index_name.split("-")
    slug = parts[-2]
    _events, truth = enterprise.generate(slug, 2, case.seed, "A")
    return truth["incidents"][0]["event_uids"][0]


def run():
    application = appmod.create_app()
    case_routes.set_reader_factory(_reader_for)
    ctx = application.app_context(); ctx.push()

    a = Candidate(handle="b2-a", name="A", email="a@e", cohort="2026-A",
                  github_id="gid-a", status="active", current_board=2)
    b = Candidate(handle="b2-b", name="B", email="b@e", cohort="2026-A",
                  github_id="gid-b", status="active", current_board=2)
    db.session.add_all([a, b]); db.session.commit()
    aid, bid = a.id, b.id

    cli = application.test_client()
    def sess(cand_id=None, admin=False):
        with cli.session_transaction() as s:
            s.clear(); s["csrf"] = "t"
            if cand_id: s["cand"] = cand_id
            if admin: s["admin"] = 1; s["admin_login"] = "rev"
    H = {"X-CSRF-Token": "t", "Content-Type": "application/json"}

    # --- authorization ------------------------------------------------------
    sess()  # no candidate
    check("no session -> 401 on /case", cli.get("/case").status_code == 401)
    sess(aid)
    check("candidate A -> 200 on /case (assignment)", cli.get("/case").status_code == 200)
    case_a = Case.query.filter_by(candidate_id=aid).first()
    check("case assigned for A", case_a is not None and case_a.status in ("assigned", "authorized", "investigating"))

    # flag off -> 404
    os.environ["RANGER_CASE_UI"] = ""
    check("flag off -> /case 404", cli.get("/case").status_code == 404)
    os.environ["RANGER_CASE_UI"] = "1"

    # wrong board -> 403
    a2 = Candidate.query.get(aid); a2.current_board = 3; db.session.commit()
    check("wrong board -> 403", cli.get("/case").status_code == 403)
    a2.current_board = 2; db.session.commit()

    # --- workspace + lifecycle ----------------------------------------------
    r = cli.get(f"/case/{case_a.id}")
    check("A opens own workspace -> 200", r.status_code == 200)
    db.session.refresh(case_a)
    check("lifecycle: opening moves to investigating", case_a.status == "investigating")

    # --- cross-candidate access --------------------------------------------
    sess(bid)
    check("B cannot open A's case -> 404", cli.get(f"/case/{case_a.id}").status_code == 404)
    sess(aid)

    # --- draft persistence + lifecycle -------------------------------------
    uid = _truth_uid(case_a)
    payload = {
        "baseline_summary": "baseline", "overall_conclusion": "one incident",
        "incidents": [{
            "label": "inc1", "disposition": "confirmed_incident", "severity": "high",
            "confidence": 70, "attack_techniques": ["T1078"], "primary_identity": "u",
            "affected_assets": ["h1"], "analyst_conclusion": "compromised",
            "cited_evidence": [{"event_uid": uid, "index": case_a.index_name,
                                "query": {"query": {"ids": {"values": [uid]}}}, "role": "primary"}],
        }],
    }
    r = cli.post(f"/case/{case_a.id}/draft", data=json.dumps(payload), headers=H)
    check("draft autosave -> 200 ok", r.status_code == 200 and r.get_json()["ok"])
    sub = CaseSubmission.query.filter_by(case_id=case_a.id, submission_status="draft").first()
    check("draft persisted to DB", sub is not None and json.loads(sub.payload)["incidents"][0]["label"] == "inc1")
    db.session.refresh(case_a)
    check("lifecycle: draft with incidents -> evidence_collected", case_a.status == "evidence_collected")

    # --- verify is truth-safe ----------------------------------------------
    r = cli.post(f"/case/{case_a.id}/verify", data=json.dumps(payload), headers=H)
    vj = r.get_json()["verification"]
    c0 = vj["incidents"][0]["citations"][0]
    check("verify: real uid reference_valid", c0["reference_valid"] and c0["exists"] and c0["reproduces"])
    check("verify is truth-safe (no claim_consistent / incident_member leaked)",
          vj["truth_consulted"] is False and "claim_consistent" not in c0 and "incident_member" not in c0)

    # --- out-of-scope evidence blocked at submit ---------------------------
    oos = json.loads(json.dumps(payload))
    oos["incidents"][0]["cited_evidence"][0]["index"] = "ranger-2026-a-gid-b-b2"
    cli.post(f"/case/{case_a.id}/draft", data=json.dumps(oos), headers=H)
    r = cli.post(f"/case/{case_a.id}/submit", data=json.dumps({}), headers=H)
    check("out-of-scope citation blocks submit -> 422", r.status_code == 422 and r.get_json()["stage"] == "evidence")
    # restore the good draft
    cli.post(f"/case/{case_a.id}/draft", data=json.dumps(payload), headers=H)

    # --- submit locks + signs ----------------------------------------------
    r = cli.post(f"/case/{case_a.id}/submit", data=json.dumps({}), headers=H)
    check("submit -> 200 signed", r.status_code == 200 and r.get_json().get("evidence_signed"))
    db.session.refresh(case_a)
    sub = CaseSubmission.query.filter_by(case_id=case_a.id).order_by(CaseSubmission.id.desc()).first()
    check("case locked (submitted)", case_a.status == "submitted" and sub.submission_status == "submitted")
    check("evidence record present + signature valid",
          sub.evidence_record and cc.verify_evidence_record(json.loads(sub.evidence_record), sub.evidence_sig))

    # --- submission locking -------------------------------------------------
    check("draft after submit -> 409", cli.post(f"/case/{case_a.id}/draft", data=json.dumps(payload), headers=H).status_code == 409)
    check("submit after submit -> 409", cli.post(f"/case/{case_a.id}/submit", data=json.dumps({}), headers=H).status_code == 409)

    # --- evidence tampering -------------------------------------------------
    rec = json.loads(sub.evidence_record)
    tampered = json.loads(json.dumps(rec))
    if tampered["cited"]:
        tampered["cited"][0]["sha256"] = "0" * 64
    check("tampered evidence record fails signature verification",
          not cc.verify_evidence_record(tampered, sub.evidence_sig))

    # --- admin read-only oversight -----------------------------------------
    sess(admin=True)
    r = cli.get("/admin/cases")
    check("admin lists cases -> 200", r.status_code == 200 and any(x["id"] == case_a.id for x in r.get_json()["cases"]))
    r = cli.get(f"/admin/cases/{case_a.id}")
    d = r.get_json()
    s0 = d["submissions"][0]
    check("admin sees valid signature + no objective grade touched",
          s0["evidence_signature_valid"] is True and s0["shadow_score"] is None)
    before_sig = sub.evidence_sig
    cli.post(f"/admin/cases/submission/{s0['id']}/feedback", data=json.dumps({"feedback": "good work"}), headers=H)
    db.session.refresh(sub)
    check("reviewer feedback set; signed evidence + objective untouched",
          sub.reviewer_feedback == "good work" and sub.evidence_sig == before_sig
          and sub.shadow_score is None)
    # ordinary candidate cannot hit admin oversight
    sess(aid)
    check("candidate cannot list admin cases -> 403", cli.get("/admin/cases").status_code == 403)

    # --- SHADOW grader endpoint (feature-gated, reviewer-only) ---------------
    shadow_sid = s0["id"]
    before_sig2 = sub.evidence_sig
    # flag OFF -> 404 even for admin
    os.environ["RANGER_SHADOW_GRADER"] = ""
    sess(admin=True)
    check("shadow endpoint 404 when flag off",
          cli.post(f"/admin/cases/submission/{shadow_sid}/shadow", data=json.dumps({}), headers=H).status_code == 404)
    # candidate cannot hit it even with flag on -> 403
    os.environ["RANGER_SHADOW_GRADER"] = "1"
    os.environ["RANGER_B2_PROFILE"] = "A"   # match the injected profile-A reader
    sess(aid)
    check("candidate cannot run shadow grader -> 403",
          cli.post(f"/admin/cases/submission/{shadow_sid}/shadow", data=json.dumps({}), headers=H).status_code == 403)
    # admin + flag on -> 200, shadow score stored, signed evidence + objective untouched
    sess(admin=True)
    r = cli.post(f"/admin/cases/submission/{shadow_sid}/shadow", data=json.dumps({}), headers=H)
    ok = r.status_code == 200 and r.get_json()["ok"]
    shadow = r.get_json().get("shadow", {}) if ok else {}
    check("shadow grade computed (0..100) + marked shadow + does not expose raw truth matching",
          ok and isinstance(shadow.get("score"), (int, float)) and 0 <= shadow["score"] <= 100
          and shadow.get("shadow") is True and "matching" not in shadow)
    db.session.refresh(sub)
    check("shadow grade persisted to shadow_* fields",
          sub.shadow_score is not None and sub.shadow_breakdown and sub.review_flags is not None)
    check("shadow grading left signed evidence + objective grade untouched",
          sub.evidence_sig == before_sig2
          and cc.verify_evidence_record(json.loads(sub.evidence_record), sub.evidence_sig))
    os.environ["RANGER_SHADOW_GRADER"] = ""

    ctx.pop()
    print(f"\n{P} passed, {F} failed")
    return F == 0


def test_case_routes():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
