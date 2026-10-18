"""F1 regression + security tests for the pathway-aware assessment contract and the
least-privilege evaluator, plus a worked senior-PARALLAX example.

Covers the required matrix: STRATA unchanged; cross-pathway authorization boundaries;
unsupported blueprint versions; critical-failure vetoes; alternate valid solutions;
missing/contradictory evidence; tampered verification results; unauthorized reviewer
changes; protected-truth non-disclosure; deterministic no-AI operation. Offline (no
cluster, no AI, no candidate access); persistence checked on sqlite via create_app.
"""
import copy
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "f1-test-secret")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import program                                   # noqa: E402
import signing                                   # noqa: E402
from siem import assessment_contract as ac       # noqa: E402
from siem import evaluator as ev                 # noqa: E402
from siem import enterprise, case_contract as cc  # noqa: E402

P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


def _strata_bp():
    return {"pathway": "strata", "blueprint_version": 1, "environment_version": "valyria-1",
            "evidence_requirements": [{"kind": "soc_objective", "satisfied_by": "board2", "required": True}],
            "objective_checks": [{"check_id": "board2", "evaluator": "event_reference", "required": True}],
            "critical_failures": [],
            "rubric_dimensions": [{"dimension": "report", "weight": 1}],
            "human_review": {"min_reviewers": 1},
            "decision_policy": {"type": ac.POLICY_STRATA_BAR}}


def _parallax_bp(activated=True, threshold=70.0):
    return {"pathway": "parallax", "blueprint_version": 1, "environment_version": "valyria-ai-1",
            "evidence_requirements": [{"kind": "exploit_trace", "satisfied_by": "agent_canary", "required": True}],
            "objective_checks": [{"check_id": "agent_canary", "evaluator": "event_reference", "required": True}],
            "critical_failures": [{"id": "unremediated_authz_vuln",
                                   "description": "an authorization vulnerability the candidate did not remediate"}],
            "rubric_dimensions": [{"dimension": "reasoning", "weight": 2},
                                  {"dimension": "secure_design", "weight": 2},
                                  {"dimension": "recommendations", "weight": 1}],
            "human_review": {"min_reviewers": 1},
            "decision_policy": {"type": ac.POLICY_PARALLAX_PORTFOLIO,
                                "activated": activated, "rubric_threshold": threshold}}


AUTH_STRATA = {"candidate_id": 1, "pathway": "strata"}
AUTH_PARALLAX = {"candidate_id": 2, "pathway": "parallax"}
REV_PASS = {"decision": "pass", "reviewer_id": "admin-1"}


def run():
    # ---- 1. STRATA behavior unchanged ----------------------------------------------
    check("STRATA PASS_BAR unchanged (95.0)", program.PASS_BAR == 95.0)
    import scenarios
    scen = scenarios.generate_board2("f1-regress")
    zero, _ = scenarios.score_board2(scen, {"alerts": []})
    check("STRATA score_board2 unchanged: empty submission -> 0", zero == 0.0)

    obj_pass = ev.signed_check("board2", True, {"src": "ci"}, score=96.0)
    d = ac.decide(_strata_bp(), authorization=AUTH_STRATA, objective_results=[obj_pass],
                  rubric_scores={"report": 100}, reviewer_decision=REV_PASS)
    check("STRATA qualifies at objective_score 96 >= 95", d["qualified"] and d["reason"] == "qualified")
    obj_low = ev.signed_check("board2", True, {"src": "ci"}, score=94.0)
    d2 = ac.decide(_strata_bp(), authorization=AUTH_STRATA, objective_results=[obj_low],
                   rubric_scores={"report": 100}, reviewer_decision=REV_PASS)
    check("STRATA fails at objective_score 94 < 95 (bar unchanged)",
          not d2["qualified"] and d2["reason"] == "below_objective_bar")

    # ---- 2. cross-pathway authorization boundary -----------------------------------
    dx = ac.decide(_parallax_bp(), authorization=AUTH_STRATA,          # strata auth on a parallax unit
                   objective_results=[ev.signed_check("agent_canary", True, score=None)],
                   rubric_scores={"reasoning": 100, "secure_design": 100, "recommendations": 100},
                   reviewer_decision=REV_PASS)
    check("cross-pathway auth rejected (strata token cannot qualify a parallax unit)",
          not dx["qualified"] and dx["reason"] == "GATE_FAILED"
          and any(e["code"] == "INSUFFICIENT_AUTHORIZATION" for e in dx.get("errors", [])))

    # ---- 3. unsupported blueprint version ------------------------------------------
    bpv = _strata_bp(); bpv["blueprint_version"] = 2
    dv = ac.decide(bpv, authorization=AUTH_STRATA, objective_results=[obj_pass],
                   reviewer_decision=REV_PASS)
    check("unsupported blueprint version rejected",
          not dv["qualified"] and dv["reason"] == "UNSUPPORTED_BLUEPRINT_VERSION")

    # ---- 4. critical-failure veto (mandatory outcome gate) -------------------------
    strong_rubric = {"reasoning": 100, "secure_design": 100, "recommendations": 100}
    gate_ok = ev.signed_check("agent_canary", True, {"canary": "reached_then_blocked"})
    veto = ac.decide(_parallax_bp(), authorization=AUTH_PARALLAX, objective_results=[gate_ok],
                     critical_findings=[{"id": "unremediated_authz_vuln", "present": True}],
                     rubric_scores=strong_rubric, reviewer_decision=REV_PASS)
    check("critical failure VETOES qualification despite perfect rubric + reviewer pass",
          not veto["qualified"] and veto["reason"] == "CRITICAL_FAILURE_VETO")
    remediated = ac.decide(_parallax_bp(), authorization=AUTH_PARALLAX, objective_results=[gate_ok],
                           critical_findings=[{"id": "unremediated_authz_vuln", "present": True,
                                               "remediated": True}],
                           rubric_scores=strong_rubric, reviewer_decision=REV_PASS)
    check("remediation yields a MET assessment but NOT a final qualification (assessment-only)",
          remediated["assessment_passed"] is True and remediated["qualified"] is False
          and remediated["reason"] == "assessment_met")

    # ---- 1b. no combination bypasses the inactive PARALLAX qualification gate -------
    combos = [
        dict(rubric_scores={"reasoning": 100, "secure_design": 100, "recommendations": 100}),
        dict(rubric_scores=strong_rubric, reviewer_decision={"decision": "pass", "reviewer_id": "a"}),
    ]
    bypass = False
    for c in combos:
        dd = ac.decide(_parallax_bp(activated=True, threshold=1.0), authorization=AUTH_PARALLAX,
                       objective_results=[gate_ok],
                       critical_findings=[{"id": "unremediated_authz_vuln", "present": True, "remediated": True}],
                       rubric_scores=c.get("rubric_scores", strong_rubric),
                       reviewer_decision=c.get("reviewer_decision", REV_PASS))
        if dd["qualified"]:
            bypass = True
    # even a signed record of the met assessment must not read as a final qualification
    sig_met = ac.sign_decision(remediated, candidate_id=2, unit_ref="C1")
    check("no score/remediation/reviewer/signature bypasses the inactive PARALLAX gate",
          not bypass and ac.verify_decision(sig_met) and sig_met["record"]["qualified"] is False)
    # a single assessment is ASSESSMENT-ONLY: the per-assessment activation flag has NO effect on it
    os.environ["RANGER_PARALLAX_QUALIFICATION_ACTIVE"] = "1"
    try:
        active = ac.decide(_parallax_bp(activated=True, threshold=1.0), authorization=AUTH_PARALLAX,
                           objective_results=[gate_ok],
                           critical_findings=[{"id": "unremediated_authz_vuln", "present": True, "remediated": True}],
                           rubric_scores=strong_rubric, reviewer_decision=REV_PASS)
    finally:
        os.environ.pop("RANGER_PARALLAX_QUALIFICATION_ACTIVE", None)
    check("single assessment never becomes a qualification, flag on or off (assessment-only)",
          active["qualified"] is False and active["assessment_passed"] is True
          and active["reason"] == "assessment_met"
          and ac.decide(_parallax_bp(), authorization=AUTH_PARALLAX, objective_results=[gate_ok],
                        critical_findings=[{"id": "unremediated_authz_vuln", "present": True, "remediated": True}],
                        rubric_scores=strong_rubric, reviewer_decision=REV_PASS)["qualified"] is False)

    # ---- 5. alternate valid solutions ----------------------------------------------
    alt_a = ev.signed_check("agent_canary", True, {"mitigation": "retrieval_authz"})
    alt_b = ev.signed_check("agent_canary", True, {"mitigation": "tool_scope"})
    da = ac.decide(_parallax_bp(), authorization=AUTH_PARALLAX, objective_results=[alt_a],
                   rubric_scores=strong_rubric, reviewer_decision=REV_PASS)
    db_ = ac.decide(_parallax_bp(), authorization=AUTH_PARALLAX, objective_results=[alt_b],
                    rubric_scores=strong_rubric, reviewer_decision=REV_PASS)
    check("two different valid mitigations both MEET the assessment (outcome, not one path)",
          da["assessment_passed"] and db_["assessment_passed"])

    # ---- 6. missing / contradictory evidence ---------------------------------------
    dm = ac.decide(_parallax_bp(), authorization=AUTH_PARALLAX, objective_results=[],
                   rubric_scores=strong_rubric, reviewer_decision=REV_PASS)
    check("missing required evidence -> not qualified (EVIDENCE_REQUIREMENT_UNMET)",
          not dm["qualified"] and any(e["code"] == "EVIDENCE_REQUIREMENT_UNMET"
                                      for e in dm.get("errors", [])))
    contra = ev.signed_check("agent_canary", False, {"canary": "never_reached"})
    dc = ac.decide(_parallax_bp(), authorization=AUTH_PARALLAX, objective_results=[contra],
                   rubric_scores=strong_rubric, reviewer_decision=REV_PASS)
    check("contradictory evidence (required check failed) -> not qualified", not dc["qualified"])

    # ---- 7. tampered verification results ------------------------------------------
    tampered = copy.deepcopy(contra); tampered["passed"] = True   # flip verdict after signing
    check("tampered result fails integrity check", not ev.verify_result_integrity(tampered))
    dt = ac.decide(_parallax_bp(), authorization=AUTH_PARALLAX, objective_results=[tampered],
                   rubric_scores=strong_rubric, reviewer_decision=REV_PASS)
    check("decision ignores a tampered result (not trustworthy) -> not qualified", not dt["qualified"])

    # ---- 8. unauthorized reviewer changes / immutability ---------------------------
    signed = ac.sign_decision(remediated, candidate_id=2, unit_ref="C1")
    check("signed decision verifies", ac.verify_decision(signed))
    try:
        ac.append_adjudication(signed, reviewer_id="", note="sneaky")
        unauth_blocked = False
    except PermissionError:
        unauth_blocked = True
    check("unauthorized reviewer adjudication refused (no reviewer_id)", unauth_blocked)
    adj = ac.append_adjudication(signed, reviewer_id="admin-9", note="concur")
    check("adjudication is append-only: new record references parent, prior UNCHANGED",
          adj["record"]["parent_hash"] == signed["record"]["record_hash"]
          and ac.verify_decision(signed) and ac.verify_decision(adj))
    mutated = copy.deepcopy(signed); mutated["record"]["qualified"] = (not mutated["record"]["qualified"])
    check("mutating a signed decision breaks verification (immutable)", not ac.verify_decision(mutated))

    # ---- 9. protected-truth non-disclosure -----------------------------------------
    blob = signing.canonical(remediated).decode().lower()
    check("decision record discloses no hidden-truth fields",
          "truth" not in blob and "answer_key" not in blob and "ground_truth" not in blob)
    check("candidate self-certification is rejected",
          ev.reject_candidate_truth({"notes": "x", "remediation_success": True})
          and not ev.reject_candidate_truth({"notes": "x", "cited_evidence": []}))

    # least-privilege evaluator: scope to one index; out-of-scope citations are ignored
    events, truth = enterprise.generate("f1-eval", 2, "f1-seed", "A")
    idx = "ranger-f1-eval-b2"
    reader = cc.InMemoryReader(idx, events)
    mal = truth["incidents"][0]["event_uids"][0]
    scope = ev.EvaluatorScope(idx, ev.ProtectedTruthHandle(lambda: truth, "f1"))
    good_sub = {"incidents": [{"label": "i", "disposition": "confirmed_incident", "severity": "high",
                               "confidence": 70, "attack_techniques": ["T1078"], "primary_identity": "u",
                               "affected_assets": ["h"], "analyst_conclusion": "x",
                               "cited_evidence": [{"event_uid": mal, "index": idx,
                                                   "query": {"query": {"ids": {"values": [mal]}}},
                                                   "role": "primary"}]}]}
    r_good = ev.get_evaluator("event_reference").verify(good_sub, scope, reader)
    oos = copy.deepcopy(good_sub); oos["incidents"][0]["cited_evidence"][0]["index"] = "ranger-OTHER-b2"
    r_oos = ev.get_evaluator("event_reference").verify(oos, scope, reader)
    check("evaluator honors an in-scope citation", r_good["passed"] and r_good["verified"])
    check("evaluator REJECTS out-of-scope refs explicitly, fails closed, no data access",
          not r_oos["passed"] and r_oos["detail"]["error"] == "unauthorized_reference_outside_scope"
          and r_oos["detail"]["data_accessed"] is False)
    check("rejection discloses no foreign existence (salted fingerprints, not index values)",
          "ranger-OTHER-b2" not in signing.canonical(r_oos).decode()
          and len(r_oos["detail"]["rejected_fingerprints"]) >= 1)
    # agent_authorization is now IMPLEMENTED by PARALLAX Lab A; the still-unbuilt PARALLAX evaluators
    # (e.g. model_artifact_integrity) remain declared-but-gated and must still raise.
    try:
        ev.get_evaluator("model_artifact_integrity").verify({}, scope, reader); gated = False
    except NotImplementedError:
        gated = True
    check("unbuilt PARALLAX evaluators are declared but gated (raise)", gated)

    # ---- 10. deterministic, no-AI ---------------------------------------------------
    d_a = ac.decide(_strata_bp(), authorization=AUTH_STRATA, objective_results=[obj_pass],
                    rubric_scores={"report": 100}, reviewer_decision=REV_PASS)
    d_b = ac.decide(_strata_bp(), authorization=AUTH_STRATA, objective_results=[obj_pass],
                    rubric_scores={"report": 100}, reviewer_decision=REV_PASS)
    s_a = ac.sign_decision(d_a, candidate_id=1, unit_ref="b2")
    s_b = ac.sign_decision(d_b, candidate_id=1, unit_ref="b2")
    check("deterministic: identical inputs -> identical signed record hash + signature",
          s_a["record"]["record_hash"] == s_b["record"]["record_hash"]
          and s_a["signature"] == s_b["signature"])
    check("decision is marked non-AI + auditable", d_a["ai_involved"] is False and d_a["auditable"] is True)

    # ---- persistence: new models exist and round-trip (sqlite via create_app) -------
    import app as appmod
    from models import db, Candidate, AssessmentBlueprint, UnitResult, BoardResult
    application = appmod.create_app(); ctx = application.app_context(); ctx.push()
    cand = Candidate(handle="f1", name="F1", email="f@e", cohort="2026-A",
                     github_id="f1-gid", status="active", current_board=2)
    db.session.add(cand); db.session.commit()
    bp = AssessmentBlueprint(pathway="parallax", blueprint_version=1,
                             environment_version="valyria-ai-1", status="approved",
                             content_hash=ac.blueprint_hash(_parallax_bp()))
    db.session.add(bp); db.session.commit()
    ur = UnitResult(candidate_id=cand.id, pathway="parallax", unit_ref="C1",
                    blueprint_version=1, blueprint_hash=signed["record"]["blueprint_hash"],
                    qualified=signed["record"]["qualified"], reason=signed["record"]["reason"],
                    record_hash=signed["record"]["record_hash"], signature=signed["signature"])
    db.session.add(ur); db.session.commit()
    check("AssessmentBlueprint + UnitResult persist; STRATA BoardResult shape intact",
          AssessmentBlueprint.query.count() == 1 and UnitResult.query.count() == 1
          and {"objective_score", "objective_passed", "objective_sig"} <= set(BoardResult.__table__.columns.keys()))
    ctx.pop()

    worked_example()
    print(f"\n{P} passed, {F} failed")
    return F == 0


def worked_example():
    """Senior PARALLAX C1 (agent/RAG) evaluation, end to end, showing the critical-failure
    veto: a strong investigation report cannot qualify a candidate who left a critical
    authorization vulnerability unremediated; remediation flips the outcome."""
    print("\n--- worked example: RANGER PARALLAX C1 (agent/RAG trust-boundary) ---")
    events, truth = enterprise.generate("parallax-c1", 2, "c1-seed", "A")
    idx = "ranger-parallax-c1-b2"
    reader = cc.InMemoryReader(idx, events)
    mal = truth["incidents"][0]["event_uids"][0]
    scope = ev.EvaluatorScope(idx, ev.ProtectedTruthHandle(lambda: truth, "c1"))
    exploit_sub = {"incidents": [{"label": "cross-tenant read via indirect injection",
                                  "disposition": "confirmed_incident", "severity": "high",
                                  "confidence": 80, "attack_techniques": ["T1078"],
                                  "primary_identity": "svc", "affected_assets": ["rag"],
                                  "analyst_conclusion": "canary reached via retrieved doc",
                                  "cited_evidence": [{"event_uid": mal, "index": idx,
                                                      "query": {"query": {"ids": {"values": [mal]}}},
                                                      "role": "primary"}]}]}
    gate = ev.get_evaluator("event_reference").verify(exploit_sub, scope, reader)
    bp = _parallax_bp()
    bp["objective_checks"] = [{"check_id": gate["check_id"], "evaluator": "event_reference", "required": True}]
    bp["evidence_requirements"] = [{"kind": "exploit_trace", "satisfied_by": gate["check_id"], "required": True}]
    strong = {"reasoning": 95, "secure_design": 92, "recommendations": 90}

    d_unremediated = ac.decide(bp, authorization=AUTH_PARALLAX, objective_results=[gate],
                               critical_findings=[{"id": "unremediated_authz_vuln", "present": True}],
                               rubric_scores=strong, reviewer_decision=REV_PASS)
    print(f"  strong report, vuln UNREMEDIATED -> qualified={d_unremediated['qualified']} "
          f"reason={d_unremediated['reason']}")
    d_fixed = ac.decide(bp, authorization=AUTH_PARALLAX, objective_results=[gate],
                        critical_findings=[{"id": "unremediated_authz_vuln", "present": True, "remediated": True}],
                        rubric_scores=strong, reviewer_decision=REV_PASS)
    rec = ac.sign_decision(d_fixed, candidate_id=2, unit_ref="C1")
    print(f"  same report, vuln REMEDIATED    -> assessment={d_fixed['assessment_outcome']} "
          f"qualified={d_fixed['qualified']} reason={d_fixed['reason']} signed_ok={ac.verify_decision(rec)}")
    check("worked example: unremediated critical authz vuln blocks qualification despite strong report",
          not d_unremediated["qualified"] and d_unremediated["reason"] == "CRITICAL_FAILURE_VETO")
    check("worked example: remediation yields a signed, verifiable ASSESSMENT result "
          "but NOT a final qualification (a single assessment is assessment-only)",
          d_fixed["assessment_passed"] and not d_fixed["qualified"]
          and d_fixed["reason"] == "assessment_met" and ac.verify_decision(rec))


def test_assessment_contract():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
