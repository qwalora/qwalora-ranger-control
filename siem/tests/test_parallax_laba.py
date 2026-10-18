"""PARALLAX Lab A - Agent & Tool Authorization Security: full vertical-slice test suite.

Covers positive, negative, tampering, authorization, cross-candidate, cross-tenant, replay,
concurrency, and STRATA-regression cases. The simulator is a bounded offline deterministic environment
(no live model, no network, no candidate code execution); every "incident" is simulated, never
presented as externally observed.
"""
import json
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "parallax-laba-test")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

import pathways  # noqa: E402
from siem import assessment_contract as ac  # noqa: E402
import siem.evaluator as ev  # noqa: E402
from parallax import laba_assessment as A, governance, review  # noqa: E402
from parallax import laba_blueprint as BP, laba_sim as sim  # noqa: E402

COHORT = "2026-PX-A"
ADMINS = {"admin-1"}


@pytest.fixture(autouse=True)
def _gates_off():
    for k in ("RANGER_PARALLAX_QUALIFICATION_ACTIVE", "RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"):
        os.environ.pop(k, None)
    yield
    for k in ("RANGER_PARALLAX_QUALIFICATION_ACTIVE", "RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"):
        os.environ.pop(k, None)


def _approval():
    return governance.approve_spec(BP.LABA_SPEC, BP.blueprint(), approver_id="admin-1",
                                   authorized_admins=ADMINS)


def _reviewer(cand, attempt=1, decision="pass", authorized=True, assigned=True):
    binding = {"candidate_key": cand, "cohort": COHORT, "assessment_id": BP.LABA_SPEC.assessment_id,
               "attempt": attempt}
    directory = review.ReviewerDirectory(authorized=({"rev-1"} if authorized else set()))
    if assigned and authorized:
        directory.assign("rev-1", binding)
    return {"reviewer_id": "rev-1", "directory": directory, "decision": decision, "note": "root cause",
            "rubric_scores": {"rootcause_analysis_quality": 85}}


def _instance(cand):
    spec, contract, inst = A.bind_instance(cohort=COHORT, candidate_key=cand, approval=_approval(),
                                           authorized_admins=ADMINS)
    return spec, contract, inst, sim.truth(inst)


def _findings(breach_ids, analysis="injection bypassed the server-side tenant check"):
    return {"findings": [{"event_id": b, "classification": "unauthorized_access", "evidence": [b]}
                         for b in breach_ids], "analysis": analysis}


def _run(cand, submission, reviewer=None):
    return A.run_assessment(submission, cohort=COHORT, candidate_key=cand, approval=_approval(),
                            authorized_admins=ADMINS, reviewer=reviewer if reviewer is not None else _reviewer(cand))


# --- positive -------------------------------------------------------------------------------------
def test_competent_findings_pass_assessment_not_pathway():
    spec, contract, inst, t = _instance("gh-alice")
    r = _run("gh-alice", _findings(sorted(t["breaches"])))
    assert r["assessment_passed"] is True
    assert r["pathway_qualified"] is False
    assert r["objective_result"]["detail"]["f1"] == 1.0
    assert r["candidate_feedback"]["verdict"] == "pass"


def test_simulated_flag_present_and_incident_not_externally_observed():
    spec, contract, inst, t = _instance("gh-alice")
    brief = A.candidate_brief(cohort=COHORT, candidate_key="gh-alice", approval=_approval(),
                              authorized_admins=ADMINS)
    assert brief["simulated"] is True and brief["case"]["simulated"] is True


# --- negative -------------------------------------------------------------------------------------
def test_deny_everything_fails_on_precision():
    spec, contract, inst, t = _instance("gh-bob")
    allids = [e.event_id for e in inst.events]
    r = _run("gh-bob", _findings(allids))
    assert r["assessment_passed"] is False
    assert r["objective_result"]["detail"]["precision"] < BP.blueprint()["decision_policy"]["rubric_threshold"]
    assert r["candidate_feedback"]["verdict"] == "fail"


def test_incomplete_noncritical_misses_fail_on_f1():
    spec, contract, inst, t = _instance("gh-carol")
    # include ALL cross-tenant breaches (so no critical veto) but miss the non-cross-tenant ones
    partial = sorted(t["cross_tenant_breaches"])
    r = _run("gh-carol", _findings(partial))
    # not critical (no cross-tenant miss, no fabrication) but recall < 1 -> F1 below threshold
    assert r["objective_result"]["critical"] is False
    assert r["assessment_passed"] is False


def test_missed_cross_tenant_breach_is_critical():
    spec, contract, inst, t = _instance("gh-dan")
    one_missing = sorted(t["breaches"] - {sorted(t["cross_tenant_breaches"])[0]})
    r = _run("gh-dan", _findings(one_missing))
    assert r["objective_result"]["critical"] is True
    assert r["assessment_passed"] is False
    assert r["candidate_feedback"]["reason"] == "missed an actual cross-tenant breach"


def test_fabricated_finding_is_critical():
    spec, contract, inst, t = _instance("gh-eve")
    fab = _findings(sorted(t["breaches"]))
    fab["findings"].append({"event_id": "E99", "classification": "unauthorized_access", "evidence": ["E99"]})
    r = _run("gh-eve", fab)
    assert r["objective_result"]["critical"] is True
    assert r["candidate_feedback"]["reason"] == "asserted a breach with no valid evidence citation"


def test_candidate_self_certification_rejected():
    spec, contract, inst, t = _instance("gh-frank")
    sub = _findings(sorted(t["breaches"]))
    sub["passed"] = True  # forbidden self-certification key
    r = _run("gh-frank", sub)
    assert r["objective_result"]["detail"].get("error") == "candidate_supplied_truth"
    assert r["assessment_passed"] is False


# --- cross-tenant semantics -----------------------------------------------------------------------
def test_authorized_cross_tenant_grant_is_not_a_breach():
    """A cross-tenant op covered by an explicit policy grant is legitimate; flagging it is a false
    positive, proving 'cross-tenant == breach' is wrong and benign ops must keep working."""
    spec, contract, inst, t = _instance("gh-grace")
    grants = inst.policy["cross_tenant_grants"]
    # find a legitimate granted cross-tenant event
    granted_legit = [e for e in inst.events
                     if [e.principal_tenant, e.resource_tenant, e.tool] in grants
                     and sim.classify(inst.policy, e) == "legitimate"]
    assert granted_legit, "instance should contain an authorized cross-tenant op"
    # flag the true breaches PLUS a granted-legit event -> that extra flag is a false positive
    sub = _findings(sorted(t["breaches"]) + [granted_legit[0].event_id])
    r = _run("gh-grace", sub)
    assert r["objective_result"]["detail"]["breach_false_positives"] >= 1


# --- authorization / governance -------------------------------------------------------------------
def test_unapproved_or_drifted_spec_refused():
    with pytest.raises(Exception):
        A.bind_instance(cohort=COHORT, candidate_key="gh-x", approval={"record": {}, "signature": "x"},
                        authorized_admins=ADMINS)


def test_material_scoring_change_invalidates_approval():
    """Finding 5: the approval binds the complete scoring spec (spec + blueprint). A material change to
    the blueprint (e.g. lowering the rubric threshold or dropping a critical failure) invalidates the
    approval until it is reissued."""
    approval = _approval()
    governance.verify_approval(approval, BP.LABA_SPEC, BP.blueprint(), authorized_admins=ADMINS)  # ok
    bp = BP.blueprint()
    bp["decision_policy"]["rubric_threshold"] = 1.0           # material change
    with pytest.raises(governance.ApprovalError):
        governance.verify_approval(approval, BP.LABA_SPEC, bp, authorized_admins=ADMINS)
    bp2 = BP.blueprint()
    bp2["critical_failures"] = []                              # remove the critical-failure veto
    with pytest.raises(governance.ApprovalError):
        governance.verify_approval(approval, BP.LABA_SPEC, bp2, authorized_admins=ADMINS)


def test_unauthorized_approver_refused():
    with pytest.raises(governance.ApprovalError):
        governance.approve_spec(BP.LABA_SPEC, BP.blueprint(), approver_id="not-an-admin",
                                authorized_admins=ADMINS)


def test_unauthorized_reviewer_refused():
    spec, contract, inst, t = _instance("gh-harry")
    with pytest.raises(review.ReviewAuthorityError):
        _run("gh-harry", _findings(sorted(t["breaches"])),
             reviewer=_reviewer("gh-harry", authorized=False))


def test_unassigned_reviewer_refused():
    spec, contract, inst, t = _instance("gh-ivan")
    with pytest.raises(review.ReviewAuthorityError):
        _run("gh-ivan", _findings(sorted(t["breaches"])),
             reviewer=_reviewer("gh-ivan", assigned=False))


def test_missing_human_review_blocks_assessment():
    spec, contract, inst, t = _instance("gh-jane")
    r = A.run_assessment(_findings(sorted(t["breaches"])), cohort=COHORT, candidate_key="gh-jane",
                         approval=_approval(), authorized_admins=ADMINS, reviewer=None)
    assert r["assessment_passed"] is False   # objective met, but no verified human review


# --- cross-candidate isolation / non-transfer -----------------------------------------------------
def test_per_candidate_instances_and_non_transfer():
    _, ca, insta, ta = _instance("gh-alice")
    _, cb, instb, tb = _instance("gh-bob")
    assert ca.seed() != cb.seed()
    # candidate A's exact breach ids used against B's instance should not pass (solutions don't transfer)
    r = _run("gh-bob", _findings(sorted(ta["breaches"])))
    assert r["assessment_passed"] is False or r["objective_result"]["critical"] is True


def test_evaluator_scope_isolation():
    """An evaluator scope built for one candidate recomputes only that candidate's truth; it cannot
    reach another candidate's sealed instance."""
    _, _, insta, ta = _instance("gh-alice")
    _, _, instb, tb = _instance("gh-bob")
    scope_a = ev.EvaluatorScope(allowed_index="parallax-laba", truth_handle=A.make_truth_handle(insta))
    resolved = scope_a.truth_handle.resolve()["instance"]
    assert {e.event_id for e in resolved.events} == {e.event_id for e in insta.events}
    assert sim.truth(resolved)["breaches"] == ta["breaches"]


# --- replay / binding -----------------------------------------------------------------------------
def test_replay_is_deterministic():
    spec, contract, inst, t = _instance("gh-alice")
    sub = _findings(sorted(t["breaches"]))
    r1 = _run("gh-alice", sub)
    r2 = _run("gh-alice", sub)
    assert r1["objective_result"]["detail"]["f1"] == r2["objective_result"]["detail"]["f1"]
    assert r1["assessment_decision"]["provenance"]["submission_sha"] == \
        r2["assessment_decision"]["provenance"]["submission_sha"]


def test_signed_decision_tamper_detected():
    spec, contract, inst, t = _instance("gh-alice")
    r = _run("gh-alice", _findings(sorted(t["breaches"])))
    assert ac.verify_decision(r["signed"]) is True
    bad = json.loads(json.dumps(r["signed"]))
    bad["record"]["qualified"] = True
    assert ac.verify_decision(bad) is False


def test_adjudication_cannot_be_replayed_onto_another_assessment():
    spec, contract, inst, t = _instance("gh-kate")
    r = _run("gh-kate", _findings(sorted(t["breaches"])))
    adj = r["adjudication"]
    directory = review.ReviewerDirectory(authorized={"rev-1"})
    binding = r["binding"]
    directory.assign("rev-1", binding)
    # the adjudication is bound to its provenance hash; verifying it against a different record fails
    with pytest.raises(review.ReviewAuthorityError):
        review.verify_adjudication(adj, directory=directory, binding=binding,
                                   assessment_record_hash="different-provenance-hash")


# --- concurrency ----------------------------------------------------------------------------------
def test_concurrent_assessments_isolated():
    cands = ["gh-c%02d" % i for i in range(8)]
    results = {}
    errors = []

    def work(c):
        try:
            spec, contract, inst, t = _instance(c)
            results[c] = _run(c, _findings(sorted(t["breaches"])))
        except Exception as e:  # noqa: BLE001
            errors.append((c, repr(e)))

    threads = [threading.Thread(target=work, args=(c,)) for c in cands]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errors, errors
    assert len(results) == len(cands)
    for c in cands:
        r = results[c]
        assert r["assessment_passed"] is True
        assert r["binding"]["candidate_key"] == c
        assert ac.verify_decision(r["signed"]) is True


# --- protected metadata / STRATA baseline ---------------------------------------------------------
def test_protected_truth_absent_from_decision_and_feedback():
    spec, contract, inst, t = _instance("gh-leo")
    r = _run("gh-leo", _findings(sorted(t["breaches"])))
    blob = json.dumps({"d": r["assessment_decision"], "fb": r["candidate_feedback"], "s": r["signed"]})
    # no injection provenance string leaks
    for e in inst.events:
        if e._injection_note:
            assert e._injection_note not in blob


def test_strata_baseline_unaffected():
    import program
    from siem.evaluator import EventReferenceEvaluator
    assert program.PASS_BAR == 95.0
    assert isinstance(ev.EVALUATORS["event_reference"], EventReferenceEvaluator)
    # Lab A implemented the previously-declared agent_authorization evaluator (no longer a stub)
    from parallax.laba_evaluator import AgentAuthorizationEvaluator
    assert isinstance(ev.EVALUATORS["agent_authorization"], AgentAuthorizationEvaluator)
    assert pathways.PATHWAY_STRATA in ac.SUPPORTED_BLUEPRINT_VERSIONS
