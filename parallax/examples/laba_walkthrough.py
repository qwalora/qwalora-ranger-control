"""Deterministic end-to-end walkthrough of the PARALLAX Lab A workflow.

Run: SECRET_KEY=demo DATABASE_URL=sqlite:///:memory: python -m parallax.examples.laba_walkthrough

It prints, for one candidate instance: the candidate-safe brief (observable case, NO sealed truth),
a candidate's evidence-backed findings submission, the server-side verified reviewer adjudication, and
the signed assessment decision (assessment-level only; never a pathway qualification). Everything is a
bounded offline SIMULATION. No awards are made; both qualification gates are off.
"""
from __future__ import annotations

import json
import os

os.environ.setdefault("SECRET_KEY", "demo")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from parallax import laba_assessment as A, governance, review          # noqa: E402
from parallax import laba_blueprint as BP, laba_sim as sim             # noqa: E402

ADMINS = {"gov-admin"}
COHORT = "demo-cohort"
CAND = "gh-demo-candidate"


def main():
    print("=" * 78)
    print("PARALLAX Lab A - Agent & Tool Authorization Security (bounded offline simulation)")
    print("=" * 78)

    # 1. governance: an authorized admin approves the versioned spec (no hardcoded approval)
    approval = governance.approve_spec(BP.LABA_SPEC, BP.blueprint(), approver_id="gov-admin",
                                       authorized_admins=ADMINS)
    print("\n[1] Spec approved via governance: %s@%s (approver=gov-admin)"
          % (BP.LABA_SPEC.assessment_id, BP.LABA_SPEC.version))

    # 2. candidate-safe brief (observable case material only)
    brief = A.candidate_brief(cohort=COHORT, candidate_key=CAND, approval=approval,
                              authorized_admins=ADMINS)
    case = brief["case"]
    print("\n[2] Candidate-safe brief (simulated=%s):" % brief["simulated"])
    print("    tenants: %s" % case["tenants"])
    print("    tools:   %s" % case["tool_catalog"])
    print("    cross-tenant grants (authorized): %s" % case["authorization_policy"]["cross_tenant_grants"])
    print("    observable events (NO truth labels): %d" % len(case["events"]))
    for e in case["events"][:4]:
        print("      %s %-10s %-16s %-12s res=%-10s outcome=%s"
              % (e["event_id"], e["role"], e["principal"], e["tool"], e["resource_tenant"],
                 e["observed_outcome"]))
    print("      ... (%d more)" % (len(case["events"]) - 4))

    # 3. a competent candidate investigates and submits evidence-backed findings.
    #    (Here we derive the correct breaches server-side to simulate a competent candidate; a real
    #     candidate reasons them out from the policy + events. The grading truth is never shown.)
    spec, contract, inst = A.bind_instance(cohort=COHORT, candidate_key=CAND, approval=approval,
                                           authorized_admins=ADMINS)
    truth = sim.truth(inst)
    submission = {
        "findings": [{"event_id": b, "classification": "unauthorized_access", "evidence": [b]}
                     for b in sorted(truth["breaches"])],
        "analysis": ("Injected instructions in retrieved content drove cross-tenant reads and a "
                     "forbidden tool call that the gateway failed to block server-side; the policy's "
                     "tenant isolation was not enforced at the tool boundary."),
    }
    print("\n[3] Candidate submission: %d findings (breaches flagged with cited evidence)"
          % len(submission["findings"]))

    # 4. server-side verified reviewer adjudication (authorized + assigned; signed, bound)
    binding = {"candidate_key": CAND, "cohort": COHORT, "assessment_id": spec.assessment_id, "attempt": 1}
    directory = review.ReviewerDirectory(authorized={"reviewer-1"})
    directory.assign("reviewer-1", binding)
    reviewer = {"reviewer_id": "reviewer-1", "directory": directory, "decision": "pass",
                "note": "root-cause analysis correct and evidence-backed",
                "rubric_scores": {"rootcause_analysis_quality": 88}}

    # 5. grade through the platform contract
    r = A.run_assessment(submission, cohort=COHORT, candidate_key=CAND, approval=approval,
                         authorized_admins=ADMINS, reviewer=reviewer)
    det = r["objective_result"]["detail"]
    print("\n[4] Objective evaluation (independent policy replay on the sealed holdout):")
    print("    breach TP/FP/FN = %d/%d/%d  precision=%.2f recall=%.2f f1=%.2f (threshold %.2f)"
          % (det["breach_true_positives"], det["breach_false_positives"], det["breach_false_negatives"],
             det["precision"], det["recall"], det["f1"], det["f1_threshold"]))
    print("\n[5] Assessment decision (signed, bound):")
    print("    assessment_passed : %s" % r["assessment_passed"])
    print("    pathway_qualified : %s   (%s)" % (r["pathway_qualified"], r["pathway_note"]))
    print("    candidate feedback: %s" % json.dumps(r["candidate_feedback"]))
    prov = r["assessment_decision"]["provenance"]
    print("    provenance bindings: submission_sha=%s… blueprint_hash=%s… contract_mac=%s… adjud=%s…"
          % (prov["submission_sha"][:10], prov["blueprint_hash"][:10], prov["contract_mac"][:10],
             (prov["adjudication_hash"] or "")[:10]))
    from siem import assessment_contract as ac
    print("    signature verifies: %s" % ac.verify_decision(r["signed"]))
    print("\nNote: SIMULATION only. No credit awarded; both qualification gates are OFF; a single lab "
          "is never a pathway qualification.")


if __name__ == "__main__":
    main()
