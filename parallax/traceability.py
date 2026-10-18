"""PARALLAX Phase 1E Workstream C - evidence-to-decision traceability verifier.

Reconstructs the complete, independently-inspectable chain for one candidate's assessment from the
EXISTING persisted + cryptographic architecture (no competing ledger): governance approval (registry),
signed decision + adjudication (assessment_store / UnitResult), reviewer assignment (reviewer_store),
and the signed audit chain (audit_integrity). Produces a machine-readable result with a four-state
verdict and the assessment-only disposition. It NEVER converts missing evidence into success and NEVER
reports a single assessment as a qualified pathway.

Verdict:
  VALID       - required evidence and signatures are present and verify.
  INVALID     - a demonstrated mismatch, unauthorized operation, or integrity failure.
  INCOMPLETE  - a required artifact is missing (e.g. no decision record yet, or no active approval).
  UNAVAILABLE - an authoritative dependency could not be accessed (DB/infra error).
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

import signing
from siem import assessment_contract as ac
from . import registry, reviewer_store, assessment_store, audit_integrity
from . import laba_blueprint as BP

VALID, INVALID, INCOMPLETE, UNAVAILABLE = "VALID", "INVALID", "INCOMPLETE", "UNAVAILABLE"

# The only assessment currently implemented is Lab A (a bounded, explicitly-SIMULATED environment).
_SPECS = {"LAB-A": lambda: (BP.LABA_SPEC, BP.blueprint())}


def _sha(obj) -> str:
    return hashlib.sha256(signing.canonical(obj)).hexdigest()


def verify_assessment(db, *, candidate_key: str, assessment_id: str) -> Dict[str, Any]:
    """Reconstruct and verify the full chain for (candidate, assessment). Returns a machine-readable
    dict: {verdict, reason, fields, disposition, simulation}. Fail-closed and never raises."""
    out: Dict[str, Any] = {"assessment_id": assessment_id, "candidate_key": candidate_key,
                           "fields": {}, "disposition": {"qualified": False, "assessment_only": True},
                           "simulation": True, "simulation_label": "Lab A bounded simulation"}
    try:
        if assessment_id not in _SPECS:
            return {**out, "verdict": INCOMPLETE, "reason": "unknown_assessment_id"}
        spec, blueprint = _SPECS[assessment_id]()

        # (a) governance approval - authoritative + signature-valid + approver still authorized
        try:
            approval = registry.active_spec_approval(db, spec, blueprint)
        except Exception as e:  # noqa: BLE001
            return {**out, "verdict": UNAVAILABLE, "reason": "governance_unavailable:%s" % type(e).__name__}
        out["fields"]["governance_approval"] = {
            "present": approval is not None,
            "content_hash": (registry.governance.scoring_spec_hash(spec, blueprint)),
            "verifies": approval is not None}
        if approval is None:
            return {**out, "verdict": INCOMPLETE, "reason": "no_active_governance_approval"}

        # (b) signed decision record
        try:
            rec = assessment_store.assessment_record_for(db, candidate_key=candidate_key,
                                                         assessment_id=assessment_id)
        except Exception as e:  # noqa: BLE001
            return {**out, "verdict": UNAVAILABLE, "reason": "records_unavailable:%s" % type(e).__name__}
        if rec is None:
            return {**out, "verdict": INCOMPLETE, "reason": "no_assessment_record"}
        signed_decision = rec["signed_decision"]
        if not ac.verify_decision(signed_decision):
            return {**out, "verdict": INVALID, "reason": "decision_signature_invalid"}
        drec = signed_decision["record"]
        decision = drec.get("decision") or {}
        prov = decision.get("provenance") or {}
        binding = prov.get("binding") or {}
        breakdown = decision.get("breakdown") or {}

        # substitution guard: the record's own signed binding must name this candidate
        if binding.get("candidate_key") != candidate_key:
            return {**out, "verdict": INVALID, "reason": "candidate_binding_mismatch"}
        if (drec.get("pathway") != "parallax") or (decision.get("pathway") != "parallax"):
            return {**out, "verdict": INVALID, "reason": "pathway_mismatch"}
        if decision.get("qualified") is True:  # a single assessment must never be qualified
            return {**out, "verdict": INVALID, "reason": "single_assessment_marked_qualified"}

        out["fields"].update({
            "assessment_version": drec.get("blueprint_version"),
            "cohort": binding.get("cohort"), "attempt": binding.get("attempt"),
            "unit_ref": drec.get("unit_ref"),
            "contract_mac": prov.get("contract_mac"),
            "blueprint_hash": drec.get("blueprint_hash") or decision.get("blueprint_hash"),
            "evidence_provenance": {"submission_sha": prov.get("submission_sha"),
                                    "objective_result_sig": prov.get("objective_result_sig")},
            "evaluator": {"id": BP.OBJECTIVE_CHECK, "blueprint_version": drec.get("blueprint_version")},
            "scoring_result": {"objective_checks_ok": (breakdown.get("objective_checks") or {}).get("ok"),
                               "evidence_ok": (breakdown.get("evidence_requirements") or {}).get("ok"),
                               "critical_veto": (breakdown.get("critical_failures") or {}).get("veto"),
                               "reason": decision.get("reason")},
            "decision_record_hash": drec.get("record_hash"),
            "decision_signing_kid": signing.kid_for(drec, signed_decision["signature"]),
            "persistence_state": "persisted",
        })

        objective_ok = (bool((breakdown.get("objective_checks") or {}).get("ok"))
                        and bool((breakdown.get("evidence_requirements") or {}).get("ok"))
                        and not bool((breakdown.get("critical_failures") or {}).get("veto")))

        # (c) reviewer adjudication (optional until a reviewer acts)
        reviewer_pass = False
        adjudication = rec.get("adjudication")
        if adjudication is not None:
            arec = adjudication.get("record") or {}
            asig = adjudication.get("signature")
            # cryptographic + binding verification (independent of current assignment liveness). The
            # adjudication record carries the binding fields FLAT (candidate_key/cohort/assessment_id/
            # attempt) plus the assessment_record_hash it is bound to.
            bound = (arec.get("candidate_key") == binding.get("candidate_key")
                     and arec.get("cohort") == binding.get("cohort")
                     and arec.get("assessment_id") == binding.get("assessment_id")
                     and int(arec.get("attempt", -1)) == int(binding.get("attempt", -2))
                     and arec.get("assessment_record_hash") == prov.get("provenance_hash"))
            if not bound or not signing.verify(arec, asig):
                return {**out, "verdict": INVALID, "reason": "adjudication_binding_or_signature_invalid"}
            reviewer_id = arec.get("reviewer_id")
            try:
                assigned_now = reviewer_store._assignments_map(
                    db, candidate_key=candidate_key, cohort=binding.get("cohort"),
                    assessment_id=assessment_id)
            except Exception:  # noqa: BLE001
                assigned_now = {}
            out["fields"]["reviewer"] = {
                "reviewer_id": reviewer_id, "decision": arec.get("decision"),
                "currently_assigned": reviewer_id in set(assigned_now.values()),
                "adjudication_record_hash": _sha(arec),
                "adjudication_signing_kid": signing.kid_for(arec, asig)}
            reviewer_pass = (arec.get("decision") == "pass" and bool(reviewer_id))
        else:
            out["fields"]["reviewer"] = {"reviewer_id": None, "decision": None,
                                         "currently_assigned": False}

        # rubric gate, recomputed independently from the adjudication's scores + blueprint threshold
        threshold = ((decision.get("policy") or {}).get("rubric_threshold"))
        rubric_scores = ((adjudication or {}).get("record") or {}).get("rubric_scores") or {}
        rubric_agg = ac._aggregate_rubric(blueprint, rubric_scores)
        rubric_ok = (rubric_agg is not None and threshold is not None and rubric_agg >= threshold)

        # (d) audit chain references + integrity
        try:
            audit = audit_integrity.integrity_report(db)
        except Exception as e:  # noqa: BLE001
            return {**out, "verdict": UNAVAILABLE, "reason": "audit_unavailable:%s" % type(e).__name__}
        out["fields"]["audit"] = {"status": audit.get("status"), "chain_ok": audit.get("chain_ok"),
                                  "event_count": audit.get("event_count"),
                                  "head_hash": audit.get("head_hash")}
        if audit.get("chain_ok") is False:
            return {**out, "verdict": INVALID, "reason": "audit_chain_broken"}

        # assessment-only disposition (NEVER qualified)
        requirements_met = bool(objective_ok and reviewer_pass and rubric_ok)
        out["disposition"] = {
            "qualified": False, "assessment_only": True,
            "requirements_met": requirements_met,
            "objective_ok": objective_ok, "reviewer_pass": reviewer_pass,
            "rubric_ok": rubric_ok, "rubric_aggregate": rubric_agg, "rubric_threshold": threshold,
            "awaiting_review": adjudication is None,
            "statement": ("individual assessment requirements met (assessment-only; NOT a pathway "
                          "qualification)" if requirements_met else
                          ("awaiting reviewer adjudication" if adjudication is None else
                           "individual assessment requirements not met"))}
        return {**out, "verdict": VALID, "reason": "ok"}
    except Exception as e:  # noqa: BLE001 - any unexpected error fails closed as UNAVAILABLE
        return {**out, "verdict": UNAVAILABLE, "reason": "unexpected:%s" % type(e).__name__}
