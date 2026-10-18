"""F5.1 - approved, versioned, CANDIDATE-SAFE scenario metadata for the Workbench.

A Case references an entry here by (scenario_ref, scenario_version). An entry carries ONLY what a
candidate is authorized to see - authorized scope, technical objectives, permitted operations,
available environment interfaces, evidence requirements, submission conditions and assessment
boundaries. It NEVER contains hidden scenario truth, expected answers, exploit solutions, model
secrets, evaluator logic, cohort variants, hints, tutorials or coaching.

Different cases reference different entries, so the workbench does not show the same challenge for
every PARALLAX case. When a case references an unknown (ref, version), the workbench shows an
accurate "instructions not available / not yet assigned" state rather than inventing content.
"""
from __future__ import annotations

import pathways

SCENARIO_CONTRACT_VERSION = 1

# scenario_ref -> scenario_version -> candidate-safe metadata.
# Each version carries an explicit `approved` flag: approval is NEVER inferred from mere presence in
# this catalog (an unapproved/draft entry is not submittable). `REVOKED` lists (ref, version) pairs
# whose assignment has been withdrawn. Superseding a version with a newer one does NOT auto-invalidate
# the older one: a candidate pinned to a previously-assigned, still-approved version keeps working to
# that version (explicit versioning policy), unless the pair is revoked.
SCENARIOS = {
    "parallax-agent-authz": {
        1: {
            "title": "Agent authorization boundary review",
            "pathway": pathways.PATHWAY_PARALLAX,
            "approved": True,
            "authorized_scope": "Investigate the provided AI-agent execution evidence within the "
                                "authorized environment. Establish, with evidence, what the agent "
                                "was authorized to do and what it actually did. Do not attempt to "
                                "access systems outside the authorized scope.",
            "technical_objectives": [
                "Characterize the agent's authorization decisions from the trace",
                "Determine whether any requested action was denied, and on what basis",
                "Assess the security significance of the observed authorization behavior",
                "State the limitations of your analysis"],
            "permitted_operations": [
                "Review and download the authorized evidence provided in your workspace",
                "Submit additional typed evidence that supports your claims",
                "Record technical findings and an investigation package"],
            "environment_interfaces": [
                "Candidate evidence workspace (read + authorized download)",
                "Typed evidence submission (schema-validated, preserved, hashed)"],
            "evidence_requirements": [
                {"kind": "agent_trace", "required": True,
                 "note": "a schema-valid agent/model execution trace supporting your claims"},
                {"kind": "technical_report", "required": True,
                 "note": "your written findings package"}],
            "submission_conditions": "At least one technical finding recorded and all required "
                                     "evidence attached. Submission is immutable once final.",
            "assessment_boundaries": "Independent technical verification and reviewer adjudication "
                                     "determine the outcome. Submission is not qualification.",
        },
    },
    "parallax-data-provenance": {
        1: {
            "title": "Synthetic-media provenance assessment",
            "pathway": pathways.PATHWAY_PARALLAX,
            "approved": True,
            "authorized_scope": "Assess the provenance signals present in the authorized media "
                                "evidence. Establish, with evidence, what can and cannot be "
                                "determined about its origin and integrity.",
            "technical_objectives": [
                "Inventory the provenance signals actually present in the evidence",
                "Distinguish verifiable integrity claims from indeterminate ones",
                "Assess the significance and the limits of what provenance establishes"],
            "permitted_operations": [
                "Review and download the authorized media evidence",
                "Submit typed supporting evidence",
                "Record technical findings and an investigation package"],
            "environment_interfaces": [
                "Candidate evidence workspace (read + authorized download)",
                "Typed evidence submission (schema-validated, preserved, hashed)"],
            "evidence_requirements": [
                {"kind": "provenance_manifest", "required": False,
                 "note": "a content-credentials / C2PA manifest, if available"},
                {"kind": "technical_report", "required": True,
                 "note": "your written findings package"}],
            "submission_conditions": "At least one technical finding recorded and the required "
                                     "report attached. Submission is immutable once final.",
            "assessment_boundaries": "A missing or indeterminate provenance signal is not evidence "
                                     "of fakery. Outcomes are independently verified.",
        },
    },
    "strata-soc-triage": {
        1: {
            "title": "SOC triage and scope reconstruction",
            "pathway": pathways.PATHWAY_STRATA,
            "approved": True,
            "authorized_scope": "Investigate the authorized telemetry within your assigned "
                                "environment and establish, with evidence, the nature and scope of "
                                "the activity. Stay within the authorized scope.",
            "technical_objectives": [
                "Reconstruct the activity timeline from authorized telemetry",
                "Establish affected assets and scope with supporting evidence",
                "Assess security significance", "State limitations"],
            "permitted_operations": [
                "Review authorized telemetry", "Record findings and an investigation package"],
            "environment_interfaces": ["Authorized investigation surface"],
            "evidence_requirements": [
                {"kind": "technical_report", "required": True, "note": "your written findings package"}],
            "submission_conditions": "At least one technical finding recorded. Submission is "
                                     "immutable once final.",
            "assessment_boundaries": "Graded against the authorized objective bar and reviewer "
                                     "adjudication.",
        },
    },
}


# (scenario_ref, scenario_version) pairs whose assignment has been revoked/superseded in a way that
# invalidates the active assignment. A pinned historical version NOT listed here stays submittable.
REVOKED = set()


def _ver(scenario_version):
    try:
        return int(scenario_version or 1)
    except (TypeError, ValueError):
        return None


def get(scenario_ref, scenario_version):
    """Return the candidate-safe metadata for a case, or None when unavailable/not assigned."""
    if not scenario_ref:
        return None
    v = _ver(scenario_version)
    if v is None:
        return None
    entry = SCENARIOS.get(scenario_ref, {}).get(v)
    if not entry:
        return None
    out = dict(entry)
    out["scenario_ref"] = scenario_ref
    out["scenario_version"] = v
    out["scenario_contract_version"] = SCENARIO_CONTRACT_VERSION
    return out


def eligibility(scenario_ref, scenario_version, *, pathway=None):
    """Fail-closed eligibility of a case's scenario assignment for final submission. Returns
    {"ok": bool, "status": <code>, "reason": <candidate-safe text or None>}.

    A missing / unknown / unsupported-version / unapproved / wrong-pathway / revoked / incomplete
    scenario is NOT submittable; crucially, a missing scenario is never treated as a scenario with no
    requirements. The `reason` is candidate-safe: it exposes no hidden truth, objectives, or hints."""
    if not scenario_ref:
        return {"ok": False, "status": "no_scenario",
                "reason": "No approved scenario is assigned to this case yet."}
    fam = SCENARIOS.get(scenario_ref)
    if not fam:
        return {"ok": False, "status": "unknown_scenario",
                "reason": "The assigned scenario is not available."}
    v = _ver(scenario_version)
    entry = fam.get(v) if v is not None else None
    if not entry:
        return {"ok": False, "status": "unsupported_version",
                "reason": "The assigned scenario version is not available."}
    if (scenario_ref, v) in REVOKED:
        return {"ok": False, "status": "revoked",
                "reason": "The assigned scenario is no longer available for submission."}
    # approval is explicit; presence in the catalog is NOT approval
    if entry.get("approved") is not True:
        return {"ok": False, "status": "unapproved",
                "reason": "The assigned scenario is not currently approved for submission."}
    if pathway is not None and (
            pathways.normalize_pathway(entry.get("pathway"))
            != pathways.normalize_pathway(pathway)):
        return {"ok": False, "status": "wrong_pathway",
                "reason": "The assigned scenario is not available for your pathway."}
    # required evidence + submission conditions must be defined for a complete, submittable scenario
    if not entry.get("evidence_requirements") or not entry.get("submission_conditions"):
        return {"ok": False, "status": "incomplete",
                "reason": "The assigned scenario is not ready for submission."}
    return {"ok": True, "status": "ok", "reason": None}
