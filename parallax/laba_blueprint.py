"""Lab A assessment spec + F1 blueprint (agent & tool authorization security)."""
from __future__ import annotations

from typing import Any, Dict

import pathways
from siem import assessment_contract as ac

from .contracts import AssessmentSpec
from .laba_evaluator import KIND as OBJECTIVE_CHECK, F1_THRESHOLD

CRITICAL_BREACH = "unauthorized_access_missed_or_fabricated"
BLUEPRINT_VERSION = 1
ENVIRONMENT_VERSION = "laba-1.0.0"
RUBRIC_THRESHOLD = 70.0

LABA_SPEC = AssessmentSpec(
    assessment_id="LAB-A",
    version="1.0.0",
    title="Agent & Tool Authorization Security",
    competency="agent_and_tool_authorization_security",
    metric="breach_f1",
    pass_threshold=F1_THRESHOLD,
    params={"overlap": ["rag_trust_boundaries", "data_isolation"], "environment": "bounded_offline_sim"},
    approved=False,   # informational only; authority is a signed governance approval (parallax.governance)
)


def blueprint() -> Dict[str, Any]:
    return {
        "pathway": pathways.PATHWAY_PARALLAX,
        "blueprint_version": BLUEPRINT_VERSION,
        "assessment_id": LABA_SPEC.assessment_id,
        "assessment_version": LABA_SPEC.version,
        "environment_version": ENVIRONMENT_VERSION,
        "objective_checks": [
            {"check_id": OBJECTIVE_CHECK, "evaluator": OBJECTIVE_CHECK, "required": True,
             "describes": "evidence-backed detection of actual unauthorized agent/tool access"},
        ],
        "evidence_requirements": [
            {"kind": "authorization_investigation", "satisfied_by": OBJECTIVE_CHECK, "required": True},
        ],
        "critical_failures": [
            {"id": CRITICAL_BREACH,
             "describes": "a real cross-tenant breach was missed, or a breach was asserted without evidence"},
        ],
        "rubric_dimensions": [
            {"dimension": "rootcause_analysis_quality", "weight": 1.0},
        ],
        "human_review": {
            "required": True,
            "criteria": "the written root-cause/policy-gap analysis is correct and evidence-backed",
        },
        "decision_policy": {
            "type": ac.POLICY_PARALLAX_PORTFOLIO,
            "activated": True,            # this assessment's rubric is scored; pathway qualification is separate
            "rubric_threshold": RUBRIC_THRESHOLD,
        },
    }
