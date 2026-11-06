"""PX-A1 (Board 3 - API object-level authorization) assessment spec + blueprint.

The candidate fixes a deliberately vulnerable notes API handler so that non-owners are denied
(object-level authorization / BOLA fix) without breaking legitimate owner access. The grader runs the
candidate's `handle()` in the sandbox against a sealed, per-instance request battery and measures pure
behavior: owner requests must succeed (allow_rate), non-owner and client-spoofing requests must be
denied (deny_rate), and a non-owner request that returns 200 is a leak (the vulnerability).

Unlike PX-D1/PX-D2 there is NO model anywhere: the authoritative score is a fully deterministic,
reproducible measurement of the candidate's code. The decision is stamped ai_involved=False.
"""
from __future__ import annotations

from typing import Any, Dict

import pathways
from siem import assessment_contract as ac

from .contracts import AssessmentSpec

OBJECTIVE_CHECK = "api_object_authorization"     # == evaluator kind == result check_id
CRITICAL_BREACH = "authz_bypass"
BLUEPRINT_VERSION = 1
ENVIRONMENT_VERSION = "pxa1-1.0.0"

OBJECTIVE_PASS = 75.0        # minimum measured composite (0-100) to PASS (authoritative)
LEAK_CEILING = 0.10         # non-owner access-success (leak) rate at/above this is a CRITICAL bypass
ALLOW_FLOOR = 0.50          # anti-gaming: denying legitimate owner access below this floor is a CRITICAL
                            # failure, so a "deny everything" handler can never pass

APISEC_SPEC = AssessmentSpec(
    assessment_id="PX-A1",
    version="1.0.0",
    title="API Object-Level Authorization (BOLA) Fix",
    competency="api_object_authorization",
    metric="authz_composite",
    pass_threshold=OBJECTIVE_PASS,
    params={"n_notes": 10, "objective_pass": OBJECTIVE_PASS,
            "leak_ceiling": LEAK_CEILING, "allow_floor": ALLOW_FLOOR},
    approved=False,   # informational; authority is a signed governance approval (parallax.governance)
)


def blueprint() -> Dict[str, Any]:
    """Immutable PX-A1 blueprint (pathway=parallax). Objective-only: the deterministic authorization
    measurement is the entire authoritative score (rubric weight 0, rubric_gates False), so the signed
    decision is ai_involved=False. Shape validated by assessment_contract.validate_blueprint."""
    return {
        "pathway": pathways.PATHWAY_PARALLAX,
        "blueprint_version": BLUEPRINT_VERSION,
        "assessment_id": APISEC_SPEC.assessment_id,
        "assessment_version": APISEC_SPEC.version,
        "environment_version": ENVIRONMENT_VERSION,
        "objective_checks": [
            {"check_id": OBJECTIVE_CHECK, "evaluator": OBJECTIVE_CHECK, "required": True,
             "describes": "measured allow/deny behavior of the candidate authorization handler"},
        ],
        "evidence_requirements": [
            {"kind": "measured_authorization_behavior", "satisfied_by": OBJECTIVE_CHECK, "required": True},
        ],
        "critical_failures": [
            {"id": CRITICAL_BREACH,
             "describes": "non-owner access-success (BOLA leak) rate at or above the ceiling, or owner "
                          "access denied below the floor"},
        ],
        "rubric_dimensions": [],
        "human_review": {
            "required": False,
            "criteria": "optional reviewer override; the score is produced automatically and "
                        "deterministically (no model in any scoring path)",
        },
        "decision_policy": {
            "type": ac.POLICY_PARALLAX_AUTO,
            "activated": True,
            "rubric_threshold": 0.0,
            "rubric_gates": False,
            "scoring_mode": "deterministic",
            "weights": {"objective": 1.0, "rubric": 0.0},
        },
    }
