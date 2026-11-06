"""PX-AR1 (Board 5 - Secure Architecture Review) assessment spec + blueprint.

The candidate reviews a system design in `architecture.py` (review(architecture) -> list[str]),
reporting the control violations present. The grader runs it in the sandbox against a sealed,
per-instance flawed+sound design pair and measures recall (violations found) and specificity (no
false findings on the sound design). No model anywhere; ai_involved=False.
"""
from __future__ import annotations

from typing import Any, Dict

import pathways
from siem import assessment_contract as ac

from .contracts import AssessmentSpec

OBJECTIVE_CHECK = "secure_architecture_review"
CRITICAL_BREACH = "architecture_gap"
BLUEPRINT_VERSION = 1
ENVIRONMENT_VERSION = "pxar1-1.0.0"

OBJECTIVE_PASS = 75.0
SECURITY_FLOOR = 0.60       # recall below this = CRITICAL gap (design flaws missed)
TASK_FLOOR = 0.70           # specificity below this = CRITICAL overblock (false findings on sound design)

ARCHITECTURE_SPEC = AssessmentSpec(
    assessment_id="PX-AR1",
    version="1.0.0",
    title="Secure Architecture Review",
    competency="secure_architecture_review",
    metric="architecture_composite",
    pass_threshold=OBJECTIVE_PASS,
    params={"objective_pass": OBJECTIVE_PASS, "security_floor": SECURITY_FLOOR, "task_floor": TASK_FLOOR},
    approved=False,
)


def blueprint() -> Dict[str, Any]:
    return {
        "pathway": pathways.PATHWAY_PARALLAX,
        "blueprint_version": BLUEPRINT_VERSION,
        "assessment_id": ARCHITECTURE_SPEC.assessment_id,
        "assessment_version": ARCHITECTURE_SPEC.version,
        "environment_version": ENVIRONMENT_VERSION,
        "objective_checks": [
            {"check_id": OBJECTIVE_CHECK, "evaluator": OBJECTIVE_CHECK, "required": True,
             "describes": "measured recall/specificity of the candidate's architecture review"},
        ],
        "evidence_requirements": [
            {"kind": "measured_architecture_review", "satisfied_by": OBJECTIVE_CHECK, "required": True},
        ],
        "critical_failures": [
            {"id": CRITICAL_BREACH,
             "describes": "recall below the floor (design flaws missed) or specificity below the floor "
                          "(false findings on a sound design)"},
        ],
        "rubric_dimensions": [],
        "human_review": {"required": False,
                         "criteria": "optional reviewer override; score is produced automatically and "
                                     "deterministically (no model in any scoring path)"},
        "decision_policy": {
            "type": ac.POLICY_PARALLAX_AUTO, "activated": True, "rubric_threshold": 0.0,
            "rubric_gates": False, "scoring_mode": "deterministic",
            "weights": {"objective": 1.0, "rubric": 0.0},
        },
    }
