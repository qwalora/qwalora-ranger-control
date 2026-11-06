"""PX-CAP (Capstone) assessment spec + blueprint. A composite board: the candidate submits one repo
with four component files (authz.py, detect.py, gates.py, architecture.py), each graded by its own
board's sandboxed measurement against a sealed per-instance fixture. The capstone passes IFF EVERY
component passes its board's bar and none critical-fails. No model anywhere; ai_involved=False.
"""
from __future__ import annotations

from typing import Any, Dict

import pathways
from siem import assessment_contract as ac

from .contracts import AssessmentSpec

OBJECTIVE_CHECK = "parallax_capstone"
CRITICAL_BREACH = "capstone_component_failure"
BLUEPRINT_VERSION = 1
ENVIRONMENT_VERSION = "pxcap-1.0.0"

OBJECTIVE_PASS = 75.0   # informational; the gate is "every component passed" (evaluator passed flag)

CAPSTONE_SPEC = AssessmentSpec(
    assessment_id="PX-CAP",
    version="1.0.0",
    title="PARALLAX Capstone (multi-competency)",
    competency="parallax_capstone",
    metric="capstone_mean_composite",
    pass_threshold=OBJECTIVE_PASS,
    params={"objective_pass": OBJECTIVE_PASS},
    approved=False,
)


def blueprint() -> Dict[str, Any]:
    return {
        "pathway": pathways.PATHWAY_PARALLAX,
        "blueprint_version": BLUEPRINT_VERSION,
        "assessment_id": CAPSTONE_SPEC.assessment_id,
        "assessment_version": CAPSTONE_SPEC.version,
        "environment_version": ENVIRONMENT_VERSION,
        "objective_checks": [
            {"check_id": OBJECTIVE_CHECK, "evaluator": OBJECTIVE_CHECK, "required": True,
             "describes": "every component board (authz, detection, gates, architecture) passed"},
        ],
        "evidence_requirements": [
            {"kind": "all_components_passed", "satisfied_by": OBJECTIVE_CHECK, "required": True},
        ],
        "critical_failures": [
            {"id": CRITICAL_BREACH,
             "describes": "any component board critical-failed or did not pass its bar"},
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
