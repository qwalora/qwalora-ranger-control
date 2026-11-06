"""PX-DE1 (Board 2 - Detection Engineering) assessment spec + blueprint.

The candidate writes detection rules in `detect.py` (detect(events) -> list[int]) that flag the
malicious events in a sealed log stream. The grader runs them in the sandbox against a sealed,
per-instance event stream and measures recall (attacks caught) and specificity (benign not alerted).
No model anywhere; ai_involved=False.
"""
from __future__ import annotations

from typing import Any, Dict

import pathways
from siem import assessment_contract as ac

from .contracts import AssessmentSpec

OBJECTIVE_CHECK = "detection_engineering"
CRITICAL_BREACH = "detection_miss"
BLUEPRINT_VERSION = 1
ENVIRONMENT_VERSION = "pxde1-1.0.0"

OBJECTIVE_PASS = 75.0        # minimum measured composite (0-100) to PASS (authoritative)
SECURITY_FLOOR = 0.60       # recall below this = CRITICAL miss (attacks slipping through)
TASK_FLOOR = 0.70           # specificity below this = CRITICAL overblock (alert fatigue / false alarms)

DETECTION_SPEC = AssessmentSpec(
    assessment_id="PX-DE1",
    version="1.0.0",
    title="Detection Engineering (SOC)",
    competency="detection_engineering",
    metric="detection_composite",
    pass_threshold=OBJECTIVE_PASS,
    params={"objective_pass": OBJECTIVE_PASS, "security_floor": SECURITY_FLOOR, "task_floor": TASK_FLOOR},
    approved=False,
)


def blueprint() -> Dict[str, Any]:
    """Immutable PX-DE1 blueprint (pathway=parallax). Objective-only: the deterministic detection
    measurement is the entire authoritative score (rubric weight 0, rubric_gates False), so the signed
    decision is ai_involved=False."""
    return {
        "pathway": pathways.PATHWAY_PARALLAX,
        "blueprint_version": BLUEPRINT_VERSION,
        "assessment_id": DETECTION_SPEC.assessment_id,
        "assessment_version": DETECTION_SPEC.version,
        "environment_version": ENVIRONMENT_VERSION,
        "objective_checks": [
            {"check_id": OBJECTIVE_CHECK, "evaluator": OBJECTIVE_CHECK, "required": True,
             "describes": "measured recall/specificity of the candidate's detection rules"},
        ],
        "evidence_requirements": [
            {"kind": "measured_detection_behavior", "satisfied_by": OBJECTIVE_CHECK, "required": True},
        ],
        "critical_failures": [
            {"id": CRITICAL_BREACH,
             "describes": "recall below the floor (attacks missed) or specificity below the floor "
                          "(too many false alerts)"},
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
