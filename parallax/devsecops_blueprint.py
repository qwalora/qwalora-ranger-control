"""PX-S1 (Board 4 - Secure Release Gate) assessment spec + blueprint.

The candidate implements CI/CD security gates in `gates.py` (secret-scan, CI merge gate, dependency/
SBOM release gate). The grader runs them in the sandbox against a sealed, per-instance battery and
measures pure behavior: the security rate (correct BLOCKS over the positive battery - secrets, failing
builds, vulnerable deps caught) and the task rate (correct ALLOWS over the negative-control battery -
clean code, green builds, clean SBOMs not blocked). No model anywhere; ai_involved=False.
"""
from __future__ import annotations

from typing import Any, Dict

import pathways
from siem import assessment_contract as ac

from .contracts import AssessmentSpec

OBJECTIVE_CHECK = "devsecops_release_gate"
CRITICAL_BREACH = "gate_bypass"
BLUEPRINT_VERSION = 1
ENVIRONMENT_VERSION = "pxs1-1.0.0"

OBJECTIVE_PASS = 75.0        # minimum measured composite (0-100) to PASS (authoritative)
SECURITY_FLOOR = 0.70       # security rate below this = CRITICAL bypass (threats getting through)
TASK_FLOOR = 0.50           # negative-control allow rate below this = CRITICAL overblock (block-all)

DEVSECOPS_SPEC = AssessmentSpec(
    assessment_id="PX-S1",
    version="1.0.0",
    title="Secure Release Gate (CI/CD DevSecOps)",
    competency="secure_release_gate",
    metric="gate_composite",
    pass_threshold=OBJECTIVE_PASS,
    params={"objective_pass": OBJECTIVE_PASS, "security_floor": SECURITY_FLOOR, "task_floor": TASK_FLOOR},
    approved=False,
)


def blueprint() -> Dict[str, Any]:
    """Immutable PX-S1 blueprint (pathway=parallax). Objective-only: the deterministic gate measurement
    is the entire authoritative score (rubric weight 0, rubric_gates False), so the signed decision is
    ai_involved=False."""
    return {
        "pathway": pathways.PATHWAY_PARALLAX,
        "blueprint_version": BLUEPRINT_VERSION,
        "assessment_id": DEVSECOPS_SPEC.assessment_id,
        "assessment_version": DEVSECOPS_SPEC.version,
        "environment_version": ENVIRONMENT_VERSION,
        "objective_checks": [
            {"check_id": OBJECTIVE_CHECK, "evaluator": OBJECTIVE_CHECK, "required": True,
             "describes": "measured block/allow behavior of the candidate's CI/CD security gates"},
        ],
        "evidence_requirements": [
            {"kind": "measured_gate_behavior", "satisfied_by": OBJECTIVE_CHECK, "required": True},
        ],
        "critical_failures": [
            {"id": CRITICAL_BREACH,
             "describes": "security rate below the floor (threats pass the gates), or allow rate below "
                          "the floor (legitimate releases blocked)"},
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
