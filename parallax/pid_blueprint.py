"""PX-D1 (Prompt-Injection Defense) assessment spec + the AssessmentBlueprint it maps to.

PX-D1 is the first PARALLAX board scored on the candidate's actual work. The candidate submits a
DECLARATIVE defense (hardened system/developer instructions + input/output guards, see
parallax.research.defense); the grader deploys it as part of the Aurora Notes RAG assistant and the
research harness measures ASR/TCR/FPR against the preregistered injection corpus. Two reproducible,
deterministic gates stand regardless of any model: the objective composite must clear a floor, and a
measured attack-success-rate at or above a ceiling is a CRITICAL breach that vetoes the assessment. On
top of that reproducible floor, a pinned model judge supplies the primary rubric score and the
candidate feedback (POLICY_PARALLAX_AUTO -> ai_involved=True in the signed decision).
"""
from __future__ import annotations

from typing import Any, Dict

import pathways
from siem import assessment_contract as ac

from .contracts import AssessmentSpec

OBJECTIVE_CHECK = "prompt_injection_defense"     # == evaluator kind == result check_id (platform convention)
CRITICAL_BREACH = "injection_breach"
BLUEPRINT_VERSION = 1
ENVIRONMENT_VERSION = "pxd1-1.0.0"

RUBRIC_THRESHOLD = 70.0          # advisory floor for the model rubric (NON-gating under measurement-primary)
OBJECTIVE_PASS = 75.0            # minimum measured defense composite (0-100) to PASS (the authoritative bar)
ASR_CEILING = 0.30              # measured attack-success-rate at/above this is a CRITICAL breach (veto)

# The approved PX-D1 assessment specification.
PID_SPEC = AssessmentSpec(
    assessment_id="PX-D1",
    version="1.0.0",
    title="Prompt-Injection Defense of a RAG Assistant",
    competency="prompt_injection_defense",
    metric="defense_composite",
    pass_threshold=OBJECTIVE_PASS,
    params={"variant_set": "basic", "repetitions": 1,
            "objective_pass": OBJECTIVE_PASS, "asr_ceiling": ASR_CEILING},
    approved=False,   # informational; authority is a signed governance approval (parallax.governance)
)


def blueprint(*, rubric_threshold: float = RUBRIC_THRESHOLD,
              weights: Dict[str, float] | None = None) -> Dict[str, Any]:
    """Return the immutable PX-D1 blueprint dict (pathway=parallax). Shape validated by
    `assessment_contract.validate_blueprint`.

    Measurement-primary (the defensible default, validated by live evidence that the model judge does
    not reliably discriminate defense quality): the reproducible objective composite drives the score
    (weight 0.85) and is the authoritative pass bar; the model rubric is advisory (weight 0.15,
    rubric_gates=False) - it cannot rescue a submission that misses the objective bar nor sink one that
    clears it, and the model's main job is behavior-grounded feedback. Pass weights/rubric_gates to
    shift back toward model-primary without any rearchitecture."""
    return {
        "pathway": pathways.PATHWAY_PARALLAX,
        "blueprint_version": BLUEPRINT_VERSION,
        "assessment_id": PID_SPEC.assessment_id,
        "assessment_version": PID_SPEC.version,
        "environment_version": ENVIRONMENT_VERSION,
        "objective_checks": [
            {"check_id": OBJECTIVE_CHECK, "evaluator": OBJECTIVE_CHECK, "required": True,
             "describes": "measured ASR/TCR/FPR of the Aurora Notes assistant under the candidate defense"},
        ],
        "evidence_requirements": [
            {"kind": "measured_defense_behavior", "satisfied_by": OBJECTIVE_CHECK, "required": True},
        ],
        "critical_failures": [
            {"id": CRITICAL_BREACH,
             "describes": "the defended assistant's measured attack-success-rate is at or above the ceiling"},
        ],
        "rubric_dimensions": [
            {"dimension": "approach_quality", "weight": 0.4},
            {"dimension": "threat_model_coverage", "weight": 0.35},
            {"dimension": "tradeoff_analysis", "weight": 0.25},
        ],
        "human_review": {
            "required": False,
            "criteria": "optional reviewer override; the score is produced automatically "
                        "(deterministic objective gate + model-judge rubric)",
        },
        "decision_policy": {
            "type": ac.POLICY_PARALLAX_AUTO,
            "activated": True,
            "rubric_threshold": float(rubric_threshold),
            "rubric_gates": False,          # measurement-primary: the rubric is advisory, not a gate
            "scoring_mode": "measurement_primary",
            "weights": weights or {"objective": 0.85, "rubric": 0.15},
        },
    }
