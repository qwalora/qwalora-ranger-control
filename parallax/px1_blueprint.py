"""PX-1 assessment spec + the F1 AssessmentBlueprint it maps to.

The blueprint is the pathway-neutral, immutable description `siem.assessment_contract.decide` consumes.
PX-1 uses the PARALLAX portfolio policy (rubric threshold + human review), a single objective check
(the `generalization_holdout` evaluator), and one critical-failure condition (data-leakage dependence)
that vetoes qualification. FINAL qualification stays gated by the platform activation flag regardless of
this blueprint, per the assessment contract.
"""
from __future__ import annotations

from typing import Any, Dict

import pathways
from siem import assessment_contract as ac

from .contracts import AssessmentSpec

OBJECTIVE_CHECK = "generalization_holdout"      # == evaluator kind == result check_id (platform convention)
CRITICAL_LEAKAGE = "data_leakage_dependence"
BLUEPRINT_VERSION = 1
ENVIRONMENT_VERSION = "px1-1.0.0"
RUBRIC_THRESHOLD = 70.0

# The approved PX-1 assessment specification (data integrity + honest generalization).
PX1_SPEC = AssessmentSpec(
    assessment_id="PX-1",
    version="1.0.0",
    title="Leakage-Safe Model Evaluation",
    competency="data_engineering_and_dataset_integrity",
    metric="roc_auc",
    pass_threshold=0.70,            # minimum holdout ROC-AUC for the objective check to pass
    params={"splits": ["train", "validation"], "sealed": ["holdout"]},
    approved=True,
)


def blueprint() -> Dict[str, Any]:
    """Return the immutable PX-1 blueprint dict (pathway=parallax). Shape validated by
    `assessment_contract.validate_blueprint`."""
    return {
        "pathway": pathways.PATHWAY_PARALLAX,
        "blueprint_version": BLUEPRINT_VERSION,
        "assessment_id": PX1_SPEC.assessment_id,
        "assessment_version": PX1_SPEC.version,
        "environment_version": ENVIRONMENT_VERSION,
        "objective_checks": [
            {"check_id": OBJECTIVE_CHECK, "evaluator": OBJECTIVE_CHECK, "required": True,
             "describes": "unseen-holdout generalization of the declared leakage-safe solution"},
        ],
        "evidence_requirements": [
            {"kind": "holdout_generalization", "satisfied_by": OBJECTIVE_CHECK, "required": True},
        ],
        "critical_failures": [
            {"id": CRITICAL_LEAKAGE,
             "describes": "the submitted solution depends on a planted, non-generalizing leak feature"},
        ],
        "rubric_dimensions": [
            {"dimension": "leakage_analysis_quality", "weight": 1.0},
        ],
        "human_review": {
            "required": True,
            "criteria": "the written leakage analysis correctly identifies and justifies the leak",
        },
        "decision_policy": {
            "type": ac.POLICY_PARALLAX_PORTFOLIO,
            "activated": True,               # blueprint-level policy is scored; platform gate still applies
            "rubric_threshold": RUBRIC_THRESHOLD,
        },
    }
