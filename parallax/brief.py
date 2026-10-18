"""Candidate-safe PX-1 brief.

Discloses only what a candidate legitimately needs: the task, the public feature schema (every column
name, with the leak unmarked), the disclosed split names, the headline metric, and the pass threshold.
It never exposes the sealed holdout, the planted leak's identity, grading internals, or the seed.
"""
from __future__ import annotations

from typing import Any, Dict

from .contracts import AssessmentSpec, GenerationContract
from .px1_dataset import Instance


def build_brief(spec: AssessmentSpec, contract: GenerationContract, instance: Instance) -> Dict[str, Any]:
    """Assemble the candidate-facing brief for a bound PX-1 instance."""
    return {
        "assessment_id": spec.assessment_id,
        "version": spec.version,
        "title": spec.title,
        "competency": spec.competency,
        "pathway": contract.pathway,
        "attempt": contract.attempt,
        "task": (
            "Build a binary classifier that GENERALIZES to unseen data. The instance contains one "
            "planted data-leakage feature that is highly predictive on train/validation but will not "
            "generalize. Identify and EXCLUDE it. Submit the feature set to use, a model configuration "
            "from the allowed family, and a short written analysis naming the leak and your reasoning."
        ),
        "metric": spec.metric,
        "pass_threshold": spec.pass_threshold,
        "disclosed_splits": ["train", "validation"],
        "sealed_splits": ["holdout"],          # named so the candidate knows grading is on unseen data
        "feature_schema": instance.public_feature_names(),   # leak NOT marked
        "label_column": instance.label_col,
        "allowed_model_families": ["logistic_regression", "random_forest"],
        "submission_shape": {
            "feature_set": "list[str] of feature column names to use (exclude the leak)",
            "model_config": {"family": "logistic_regression|random_forest", "C/n_estimators/max_depth": "optional"},
            "leakage_analysis": "str: identify the leak and justify",
        },
        # deliberately absent: holdout data/labels, the leak's identity, the seed, grading internals.
    }
