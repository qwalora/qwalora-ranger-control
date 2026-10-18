"""Candidate-safe Lab A brief + case material.

Carries the observable case (tenants, principals, authorization policy incl. explicit cross-tenant
grants, tool catalog, and the observable event log) and the submission shape. The sealed truth
(per-event classification) and the injected-instruction provenance are excluded by construction
(`laba_sim.observable` never includes them).
"""
from __future__ import annotations

from typing import Any, Dict

from .contracts import AssessmentSpec, GenerationContract
from . import laba_sim as sim


def build_brief(spec: AssessmentSpec, contract: GenerationContract, instance: sim.Instance) -> Dict[str, Any]:
    return {
        "assessment_id": spec.assessment_id,
        "version": spec.version,
        "title": spec.title,
        "competency": spec.competency,
        "pathway": contract.pathway,
        "attempt": contract.attempt,
        "simulated": sim.SIMULATED,
        "task": (
            "You are investigating a bounded, SIMULATED enterprise AI agent. Using the authorization "
            "policy and the observable event log, classify each relevant event as 'unauthorized_access' "
            "(a breach that completed despite the policy), 'blocked_attempt' (an unauthorized attempt "
            "correctly denied), or 'legitimate'. Some cross-tenant operations are AUTHORIZED by explicit "
            "grants in the policy - those are legitimate, not breaches. Back every finding with a cited "
            "event id. Then write a short root-cause / policy-gap analysis. Flagging everything, or "
            "denying everything, will not pass."
        ),
        "metric": spec.metric,
        "pass_threshold": spec.pass_threshold,
        "case": sim.observable(instance),      # tenants, policy, tools, observable events (no truth)
        "submission_shape": {
            "findings": "list of {event_id, classification, evidence:[event_id,...]}; cite the event itself",
            "analysis": "str: root-cause / policy-gap narrative (human-reviewed)",
        },
        # deliberately absent: per-event truth labels, injected-instruction provenance, the seed.
    }
