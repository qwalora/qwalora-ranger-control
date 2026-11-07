"""Assessor rubric for the subjective (written-report) clearance channel.

Clearing a STRATA board needs two things: the objective grade (machine, signed) AND an
approved report. The report half used to be a bare approve/reject with a free-text note,
which made the human-adjudication channel the weakest link in the credential. This module
gives that channel structure: a fixed set of weighted criteria per role, a numeric bar, and
a composite the reviewer cannot hand-wave around. The review route scores each criterion,
computes the composite here, gates approval on the bar, and Ed25519-signs the result, so a
report clearance is as auditable and reproducible as an objective one.

Each criterion is scored 0-4 by the reviewer (0 absent, 1 poor, 2 adequate, 3 strong,
4 exemplary). The composite is the weight-normalized percentage. A report must reach
REPORT_BAR to be approvable without an explicit, recorded override.
"""
from __future__ import annotations

REPORT_BAR = 70.0           # composite (0..100) a report needs to be approvable
MAX_PER_CRITERION = 4       # reviewer scores each criterion 0..4

# Blue-team rubric: SOC triage, threat hunt, detection engineering, incident response.
BLUE_RUBRIC = [
    {"id": "accuracy", "label": "Findings accuracy", "weight": 0.30,
     "desc": "Findings are technically correct and consistent with the evidence; verdicts, "
             "techniques and scope match what the telemetry supports."},
    {"id": "evidence", "label": "Evidence & citation", "weight": 0.20,
     "desc": "Every material claim is grounded in specific, checkable evidence (alert/event ids, "
             "log lines, hosts, accounts), not assertion."},
    {"id": "reasoning", "label": "Analytical reasoning", "weight": 0.20,
     "desc": "Conclusions follow from the evidence; the kill chain / hypothesis is reasoned, not "
             "guessed; alternatives are considered and ruled out."},
    {"id": "scope", "label": "Scope & completeness", "weight": 0.15,
     "desc": "The full incident is scoped: no major compromised host, account, persistence or "
             "stage of the chain is missed, and benign activity is not over-called."},
    {"id": "communication", "label": "Communication & actionability", "weight": 0.15,
     "desc": "Clear, professional writeup a responder could act on: structured, prioritized, with "
             "concrete containment / next steps."},
]

# Offensive rubric: red-team engagement and capstone.
OFFENSIVE_RUBRIC = [
    {"id": "attack_narrative", "label": "Attack narrative", "weight": 0.25,
     "desc": "A coherent, reproducible account of the path from foothold to objective, mapped to "
             "ATT&CK, that another operator could follow."},
    {"id": "evidence", "label": "Evidence & proof", "weight": 0.20,
     "desc": "Each step is proven with concrete artifacts (commands, outputs, screenshots, hashes), "
             "not claimed."},
    {"id": "impact", "label": "Impact & objectives", "weight": 0.20,
     "desc": "The engagement objectives are met and the business impact is demonstrated and "
             "accurately characterized."},
    {"id": "opsec", "label": "Tradecraft & OPSEC", "weight": 0.15,
     "desc": "Technique selection and operational security are sound and justified for the scope."},
    {"id": "remediation", "label": "Remediation guidance", "weight": 0.10,
     "desc": "Actionable, prioritized defensive recommendations tied to the findings."},
    {"id": "communication", "label": "Communication", "weight": 0.10,
     "desc": "Clear, professional, well-structured reporting suitable for a client deliverable."},
]

_OFFENSIVE_ROLES = {"red-teamer", "capstone"}


def rubric_for(role):
    """The criteria list for a board role. Blue-team roles share BLUE_RUBRIC; the offensive
    rungs use OFFENSIVE_RUBRIC. Unknown roles fall back to the blue rubric."""
    return OFFENSIVE_RUBRIC if str(role or "") in _OFFENSIVE_ROLES else BLUE_RUBRIC


def criterion_ids(role):
    return [c["id"] for c in rubric_for(role)]


def _clamp(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if v != v:  # NaN
        return None
    return max(0.0, min(float(MAX_PER_CRITERION), v))


def score(role, scores):
    """Composite 0..100 from per-criterion 0..4 scores (a dict id->value). The weights are
    renormalized over the criteria that were actually scored, so a partial review still yields
    a meaningful number, but completeness is reported separately. Returns
    (composite, normalized_scores, complete) where complete is True only when every criterion
    for the role has a valid score."""
    crits = rubric_for(role)
    scores = scores or {}
    norm = {}
    total_w = 0.0
    earned = 0.0
    complete = True
    for c in crits:
        v = _clamp(scores.get(c["id"]))
        if v is None:
            complete = False
            continue
        norm[c["id"]] = v
        total_w += c["weight"]
        earned += c["weight"] * (v / MAX_PER_CRITERION)
    composite = round(100.0 * earned / total_w, 1) if total_w else 0.0
    return composite, norm, complete


def meets_bar(role, scores):
    """True only when the review is complete AND the composite reaches REPORT_BAR."""
    composite, _norm, complete = score(role, scores)
    return bool(complete and composite >= REPORT_BAR), composite
