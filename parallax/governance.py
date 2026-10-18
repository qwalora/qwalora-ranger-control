"""PARALLAX governance: signed, versioned, independently-authorized approvals.

Two approval kinds, both signed by a server-side AUTHORIZED admin (never read from candidate input)
and both bound to a CONTENT HASH so any material change invalidates the approval until it is reissued:

  - SPEC/SCORING approval (findings 2.5): binds the COMPLETE consequential scoring specification of one
    assessment - its identity (assessment_id, version, competency), its metric and pass threshold, and
    the full blueprint hash (which covers the rubric dimensions, critical-failure conditions, the
    objective evaluator/objective checks, the decision policy, evidence requirements and environment
    version). Changing any of these yields a different scoring-spec hash, so the prior approval no
    longer verifies and the assessment cannot bind until reauthorized.

  - PORTFOLIO approval (finding 2): binds the EXACT required-competency inventory (each competency ->
    assessment_id + version) and the policy content hash. An arbitrary, caller-asserted one-competency
    portfolio is not approved unless an authorized admin has signed exactly that inventory.

Authorized admins are supplied server-side by the caller (backed in production by the platform's
reviewer/admin roles). There is no caller-controlled `approved` boolean anywhere.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable

import signing
from siem import assessment_contract as ac


class ApprovalError(Exception):
    """Raised when an approval is missing, unauthorized, or does not match the thing it approves."""


# --- assessment spec + blueprint (complete scoring spec) -----------------------------------------
def scoring_spec_hash(spec, blueprint: Dict[str, Any]) -> str:
    """Hash over the COMPLETE consequential scoring specification: spec identity + metric + threshold
    + competency, and the full blueprint hash (rubric, critical failures, objective evaluator/checks,
    decision policy, evidence requirements, environment version). Any material change moves this hash."""
    body = {
        "assessment_id": spec.assessment_id, "version": spec.version, "competency": spec.competency,
        "metric": spec.metric, "pass_threshold": spec.pass_threshold,
        "spec_content_hash": spec.content_hash(),
        "blueprint_hash": ac.blueprint_hash(blueprint),
        # explicit, redundant pins so the binding is self-describing in the signed record:
        "objective_checks": sorted((c.get("check_id"), c.get("evaluator"))
                                   for c in (blueprint.get("objective_checks") or [])),
        "critical_failures": sorted(cf.get("id") for cf in (blueprint.get("critical_failures") or [])),
        "rubric_dimensions": sorted((d.get("dimension"), d.get("weight"))
                                    for d in (blueprint.get("rubric_dimensions") or [])),
        "decision_policy": blueprint.get("decision_policy"),
        "environment_version": blueprint.get("environment_version"),
    }
    return hashlib.sha256(signing.canonical(body)).hexdigest()


def _spec_body(spec, blueprint, approver_id):
    return {"kind": "parallax_scoring_spec_approval", "assessment_id": spec.assessment_id,
            "version": spec.version, "competency": spec.competency, "approver_id": approver_id,
            "scoring_spec_hash": scoring_spec_hash(spec, blueprint)}


def approve_spec(spec, blueprint: Dict[str, Any], *, approver_id: str,
                 authorized_admins: Iterable[str]) -> Dict[str, Any]:
    """Issue a signed approval binding the full scoring spec of (spec, blueprint)."""
    if not approver_id or approver_id not in set(authorized_admins or ()):
        raise ApprovalError("approver %r is not an authorized PARALLAX approver" % approver_id)
    body = _spec_body(spec, blueprint, approver_id)
    return {"record": body, "signature": signing.sign(body)}


def verify_approval(approval: Dict[str, Any], spec, blueprint: Dict[str, Any], *,
                    authorized_admins: Iterable[str]) -> None:
    """Fail closed unless `approval` is a valid, authorized, signed approval for EXACTLY this spec AND
    blueprint. A material change to either (rubric, critical failures, evaluator, threshold, ...) makes
    the stored scoring-spec hash no longer match, so the approval is rejected until reissued."""
    if not isinstance(approval, dict):
        raise ApprovalError("a signed approval record is required (no caller-controlled boolean)")
    rec = approval.get("record") or {}
    sig = approval.get("signature")
    if rec.get("approver_id") not in set(authorized_admins or ()):
        raise ApprovalError("approval was not issued by an authorized approver")
    expect = _spec_body(spec, blueprint, rec.get("approver_id"))
    if rec != expect:
        raise ApprovalError("approval does not match the current scoring specification "
                            "(spec or blueprint changed since approval; reauthorization required)")
    if not signing.verify(rec, sig):
        raise ApprovalError("approval signature invalid")


def is_approved(approval, spec, blueprint, *, authorized_admins) -> bool:
    try:
        verify_approval(approval, spec, blueprint, authorized_admins=authorized_admins)
        return True
    except ApprovalError:
        return False


# --- portfolio policy ----------------------------------------------------------------------------
def portfolio_content_hash(policy) -> str:
    """Hash over a portfolio policy's version and its EXACT required-competency inventory (each
    competency bound to its assessment_id + version). Two different inventories never share a hash."""
    body = {"version": policy.version,
            "required": sorted((r["competency"], r["assessment_id"], r.get("assessment_version"))
                               for r in policy.required)}
    return hashlib.sha256(signing.canonical(body)).hexdigest()


def _portfolio_body(policy, approver_id):
    return {"kind": "parallax_portfolio_approval", "version": policy.version,
            "approver_id": approver_id, "portfolio_content_hash": portfolio_content_hash(policy),
            "required": sorted((r["competency"], r["assessment_id"], r.get("assessment_version"))
                               for r in policy.required)}


def approve_portfolio(policy, *, approver_id: str, authorized_admins: Iterable[str]) -> Dict[str, Any]:
    """Issue a signed approval binding the EXACT required-competency inventory of `policy`."""
    if not approver_id or approver_id not in set(authorized_admins or ()):
        raise ApprovalError("approver %r is not an authorized PARALLAX portfolio approver" % approver_id)
    if not policy.required:
        raise ApprovalError("a portfolio policy must enumerate at least one required competency")
    body = _portfolio_body(policy, approver_id)
    return {"record": body, "signature": signing.sign(body)}


def verify_portfolio_approval(approval: Dict[str, Any], policy, *,
                              authorized_admins: Iterable[str]) -> None:
    """Fail closed unless `approval` is a valid, authorized, signed approval binding EXACTLY this
    policy's version and required-competency inventory."""
    if not isinstance(approval, dict):
        raise ApprovalError("a signed portfolio approval record is required (no caller-controlled flag)")
    rec = approval.get("record") or {}
    sig = approval.get("signature")
    if rec.get("approver_id") not in set(authorized_admins or ()):
        raise ApprovalError("portfolio approval was not issued by an authorized approver")
    expect = _portfolio_body(policy, rec.get("approver_id"))
    if rec != expect:
        raise ApprovalError("portfolio approval does not match the current required-competency "
                            "inventory (reauthorization required)")
    if not signing.verify(rec, sig):
        raise ApprovalError("portfolio approval signature invalid")
