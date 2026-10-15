"""F1 - the common, pathway-aware assessment contract.

ONE qualification surface for both pathways. It does NOT replace or alter STRATA grading:
STRATA's objective score still comes from `scenarios.score_board2` and its bar is still
`program.PASS_BAR = 95.0`; this contract only REPRESENTS that policy so both pathways share
one auditable decision shape. There is no second qualification engine.

A blueprint is a versioned, immutable description separating the ten required concerns:

  1 program pathway            blueprint["pathway"]            (strata | parallax; stable ids)
  2 versioned blueprint        blueprint["blueprint_version"] (+ content hash; immutable)
  3 candidate authorization    decide(authorization=...)      (must match the pathway)
  4 scenario/environment ver   blueprint["environment_version"] + decide(scenario_version=)
  5 evidence requirements      blueprint["evidence_requirements"]
  6 objective technical checks blueprint["objective_checks"]  (verified by evaluators)
  7 critical failure conditions blueprint["critical_failures"] (VETO; cannot be outvoted)
  8 human-review criteria      blueprint["human_review"]      (reviewer decision)
  9 qualification decision policy blueprint["decision_policy"]
  10 signed evidence + decision records  sign_decision / append_adjudication (append-only)

The decision is deterministic and needs no AI. A critical-failure veto forces non-
qualification regardless of rubric or reviewer. A PARALLAX pass threshold is NOT active
until explicitly approved (decision_policy.activated); until then PARALLAX never returns
qualified=True.
"""
from __future__ import annotations

import hashlib

import program          # PASS_BAR (STRATA), unchanged
import signing
import pathways
from . import evaluator as ev

ASSESSMENT_CONTRACT_VERSION = 1

# Which blueprint versions each pathway supports. An unsupported version is rejected.
SUPPORTED_BLUEPRINT_VERSIONS = {"strata": {1}, "parallax": {1}}

POLICY_STRATA_BAR = "strata_objective_bar"
POLICY_PARALLAX_PORTFOLIO = "parallax_portfolio"


def _err(code, msg, **kv):
    d = {"code": code, "message": msg}; d.update(kv); return d


def blueprint_hash(bp: dict) -> str:
    """Stable content hash of a blueprint (immutability anchor)."""
    return hashlib.sha256(signing.canonical(bp)).hexdigest()


def validate_blueprint(bp: dict) -> dict:
    """Structural validation of a blueprint. Returns {ok, errors}."""
    errors = []
    if not isinstance(bp, dict):
        return {"ok": False, "errors": [_err("BAD_BLUEPRINT", "blueprint must be an object")]}
    pw = pathways.normalize_pathway(bp.get("pathway"))
    if pw not in pathways.PATHWAYS:
        errors.append(_err("INVALID_PATHWAY", f"unknown pathway {bp.get('pathway')!r}"))
    if not isinstance(bp.get("blueprint_version"), int):
        errors.append(_err("MISSING_VERSION", "blueprint_version (int) required"))
    pol = (bp.get("decision_policy") or {}).get("type")
    if pol not in (POLICY_STRATA_BAR, POLICY_PARALLAX_PORTFOLIO):
        errors.append(_err("BAD_POLICY", f"unknown decision policy {pol!r}"))
    # objective checks must reference known evaluator kinds
    for oc in (bp.get("objective_checks") or []):
        if oc.get("evaluator") not in ev.EVALUATORS:
            errors.append(_err("UNKNOWN_EVALUATOR", f"no evaluator {oc.get('evaluator')!r}",
                               check_id=oc.get("check_id")))
    return {"ok": not errors, "errors": errors}


def _aggregate_rubric(bp, rubric_scores):
    """Weighted rubric aggregate in [0,100]. Missing dimensions score 0."""
    dims = bp.get("rubric_dimensions") or []
    if not dims:
        return None
    total_w = sum(d.get("weight", 0) for d in dims) or 1
    agg = sum((rubric_scores or {}).get(d["dimension"], 0) * d.get("weight", 0) for d in dims)
    return round(agg / total_w, 2)


def decide(blueprint: dict, *, authorization: dict, objective_results: list,
           critical_findings: list | None = None, rubric_scores: dict | None = None,
           reviewer_decision: dict | None = None, scenario_version: str | None = None) -> dict:
    """Combine the ten concerns into a single auditable qualification decision. Pure and
    deterministic (no AI). Returns a decision dict; qualified is True only when EVERY gate
    passes and no critical failure vetoes."""
    critical_findings = critical_findings or []
    reviewer_decision = reviewer_decision or {}
    breakdown = {}
    gate_errors = []
    pw = pathways.normalize_pathway(blueprint.get("pathway"))

    # (2) blueprint support / validity
    vb = validate_blueprint(blueprint)
    if not vb["ok"]:
        return _fail(blueprint, pw, "INVALID_BLUEPRINT", vb["errors"], breakdown)
    bver = blueprint.get("blueprint_version")
    if bver not in SUPPORTED_BLUEPRINT_VERSIONS.get(pw, set()):
        return _fail(blueprint, pw, "UNSUPPORTED_BLUEPRINT_VERSION",
                     [_err("UNSUPPORTED_BLUEPRINT_VERSION",
                           f"pathway {pw!r} does not support blueprint v{bver}")], breakdown)

    # (3) candidate authorization - must exist and be scoped to THIS pathway
    auth_pw = pathways.normalize_pathway((authorization or {}).get("pathway"))
    authorized = bool((authorization or {}).get("candidate_id")) and auth_pw == pw
    breakdown["authorization"] = {"ok": authorized, "authorization_pathway": auth_pw,
                                  "blueprint_pathway": pw}
    if not authorized:
        gate_errors.append(_err("INSUFFICIENT_AUTHORIZATION",
                                "candidate is not authorized for this pathway", pathway=pw))

    # (4) scenario / environment version binding (immutable)
    env_ver = blueprint.get("environment_version")
    ver_ok = (scenario_version is None) or (scenario_version == env_ver)
    breakdown["version_binding"] = {"ok": ver_ok, "environment_version": env_ver,
                                    "scenario_version": scenario_version}
    if not ver_ok:
        gate_errors.append(_err("VERSION_MISMATCH",
                                f"scenario_version {scenario_version!r} != blueprint {env_ver!r}"))

    # (6) objective technical checks - count only evaluator-verified, untampered results
    checks_by_id = {r.get("check_id"): r for r in (objective_results or [])}
    required_checks = [c for c in (blueprint.get("objective_checks") or []) if c.get("required", True)]
    obj_detail = []
    objective_score = None
    all_required_passed = True
    for c in required_checks:
        r = checks_by_id.get(c["check_id"])
        trustworthy = bool(r) and r.get("verified") is True and ev.verify_result_integrity(r)
        passed = trustworthy and bool(r.get("passed"))
        if r is not None and "score" in r:
            objective_score = r.get("score")
        obj_detail.append({"check_id": c["check_id"], "present": bool(r),
                           "trustworthy": trustworthy, "passed": passed})
        if not passed:
            all_required_passed = False
    breakdown["objective_checks"] = {"ok": all_required_passed, "detail": obj_detail}

    # (5) evidence requirements - each required kind satisfied by a trustworthy passing check
    ev_detail = []
    evidence_ok = True
    present_kinds = {r.get("check_id"): r for r in (objective_results or [])}
    for req in (blueprint.get("evidence_requirements") or []):
        rid = req.get("satisfied_by")   # check_id expected to satisfy this evidence requirement
        r = present_kinds.get(rid)
        ok = bool(r) and r.get("verified") is True and ev.verify_result_integrity(r) and bool(r.get("passed"))
        ev_detail.append({"requirement": req.get("kind"), "satisfied_by": rid, "ok": ok})
        if req.get("required", True) and not ok:
            evidence_ok = False
    breakdown["evidence_requirements"] = {"ok": evidence_ok, "detail": ev_detail}
    if not evidence_ok:
        gate_errors.append(_err("EVIDENCE_REQUIREMENT_UNMET", "a required evidence kind is unmet"))

    # (7) critical failure conditions - VETO (cannot be outvoted by rubric/reviewer)
    required_cf = {cf["id"] for cf in (blueprint.get("critical_failures") or [])}
    present_cf = sorted({f.get("id") for f in critical_findings
                         if f.get("present") and not f.get("remediated") and f.get("id") in required_cf})
    critical_veto = bool(present_cf)
    breakdown["critical_failures"] = {"veto": critical_veto, "present": present_cf}

    # (8) human-review criteria
    reviewer_pass = (reviewer_decision.get("decision") == "pass"
                     and bool(reviewer_decision.get("reviewer_id")))
    breakdown["human_review"] = {"ok": reviewer_pass, "decision": reviewer_decision.get("decision"),
                                 "reviewer_id": reviewer_decision.get("reviewer_id")}

    # (9) decision policy
    policy = blueprint.get("decision_policy") or {}
    ptype = policy.get("type")
    rubric_agg = _aggregate_rubric(blueprint, rubric_scores)
    breakdown["rubric"] = {"aggregate": rubric_agg}
    policy_detail = {"type": ptype}

    if gate_errors:
        return _fail(blueprint, pw, "GATE_FAILED", gate_errors, breakdown)
    if critical_veto:
        return _fail(blueprint, pw, "CRITICAL_FAILURE_VETO",
                     [_err("CRITICAL_FAILURE_VETO", "an unremediated critical failure vetoes qualification",
                           present=present_cf)], breakdown)

    if ptype == POLICY_STRATA_BAR:
        # STRATA: objective bar is authoritative and UNCHANGED (program.PASS_BAR). The
        # objective_score is supplied by scenarios.score_board2 upstream; we do not recompute it.
        bar = program.PASS_BAR
        qualified = (objective_score is not None) and (objective_score >= bar) and all_required_passed
        policy_detail.update({"bar": bar, "objective_score": objective_score})
        reason = "qualified" if qualified else "below_objective_bar"
    elif ptype == POLICY_PARALLAX_PORTFOLIO:
        activated = bool(policy.get("activated"))
        threshold = policy.get("rubric_threshold")
        if not activated or threshold is None:
            # threshold not approved yet -> never qualifies (gate held open on purpose)
            return _fail(blueprint, pw, "POLICY_NOT_ACTIVATED",
                         [_err("POLICY_NOT_ACTIVATED",
                               "PARALLAX qualification threshold is not activated (needs separate approval)")],
                         breakdown)
        rubric_ok = (rubric_agg is not None) and (rubric_agg >= threshold)
        qualified = all_required_passed and evidence_ok and reviewer_pass and rubric_ok
        policy_detail.update({"rubric_threshold": threshold, "rubric_aggregate": rubric_agg,
                              "activated": activated})
        reason = "qualified" if qualified else "portfolio_requirements_unmet"
    else:
        return _fail(blueprint, pw, "BAD_POLICY", [_err("BAD_POLICY", f"unknown policy {ptype!r}")],
                     breakdown)

    return {"qualified": bool(qualified), "reason": reason, "pathway": pw,
            "blueprint_version": bver, "blueprint_hash": blueprint_hash(blueprint),
            "policy": policy_detail, "breakdown": breakdown,
            "auditable": True, "ai_involved": False,
            "contract_version": ASSESSMENT_CONTRACT_VERSION}


def _fail(blueprint, pw, reason, errors, breakdown):
    return {"qualified": False, "reason": reason, "pathway": pw,
            "blueprint_version": blueprint.get("blueprint_version"),
            "blueprint_hash": blueprint_hash(blueprint) if isinstance(blueprint, dict) else None,
            "errors": errors, "breakdown": breakdown,
            "auditable": True, "ai_involved": False,
            "contract_version": ASSESSMENT_CONTRACT_VERSION}


# --- signed, immutable, append-only decision records -------------------------
def sign_decision(decision: dict, *, candidate_id, unit_ref) -> dict:
    """Produce an immutable, signed qualification record. The signature covers the decision
    plus identity + a record hash; reviewers can append adjudications later WITHOUT mutating
    this record (see append_adjudication)."""
    record = {"kind": "qualification_decision", "candidate_id": candidate_id,
              "unit_ref": unit_ref, "pathway": decision.get("pathway"),
              "blueprint_version": decision.get("blueprint_version"),
              "blueprint_hash": decision.get("blueprint_hash"),
              "qualified": decision.get("qualified"), "reason": decision.get("reason"),
              "decision": decision, "parent_hash": None}
    record["record_hash"] = hashlib.sha256(signing.canonical(record)).hexdigest()
    return {"record": record, "signature": signing.sign(record)}


def verify_decision(signed: dict) -> bool:
    """True if a signed decision record is intact (content matches signature + record_hash)."""
    rec = signed.get("record", {})
    sig = signed.get("signature")
    expect = hashlib.sha256(
        signing.canonical({k: rec.get(k) for k in rec if k != "record_hash"})).hexdigest()
    return rec.get("record_hash") == expect and signing.verify(rec, sig)


def append_adjudication(prior_signed: dict, *, reviewer_id: str, note: str,
                        decision_override: bool | None = None) -> dict:
    """Append a reviewer adjudication as a NEW signed record that references the prior one
    by hash. The prior record is never mutated (immutability). Returns the new signed record.
    Raises if the reviewer_id is missing (unauthorized changes are refused)."""
    if not reviewer_id:
        raise PermissionError("an authorized reviewer_id is required to adjudicate")
    prior = prior_signed.get("record", {})
    rec = {"kind": "reviewer_adjudication", "reviewer_id": reviewer_id, "note": note,
           "decision_override": decision_override, "parent_hash": prior.get("record_hash"),
           "candidate_id": prior.get("candidate_id"), "unit_ref": prior.get("unit_ref"),
           "pathway": prior.get("pathway")}
    rec["record_hash"] = hashlib.sha256(signing.canonical(rec)).hexdigest()
    return {"record": rec, "signature": signing.sign(rec)}
