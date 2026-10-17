"""STRATA S5 - the governed Board 2 qualification decision service.

This is the ONLY path that may award Board 2 objective credit, and it is default-off. It is kept
strictly distinct from three cheaper things that must never, alone, qualify a candidate:

    shadow evaluation          -> advisory score for reviewers (siem.enterprise_grader, shadow=True)
    proposed qualification     -> this service in mode="proposed": computes + signs a decision record
                                  for calibration/comparison, but NEVER awards objective credit
    authorized qualification   -> this service in mode="authorized": awards objective credit, and
                                  only when the activation gate is open

The authorized decision requires ALL of:
  * an APPROVED, versioned rubric (named by a signed activation authorization, not a bare number)
  * an authenticated, authorized evaluation principal (or a trusted internal service identity)
  * a finalized, signed, UNMODIFIED submission whose preserved record binds to this exact candidate,
    case, cohort, board, attempt and scenario
  * citations independently re-verified against the authorized index, and protected truth recomputed
    server-side from the PINNED scenario (never stored, never candidate-facing)
  * a score from the correct pinned scenario at the UNCHANGED 95% objective standard
  * all applicable critical-failure rules
  * an auditable, Ed25519-signed decision record, persisted idempotently (no duplicate award)
  * the separate human report-approval gate still applied elsewhere (this service never approves it)

The activation gate is NOT a bare environment flag: it requires a signed ActivationAuthorization
naming the approved rubric. A production activation additionally requires the RANGER_B2_QUAL_ACTIVE
environment flag; a test activation is refused when the process declares itself production. So in
production, with neither a signed activation nor the flag, the gate is closed.
"""
from __future__ import annotations

import datetime as _dt
import json
import os

import signing
import program as _program
import strata_board2 as b2
import strata_catalog as cat
from siem import case_contract as cc
from siem import enterprise_grader as eg

QUAL_DECISION_VERSION = 1
PASS_BAR = _program.PASS_BAR          # 95.0 - unchanged

# Critical-failure rules: any one makes the attempt a FAIL regardless of composite score.
CRIT_FOREIGN_CITATION = "FOREIGN_OR_OUT_OF_SCOPE_CITATION"
CRIT_UNSIGNED_OR_ALTERED = "UNSIGNED_OR_ALTERED_EVIDENCE"
CRIT_UNSUPPORTED_CONFIRMED = "CONFIRMED_INCIDENT_WITHOUT_VALID_EVIDENCE"
CRIT_FALSE_INCIDENT = "FALSE_INCIDENT_CLAIMED"
CRIT_SCENARIO_MISMATCH = "SCENARIO_IDENTITY_MISMATCH"


class QualificationError(RuntimeError):
    pass


class QualificationAuthError(QualificationError):
    """The evaluation principal is not authorized."""


class QualificationNotActivated(QualificationError):
    """The authorized qualification gate is closed (no valid activation / flag)."""


class QualificationEvidenceError(QualificationError):
    """The submission is not a finalized, signed, unmodified, correctly-bound record."""


# ------------------------------------------------------------------ activation authorization -----
def build_activation(rubric_version, *, approved_by, environment="test", deployment_id=None,
                     calibration_ref=None, shadow_run_ref=None, ttl_seconds=3600):
    """Create a SIGNED activation authorization. In production this artifact is produced only after
    the enterprise rubric is approved and the calibration + shadow-run requirements are met, the
    intended deployment is named, and the user explicitly authorizes activation; the signature makes
    it unforgeable without the signing key. Tests build one with environment='test'."""
    now = _dt.datetime.now(_dt.timezone.utc)
    payload = {
        "kind": "board2-qualification-activation",
        "rubric_version": int(rubric_version),
        "environment": environment,
        "deployment_id": deployment_id,
        "approved_by": approved_by,
        "calibration_ref": calibration_ref,
        "shadow_run_ref": shadow_run_ref,
        "issued_at": now.isoformat(),
        "expires_at": (now + _dt.timedelta(seconds=ttl_seconds)).isoformat(),
    }
    return {"payload": payload, "sig": signing.sign(payload)}


def verify_activation(activation):
    """Verify an activation authorization: signature valid, not expired. Returns the payload or
    raises QualificationNotActivated."""
    if not isinstance(activation, dict) or "payload" not in activation or "sig" not in activation:
        raise QualificationNotActivated("no activation authorization supplied")
    payload, sig = activation["payload"], activation["sig"]
    if not signing.verify(payload, sig):
        raise QualificationNotActivated("activation authorization signature is invalid")
    if payload.get("kind") != "board2-qualification-activation":
        raise QualificationNotActivated("activation authorization is not for Board 2 qualification")
    try:
        exp = _dt.datetime.fromisoformat(payload["expires_at"])
    except Exception as e:  # noqa: BLE001
        raise QualificationNotActivated(f"activation authorization has no valid expiry: {e}")
    if _dt.datetime.now(_dt.timezone.utc) >= exp:
        raise QualificationNotActivated("activation authorization has expired")
    return payload


def load_activation():
    """Load a signed activation authorization from the environment (RANGER_B2_QUAL_ACTIVATION, a
    base64 JSON {payload, sig}), or None. Returning None keeps the authorized gate CLOSED: the route
    then can only produce a 'proposed' decision, never award objective credit. This is deliberately
    NOT a bare on/off flag - the artifact must be a validly signed activation."""
    raw = os.environ.get("RANGER_B2_QUAL_ACTIVATION")
    if not raw:
        return None
    import base64
    try:
        return json.loads(base64.b64decode(raw).decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


_KNOWN_ENVS = ("production", "test", "development", "ci", "staging")


def _ranger_env() -> str:
    return os.environ.get("RANGER_ENV", "").strip().lower()


def _prod_flag() -> bool:
    return os.environ.get("RANGER_B2_QUAL_ACTIVE", "").strip().lower() in ("1", "true", "yes", "on")


def _test_qual_allowed() -> bool:
    return os.environ.get("RANGER_ALLOW_TEST_QUAL", "").strip().lower() in ("1", "true", "yes", "on")


def assert_gate_open(activation, rubric_version):
    """Raise QualificationNotActivated unless the authorized-qualification gate is open for this
    rubric. A bare environment flag is never sufficient - a valid signed activation is required, and
    production authorization is fail-closed when RANGER_ENV is missing or unrecognized."""
    payload = verify_activation(activation)
    if int(payload["rubric_version"]) != int(rubric_version):
        raise QualificationNotActivated(
            f"activation covers rubric {payload['rubric_version']}, not {rubric_version}")
    env = payload.get("environment")
    renv = _ranger_env()
    if env == "production":
        # fail closed unless the process positively declares itself the intended production deployment
        if renv != "production":
            raise QualificationNotActivated(
                f"production activation requires RANGER_ENV=production (got {renv!r}); fail closed")
        if not _prod_flag():
            raise QualificationNotActivated(
                "production activation present but RANGER_B2_QUAL_ACTIVE is not set (gate closed)")
        want_dep = os.environ.get("RANGER_DEPLOYMENT_ID", "").strip()
        got_dep = str(payload.get("deployment_id") or "").strip()
        if not want_dep or not got_dep or want_dep != got_dep:
            raise QualificationNotActivated(
                "production activation does not match the intended deployment identity")
        if not (payload.get("calibration_ref") and payload.get("shadow_run_ref")):
            raise QualificationNotActivated(
                "production activation lacks calibration/shadow-run authorization evidence")
    elif env == "test":
        # a signed test activation grades ONLY inside an explicitly permitted isolated test env
        if renv == "production":
            raise QualificationNotActivated(
                "a test activation cannot authorize grading in a production process")
        if not _test_qual_allowed():
            raise QualificationNotActivated(
                "a test activation requires RANGER_ALLOW_TEST_QUAL in a permitted isolated test env")
    else:
        raise QualificationNotActivated(f"unknown activation environment {env!r}")
    return payload


# ------------------------------------------------------------------ principal authorization -----
def _authorize_principal(principal):
    """An authorized evaluator is either an authenticated administrator (strata_catalog authz:
    session in a request, or a trusted persisted reviewer outside one), OR a genuine trusted internal
    service whose identity is proved by a token matching RANGER_EVALUATOR_TOKEN (a shared secret set
    only in the trusted service context) - NOT a bare dict asserting {'trusted': True}. When no
    service token is configured, the service path is unavailable (fail closed)."""
    if isinstance(principal, dict) and principal.get("service"):
        import hmac as _hmac
        want = os.environ.get("RANGER_EVALUATOR_TOKEN", "")
        got = str(principal.get("token") or "")
        if want and got and _hmac.compare_digest(got, want):
            return f"service:{principal['service']}"
        raise QualificationAuthError(
            "internal service evaluator identity is not proven by a valid service token")
    ok, who = cat._is_authorized_admin(principal)
    if ok:
        return who
    raise QualificationAuthError("qualification requires an authenticated authorized evaluator")


# ------------------------------------------------------------------ evidence binding checks ------
_FINAL_STATES = ("submitted", "under_review", "evaluated", "feedback", "closed")


def _check_submission_binding(submission_row, case, assignment, rubric_version):
    """Verify the submission is finalized and its SIGNED evidence record is unmodified AND binds the
    WHOLE stored payload to this exact candidate/case/cohort/board/attempt/index/scenario/rubric.
    Returns (record, payload). Raises QualificationEvidenceError on any failure (fail closed)."""
    if submission_row is None:
        raise QualificationEvidenceError("no submission to grade")
    if submission_row.submission_status not in _FINAL_STATES:
        raise QualificationEvidenceError(
            f"submission is not finalized (status={submission_row.submission_status})")
    rec_raw, sig = submission_row.evidence_record, submission_row.evidence_sig
    if not rec_raw or not sig:
        raise QualificationEvidenceError("submission has no signed evidence record")
    try:
        record = json.loads(rec_raw)
    except Exception as e:  # noqa: BLE001
        raise QualificationEvidenceError(f"evidence record is unreadable: {e}")
    # (2) signature proves integrity + origin (record unmodified since signing).
    if not cc.verify_evidence_record(record, sig):
        raise QualificationEvidenceError("evidence signature invalid (altered or foreign record)")
    # the full stored payload must match the digest bound into the signed record: this catches a
    # payload edited after signing (conclusions, timeline, citations, detection assessment, ...).
    try:
        payload = json.loads(submission_row.payload) if submission_row.payload else {}
    except Exception as e:  # noqa: BLE001
        raise QualificationEvidenceError(f"submission payload is unreadable: {e}")
    bound = record.get("payload_sha256")
    if not bound:
        raise QualificationEvidenceError("signed record does not bind the full payload (stale record)")
    if cc.payload_digest(payload) != bound:
        raise QualificationEvidenceError("stored payload was modified after signing (digest mismatch)")
    # (3) the signed record must bind to the correct identity + index + versions.
    exp_ref = b2.schema.case_ref(assignment.slug, b2.BOARD, assignment.seed)
    checks = {
        "candidate": (record.get("candidate"), assignment.slug),
        "board": (int(record.get("board") or 0), b2.BOARD),
        "cohort": (record.get("cohort"), assignment.cohort),
        "scenario_ref": (record.get("scenario_ref"), exp_ref),
        "case_id": (record.get("case_id"), case.id),
        "index": (record.get("index"), assignment.index_name),
        "scenario_version": (int(record.get("scenario_version") or 0), int(assignment.spec_version)),
        "rubric_version": (int(record.get("rubric_version") or 0), int(rubric_version)),
    }
    for name, (got, want) in checks.items():
        if got != want:
            raise QualificationEvidenceError(
                f"signed record {name} mismatch (got {got!r}, expected {want!r})")
    rec_attempt = record.get("attempt")
    if rec_attempt is not None and int(rec_attempt) != int(assignment.attempt):
        raise QualificationEvidenceError("signed record attempt does not match the assignment")
    if int(getattr(submission_row, "attempt", 1) or 1) != int(assignment.attempt):
        raise QualificationEvidenceError("submission attempt does not match the assignment")
    return record, payload


# ------------------------------------------------------------------ critical failures ------------
def _critical_failures(payload, verification, grader_result, assignment):
    fails = []
    # a confirmed incident with no reference-valid citation, or any out-of-scope/foreign citation
    for inc in verification.get("incidents", []):
        cites = inc.get("citations", [])
        for ct in cites:
            idx = ct.get("index")
            if idx and idx != assignment.index_name:
                fails.append(CRIT_FOREIGN_CITATION)
            if ct.get("in_scope") is False:
                fails.append(CRIT_FOREIGN_CITATION)
    for inc in payload.get("incidents", []):
        if str(inc.get("disposition", "")).strip().lower() == "confirmed_incident":
            # find its verification entry by position
            pass
    # structural: a confirmed incident that earned no reference_valid citation at all
    vinc = verification.get("incidents", [])
    for i, inc in enumerate(payload.get("incidents", [])):
        if str(inc.get("disposition", "")).strip().lower() == "confirmed_incident":
            v = vinc[i] if i < len(vinc) else {}
            if not any(c.get("reference_valid") for c in v.get("citations", [])):
                fails.append(CRIT_UNSUPPORTED_CONFIRMED)
    if eg.TRIG_FALSE_INCIDENT in (grader_result.get("review_flags") or []):
        fails.append(CRIT_FALSE_INCIDENT)
    # stable de-dup
    out, seen = [], set()
    for f in fails:
        if f not in seen:
            seen.add(f); out.append(f)
    return out


# ------------------------------------------------------------------ the decision ----------------
def decide(db, case, submission_row, assignment, reader, *, principal, rubric_version=None,
           activation=None, mode="authorized", candidate_id=None):
    """Produce a governed qualification decision. In mode='authorized' (gate must be open) a pass
    awards Board 2 objective credit idempotently; in mode='proposed' it never awards. Returns the
    persisted QualificationDecision."""
    from models import QualificationDecision, BoardResult
    rubric_version = rubric_version if rubric_version is not None else cc.RUBRIC_VERSION
    who = _authorize_principal(principal)
    if mode not in ("authorized", "proposed"):
        raise QualificationError(f"unknown mode {mode!r}")
    if mode == "authorized":
        assert_gate_open(activation, rubric_version)   # closed by default; needs a signed activation

    # Idempotency: a decision already recorded for this (case, attempt, submission, rubric, mode).
    # A cached result is trusted ONLY if its own signature still verifies (a tampered stored decision
    # is not reused).
    existing = QualificationDecision.query.filter_by(
        case_id=case.id, attempt=assignment.attempt, submission_id=submission_row.id,
        rubric_version=rubric_version, mode=mode).first()
    if existing:
        if not verify_decision(existing):
            raise QualificationError(f"cached decision {existing.id} failed signature verification; "
                                     f"refusing to trust it")
        return existing

    # (finalized, signed, correctly-bound submission with the full payload digest) - raises on failure
    _record, payload = _check_submission_binding(submission_row, case, assignment, rubric_version)

    # scenario identity must match the case/binding the submission was made under
    if case.content_hash and assignment.content_hash and case.content_hash != assignment.content_hash:
        raise QualificationEvidenceError("case pinned content hash differs from the assignment")

    # protected truth recomputed from the PINNED scenario (never stored, never candidate-facing)
    truth = b2.grading_truth(assignment, candidate_id=candidate_id)
    # independent citation verification against the authorized index (truth-aware, server-side)
    verification = cc.verify_evidence(payload, reader, assignment.index_name, truth=truth)
    grader = eg.score_board2_enterprise(truth, payload, reader, assignment.index_name,
                                        verification=verification)
    score = float(grader["score"])
    normalized = float(grader.get("normalized") or (score / 100.0))

    crit = _critical_failures(payload, verification, grader, assignment)
    passed = (score >= PASS_BAR) and not crit

    now = _dt.datetime.now(_dt.timezone.utc)
    record = {
        "decision_version": QUAL_DECISION_VERSION,
        "kind": "board2-qualification-decision",
        "mode": mode,
        "rubric_version": rubric_version,
        "grader_version": grader.get("version"),
        "principal": who,
        "candidate_slug": assignment.slug,
        "candidate_id": case.candidate_id,
        "case_id": case.id,
        "attempt": assignment.attempt,
        "board": b2.BOARD,
        "cohort": assignment.cohort,
        "scenario": {"spec_id": assignment.spec_id, "spec_version": assignment.spec_version,
                     "content_hash": assignment.content_hash, "variant_id": assignment.variant_id,
                     "dataset_fingerprint": assignment.dataset_fingerprint},
        "score": round(score, 1),
        "normalized": round(normalized, 4),
        "pass_bar": PASS_BAR,
        "passed": bool(passed),
        "critical_failures": crit,
        "decided_at": now.isoformat(),
    }
    sig = signing.sign(record)

    decision = QualificationDecision(
        case_id=case.id, candidate_id=case.candidate_id, submission_id=submission_row.id,
        attempt=assignment.attempt, board=b2.BOARD, rubric_version=rubric_version, mode=mode,
        score=round(score, 1), normalized=round(normalized, 4), passed=bool(passed),
        critical_failures=json.dumps(crit), scenario_fingerprint=assignment.dataset_fingerprint,
        spec_id=assignment.spec_id, spec_version=assignment.spec_version,
        content_hash=assignment.content_hash, variant_id=assignment.variant_id,
        principal=who, decision_record=json.dumps(record), decision_sig=sig,
        awarded_objective=False)
    db.session.add(decision)

    # Authorized pass -> award objective credit idempotently. This is the ONLY authorized writer of
    # Board 2 objective credit; the generic grader chokepoint stays refusing Board 2. The human
    # report-approval gate is SEPARATE and is not touched here.
    if mode == "authorized" and passed:
        br = BoardResult.query.filter_by(candidate_id=case.candidate_id, board=b2.BOARD).first()
        if br is None:
            br = BoardResult(candidate_id=case.candidate_id, board=b2.BOARD)
            db.session.add(br)
        br.objective_score = round(score, 1)
        br.objective_passed = True
        br.objective_sig = sig
        decision.awarded_objective = True
    try:
        db.session.commit()
    except Exception:                       # a concurrent evaluator won the unique decision
        db.session.rollback()
        won = QualificationDecision.query.filter_by(
            case_id=case.id, attempt=assignment.attempt, submission_id=submission_row.id,
            rubric_version=rubric_version, mode=mode).first()
        if won:
            return won
        raise
    return decision


def verify_decision(decision) -> bool:
    """Verify a persisted decision's Ed25519 signature over its own record (audit)."""
    try:
        return signing.verify(json.loads(decision.decision_record), decision.decision_sig)
    except Exception:  # noqa: BLE001
        return False
