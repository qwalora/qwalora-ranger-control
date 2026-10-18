"""PARALLAX Lab A workbench routes - DEVELOPMENT ONLY, multiply gated and fail-closed.

Every route 404s unless ALL hold:
  - `RANGER_PARALLAX_LABA` is set (feature flag), AND
  - `RANGER_PARALLAX_LABA_ENV` explicitly asserts a non-production environment
    (development/nonproduction/test), AND no production marker (RANGER_ENV/APP_ENV/ENVIRONMENT=prod*)
    is present.

Identity is the authenticated candidate SESSION (`session["cand"]`), never a caller-supplied handle.
Governance approval is NOT minted here: the route uses a pre-supplied SIGNED approval
(`RANGER_PARALLAX_LABA_APPROVAL_B64`, produced out-of-band by an authorized admin via
`parallax.governance.approve_spec`) and verifies it against the current spec AND blueprint before use;
a list of admin names in the environment does not, by itself, authorize anything. The route serves a
candidate-safe brief and a DRY-RUN objective check only: no credit, no persisted record, no pathway
qualification.
"""
from __future__ import annotations

import base64
import json
import os

from flask import jsonify, request, session


def _flag_on() -> bool:
    return str(os.environ.get("RANGER_PARALLAX_LABA", "")).strip().lower() in ("1", "true", "yes")


def _nonprod() -> bool:
    if not _flag_on():
        return False
    if os.environ.get("RANGER_PARALLAX_LABA_ENV", "").strip().lower() not in (
            "development", "dev", "nonproduction", "non-production", "test", "staging"):
        return False
    for marker in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
        if os.environ.get(marker, "").strip().lower() in ("prod", "production"):
            return False
    return True


def _admins():
    return {a.strip() for a in os.environ.get("RANGER_PARALLAX_ADMINS", "").split(",") if a.strip()}


def register(app, candidate_model=None, db=None, helpers=None):
    from parallax import laba_assessment as A, governance
    from parallax import laba_blueprint as BP

    def _authenticated_candidate():
        c = session.get("cand")
        return str(c) if c else None

    def _load_approval():
        admins = _admins()
        b64 = os.environ.get("RANGER_PARALLAX_LABA_APPROVAL_B64")
        if not admins or not b64:
            return None, admins
        try:
            approval = json.loads(base64.b64decode(b64).decode("utf-8"))
            governance.verify_approval(approval, BP.LABA_SPEC, BP.blueprint(), authorized_admins=admins)
            return approval, admins
        except Exception:  # noqa: BLE001 - any load/verify failure => no usable approval (fail closed)
            return None, admins

    def _preconditions():
        if not _nonprod():
            return None, None, None, ("not found", 404)
        ckey = _authenticated_candidate()
        if not ckey:
            return None, None, None, (jsonify(error="authenticated candidate session required"), 401)
        approval, admins = _load_approval()
        if not approval:
            return None, None, None, (jsonify(
                error="no valid signed PARALLAX approval configured for this environment"), 409)
        return ckey, approval, admins, None

    @app.get("/parallax/laba/brief")
    def parallax_laba_brief():
        ckey, approval, admins, err = _preconditions()
        if err:
            return err
        cohort = (request.values.get("cohort") or os.environ.get("DEFAULT_COHORT") or "dev").strip()
        brief = A.candidate_brief(cohort=cohort, candidate_key=ckey, approval=approval,
                                  authorized_admins=admins)
        return jsonify(ok=True, brief=brief, note="development preview; no award, no qualification"), 200

    @app.post("/parallax/laba/evaluate")
    def parallax_laba_evaluate():
        ckey, approval, admins, err = _preconditions()
        if err:
            return err
        cohort = (request.values.get("cohort") or os.environ.get("DEFAULT_COHORT") or "dev").strip()
        submission = (request.get_json(silent=True) or {}).get("submission") or {}
        # DRY RUN: no server-side reviewer -> assessment cannot be 'met'; objective verdict only.
        # No persistence, no award, no pathway qualification.
        r = A.run_assessment(submission, cohort=cohort, candidate_key=ckey, approval=approval,
                             authorized_admins=admins, reviewer=None)
        return jsonify(ok=True, dry_run=True, assessment_passed=r["assessment_passed"],
                       pathway_qualified=r["pathway_qualified"],
                       candidate_feedback=r["candidate_feedback"],
                       note="development dry-run; human review + governance gates not applied here"), 200
