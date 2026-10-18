"""PARALLAX Lab A workbench routes - DEVELOPMENT ONLY, behind a default-off flag.

Every route 404s unless `RANGER_PARALLAX_LABA` is set, so production stays dark. This surface is a
development preview of the Lab A candidate experience: it serves the candidate-safe brief and runs a
DRY-RUN objective check. It never awards credit, never writes qualification records, never performs a
pathway qualification, and requires server-side governance configuration (`RANGER_PARALLAX_ADMINS`) to
even mint a brief - so it is fail-closed by default.

Reviewer adjudication (the human-review gate) is deliberately NOT exposed here; a passing ASSESSMENT
still requires a verified, authorized, assigned reviewer adjudication through the server-side path, and
pathway qualification requires the separate approved portfolio + activation. This route can therefore
never, by itself, qualify anyone.
"""
from __future__ import annotations

import os

from flask import jsonify, request, session


def _on() -> bool:
    return str(os.environ.get("RANGER_PARALLAX_LABA", "")).strip().lower() in ("1", "true", "yes")


def _admins():
    raw = os.environ.get("RANGER_PARALLAX_ADMINS", "")
    return {a.strip() for a in raw.split(",") if a.strip()}


def register(app, candidate_model=None, db=None, helpers=None):
    from parallax import laba_assessment as A, governance
    from parallax import laba_blueprint as BP

    def _candidate_key():
        # dev: prefer an authenticated candidate session, else an explicit handle (dev only)
        c = session.get("cand")
        if c:
            return str(c)
        data = request.get_json(silent=True) or request.values
        return (data.get("handle") or "").strip() or None

    def _dev_approval():
        admins = _admins()
        if not admins:
            return None, None
        approver = sorted(admins)[0]
        return governance.approve_spec(BP.LABA_SPEC, approver_id=approver,
                                       authorized_admins=admins), admins

    @app.get("/parallax/laba/brief")
    def parallax_laba_brief():
        if not _on():
            return ("not found", 404)
        ckey = _candidate_key()
        if not ckey:
            return jsonify(error="candidate handle required"), 400
        approval, admins = _dev_approval()
        if not approval:
            return jsonify(error="PARALLAX governance not configured (set RANGER_PARALLAX_ADMINS)"), 409
        cohort = (request.values.get("cohort") or os.environ.get("DEFAULT_COHORT") or "dev").strip()
        brief = A.candidate_brief(cohort=cohort, candidate_key=ckey, approval=approval,
                                  authorized_admins=admins)
        return jsonify(ok=True, brief=brief, note="development preview; no award, no qualification"), 200

    @app.post("/parallax/laba/evaluate")
    def parallax_laba_evaluate():
        if not _on():
            return ("not found", 404)
        ckey = _candidate_key()
        if not ckey:
            return jsonify(error="candidate handle required"), 400
        approval, admins = _dev_approval()
        if not approval:
            return jsonify(error="PARALLAX governance not configured (set RANGER_PARALLAX_ADMINS)"), 409
        cohort = (request.values.get("cohort") or os.environ.get("DEFAULT_COHORT") or "dev").strip()
        submission = (request.get_json(silent=True) or {}).get("submission") or {}
        # DRY RUN: no server-side reviewer -> assessment cannot be 'met'; returns the objective verdict
        # only. No persistence, no award, no pathway qualification.
        r = A.run_assessment(submission, cohort=cohort, candidate_key=ckey, approval=approval,
                             authorized_admins=admins, reviewer=None)
        return jsonify(ok=True, dry_run=True, assessment_passed=r["assessment_passed"],
                       pathway_qualified=r["pathway_qualified"],
                       candidate_feedback=r["candidate_feedback"],
                       note="development dry-run; human review + governance gates not applied here"), 200
