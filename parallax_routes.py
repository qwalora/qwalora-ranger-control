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


# Per-candidate research-run rate limiting (Phase 2C isolation control). Best-effort in-process window;
# a multi-worker deployment would use a shared store (documented as a limitation in the 2C report).
_RUN_HITS: dict = {}


def _rate_limited(key: str) -> bool:
    import time as _t
    try:
        limit = int(os.environ.get("RANGER_RESEARCH_RUN_LIMIT_PER_MIN", "20") or "20")
    except ValueError:
        limit = 20
    now = _t.time()
    window = [t for t in _RUN_HITS.get(key, []) if now - t < 60.0]
    if len(window) >= limit:
        _RUN_HITS[key] = window
        return True
    window.append(now)
    _RUN_HITS[key] = window
    return False


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

    # ---- Phase 1E: durable, integrated assessment lifecycle (still nonprod + flag gated) ----------
    # These endpoints drive the DURABLE persistence modules through real request + persistence
    # boundaries. Governance approval is read from the authoritative persisted registry (never minted
    # in a candidate route). Identity is always the authenticated session, never a query parameter.
    import strata_catalog as _cat
    from parallax import (registry as _reg, reviewer_store as _rev, assessment_store as _store,
                          review as _review, traceability as _trace)

    def _resolve_candidate_key():
        """Resolve the AUTHENTICATED session identity (session['cand'] is the Candidate id set by the
        GitHub-OAuth flow) to a stable candidate_key (github_id, else handle), enforcing active status.
        Identity never comes from a query parameter or request body."""
        cid = session.get("cand")
        if not cid or candidate_model is None:
            return None
        c = candidate_model.query.get(cid)
        if c is None or getattr(c, "status", None) != "active":
            return None
        return c.github_id or c.handle

    def _persisted_ctx():
        """(candidate_key, approval, admins, err) for the durable path: authenticated candidate session
        + the PERSISTED, signature-verified governance approval from the registry."""
        if not _nonprod():
            return None, None, None, ("not found", 404)
        ckey = _resolve_candidate_key()
        if not ckey:
            return None, None, None, (jsonify(error="active authenticated candidate session required"), 401)
        try:
            approval = _reg.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint())
            admins = _reg.authorized_admins(db)
        except Exception:  # noqa: BLE001 - authoritative dependency unavailable -> fail closed
            return None, None, None, (jsonify(error="governance registry unavailable"), 503)
        if not approval:
            return None, None, None, (jsonify(
                error="no active persisted PARALLAX approval; an authorized admin must approve the "
                      "scoring spec first"), 409)
        return ckey, approval, admins, None

    def _reviewer_identity():
        return str(session.get("admin_gid") or "").strip() or None

    def _admin_principal():
        from models import AdminUser
        gid = _reviewer_identity()
        return AdminUser.query.filter_by(github_id=gid).first() if gid else None

    @app.post("/parallax/laba/assessment")
    def parallax_laba_assessment_submit():
        ckey, approval, admins, err = _persisted_ctx()
        if err:
            return err
        cohort = (request.values.get("cohort") or os.environ.get("DEFAULT_COHORT") or "dev").strip()
        submission = (request.get_json(silent=True) or {}).get("submission") or {}
        env = A.run_assessment(submission, cohort=cohort, candidate_key=ckey, approval=approval,
                               authorized_admins=admins, reviewer=None)   # reviewer applied separately
        try:
            res = _store.record_assessment(db, env, candidate_key=ckey)
        except _store.AssessmentPersistError as e:
            return jsonify(error="could not persist assessment: %s" % e), 409
        tr = _trace.verify_assessment(db, candidate_key=ckey, assessment_id="LAB-A")
        return jsonify(ok=True, simulation=True,
                       simulation_label="Lab A bounded simulation (not live infrastructure)",
                       assessment_id="LAB-A", decision_record_hash=res["decision_row"].record_hash,
                       disposition=tr["disposition"],
                       note="assessment-only; never a pathway qualification"), 201

    @app.get("/parallax/laba/assessment/status")
    def parallax_laba_assessment_status():
        ckey, approval, admins, err = _persisted_ctx()
        if err:
            return err
        tr = _trace.verify_assessment(db, candidate_key=ckey, assessment_id="LAB-A")
        return jsonify(ok=True, verdict=tr["verdict"], disposition=tr["disposition"],
                       scoring_result=tr["fields"].get("scoring_result"),
                       simulation=tr["simulation"], simulation_label=tr["simulation_label"],
                       pathway_qualified=False), 200

    def _reviewer_guard():
        if not _nonprod():
            return None, ("not found", 404)
        if not session.get("admin"):
            return None, (jsonify(error="reviewer authentication required"), 401)
        rid = _reviewer_identity()
        if not rid:
            return None, (jsonify(error="reviewer identity could not be resolved from session"), 401)
        return rid, None

    @app.get("/parallax/laba/review/assignments")
    def parallax_laba_review_assignments():
        rid, err = _reviewer_guard()
        if err:
            return err
        from models import ParallaxReviewerAssignment
        rows = ParallaxReviewerAssignment.query.filter_by(reviewer_id=rid, status="active").all()
        items = []
        for r in rows:
            if not _rev._is_active(r):
                continue   # only live assignments (not expired)
            tr = _trace.verify_assessment(db, candidate_key=r.candidate_key,
                                          assessment_id=r.assessment_id)
            items.append({"candidate_key": r.candidate_key, "cohort": r.cohort,
                          "assessment_id": r.assessment_id, "attempt": r.attempt,
                          "verdict": tr["verdict"], "disposition": tr["disposition"],
                          "scoring_result": tr["fields"].get("scoring_result"), "simulation": True})
        return jsonify(ok=True, assignments=items), 200

    @app.post("/parallax/laba/review/adjudicate")
    def parallax_laba_review_adjudicate():
        rid, err = _reviewer_guard()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        ckey = str(body.get("candidate_key") or "").strip()
        decision = str(body.get("decision") or "").strip()
        note = str(body.get("note") or "")[:500]
        rubric_scores = body.get("rubric_scores") or {}
        if decision not in ("pass", "fail"):
            return jsonify(error="decision must be 'pass' or 'fail'"), 400
        rec = _store.assessment_record_for(db, candidate_key=ckey, assessment_id="LAB-A")
        if rec is None:
            return jsonify(error="no assessment record to adjudicate"), 404
        drec = rec["signed_decision"]["record"]
        prov = ((drec.get("decision") or {}).get("provenance") or {})
        binding = prov.get("binding") or {}
        prov_hash = prov.get("provenance_hash")
        directory = _rev.directory_for(db, binding)
        try:
            # make_adjudication enforces: rid is an authorized reviewer AND is the assigned reviewer
            # for this exact binding; an admin without an assignment cannot adjudicate.
            adj = _review.make_adjudication(reviewer_id=rid, directory=directory, binding=binding,
                                            assessment_record_hash=prov_hash, decision=decision,
                                            note=note, rubric_scores=rubric_scores)
        except _review.ReviewAuthorityError as e:
            return jsonify(error="reviewer not authorized/assigned for this assessment: %s" % e), 403
        try:
            _store.record_assessment(db, {"signed": rec["signed_decision"], "adjudication": adj},
                                     candidate_key=ckey)
        except _store.AssessmentPersistError as e:
            return jsonify(error="could not persist adjudication: %s" % e), 409
        tr = _trace.verify_assessment(db, candidate_key=ckey, assessment_id="LAB-A")
        return jsonify(ok=True, simulation=True, verdict=tr["verdict"], disposition=tr["disposition"],
                       pathway_qualified=False), 201

    @app.post("/parallax/laba/admin/assign-reviewer")
    def parallax_laba_admin_assign_reviewer():
        if not _nonprod():
            return ("not found", 404)
        ok, _who = _cat._is_authorized_admin(None)   # session-bound authority (ignores any argument)
        if not ok:
            return jsonify(error="authorized administrator session required"), 403
        body = request.get_json(silent=True) or {}
        reviewer_id = str(body.get("reviewer_id") or "").strip()
        ckey = str(body.get("candidate_key") or "").strip()
        cohort = str(body.get("cohort") or os.environ.get("DEFAULT_COHORT") or "dev").strip()
        attempt = int(body.get("attempt") or 1)
        try:
            _rev.assign_reviewer(db, principal=_admin_principal(), reviewer_id=reviewer_id,
                                 candidate_key=ckey, cohort=cohort, assessment_id="LAB-A",
                                 attempt=attempt)
        except _rev.AssignmentError as e:
            return jsonify(error="assignment refused: %s" % e), 409
        except _reg.RegistryAuthError as e:
            return jsonify(error="not authorized: %s" % e), 403
        return jsonify(ok=True, assigned=reviewer_id, candidate_key=ckey, assessment_id="LAB-A",
                       attempt=attempt), 201

    # ---- Phase 2A: AI-security research harness integration (nonprod + flag gated) ---------------
    # Authorized researcher (authenticated candidate session) initiates a BOUNDED prompt-injection
    # campaign against the configured model backend. With no authorized real model configured the
    # backend is the deterministic STUB and the run is persisted with backend_provenance="simulated"
    # (explicitly NOT an empirical finding). Research runs are assessment/qualification-neutral.
    def parallax_research_run():
        if not _nonprod():
            return ("not found", 404)
        rid = _resolve_candidate_key()
        if not rid:
            return jsonify(error="active authenticated researcher session required"), 401
        if _rate_limited("run:%s" % rid):
            return jsonify(error="research-run rate limit exceeded; try again shortly"), 429
        from parallax.research import harness as _h, corpus as _corpus, model_backend as _mb
        from parallax.research import store as _rstore
        body = request.get_json(silent=True) or {}
        try:
            reps = max(1, min(int(body.get("repetitions") or 1), 3))   # bounded
        except (TypeError, ValueError):
            reps = 1
        backend = _mb.from_config()     # real endpoint if configured, else deterministic stub
        camp = _h.run_campaign(backend, _corpus.default_corpus(), repetitions=reps)
        camp["metrics"] = _h.compute_metrics(camp["records"])
        try:
            row = _rstore.persist_run(db, researcher_id=rid, campaign=camp)
        except _rstore.ResearchStoreError as e:
            return jsonify(error="could not persist research run: %s" % e), 409
        prov = row.backend_provenance
        return jsonify(
            ok=True, run_id=row.run_id, backend_provenance=prov,
            is_empirical_finding=(prov == "infrastructure_backed"),
            findings_available=camp["metrics"]["findings_available"],
            model=camp["manifest"]["backend"], n_records=row.record_count,
            metrics_summary={"real_backend_n": camp["metrics"]["real_backend"]["n"],
                             "simulated_backend_n": camp["metrics"]["simulated_backend"]["n"]},
            note=("SIMULATED harness plumbing run - NOT an empirical AI-security finding; no real model "
                  "is configured in this environment" if prov == "simulated"
                  else "infrastructure-backed research run"),
            assessment_only=True, pathway_qualified=False), 201
    app.add_url_rule("/parallax/research/run", "parallax_research_run", parallax_research_run,
                     methods=["POST"])

    def parallax_research_get(run_id):
        if not _nonprod():
            return ("not found", 404)
        rid = _resolve_candidate_key()
        if not rid:
            return jsonify(error="active authenticated researcher session required"), 401
        from parallax.research import store as _rstore
        try:
            run = _rstore.get_run(db, run_id=run_id, authenticated_researcher_id=rid)
        except _rstore.ResearchStoreError:
            return jsonify(error="not found"), 404     # never reveal another researcher's run exists
        if run is None:
            return jsonify(error="not found"), 404
        return jsonify(ok=True, run_id=run["run_id"], backend_provenance=run["backend_provenance"],
                       signature_verifies=run["signature_verifies"],
                       is_empirical_finding=run["is_empirical_finding"],
                       record_count=run["record_count"], model_id=run["model_id"],
                       metrics=run["record"].get("metrics"), assessment_only=True,
                       pathway_qualified=False), 200
    app.add_url_rule("/parallax/research/run/<run_id>", "parallax_research_get", parallax_research_get,
                     methods=["GET"])

    # ---- Phase 2C: model readiness/health for the research workspace (nonprod + flag gated) --------
    # Reports the configured backend's identity/provenance. For a REAL backend it performs a tiny
    # liveness generation with the backend's own timeout and reports the result honestly; a failure is
    # surfaced (live=False + error), never faked. For the stub it reports simulated / not a finding.
    def parallax_research_model_health():
        if not _nonprod():
            return ("not found", 404)
        rid = _resolve_candidate_key()
        if not rid:
            return jsonify(error="active authenticated researcher session required"), 401
        from parallax.research import model_backend as _mb
        try:
            be = _mb.from_config()
        except _mb.ModelBackendError as e:
            return jsonify(ok=False, configured=False, error=str(e)), 200
        ident = be.identity()
        info = {"ok": True, "backend": ident["backend"], "is_real": ident["is_real"],
                "model_id": ident["model_id"], "runtime": ident["runtime"],
                "backend_provenance": "infrastructure_backed" if ident["is_real"] else "simulated"}
        if ident["is_real"]:
            try:
                r = be.generate(_mb.GenRequest(system="You are a helpful assistant.", developer="",
                                               task="Reply with the single word OK.", context=[],
                                               max_tokens=8))
                info.update(live=True, sample_len=len(r.text or ""), latency_s=r.meta.get("latency_s"))
            except _mb.ModelBackendError as e:
                info.update(live=False, error=str(e))
        else:
            info.update(live=False, note="no real model configured; deterministic stub (not a finding)")
        return jsonify(info), 200
    app.add_url_rule("/parallax/research/model/health", "parallax_research_model_health",
                     parallax_research_model_health, methods=["GET"])
