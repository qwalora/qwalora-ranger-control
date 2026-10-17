"""Ranger-native SOC case management, investigation workspace, and submission UI
(Board 2, Milestone 2).

Mounted on the existing Ranger portal; it reuses the portal's candidate session and
authorization, the real Case / CaseSubmission models, and signing.py. No new auth
system, no separate portal. Everything is behind the RANGER_CASE_UI feature flag so
production stays dark until validation is complete; general candidate access and
act-as remain governed by their own controls.

Security properties enforced here:
  - A candidate may only see and act on their OWN case (case.candidate_id).
  - Evidence is verified server-side against the candidate's OWN authorized index;
    existence, scope, and query reproducibility are candidate-visible, but the hidden
    scenario truth is NEVER consulted on candidate-facing paths or returned.
  - A submitted case is immutable; its evidence record is Ed25519-signed.
  - Admin/reviewer oversight is read-only for signed evidence and objective grades;
    reviewers may add feedback only.
"""
from __future__ import annotations

import json
import os

from flask import abort, jsonify, redirect, render_template, request, session

from siem import authz, case_contract as cc

CASE_BOARD = 2


def _flag_on():
    return os.environ.get("RANGER_CASE_UI", "").strip().lower() in ("1", "true", "yes", "on")


def _shadow_on():
    """The SHADOW enterprise grader is independently gated and OFF by default. It
    never drives qualification; it only records a comparison grade for reviewers."""
    return os.environ.get("RANGER_SHADOW_GRADER", "").strip().lower() in ("1", "true", "yes", "on")


# --- evidence reader (live OpenSearch); injectable for tests -----------------
class LiveReader:
    """Reads the candidate's OWN authorized index to check evidence. Built from the
    broker credential but only ever queried with the candidate's own index, so it
    cannot reach another candidate's data."""

    def __init__(self, cluster):
        self._c = cluster

    def get_source(self, index, event_uid):
        try:
            code, body = self._c._req("GET", f"/{index}/_doc/{event_uid}")
            if code == 200 and isinstance(body, dict) and body.get("found"):
                return body.get("_source")
        except Exception:  # noqa: BLE001
            return None
        return None

    def query_matches(self, index, query, event_uid, time_context=None):
        qbody = query.get("query", query) if isinstance(query, dict) else {"match_all": {}}
        must = [qbody, {"ids": {"values": [event_uid]}}]
        if time_context:
            must.append({"range": {"@timestamp": time_context}})
        body = {"size": 1, "terminate_after": 1, "timeout": "5s",
                "query": {"bool": {"must": must}}}
        try:
            code, resp = self._c._req("GET", f"/{index}/_search", body=body)
            if code != 200:
                return False
            return (resp.get("hits", {}).get("total", {}).get("value", 0) or 0) >= 1
        except Exception:  # noqa: BLE001
            return False


def _default_reader_factory(case):
    """Build a LiveReader scoped to the case's authorized index."""
    from siem.live import LiveCluster
    import base64
    ca_path = None
    cab = os.environ.get("RANGER_CA_B64")
    if cab:
        ca_path = "/tmp/ranger-ca.pem"
        if not os.path.exists(ca_path):
            with open(ca_path, "wb") as f:
                f.write(base64.b64decode(cab))
    cl = LiveCluster(os.environ.get("OPENSEARCH_URL", "https://opensearch.railway.internal:9200"),
                     os.environ.get("OPENSEARCH_ADMIN_USER", "admin"),
                     os.environ["OPENSEARCH_ADMIN_PASSWORD"], ca_path=ca_path, timeout=20)
    return LiveReader(cl)


_reader_factory = _default_reader_factory


def set_reader_factory(fn):
    """Override how the evidence reader is built (tests inject an in-memory reader)."""
    global _reader_factory
    _reader_factory = fn


def register(app, candidate_model, db, helpers):
    """Wire the case UI onto the portal. helpers: {ensure_seed, current_seed}."""
    Case = _model(db, "Case")
    CaseSubmission = _model(db, "CaseSubmission")
    ensure_seed = helpers["ensure_seed"]
    _DEFCO = os.environ.get("DEFAULT_COHORT", "2026-A")
    ORG = "valyria-financial"

    def _guard():
        if not _flag_on():
            abort(404)

    def _candidate():
        cid = session.get("cand")
        if not cid:
            abort(401)
        c = candidate_model.query.get(cid)
        if not c:
            abort(401)
        if c.status != "active":
            abort(403)
        if int(c.current_board or 0) != CASE_BOARD:
            abort(403)
        return c

    def _slug(c):
        return authz._slug(c.github_id or c.handle)

    def _ensure_case(c):
        """Assign (idempotently) the candidate's Board 2 qualification case."""
        cohort = c.cohort or _DEFCO
        case = (Case.query.filter_by(candidate_id=c.id, board=CASE_BOARD,
                                     plane="qualification")
                .order_by(Case.attempt.desc()).first())
        if case:
            return case
        a = ensure_seed(c, CASE_BOARD)
        db.session.commit()
        slug = _slug(c)
        idx = authz.index_name(cohort, slug, CASE_BOARD)
        case = Case(candidate_id=c.id, board=CASE_BOARD, cohort=cohort,
                    plane="qualification", workflow="qualification",
                    index_name=idx, seed=a.seed,
                    scenario_version=cc.SCENARIO_VERSION, rubric_version=cc.RUBRIC_VERSION,
                    attempt=1, status="assigned")
        db.session.add(case)
        db.session.commit()
        return case

    def _own_case(cid):
        c = _candidate()
        case = Case.query.get(cid)
        if not case or case.candidate_id != c.id:
            abort(404)   # do not reveal another candidate's case exists
        return c, case

    def _draft(case):
        sub = (CaseSubmission.query.filter_by(case_id=case.id, attempt=case.attempt,
                                              submission_status="draft")
               .order_by(CaseSubmission.id.desc()).first())
        return sub

    def _window(case):
        # Candidate-facing window label (no truth): derived from the scenario anchor.
        return (os.environ.get("RANGER_SIEM_TIME_FROM", "2026-02-28T00:00:00.000Z"),
                os.environ.get("RANGER_SIEM_TIME_TO", "2026-04-01T00:00:00.000Z"))

    def _locked(case):
        return case.status in ("submitted", "under_review", "evaluated", "feedback", "closed")

    # --- candidate: overview -------------------------------------------------
    @app.get("/case")
    def case_overview():
        _guard()
        c = _candidate()
        case = _ensure_case(c)
        wf, wt = _window(case)
        return render_template("case_overview.html",
                               case=case, brief=cc.candidate_brief(ORG, wf, wt),
                               org=ORG, window_from=wf, window_to=wt,
                               locked=_locked(case))

    # --- candidate: investigation workspace ---------------------------------
    @app.get("/case/<int:cid>")
    def case_workspace(cid):
        _guard()
        c, case = _own_case(cid)
        if case.status == "assigned":
            case.status = "authorized"
        if case.status == "authorized":
            case.status = "investigating"
            from datetime import datetime, timezone
            case.started_at = datetime.now(timezone.utc)
        db.session.commit()
        sub = _draft(case)
        payload = json.loads(sub.payload) if (sub and sub.payload) else None
        latest = (CaseSubmission.query.filter_by(case_id=case.id)
                  .order_by(CaseSubmission.id.desc()).first())
        wf, wt = _window(case)
        return render_template("case_workspace.html",
                               case=case, payload=payload, org=ORG,
                               window_from=wf, window_to=wt,
                               submission_status=(latest.submission_status if latest else "none"),
                               locked=_locked(case), roles=cc.ROLES,
                               dispositions=cc.DISPOSITIONS, severities=cc.SEVERITIES)

    # --- candidate: autosave draft ------------------------------------------
    @app.post("/case/<int:cid>/draft")
    def case_draft(cid):
        _guard()
        c, case = _own_case(cid)
        if _locked(case):
            return jsonify({"ok": False, "error": "case is submitted and locked"}), 409
        payload = request.get_json(silent=True) or {}
        validation = cc.validate_submission(payload)
        sub = _draft(case)
        if sub is None:
            sub = CaseSubmission(case_id=case.id, candidate_id=c.id, attempt=case.attempt,
                                 submission_status="draft", rubric_version=case.rubric_version)
            db.session.add(sub)
        sub.payload = json.dumps(payload)
        sub.validation = json.dumps(validation)
        if case.status == "investigating" and payload.get("incidents"):
            case.status = "evidence_collected"
        db.session.commit()
        return jsonify({"ok": True, "validation": validation, "submission_id": sub.id})

    # --- candidate: verify evidence (truth-safe) ----------------------------
    @app.post("/case/<int:cid>/verify")
    def case_verify(cid):
        _guard()
        c, case = _own_case(cid)
        payload = request.get_json(silent=True)
        if payload is None:
            sub = _draft(case)
            payload = json.loads(sub.payload) if (sub and sub.payload) else {}
        reader = _reader_factory(case)
        result = cc.candidate_verification(payload, reader, case.index_name)
        return jsonify({"ok": True, "verification": result})

    # --- candidate: submit (lock + sign) ------------------------------------
    @app.post("/case/<int:cid>/submit")
    def case_submit(cid):
        _guard()
        c, case = _own_case(cid)
        if _locked(case):
            return jsonify({"ok": False, "error": "already submitted"}), 409
        sub = _draft(case)
        payload = json.loads(sub.payload) if (sub and sub.payload) else (request.get_json(silent=True) or {})
        validation = cc.validate_submission(payload)
        if not validation["ok"]:
            return jsonify({"ok": False, "stage": "validation", "validation": validation}), 422
        reader = _reader_factory(case)
        verification = cc.candidate_verification(payload, reader, case.index_name)
        # Every cited reference must be real, in-scope, and reproducible to submit.
        bad = [ct for inc in verification["incidents"] for ct in inc["citations"]
               if not ct["reference_valid"]]
        if bad:
            return jsonify({"ok": False, "stage": "evidence", "verification": verification}), 422
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        from siem import schema as _schema
        meta = {"candidate": _slug(c), "board": CASE_BOARD, "cohort": case.cohort,
                # opaque case reference, not the protected seed (which stays on the Case row only)
                "scenario_ref": _schema.case_ref(_slug(c), CASE_BOARD, case.seed),
                "scenario_version": case.scenario_version,
                "rubric_version": case.rubric_version, "case_id": case.id,
                "submitted_at": now_iso}
        record, sig = cc.preserve_and_sign(payload, reader, case.index_name, meta)
        if sub is None:
            sub = CaseSubmission(case_id=case.id, candidate_id=c.id, attempt=case.attempt,
                                 rubric_version=case.rubric_version)
            db.session.add(sub)
        sub.payload = json.dumps(payload)
        sub.validation = json.dumps(validation)
        sub.verification = json.dumps(verification)
        sub.evidence_record = json.dumps(record)
        sub.evidence_sig = sig
        sub.submission_status = "submitted"
        sub.submitted_at = datetime.now(timezone.utc)
        case.status = "submitted"
        case.submitted_at = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify({"ok": True, "submission_status": "submitted",
                        "evidence_signed": True, "case_status": case.status})

    # --- admin/reviewer oversight (read-only for signed evidence + grades) ---
    def _admin():
        if not session.get("admin"):
            abort(403)
        return session.get("admin_login") or str(session.get("admin"))

    @app.get("/admin/cases")
    def admin_cases():
        _guard()
        _admin()
        rows = Case.query.order_by(Case.id.desc()).limit(500).all()
        return jsonify({"ok": True, "cases": [
            {"id": r.id, "candidate_id": r.candidate_id, "cohort": r.cohort,
             "plane": r.plane, "workflow": r.workflow, "status": r.status,
             "attempt": r.attempt, "scenario_version": r.scenario_version,
             "rubric_version": r.rubric_version} for r in rows]})

    @app.get("/admin/cases/<int:cid>")
    def admin_case_detail(cid):
        _guard()
        _admin()
        case = Case.query.get(cid)
        if not case:
            abort(404)
        subs = (CaseSubmission.query.filter_by(case_id=cid)
                .order_by(CaseSubmission.id.desc()).all())
        def view(s):
            return {"id": s.id, "attempt": s.attempt, "status": s.submission_status,
                    "rubric_version": s.rubric_version,
                    "payload": json.loads(s.payload) if s.payload else None,
                    "verification": json.loads(s.verification) if s.verification else None,
                    "evidence_record": json.loads(s.evidence_record) if s.evidence_record else None,
                    "evidence_sig": s.evidence_sig,
                    "evidence_signature_valid": (
                        cc.verify_evidence_record(json.loads(s.evidence_record), s.evidence_sig)
                        if (s.evidence_record and s.evidence_sig) else None),
                    "shadow_score": s.shadow_score,
                    "shadow_breakdown": json.loads(s.shadow_breakdown) if s.shadow_breakdown else None,
                    "review_flags": json.loads(s.review_flags) if s.review_flags else None,
                    "reviewer_feedback": s.reviewer_feedback}
        return jsonify({"ok": True, "case": {"id": case.id, "status": case.status,
                        "candidate_id": case.candidate_id},
                        "submissions": [view(s) for s in subs]})

    @app.post("/admin/cases/submission/<int:sid>/feedback")
    def admin_case_feedback(sid):
        """Reviewer may add feedback ONLY. This route never touches the signed
        evidence record/signature, the shadow score, or any objective grade."""
        _guard()
        who = _admin()
        s = CaseSubmission.query.get(sid)
        if not s:
            abort(404)
        from datetime import datetime, timezone
        s.reviewer_feedback = (request.get_json(silent=True) or {}).get("feedback", "")
        s.reviewer_id = who
        s.reviewed_at = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify({"ok": True})

    @app.post("/admin/cases/submission/<int:sid>/shadow")
    def admin_case_shadow(sid):
        """Compute (or recompute) the SHADOW enterprise grade for a submitted
        submission and store it on the shadow-only fields. Reviewer-only and gated
        by RANGER_SHADOW_GRADER. It NEVER writes an objective grade, never alters
        the signed evidence record/signature, and never affects clearance. The
        hidden truth is consulted server-side only and never returned raw."""
        _guard()
        self_who = _admin()
        if not _shadow_on():
            abort(404)
        s = CaseSubmission.query.get(sid)
        if not s:
            abort(404)
        if s.submission_status not in ("submitted", "under_review", "evaluated"):
            return jsonify({"ok": False, "error": "submission is not finalized"}), 409
        case = Case.query.get(s.case_id)
        cand = candidate_model.query.get(s.candidate_id)
        if not case or not cand:
            abort(404)
        from siem import enterprise, enterprise_grader as eg
        profile = os.environ.get("RANGER_B2_PROFILE", "B")
        _events, truth = enterprise.generate(_slug(cand), CASE_BOARD, case.seed, profile)
        payload = json.loads(s.payload) if s.payload else {}
        reader = _reader_factory(case)
        result = eg.score_board2_enterprise(truth, payload, reader, case.index_name)
        s.shadow_score = result["score"]
        s.shadow_breakdown = json.dumps(result["components"])
        s.review_flags = json.dumps(result["review_flags"])
        # objective grade, evidence record + signature, and clearance are untouched.
        db.session.commit()
        # Return the breakdown WITHOUT the raw matching detail (which would echo the
        # truth event_uids); reviewers get scores, anchors, and flags only.
        safe = {"score": result["score"], "normalized": result["normalized"],
                "components": result["components"], "review_flags": result["review_flags"],
                "version": result["version"], "rubric_version": result["rubric_version"],
                "shadow": True, "pass_bar_reference": result["pass_bar_reference"]}
        return jsonify({"ok": True, "shadow": safe})

    app.logger.info("case UI registered at /case (flag RANGER_CASE_UI=%s, shadow=%s)",
                    _flag_on(), _shadow_on())


def _model(db, name):
    """Fetch a mapped model class by name from the SQLAlchemy registry."""
    for m in db.Model.registry.mappers:
        if m.class_.__name__ == name:
            return m.class_
    raise RuntimeError(f"model {name} not registered")
