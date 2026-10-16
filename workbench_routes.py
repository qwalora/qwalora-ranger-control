"""F5 - Candidate Workbench routes (pathway-aware), wired into the existing Flask app via
`register(app, candidate_model, db, helpers)`, exactly like case_routes.py (no blueprints).

Every route guards on the RANGER_WORKBENCH flag (404 when off, so production stays dark), reads
identity from session["cand"], enforces Candidate.status == "active", derives pathway server-side
from the cohort, and returns 404 on any ownership mismatch. All heavy logic lives in workbench_core;
these handlers are thin and never make a security decision the core didn't.
"""
from __future__ import annotations

from flask import (session, request, render_template, redirect, url_for, abort, Response)

import workbench_core as wc


def register(app, candidate_model, db, helpers=None):
    Candidate = candidate_model

    # ---- guards -------------------------------------------------------------
    def _guard():
        if not wc.workbench_enabled():
            abort(404)

    def _wants_json():
        return request.path.endswith(".json") or "application/json" in (request.headers.get("Accept") or "")

    def _cand():
        """Authenticated + ADMITTED candidate, or a redirect/401. A GitHub login alone is not
        admission: status must be 'active'."""
        cid = session.get("cand")
        if not cid:
            if _wants_json():
                abort(401)
            return None, redirect(url_for("gh_login"))
        c = Candidate.query.get(cid)
        if c is None:
            session.pop("cand", None)
            return None, redirect(url_for("gh_login"))
        if c.status != "active":
            # authenticated applicant who is not admitted: no workbench access
            return None, (_render_locked(c))
        return c, None

    def _render_locked(c):
        return render_template("workbench_locked.html", status=c.status,
                               flags=wc.flags_snapshot()), 403

    def _err_redirect(cid, err):
        return redirect(url_for("workbench_case", cid=cid, err=err))

    # ---- overview -----------------------------------------------------------
    @app.get("/workbench")
    def workbench_home():
        _guard()
        c, resp = _cand()
        if resp is not None:
            return resp
        pathway = wc.resolve_pathway(db, c)
        cases = wc.list_cases(db, c) if wc._flag_on(wc.FLAG_CASE_ACCESS) else []
        from models import EvidenceArtifact
        evidence_pending = EvidenceArtifact.query.filter_by(
            candidate_id=c.id, validation_state="needs_review").count()
        vm = {
            "candidate": {"handle": c.handle, "name": c.name, "cohort": c.cohort,
                          "status": c.status},
            "pathway": pathway,
            "pathway_brand": __import__("pathways").branding(pathway).get("name") or pathway.upper(),
            "flags": wc.flags_snapshot(),
            "cases": [wc.case_scope_view(cs, pathway) for cs in cases],
            "evidence_pending": evidence_pending,
            "qualification": _qualification_view(pathway),
        }
        return render_template("workbench_overview.html", vm=vm)

    # ---- investigation workspace -------------------------------------------
    @app.get("/workbench/case/<int:cid>")
    def workbench_case(cid):
        _guard()
        c, resp = _cand()
        if resp is not None:
            return resp
        if not wc._flag_on(wc.FLAG_CASE_ACCESS):
            abort(404)
        try:
            case = wc.own_case(db, c, cid)
        except wc.WorkbenchError as e:
            abort(e.http)
        pathway = wc.resolve_pathway(db, c)
        sub = wc._submission(db, case, c)
        import json as _json
        payload = _json.loads(sub.payload) if (sub and sub.payload) else {}
        vm = {
            "case": wc.case_scope_view(case, pathway),
            "pathway": pathway,
            "flags": wc.flags_snapshot(),
            "evidence": [_evidence_vm(e) for e in wc.candidate_evidence(db, c, case.id)],
            "permitted_evidence_types": wc.permitted_evidence_types(pathway),
            "payload": payload,
            "submission": _submission_vm(sub),
            "receipt_ok": wc.verify_receipt(sub) if sub else False,
            "status": wc.assessment_status_view(case, sub, pathway),
            "locked": bool(sub and sub.submission_status != "draft"),
            "err": request.args.get("err"),
        }
        return render_template("workbench_case.html", vm=vm)

    @app.post("/workbench/case/<int:cid>/draft")
    def workbench_draft(cid):
        _guard()
        c, resp = _cand()
        if resp is not None:
            return resp
        try:
            case = wc.own_case(db, c, cid)
        except wc.WorkbenchError as e:
            abort(e.http)
        import json as _json
        sub = wc._submission(db, case, c)
        payload = _json.loads(sub.payload) if (sub and sub.payload) else {}
        findings = list(payload.get("findings") or [])
        action = request.form.get("action", "save")
        if action == "add_finding":
            claim = (request.form.get("claim") or "").strip()
            if claim:
                findings.append({
                    "claim": claim, "scope": request.form.get("scope"),
                    "methodology": request.form.get("methodology"),
                    "observed_outcome": request.form.get("observed_outcome"),
                    "significance": request.form.get("significance"),
                    "remediation": request.form.get("remediation"),
                    "limitations": request.form.get("limitations"),
                    "evidence_refs": request.form.getlist("finding_evidence_refs")})
        elif action == "remove_finding":
            try:
                findings.pop(int(request.form.get("index", -1)))
            except (ValueError, IndexError):
                pass
        notes = [n for n in (request.form.get("notes") or "").splitlines() if n.strip()] \
            if action == "save" else (payload.get("notes") or [])
        refs = request.form.getlist("evidence_refs") if action == "save" else \
            (payload.get("evidence_refs") or [])
        merged = {"findings": findings, "notes": notes, "evidence_refs": refs,
                  "approach": request.form.get("approach") if action == "save"
                  else payload.get("approach"),
                  "submission_version": payload.get("submission_version", 0)}
        try:
            wc.save_draft(db, case, c, merged)
        except wc.WorkbenchError as e:
            return _err_redirect(cid, e.code)
        return redirect(url_for("workbench_case", cid=cid))

    @app.post("/workbench/case/<int:cid>/evidence")
    def workbench_evidence(cid):
        _guard()
        c, resp = _cand()
        if resp is not None:
            return resp
        try:
            case = wc.own_case(db, c, cid)
            pathway = wc.resolve_pathway(db, c)
            f = request.files.get("file")
            if f is None or not f.filename:
                raise wc.WorkbenchError("NO_FILE", 400, "no file provided")
            store = wc.evidence_store()
            wc.submit_evidence(db, store, case, c, pathway, f.stream,
                               evidence_type=request.form.get("evidence_type", ""),
                               declared_media_type=f.mimetype,
                               source_identity=f"candidate:{c.id}")
        except wc.WorkbenchError as e:
            return _err_redirect(cid, e.code)
        return redirect(url_for("workbench_case", cid=cid))

    @app.get("/workbench/case/<int:cid>/evidence/<eid>/download")
    def workbench_evidence_download(cid, eid):
        _guard()
        c, resp = _cand()
        if resp is not None:
            return resp
        try:
            case = wc.own_case(db, c, cid)
            pathway = wc.resolve_pathway(db, c)
            store = wc.evidence_store()
            row, data = wc.retrieve_evidence(db, store, c, pathway, eid)
            if row.case_id != case.id:
                abort(404)
        except wc.WorkbenchError as e:
            abort(e.http)
        return Response(data, mimetype=row.blob_media_type or "application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="{eid}"'})

    @app.post("/workbench/case/<int:cid>/submit")
    def workbench_submit(cid):
        _guard()
        c, resp = _cand()
        if resp is not None:
            return resp
        try:
            case = wc.own_case(db, c, cid)
            pathway = wc.resolve_pathway(db, c)
            store = wc.evidence_store()
            wc.finalize_submission(db, store, case, c, pathway)
        except wc.WorkbenchError as e:
            return _err_redirect(cid, e.code)
        return redirect(url_for("workbench_case", cid=cid))

    # ---- reviewer views (scoped; no superuser bypass) ----------------------
    @app.get("/workbench/review/submissions")
    def workbench_review_list():
        _guard()
        if not session.get("admin"):
            abort(403)
        scope = wc.reviewer_scope(session.get("admin_login"))
        if not scope:
            abort(403)   # a reviewer with no cohort authorization has no access
        from models import CaseSubmission, Case
        rows = []
        subs = CaseSubmission.query.filter(CaseSubmission.submission_status != "draft").order_by(
            CaseSubmission.id.desc()).all()
        for s in subs:
            case = Case.query.get(s.case_id)
            if not case:
                continue
            co = _cohort_pathway(db, case.cohort)
            if not wc.reviewer_can_see(scope, cohort=case.cohort, pathway=co):
                continue
            rows.append({"sid": s.id, "case_id": s.case_id, "candidate_id": s.candidate_id,
                         "cohort": case.cohort, "pathway": co, "status": s.submission_status,
                         "submitted_at": wc._s(s.submitted_at)})
        return render_template("workbench_review.html", rows=rows, scope=sorted(scope["cohorts"]))

    @app.get("/workbench/review/submission/<int:sid>")
    def workbench_review_detail(sid):
        _guard()
        if not session.get("admin"):
            abort(403)
        scope = wc.reviewer_scope(session.get("admin_login"))
        if not scope:
            abort(403)
        from models import CaseSubmission, Case
        s = CaseSubmission.query.get(sid)
        if not s:
            abort(404)
        case = Case.query.get(s.case_id)
        co = _cohort_pathway(db, case.cohort) if case else None
        if not case or not wc.reviewer_can_see(scope, cohort=case.cohort, pathway=co):
            abort(404)   # outside the reviewer's scope -> never reveal it exists
        import json as _json
        payload = _json.loads(s.payload) if s.payload else {}
        receipt = _json.loads(s.evidence_record) if s.evidence_record else None
        vm = {"sid": s.id, "case_id": s.case_id, "candidate_id": s.candidate_id,
              "cohort": case.cohort, "pathway": co, "status": s.submission_status,
              "payload": payload, "receipt": receipt, "receipt_ok": wc.verify_receipt(s),
              "evidence": [_evidence_vm(e) for e in
                           wc.candidate_evidence_by_case(db, s.candidate_id, s.case_id)]}
        return render_template("workbench_review_detail.html", vm=vm)

    return app


def _cohort_pathway(db, cohort_name):
    from models import Cohort
    import pathways as _pw
    co = Cohort.query.filter_by(name=cohort_name).first() if cohort_name else None
    return _pw.normalize_pathway(co.pathway if co and co.pathway else _pw.DEFAULT_PATHWAY)


# ---- view-model helpers ----------------------------------------------------
def _qualification_view(pathway):
    import pathways as _pw
    from siem import assessment_contract as ac
    if _pw.normalize_pathway(pathway) == _pw.PATHWAY_PARALLAX:
        return {"eligible": False, "active": ac.parallax_qualification_active(),
                "statement": "PARALLAX qualification is inactive. Assessments may be completed for "
                             "technical verification; no qualification is conferred."}
    return {"eligible": True, "active": True,
            "statement": "STRATA qualification follows the authorized objective bar and reviewer "
                         "adjudication."}


def _evidence_vm(e):
    return {"evidence_id": e.evidence_id, "evidence_type": e.evidence_type,
            "validation_state": e.validation_state, "scan_state": e.scan_state,
            "media_type": e.blob_media_type, "bytes": e.blob_bytes,
            "sha256": (e.content_hash or "")[:16]}


def _submission_vm(sub):
    if not sub:
        return None
    return {"id": sub.id, "status": sub.submission_status, "attempt": sub.attempt,
            "submitted_at": wc._s(sub.submitted_at),
            "has_receipt": bool(sub.evidence_record and sub.evidence_sig)}


def _parse_json_field(raw, default):
    import json as _json
    if not raw:
        return default
    try:
        v = _json.loads(raw)
        return v if isinstance(v, type(default)) else default
    except Exception:
        return default
