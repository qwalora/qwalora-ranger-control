"""Qwalora Ranger - control plane.

Minimal, honest launch surface:

  Public
    GET  /                      landing
    GET  /healthz               liveness + db check (Railway healthcheck)
    GET  /enroll                enrollment form
    POST /enroll                create candidate, issue submission token, queue range
    POST /reports               submit a written report  (X-Candidate-Token header)

  Admin (bearer ADMIN_TOKEN, or session login at /admin/login)
    GET  /admin                 dashboard: candidates + reports, approve/reject
    POST /admin/reports/<id>    set review status + notes
    GET  /roster.json?cohort=   roster in the exact shape cohort-sync consumes

Objective grading is NOT here. It stays answer-free and program-side: the
program clones each repo, re-measures, and signs the cohort. This plane holds
the human-review surface and the Ludus provisioning queue.
"""
import datetime as _dt
import functools
import os

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   session, url_for)

from broker import broker_status, queue_range
from models import Candidate, RangeRequest, Report, db

DEFAULT_COHORT = os.environ.get("DEFAULT_COHORT", "2026-A")
ROLES = ["red-teamer", "detection-engineer", "soc-analyst", "incident-responder"]
BOARDS = ["board1", "board2", "board3", "board4", "board5", "board6"]
ROLE_TITLES = {"red-teamer": "Red Team", "detection-engineer": "Detection Engineering",
               "soc-analyst": "SOC Analyst triage", "incident-responder": "Incident Response"}


def _initials(name):
    parts = [p for p in (name or "").split() if p]
    if not parts:
        return "?"
    return (parts[0][0] + (parts[-1][0] if len(parts) > 1 else "")).upper()


def _ago(dt):
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    s = (_dt.datetime.now(_dt.timezone.utc) - dt).total_seconds()
    if s < 90:
        return "now"
    if s < 3600:
        return f"{int(s // 60)}m"
    if s < 86400:
        return f"{int(s // 3600)}h"
    return f"{int(s // 86400)}d"


def _normalize_db_url(url):
    if not url:
        return "sqlite:///local.db"
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
    app.config["SQLALCHEMY_DATABASE_URI"] = _normalize_db_url(os.environ.get("DATABASE_URL"))
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True, "pool_recycle": 280}
    db.init_app(app)
    with app.app_context():
        db.create_all()

    admin_token = os.environ.get("ADMIN_TOKEN")

    # --- auth helpers --------------------------------------------------------
    def _is_admin():
        if session.get("admin"):
            return True
        auth = request.headers.get("Authorization", "")
        if admin_token and auth.startswith("Bearer "):
            return auth[len("Bearer "):] == admin_token
        return False

    def admin_required(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            if not admin_token:
                abort(503, "ADMIN_TOKEN is not configured on this service.")
            if not _is_admin():
                # API callers get 401; browsers get the login page.
                if request.headers.get("Authorization") or request.path.endswith(".json"):
                    abort(401)
                return redirect(url_for("admin_login", next=request.path))
            return fn(*a, **k)
        return wrapper

    # --- public --------------------------------------------------------------
    ranger_site = os.environ.get("RANGER_SITE_URL", "https://ranger.qwalora.com")

    @app.get("/")
    def index():
        # The portal has no landing of its own; it hosts auth + the signed-in app.
        return redirect(ranger_site, code=302)

    @app.get("/healthz")
    def healthz():
        try:
            db.session.execute(db.text("SELECT 1"))
            dbok = True
        except Exception:
            dbok = False
        code = 200 if dbok else 503
        return jsonify(status="ok" if dbok else "degraded", db=dbok,
                       broker=broker_status()), code

    @app.get("/enroll")
    def enroll_form():
        return render_template("enroll.html", cohort=DEFAULT_COHORT)

    @app.post("/enroll")
    def enroll():
        handle = (request.form.get("handle") or "").strip().lstrip("@")
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip()
        cohort = (request.form.get("cohort") or DEFAULT_COHORT).strip()
        repo = (request.form.get("repo") or "").strip() or None
        if not (handle and name and email):
            return render_template("enroll.html", cohort=cohort,
                                   error="GitHub handle, name, and email are all required."), 400

        existing = Candidate.query.filter_by(handle=handle).first()
        if existing:
            return render_template("enroll.html", cohort=cohort,
                                   error=f"'{handle}' is already enrolled."), 409

        c = Candidate(handle=handle, name=name, email=email, cohort=cohort, repo=repo)
        db.session.add(c)
        db.session.flush()  # assign id before queuing

        status, range_id, detail = queue_range(c)
        db.session.add(RangeRequest(candidate_id=c.id, status=status,
                                    ludus_range_id=range_id, detail=detail))
        db.session.commit()
        return render_template("enroll_done.html", candidate=c, range_status=status,
                               range_detail=detail)

    @app.post("/reports")
    def submit_report():
        token = request.headers.get("X-Candidate-Token", "")
        data = request.get_json(silent=True) or request.form
        handle = (data.get("handle") or "").strip().lstrip("@")
        board = (data.get("board") or "").strip()
        role = (data.get("role") or "").strip()
        body = (data.get("body") or "").strip()
        if not (handle and board and role and body):
            return jsonify(error="handle, board, role, body are required"), 400
        if board not in BOARDS or role not in ROLES:
            return jsonify(error="unknown board or role", boards=BOARDS, roles=ROLES), 400

        c = Candidate.query.filter_by(handle=handle).first()
        if not c or not token or token != c.token:
            return jsonify(error="invalid candidate token"), 401

        r = Report(candidate_id=c.id, board=board, role=role, body=body)
        db.session.add(r)
        db.session.commit()
        return jsonify(ok=True, report_id=r.id, status=r.status), 201

    # --- admin ---------------------------------------------------------------
    @app.get("/admin/login")
    def admin_login():
        if not admin_token:
            abort(503, "ADMIN_TOKEN is not configured on this service.")
        return render_template("admin_login.html", nxt=request.args.get("next", "/admin"))

    @app.post("/admin/login")
    def admin_login_post():
        if not admin_token:
            abort(503)
        if (request.form.get("token") or "") == admin_token:
            session["admin"] = True
            return redirect(request.form.get("next") or url_for("admin"))
        return render_template("admin_login.html", nxt=request.form.get("next", "/admin"),
                               error="Wrong token."), 401

    @app.get("/admin/logout")
    def admin_logout():
        session.pop("admin", None)
        return redirect(url_for("index"))

    @app.get("/admin")
    @admin_required
    def admin():
        demo = bool(os.environ.get("QW_DEMO"))
        pending = Report.query.filter_by(status="pending").order_by(Report.created_at.desc()).all()
        all_n = Report.query.count()
        approved_n = Report.query.filter_by(status="approved").count()
        needs_n = Report.query.filter_by(status="needs_changes").count()

        board_counts = {}
        for r in pending:
            board_counts[r.board] = board_counts.get(r.board, 0) + 1
        boards_vm = [{"name": b, "count": board_counts.get(b, 0)} for b in BOARDS[:4]]

        def tags_for(r):
            return [{"t": "capstone", "cls": "pill-violet", "dot": None}] if r.board == BOARDS[-1] else []

        sel_id = request.args.get("r", type=int)
        active_id = sel_id if sel_id else (pending[0].id if pending else None)

        items = []
        for r in pending:
            c = r.candidate
            items.append({
                "id": r.id, "ini": _initials(c.name), "name": c.name, "time": _ago(r.created_at),
                "subject": f"{r.board} · {ROLE_TITLES.get(r.role, r.role)}",
                "preview": " ".join((r.body or "").split())[:90],
                "role": r.role, "tags": tags_for(r), "unread": True, "on": (r.id == active_id)})

        sel = None
        target = next((r for r in pending if r.id == active_id), None)
        if target is None and active_id:
            target = Report.query.get(active_id)
        if target:
            c = target.candidate
            paras = [p.strip() for p in (target.body or "").split("\n") if p.strip()] or \
                    ["No written analysis was submitted with this report."]
            evidence = sig = None
            if demo:
                evidence = [{"label": "Exploit captured", "cls": "pill-ok", "dot": "dot-ok"},
                            {"label": "Detection fired", "cls": "pill-ok", "dot": "dot-ok"},
                            {"label": "Triage: malicious", "cls": "pill-amber", "dot": "dot-amber"},
                            {"label": "Flag: domain-admin", "cls": "pill-ok", "dot": "dot-ok"}]
                sig = "9f2a4c…e71b"
            smap = {"pending": ("Pending", "pill-amber", "dot-amber"),
                    "approved": ("Approved", "pill-ok", "dot-ok"),
                    "rejected": ("Rejected", "pill-amber", "dot-amber"),
                    "needs_changes": ("Needs changes", "pill-amber", "dot-amber")}
            sl, scls, sdot = smap.get(target.status, ("Pending", "pill-amber", "dot-amber"))
            sel = {
                "id": target.id, "ini": _initials(c.name), "name": c.name, "handle": c.handle,
                "board": target.board, "role_title": ROLE_TITLES.get(target.role, target.role),
                "time": _ago(target.created_at), "rid": f"RGR-{DEFAULT_COHORT}-{target.id:02d}",
                "subject_line": f"{c.name.split()[0]} submitted {target.board} "
                                f"{ROLE_TITLES.get(target.role, target.role)} for review.",
                "participants": [_initials(c.name), "FK"], "participants_more": 0,
                "m_roles": 4, "m_boards": len(BOARDS), "m_flags": len(tags_for(target)),
                "m_signals": (len(evidence) if evidence else 0),
                "remeasure_label": (f"Program re-measured the repo · {len(evidence)} signals"
                                    if evidence else "Re-measurement runs at cohort sync"),
                "engine": "ed25519", "evidence": evidence, "sig": sig, "analysis": paras,
                "status_label": sl, "status_cls": scls, "status_dot": sdot}

        vm = {"cohort": DEFAULT_COHORT, "broker": broker_status(),
              "nav": {"all": all_n, "pending": len(pending), "approved": approved_n,
                      "needs": needs_n, "boards": boards_vm, "flagged": 0},
              "queue": items, "selected": sel}
        return render_template("admin.html", vm=vm)

    @app.post("/admin/reports/<int:rid>")
    @admin_required
    def review_report(rid):
        r = Report.query.get_or_404(rid)
        action = request.form.get("action")
        m = {"approve": "approved", "reject": "rejected", "changes": "needs_changes"}
        if action in m:
            r.status = m[action]
            r.reviewer_notes = (request.form.get("notes") or "").strip() or None
            r.reviewed_at = _dt.datetime.now(_dt.timezone.utc)
            db.session.commit()
        return redirect(url_for("admin"))

    @app.get("/roster.json")
    @admin_required
    def roster_json():
        cohort = request.args.get("cohort", DEFAULT_COHORT)
        cands = Candidate.query.filter_by(cohort=cohort).order_by(Candidate.handle).all()
        return jsonify(cohort=cohort,
                       candidates=[c.roster_entry() for c in cands])

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
