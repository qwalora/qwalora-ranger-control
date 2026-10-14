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
import hashlib
import os
import urllib.parse

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   session, url_for)

import broker
import program as P
import signing
from broker import broker_status
from crypto import decrypt, encrypt
from models import (Badge, BoardResult, Candidate, RangeRequest, Report, db,
                    ensure_schema)

DEFAULT_COHORT = os.environ.get("DEFAULT_COHORT", "2026-A")
# Per-host isolated-range concurrency cap (RAM budget). 64GB host ~2 full GOAD.
MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT_RANGES", "2"))
ROLES = list(dict.fromkeys(P.ROLES + [
    "red-teamer", "detection-engineer", "soc-analyst", "incident-responder"]))
BOARDS = [P.bstr(b["n"]) for b in P.BOARD_PLAN]
ROLE_TITLES = {**P.ROLE_TITLES, "detection-engineering": "Detection Engineering"}


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


def _iso(dt):
    """Canonical UTC ISO string that round-trips identically on SQLite and
    Postgres (SQLite reads timestamps back naive). Used for everything that is
    signed and re-emitted, so signatures verify regardless of the DB backend."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).isoformat()


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
        ensure_schema(db)  # add post-launch columns to an existing DB, idempotent

    admin_token = os.environ.get("ADMIN_TOKEN")

    # Cache-bust static assets: version the stylesheet URL by its content hash so a
    # new deploy is never masked by a stale cached app.css on any origin.
    try:
        _css_bytes = open(os.path.join(app.static_folder, "app.css"), "rb").read()
        asset_ver = hashlib.md5(_css_bytes).hexdigest()[:10]
    except Exception:
        asset_ver = "1"

    @app.context_processor
    def _inject_asset_ver():
        return {"asset_ver": asset_ver}

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

    # --- range helpers -------------------------------------------------------
    def _candidate_key(c):
        """Decrypted per-user Ludus API key, or None (mock has no real key)."""
        return decrypt(c.ludus_key_enc)

    def _latest_range(c):
        return (RangeRequest.query.filter_by(candidate_id=c.id)
                .order_by(RangeRequest.id.desc()).first())

    def _ensure_ludus_user(c):
        """Lazily create the candidate's Ludus user (only needed for isolated
        boards). Idempotent. Stores the encrypted per-user key."""
        if c.ludus_user_id:
            return
        uid, key, _ = broker.ensure_user(c)
        c.ludus_user_id = uid
        if key:
            c.ludus_key_enc = encrypt(key)

    def _board_range(c, n):
        return (RangeRequest.query
                .filter_by(candidate_id=c.id, board=n)
                .order_by(RangeRequest.id.desc()).first())

    def _slots_used(host="primary"):
        """Isolated ranges currently holding a RAM slot on a host."""
        return (RangeRequest.query
                .filter(RangeRequest.host == host,
                        RangeRequest.status.in_(RangeRequest.OCCUPIES_SLOT))
                .count())

    def _try_deploy(c, rr):
        """Deploy an isolated range if a slot is free, else park it as
        queued_slot. Returns the resulting status."""
        if _slots_used(rr.host) >= MAX_CONCURRENT:
            rr.status = "queued_slot"
            rr.detail = f"waiting for a slot on {rr.host} (cap {MAX_CONCURRENT})"
            return rr.status
        _ensure_ludus_user(c)
        key = _candidate_key(c)
        broker.set_range_config(c, P.template_of(rr.board) or broker.GOAD_TEMPLATE, user_key=key)
        status, range_id, detail = broker.deploy_range(c, user_key=key)
        rr.status = status
        if range_id:
            rr.ludus_range_id = range_id
        rr.wireguard_config = broker.wireguard_config(c, user_key=key)
        st, sdetail = broker.range_status(c, user_key=key)
        rr.status = st
        rr.detail = f"{detail}; {sdetail}"
        rr.last_checked_at = _dt.datetime.now(_dt.timezone.utc)
        return rr.status

    def _provision_for_board(c, n, auto_deploy=True):
        """Open board n's lab for the candidate.

        Shared boards are ready instantly (a seeded session, no VM). Isolated
        boards stage a Ludus range and deploy it if a slot is free, otherwise
        queue it. Idempotent per (candidate, board)."""
        rr = _board_range(c, n)
        if rr is None:
            rr = RangeRequest(candidate_id=c.id, board=n, template=P.template_of(n))
            db.session.add(rr)
        if not P.is_isolated(n):
            rr.host = "shared"
            rr.status = "deployed"  # shared environment access granted immediately
            rr.detail = "shared instrumented environment; per-candidate dataset seeded"
            return rr
        rr.host = rr.host or "primary"
        if auto_deploy:
            _try_deploy(c, rr)
        else:
            _ensure_ludus_user(c)
            rr.status = rr.status if rr.status in RangeRequest.ACTIVE else "configured"
            rr.detail = rr.detail or "configured; deploy on lab-start"
        return rr

    def _reconcile(host="primary"):
        """Promote queued ranges into freed slots, oldest first. Called after a
        teardown and by the admin reconcile endpoint. Keeps the host at its cap."""
        promoted = 0
        while _slots_used(host) < MAX_CONCURRENT:
            rr = (RangeRequest.query
                  .filter_by(host=host, status="queued_slot")
                  .order_by(RangeRequest.id.asc()).first())
            if not rr:
                break
            c = Candidate.query.get(rr.candidate_id)
            _try_deploy(c, rr)
            promoted += 1
        db.session.commit()
        return promoted

    # --- grading + promotion engine -----------------------------------------
    def _board_result(c, n, create=True):
        br = BoardResult.query.filter_by(candidate_id=c.id, board=n).first()
        if br is None and create:
            br = BoardResult(candidate_id=c.id, board=n, role=P.role_of(n))
            db.session.add(br)
            db.session.flush()
        return br

    def _mint_badge(c, level, name, role):
        """Create a signed badge once per (candidate, level). Idempotent."""
        existing = Badge.query.filter_by(candidate_id=c.id, level=level).first()
        if existing:
            return existing
        issued = _dt.datetime.now(_dt.timezone.utc)
        claim = {"kind": "badge", "handle": c.handle, "cohort": c.cohort,
                 "level": level, "name": name, "role": role,
                 "issued_at": _iso(issued)}
        b = Badge(candidate_id=c.id, level=level, name=name, role=role,
                  issued_at=issued, signature=signing.sign(claim))
        db.session.add(b)
        return b

    def _teardown_ranges(c):
        """Destroy all of the candidate's isolated ranges and free their slots."""
        key = _candidate_key(c)
        freed_hosts = set()
        for rr in RangeRequest.query.filter_by(candidate_id=c.id).all():
            if rr.host != "shared" and rr.status in RangeRequest.OCCUPIES_SLOT:
                broker.destroy_range(c, user_key=key)
                rr.status = "destroyed"
                rr.detail = "torn down"
                freed_hosts.add(rr.host or "primary")
        return freed_hosts

    def _exit_candidate(c, status, reason):
        """Terminal exit: set status, tear down ranges, revoke token. Earned
        badges and signed clearances are kept."""
        if c.status in Candidate.TERMINAL:
            return
        freed = _teardown_ranges(c)
        c.status = status
        c.exit_reason = reason
        c.exited_at = _dt.datetime.now(_dt.timezone.utc)
        c.token = "revoked-" + c.token[:8]  # revoke submission token
        db.session.flush()
        for h in freed:
            _reconcile(h)

    def _promote(c):
        """Clear the current board, sign it, mint the badge, and open the next
        board (or graduate). Transactional + idempotent."""
        n = c.current_board
        br = _board_result(c, n)
        if br.cleared:
            return False  # already promoted past this board
        cleared_at = _dt.datetime.now(_dt.timezone.utc)
        claim = {"kind": "clearance", "handle": c.handle, "cohort": c.cohort,
                 "board": n, "role": P.role_of(n),
                 "objective_score": br.objective_score, "cleared_at": _iso(cleared_at)}
        br.cleared = True
        br.cleared_at = cleared_at
        br.signature = signing.sign(claim)
        lvl, name, role = P.badge_for(n)
        _mint_badge(c, lvl, name, role)

        # Free the cleared board's isolated range so the candidate never holds
        # two RAM slots, and pull a queued range into the freed slot.
        rr = _board_range(c, n)
        if rr and rr.host != "shared" and rr.status in RangeRequest.OCCUPIES_SLOT:
            broker.destroy_range(c, user_key=_candidate_key(c))
            rr.status = "destroyed"
            rr.detail = "torn down on promotion"
            db.session.flush()
            _reconcile(rr.host or "primary")

        if n >= P.LAST_BOARD:
            _mint_badge(c, P.CERTIFIED["level"], P.CERTIFIED["name"], P.CERTIFIED["role"])
            _exit_candidate(c, "graduated", "cleared the capstone")
        else:
            c.current_board = n + 1
            c.current_role = P.role_of(n + 1)
            _provision_for_board(c, n + 1, auto_deploy=True)
        return True

    def _evaluate_gate(c):
        """Promote if the current board's objective passed AND its report is
        approved. Safe to call after either grade lands."""
        if not c.is_active:
            return False
        n = c.current_board
        br = _board_result(c, n, create=False)
        if not br or not br.objective_passed or br.report_status != "approved":
            return False
        return _promote(c)

    def _record_objective(c, n, score):
        br = _board_result(c, n)
        br.objective_score = float(score)
        br.objective_passed = float(score) >= P.PASS_BAR
        attest = {"kind": "objective", "handle": c.handle, "board": n,
                  "score": float(score), "passed": br.objective_passed,
                  "at": _dt.datetime.now(_dt.timezone.utc).isoformat()}
        br.objective_sig = signing.sign(attest)
        return br

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

        c = Candidate(handle=handle, name=name, email=email, cohort=cohort, repo=repo,
                      current_board=1, current_role=P.role_of(1))
        db.session.add(c)
        db.session.flush()  # assign id before provisioning

        # Progression model: enrollment opens board 1 (SOC, a shared environment),
        # so a new ranger starts triaging immediately. Isolated GOAD ranges are
        # provisioned later, when they are promoted into the red-team boards.
        rr = _provision_for_board(c, 1)
        db.session.commit()
        return render_template("enroll_done.html", candidate=c,
                               range_status=rr.status, range_detail=rr.detail,
                               broker_mode=broker.mode())

    def _auth_candidate(data):
        """Resolve + authenticate a candidate from X-Candidate-Token + handle."""
        token = request.headers.get("X-Candidate-Token", "")
        handle = (data.get("handle") or "").strip().lstrip("@")
        if not handle:
            return None, (jsonify(error="handle is required"), 400)
        c = Candidate.query.filter_by(handle=handle).first()
        if not c or not token or token != c.token:
            return None, (jsonify(error="invalid candidate token"), 401)
        return c, None

    @app.post("/labs/start")
    def lab_start():
        """Start (deploy) the current board's lab.

        Shared boards are already open, so this just confirms access. Isolated
        boards deploy the Ludus range if a slot is free, otherwise queue it and
        report the wait. Returns the range status and WireGuard config."""
        data = request.get_json(silent=True) or request.form
        c, err = _auth_candidate(data)
        if err:
            return err
        if not c.is_active:
            return jsonify(error=f"candidate is {c.status}"), 409
        n = c.current_board
        rr = _provision_for_board(c, n, auto_deploy=True)
        db.session.commit()
        return jsonify(ok=True, handle=c.handle, board=n, role=c.current_role,
                       tier=P.tier_of(n), range_status=rr.status,
                       range_id=rr.ludus_range_id, wireguard=rr.wireguard_config,
                       detail=rr.detail, mode=broker.mode()), 200

    @app.post("/labs/status")
    def lab_status():
        data = request.get_json(silent=True) or request.form
        c, err = _auth_candidate(data)
        if err:
            return err
        n = c.current_board
        rr = _board_range(c, n)
        if rr is None:
            return jsonify(ok=True, handle=c.handle, board=n, range_status="none",
                           detail="no range provisioned yet"), 200
        if P.is_isolated(n) and rr.status in ("deploying", "deployed"):
            key = _candidate_key(c)
            st, sdetail = broker.range_status(c, user_key=key)
            rr.status, rr.detail = st, sdetail
            rr.last_checked_at = _dt.datetime.now(_dt.timezone.utc)
            db.session.commit()
        return jsonify(ok=True, handle=c.handle, board=n, tier=P.tier_of(n),
                       range_status=rr.status, range_id=rr.ludus_range_id,
                       detail=rr.detail, mode=broker.mode()), 200

    @app.post("/reports")
    def submit_report():
        data = request.get_json(silent=True) or request.form
        body = (data.get("body") or "").strip()
        c, err = _auth_candidate(data)
        if err:
            return err
        if not c.is_active:
            return jsonify(error=f"candidate is {c.status}, not accepting reports"), 409

        # A report is for the candidate's CURRENT board; board/role default to it.
        n = c.current_board
        board = (data.get("board") or P.bstr(n)).strip()
        role = (data.get("role") or c.current_role or P.role_of(n)).strip()
        if P.bint(board) != n:
            return jsonify(error=f"you are on {P.bstr(n)}; submit for that board",
                           current_board=P.bstr(n)), 409
        if not body:
            return jsonify(error="body is required"), 400

        # The report must tie back to real lab work. For isolated boards the range
        # must be deployed; shared boards are always open. REPORTS_REQUIRE_RANGE=0
        # bypasses for seed/demo data.
        if os.environ.get("REPORTS_REQUIRE_RANGE", "1") != "0" and P.is_isolated(n):
            rr = _board_range(c, n)
            if rr is None or not rr.is_deployed:
                return jsonify(error="deploy your lab before submitting a report",
                               hint="POST /labs/start first",
                               range_status=(rr.status if rr else "none")), 409

        r = Report(candidate_id=c.id, board=board, role=role, body=body)
        db.session.add(r)
        db.session.commit()
        return jsonify(ok=True, report_id=r.id, board=board, status=r.status), 201

    @app.post("/grade")
    def grade():
        """Objective grade callback from the lab-repo CI (GitHub Actions).

        Authenticated by the shared CI token. Records the answer-free score for a
        board and evaluates the promotion gate. Body: {handle, board, score}."""
        ci_token = os.environ.get("CI_TOKEN")
        if not ci_token or request.headers.get("X-CI-Token", "") != ci_token:
            return jsonify(error="invalid CI token"), 401
        data = request.get_json(silent=True) or request.form
        handle = (data.get("handle") or "").strip().lstrip("@")
        board = P.bint(data.get("board"))
        try:
            score = float(data.get("score"))
        except (TypeError, ValueError):
            return jsonify(error="score must be numeric"), 400
        c = Candidate.query.filter_by(handle=handle).first()
        if not c:
            return jsonify(error="unknown candidate"), 404
        if board is None or not P.board_meta(board):
            return jsonify(error="unknown board"), 400
        _record_objective(c, board, score)
        promoted = _evaluate_gate(c) if board == c.current_board else False
        db.session.commit()
        return jsonify(ok=True, handle=c.handle, board=board, score=score,
                       passed=score >= P.PASS_BAR, promoted=promoted,
                       current_board=c.current_board, status=c.status), 200

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
        status = request.args.get("status", "pending")
        board = (request.args.get("board") or "").strip()
        qtext = (request.args.get("q") or "").strip()
        order = request.args.get("order", "desc")
        sel_id = request.args.get("r", type=int)

        all_n = Report.query.count()
        pending_n = Report.query.filter_by(status="pending").count()
        approved_n = Report.query.filter_by(status="approved").count()
        needs_n = Report.query.filter_by(status="needs_changes").count()

        qry = Report.query
        if status in ("pending", "approved", "needs_changes", "rejected"):
            qry = qry.filter_by(status=status)
        if board:
            qry = qry.filter_by(board=board)
        if qtext:
            like = f"%{qtext}%"
            qry = qry.join(Candidate).filter(
                db.or_(Candidate.name.ilike(like), Candidate.handle.ilike(like)))
        qry = qry.order_by(Report.created_at.asc() if order == "asc"
                           else Report.created_at.desc())
        rows = qry.all()

        board_counts = {}
        for r in Report.query.filter_by(status="pending").all():
            board_counts[r.board] = board_counts.get(r.board, 0) + 1
        boards_vm = [{"name": b, "count": board_counts.get(b, 0), "on": (board == b)}
                     for b in BOARDS[:4]]

        def tags_for(r):
            return [{"t": "capstone", "cls": "pill-violet", "dot": None}] if r.board == BOARDS[-1] else []

        active_id = sel_id if sel_id else (rows[0].id if rows else None)
        parts = [f"status={status}"]
        if board:
            parts.append(f"board={board}")
        if qtext:
            parts.append("q=" + urllib.parse.quote(qtext))
        qs = "&".join(parts)  # filters only, no order/selection

        items = []
        for r in rows:
            c = r.candidate
            items.append({
                "id": r.id, "ini": _initials(c.name), "name": c.name, "time": _ago(r.created_at),
                "subject": f"{r.board} · {ROLE_TITLES.get(r.role, r.role)}",
                "preview": " ".join((r.body or "").split())[:90],
                "role": r.role, "tags": tags_for(r), "unread": (r.status == "pending"),
                "on": (r.id == active_id)})

        sel = None
        target = next((r for r in rows if r.id == active_id), None)
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

        title_map = {"pending": "Pending", "approved": "Approved",
                     "needs_changes": "Needs changes", "rejected": "Rejected", "all": "All reports"}
        vm = {"cohort": DEFAULT_COHORT, "broker": broker_status(),
              "nav": {"all": all_n, "pending": pending_n, "approved": approved_n,
                      "needs": needs_n, "boards": boards_vm, "flagged": needs_n},
              "queue": items, "selected": sel,
              "active_status": status, "active_board": board, "q": qtext, "order": order,
              "qs": qs, "title": (title_map.get(status, "Reports") if not board else board),
              "count": len(rows)}
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
            # Feed the subjective channel into the board result, then re-check the
            # promotion gate (promotes if the objective grade is already in).
            c = r.candidate
            n = P.bint(r.board)
            if n is not None and c.is_active:
                br = _board_result(c, n)
                br.report_id = r.id
                br.report_status = r.status
                if action == "approve" and n == c.current_board:
                    _evaluate_gate(c)
            db.session.commit()
        return redirect(url_for("admin", status=request.form.get("return_status", "pending")))

    _RANGE_UI = {
        "deployed": ("Deployed", "pill-ok", "dot-ok"),
        "deploying": ("Deploying", "pill-amber", "dot-amber"),
        "configured": ("Configured", "pill-violet", "dot-violet"),
        "failed": ("Failed", "pill-amber", "dot-amber"),
        "destroyed": ("Destroyed", "pill", "dot"),
        "queued": ("Configured", "pill-violet", "dot-violet"),  # legacy
    }

    @app.get("/admin/ranges")
    @admin_required
    def admin_ranges():
        cohort = request.args.get("cohort", DEFAULT_COHORT)
        cands = (Candidate.query.filter_by(cohort=cohort)
                 .order_by(Candidate.handle).all())
        rows = []
        counts = {"deployed": 0, "deploying": 0, "configured": 0, "failed": 0}
        for c in cands:
            rr = _latest_range(c)
            st = rr.status if rr else "none"
            label, pcls, dot = _RANGE_UI.get(st, ("None", "pill", "dot"))
            key = "configured" if st in ("configured", "queued") else st
            if key in counts:
                counts[key] += 1
            rows.append({
                "cid": c.id, "ini": _initials(c.name), "name": c.name,
                "handle": c.handle, "ludus_user": c.ludus_user_id or "-",
                "status": st, "label": label, "pcls": pcls, "dot": dot,
                "range_id": (rr.ludus_range_id if rr else None),
                "template": (rr.template if rr else None),
                "has_wg": bool(rr and rr.wireguard_config),
                "checked": _ago(rr.last_checked_at) if rr and rr.last_checked_at else "",
                "detail": (rr.detail if rr else "no range provisioned"),
            })
        vm = {"cohort": DEFAULT_COHORT, "broker": broker_status(),
              "mode": broker.mode(), "template": broker.GOAD_TEMPLATE,
              "rows": rows, "counts": counts, "total": len(rows)}
        return render_template("admin_ranges.html", vm=vm)

    @app.post("/admin/ranges/<int:cid>")
    @admin_required
    def admin_range_action(cid):
        c = Candidate.query.get_or_404(cid)
        action = request.form.get("action")
        n = c.current_board
        rr = _board_range(c, n)
        key = _candidate_key(c)
        if action == "deploy":
            rr = _provision_for_board(c, n, auto_deploy=True)
        elif action == "refresh" and rr is not None and P.is_isolated(n):
            st, sdetail = broker.range_status(c, user_key=key)
            rr.status, rr.detail = st, sdetail
            rr.last_checked_at = _dt.datetime.now(_dt.timezone.utc)
        elif action == "destroy" and rr is not None:
            host = rr.host or "primary"
            if rr.host != "shared":
                broker.destroy_range(c, user_key=key)
            rr.status = "destroyed"
            rr.detail = "torn down by admin"
            db.session.flush()
            _reconcile(host)  # a freed slot pulls in a queued range
        db.session.commit()
        return redirect(url_for("admin_ranges"))

    @app.post("/admin/reconcile")
    @admin_required
    def admin_reconcile():
        host = request.form.get("host") or request.args.get("host") or "primary"
        promoted = _reconcile(host)
        return jsonify(ok=True, host=host, deployed_from_queue=promoted,
                       slots_used=_slots_used(host), cap=MAX_CONCURRENT)

    @app.post("/admin/candidates/<int:cid>/exit")
    @admin_required
    def admin_exit(cid):
        c = Candidate.query.get_or_404(cid)
        reason = (request.form.get("reason") or "").strip()
        kind = (request.form.get("kind") or "withdrawn").strip()
        status = kind if kind in Candidate.TERMINAL else "withdrawn"
        _exit_candidate(c, status, reason or status)
        db.session.commit()
        return jsonify(ok=True, handle=c.handle, status=c.status,
                       exit_reason=c.exit_reason)

    # --- public verification -------------------------------------------------
    @app.get("/pubkey")
    def pubkey():
        return jsonify(alg="ed25519", public_key=signing.public_key_b64())

    @app.get("/badges/<handle>.json")
    def badges_json(handle):
        """Signed, verifiable badges + board clearances for a candidate. This is
        what the public status page checks in-browser; it reveals no grades of
        other candidates and no answer keys."""
        handle = handle.lstrip("@")
        c = Candidate.query.filter_by(handle=handle).first()
        if not c:
            return jsonify(error="unknown candidate"), 404
        badges = [{"level": b.level, "name": b.name, "role": b.role,
                   "issued_at": _iso(b.issued_at),
                   "signature": b.signature, "revoked": b.revoked}
                  for b in sorted(c.badges, key=lambda x: str(x.level))]
        clearances = [{"board": br.board, "role": br.role,
                       "objective_score": br.objective_score,
                       "cleared_at": _iso(br.cleared_at),
                       "signature": br.signature}
                      for br in sorted(c.board_results, key=lambda x: x.board)
                      if br.cleared]
        return jsonify(handle=c.handle, cohort=c.cohort, status=c.status,
                       current_board=c.current_board, alg="ed25519",
                       public_key=signing.public_key_b64(),
                       badges=badges, clearances=clearances)

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
