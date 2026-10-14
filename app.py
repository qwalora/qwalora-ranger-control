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
import githuboauth
import program as P
import scenarios
import notify
import signing
from broker import broker_status
from crypto import decrypt, encrypt
from models import (Badge, BoardResult, Candidate, Cohort, Notification,
                    RangeRequest, Report, ScenarioAssignment, db, ensure_schema)

DEFAULT_COHORT = os.environ.get("DEFAULT_COHORT", "2026-A")
# Per-host isolated-range concurrency cap (RAM budget). 64GB host ~2 full GOAD.
MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT_RANGES", "2"))
# Background maintenance: poll deploying ranges, reconcile the queue, reclaim
# ranges. Enable on the server (ENABLE_SCHEDULER=1); off by default so imports
# and tests don't spin a thread.
ENABLE_SCHEDULER = os.environ.get("ENABLE_SCHEDULER", "0") == "1"
RECONCILE_INTERVAL = int(os.environ.get("RECONCILE_INTERVAL_SECONDS", "60"))
# Reclaim isolated ranges past a hard age cap, or idle (no candidate touch) too
# long, so a stalled ranger never permanently holds a slot. 0 disables either.
RANGE_MAX_AGE_HOURS = float(os.environ.get("RANGE_MAX_AGE_HOURS", "48"))
RANGE_IDLE_HOURS = float(os.environ.get("RANGE_IDLE_HOURS", "8"))
# The program window: 26 weeks / 130 days. The clock starts when a cohort is
# activated. Enforcement (window-expiry + inactivity washout) is a toggle, off
# by default so a deploy never mass-washes-out; turn on when you want the 130-day
# structure enforced. Thresholds are generous and configurable.
PROGRAM_DAYS = int(os.environ.get("PROGRAM_DAYS", "130"))
WASHOUT_IDLE_DAYS = int(os.environ.get("WASHOUT_IDLE_DAYS", "21"))
ENFORCE_DEADLINES = os.environ.get("ENFORCE_DEADLINES", "0") == "1"


def _aware(d):
    """SQLite drops tzinfo; treat stored naive datetimes as UTC."""
    if d is not None and d.tzinfo is None:
        return d.replace(tzinfo=_dt.timezone.utc)
    return d


def _bootstrap_cohorts():
    """Make sure the cohorts table reflects reality on boot: a row for every
    cohort any candidate is in, a row for DEFAULT_COHORT, and exactly one active
    cohort. Idempotent and race-safe (two workers may both run it)."""
    try:
        names = {DEFAULT_COHORT}
        for (nm,) in db.session.query(Candidate.cohort).distinct().all():
            if nm:
                names.add(nm)
        existing = {c.name: c for c in Cohort.query.all()}
        seq = max([c.sequence for c in existing.values()], default=0)
        for nm in sorted(names):
            if nm not in existing:
                seq += 1
                db.session.add(Cohort(name=nm, sequence=seq, status="scheduled"))
        db.session.commit()
        # Ensure exactly one active cohort. If none, activate the lowest-sequence
        # one that still has non-terminal candidates, else DEFAULT_COHORT.
        if not Cohort.query.filter_by(status="active").first():
            cohorts = Cohort.query.order_by(Cohort.sequence.asc()).all()
            pick = None
            for c in cohorts:
                total = Candidate.query.filter_by(cohort=c.name).count()
                active = Candidate.query.filter_by(cohort=c.name, status="active").count()
                if total == 0 or active > 0:
                    pick = c
                    break
            pick = pick or next((c for c in cohorts if c.name == DEFAULT_COHORT), None) or (cohorts[0] if cohorts else None)
            if pick:
                pick.status = "active"
                pick.activated_at = _dt.datetime.now(_dt.timezone.utc)
                db.session.commit()
    except Exception:
        db.session.rollback()
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


def _badge_chain(c):
    """The six-rung ladder for a candidate, with earned flags, plus certified."""
    earned = {b.level for b in c.badges}
    chain = [{"level": str(b["n"]), "name": b["badge"], "role": b["role"],
              "board": b["n"], "earned": str(b["n"]) in earned}
             for b in P.BOARD_PLAN]
    return {"chain": chain, "certified": ("certified" in earned)}


STATUS_UI = {
    "active": ("Active", "pill-violet", "dot-violet"),
    "graduated": ("Graduated", "pill-ok", "dot-ok"),
    "washed_out": ("Washed out", "pill-amber", "dot-amber"),
    "withdrawn": ("Withdrawn", "pill", "dot"),
}


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
    # SECRET_KEY must be a stable secret so sessions survive restarts and are
    # consistent across workers. A per-boot random fallback silently logs people
    # out; warn loudly if it is missing instead of pretending it is fine.
    secret = os.environ.get("SECRET_KEY")
    if not secret:
        import logging
        logging.getLogger(__name__).warning(
            "SECRET_KEY is not set; using an ephemeral key. Sessions will not "
            "persist across restarts or workers. Set SECRET_KEY in the environment.")
        secret = os.urandom(32).hex()
    app.config["SECRET_KEY"] = secret
    # Harden session cookies. COOKIE_INSECURE=1 is only for local http testing.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_INSECURE") != "1"
    app.config["SQLALCHEMY_DATABASE_URI"] = _normalize_db_url(os.environ.get("DATABASE_URL"))
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True, "pool_recycle": 280}
    db.init_app(app)
    with app.app_context():
        # Two gunicorn workers import the app concurrently and both run these.
        # create_all() is checkfirst, but the check+create still races between
        # workers on a brand-new table; the loser sees "already exists". Swallow
        # so a worker never crash-loops on first boot after a schema addition.
        try:
            db.create_all()
        except Exception:
            db.session.rollback()
        ensure_schema(db)  # add post-launch columns to an existing DB, idempotent
        _bootstrap_cohorts()  # make sure cohort rows exist and one is active

    admin_token = os.environ.get("ADMIN_TOKEN")
    # Once GitHub reviewer sign-in is confirmed, set DISABLE_ADMIN_TOKEN=1 to
    # retire the shared token entirely (reviewers then get in only via OAuth).
    token_disabled = os.environ.get("DISABLE_ADMIN_TOKEN") == "1"

    # Cache-bust static assets: version the stylesheet URL by its content hash so a
    # new deploy is never masked by a stale cached app.css on any origin.
    try:
        _css_bytes = open(os.path.join(app.static_folder, "app.css"), "rb").read()
        asset_ver = hashlib.md5(_css_bytes).hexdigest()[:10]
    except Exception:
        asset_ver = "1"

    def _csrf_token():
        t = session.get("csrf")
        if not t:
            import secrets as _s
            t = _s.token_urlsafe(24)
            session["csrf"] = t
        return t

    @app.context_processor
    def _inject_asset_ver():
        return {"asset_ver": asset_ver, "oauth_enabled": githuboauth.enabled(),
                "csrf_token": _csrf_token(), "token_disabled": token_disabled}

    # --- CSRF: browser (cookie-authed) POSTs must carry the session token ----
    # API endpoints authenticate with header tokens (not cookies), so CSRF does
    # not apply to them; they are exempt.
    _CSRF_EXEMPT = {"submit_report", "grade", "lab_start", "lab_status",
                    "grade_submit", "lab_dataset"}

    @app.before_request
    def _csrf_protect():
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return
        ep = request.endpoint or ""
        if ep in _CSRF_EXEMPT:
            return
        # Header-token authed (not cookie) -> CSRF is not the threat.
        if (request.headers.get("Authorization") or request.headers.get("X-CI-Token")
                or request.headers.get("X-Candidate-Token")):
            return
        import hmac as _hmac
        sent = request.form.get("csrf") or request.headers.get("X-CSRF-Token") or ""
        have = session.get("csrf") or ""
        if not have or not _hmac.compare_digest(sent, have):
            abort(400, "CSRF token missing or invalid. Reload and try again.")

    # --- rate limiting: in-memory per-IP sliding window ----------------------
    # Per-worker (gunicorn has a few), so effective limits are a small multiple;
    # enough to blunt brute force and abuse. (count, window_seconds) per endpoint.
    import collections as _collections
    import time as _time
    _RL = _collections.defaultdict(list)
    _RL_LIMITS = {
        "admin_login_post": (10, 300), "gh_login": (30, 300), "gh_callback": (30, 300),
        "grade": (120, 60), "enroll": (20, 3600), "submit_report": (120, 60),
        "lab_start": (30, 60), "candidate_start": (30, 60),
        "grade_submit": (120, 60), "lab_dataset": (120, 60),
    }

    def _client_ip():
        xff = request.headers.get("X-Forwarded-For", "")
        return (xff.split(",")[0].strip() if xff else request.remote_addr) or "?"

    @app.before_request
    def _ratelimit():
        lim = _RL_LIMITS.get(request.endpoint or "")
        if not lim:
            return
        n, window = lim
        now = _time.time()
        if len(_RL) > 20000:  # coarse memory guard
            _RL.clear()
        bucket = _RL[(request.endpoint, _client_ip())]
        cutoff = now - window
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= n:
            abort(429, "Too many requests. Slow down and try again shortly.")
        bucket.append(now)

    @app.after_request
    def _security_headers(resp):
        # Defense in depth: we advertise security, so the portal models it.
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Strict-Transport-Security",
                                "max-age=31536000; includeSubDomains")
        # Self-hosted assets only; inline styles/handlers are still used in a few
        # templates, so inline is permitted for now (CSP nonces are a follow-up).
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'")
        return resp

    # --- auth helpers --------------------------------------------------------
    def _is_admin():
        if session.get("admin"):
            return True
        auth = request.headers.get("Authorization", "")
        if admin_token and not token_disabled and auth.startswith("Bearer "):
            import hmac as _hmac
            return _hmac.compare_digest(auth[len("Bearer "):], admin_token)
        return False

    def _auth_available():
        # There is a way to become admin if OAuth reviewer sign-in is on, or the
        # shared token is still enabled.
        return githuboauth.enabled() or (admin_token and not token_disabled)

    def admin_required(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            if not _auth_available():
                abort(503, "No admin sign-in is configured on this service.")
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

    # --- scenario uniqueness -------------------------------------------------
    def _assign_seed(github_id, board, cohort):
        """Record a fresh scenario seed for this person+board, never one they
        have already been given (across any cohort). The seed is the generator's
        reproducibility key; a new seed is a new, never-seen scenario."""
        seen = {a.seed for a in ScenarioAssignment.query
                .filter_by(github_id=github_id, board=board).all()}
        import secrets as _secrets
        seed = None
        for _ in range(8):
            cand = _secrets.token_hex(8)
            if cand not in seen:
                seed = cand
                break
        seed = seed or _secrets.token_hex(12)  # vanishingly unlikely fallback
        a = ScenarioAssignment(github_id=github_id, board=board, cohort=cohort, seed=seed)
        db.session.add(a)
        return a

    def _ensure_seed(c, board):
        """One scenario assignment per (person, board, cohort). Idempotent."""
        gid = c.github_id or c.handle
        a = (ScenarioAssignment.query
             .filter_by(github_id=gid, board=board, cohort=c.cohort).first())
        if a is None:
            a = _assign_seed(gid, board, c.cohort)
        return a

    def _current_seed(c):
        gid = c.github_id or c.handle
        a = (ScenarioAssignment.query
             .filter_by(github_id=gid, board=c.current_board, cohort=c.cohort)
             .order_by(ScenarioAssignment.id.desc()).first())
        return a.seed if a else None

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
        # For flag-capture boards, hand the range its per-seed flags to plant, so
        # each ranger's range holds their own secrets. The grader derives the same
        # flags from the seed independently, so this only affects the live range.
        tvars = None
        if scenarios.kind(rr.board) == "flags":
            seed = _current_seed(c)
            if seed:
                tvars = {"ranger_flags": scenarios.flags_for_board(rr.board, seed)}
        broker.set_range_config(c, P.template_of(rr.board) or broker.GOAD_TEMPLATE,
                                user_key=key, template_vars=tvars)
        status, range_id, detail = broker.deploy_range(c, user_key=key)
        rr.status = status
        if range_id:
            rr.ludus_range_id = range_id
        rr.wireguard_config = broker.wireguard_config(c, user_key=key)
        st, sdetail = broker.range_status(c, user_key=key)
        now = _dt.datetime.now(_dt.timezone.utc)
        rr.status = st
        rr.detail = f"{detail}; {sdetail}"
        rr.last_checked_at = now
        rr.last_active_at = now  # starting the lab is activity
        if st == "deployed":
            if not rr.deployed_at:
                _notify(c, "range", "Your board %d lab is ready" % rr.board,
                        "Your range is deployed. Download WireGuard from your dashboard and begin.")
            rr.deployed_at = rr.deployed_at or now
        return rr.status

    def _provision_for_board(c, n, auto_deploy=True):
        """Open board n's lab for the candidate.

        Shared boards are ready instantly (a seeded session, no VM). Isolated
        boards stage a Ludus range and deploy it if a slot is free, otherwise
        queue it. Idempotent per (candidate, board)."""
        _ensure_seed(c, n)  # every board the ranger enters gets a unique scenario seed
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

    def _touch(c, n=None):
        """Mark the candidate's range for board n (default: current) as just
        used, so idle reclamation leaves an in-use range alone."""
        rr = _board_range(c, n if n is not None else c.current_board)
        if rr is not None:
            rr.last_active_at = _dt.datetime.now(_dt.timezone.utc)

    def _notify(c, kind, title, body=None, email=True):
        """Record a dashboard notification and, when SMTP is set, email it.
        Best-effort: never raises into the engine."""
        try:
            db.session.add(Notification(candidate_id=c.id, kind=kind,
                                        title=title[:160], body=(body or "")[:400]))
            if email and c.email:
                notify.send_email(c.email, "Qwalora Ranger - " + title,
                                  (body + "\n\n" if body else "") +
                                  "View your dashboard: %s/me" % githuboauth.base_url())
        except Exception:  # noqa: BLE001
            pass

    def _known_hosts():
        hosts = {h for (h,) in db.session.query(RangeRequest.host).distinct().all()
                 if h and h != "shared"}
        hosts.add("primary")
        return hosts

    def _poll_deploying():
        """Refresh the status of ranges mid-flight (deploying), so the dashboard
        advances without a human clicking Refresh. Returns how many changed."""
        changed = 0
        rows = RangeRequest.query.filter(RangeRequest.status == "deploying").all()
        for rr in rows:
            c = Candidate.query.get(rr.candidate_id)
            if not c:
                continue
            now = _dt.datetime.now(_dt.timezone.utc)
            try:
                st, sdetail = broker.range_status(c, user_key=_candidate_key(c))
            except Exception:  # noqa: BLE001
                continue
            rr.last_checked_at = now
            if st != rr.status:
                rr.status = st
                rr.detail = sdetail
                changed += 1
            if st == "deployed" and not rr.deployed_at:
                rr.deployed_at = now
                if not rr.wireguard_config:
                    try:
                        rr.wireguard_config = broker.wireguard_config(c, user_key=_candidate_key(c))
                    except Exception:  # noqa: BLE001
                        pass
                _notify(c, "range", "Your board %d lab is ready" % rr.board,
                        "Your range is deployed. Download WireGuard from your dashboard and begin.")
        return changed

    def _expire_ranges():
        """Reclaim isolated ranges that are past the hard age cap or have been
        idle too long, so a stalled ranger never permanently clogs a slot. Board
        progress is untouched; the ranger just redeploys when they return."""
        now = _dt.datetime.now(_dt.timezone.utc)

        def _aware(d):  # SQLite drops tzinfo; treat stored times as UTC
            if d is not None and d.tzinfo is None:
                return d.replace(tzinfo=_dt.timezone.utc)
            return d

        reclaimed = []
        rows = RangeRequest.query.filter(RangeRequest.status.in_(RangeRequest.OCCUPIES_SLOT)).all()
        for rr in rows:
            if rr.host == "shared":
                continue
            base_age = _aware(rr.deployed_at or rr.created_at)
            base_idle = _aware(rr.last_active_at or rr.deployed_at or rr.created_at)
            age_h = (now - base_age).total_seconds() / 3600.0 if base_age else 0
            idle_h = (now - base_idle).total_seconds() / 3600.0 if base_idle else 0
            reason = None
            if RANGE_MAX_AGE_HOURS and age_h >= RANGE_MAX_AGE_HOURS:
                reason = f"reclaimed: reached max age {RANGE_MAX_AGE_HOURS:g}h"
            elif RANGE_IDLE_HOURS and idle_h >= RANGE_IDLE_HOURS:
                reason = f"reclaimed: idle {RANGE_IDLE_HOURS:g}h"
            if not reason:
                continue
            c = Candidate.query.get(rr.candidate_id)
            try:
                if c:
                    broker.destroy_range(c, user_key=_candidate_key(c))
            except Exception:  # noqa: BLE001
                pass
            rr.status = "destroyed"
            rr.detail = reason
            reclaimed.append(rr.host or "primary")
        return reclaimed

    def _maintenance():
        """One pass: start due cohorts, enforce the program window + inactivity,
        advance in-flight deploys, reclaim stale ranges, then fill freed slots.
        Used by the scheduler and the admin Reconcile button."""
        _activate_due_cohorts()
        _enforce_program()
        _poll_deploying()
        freed = _expire_ranges()
        db.session.flush()
        hosts = set(_known_hosts()) | set(freed)
        promoted = 0
        for h in hosts:
            promoted += _reconcile(h)
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

    def _active_cohort():
        return Cohort.query.filter_by(status="active").order_by(Cohort.sequence.asc()).first()

    def _active_cohort_name():
        c = _active_cohort()
        return c.name if c else DEFAULT_COHORT

    def _advance_cohorts(just_touched=None):
        """If the active cohort is done, every candidate in it has exited, mark
        it completed and activate the next scheduled cohort. Called whenever a
        candidate reaches a terminal state, so cohort B kicks off on its own when
        A finishes, with no rebuild. A cohort with zero candidates is never
        auto-completed (it is just new/empty)."""
        active = _active_cohort()
        if not active:
            return
        total = Candidate.query.filter_by(cohort=active.name).count()
        remaining = Candidate.query.filter_by(cohort=active.name, status="active").count()
        if total == 0 or remaining > 0:
            return  # nothing enrolled yet, or still in progress
        active.status = "completed"
        active.completed_at = _dt.datetime.now(_dt.timezone.utc)
        nxt = (Cohort.query.filter_by(status="scheduled")
               .filter(Cohort.sequence > active.sequence)
               .order_by(Cohort.sequence.asc()).first()
               or Cohort.query.filter_by(status="scheduled")
               .order_by(Cohort.sequence.asc()).first())
        if nxt:
            nxt.status = "active"
            nxt.activated_at = _dt.datetime.now(_dt.timezone.utc)
        db.session.flush()

    def _cohort_day(co):
        """1-based day number of an active cohort since activation, or None."""
        if not co or not co.activated_at:
            return None
        return (_dt.datetime.now(_dt.timezone.utc) - _aware(co.activated_at)).days + 1

    def _activate_due_cohorts():
        """When no cohort is live and a scheduled one's start date has arrived,
        start it. (Completion-based advance is handled separately.)"""
        if _active_cohort():
            return
        now = _dt.datetime.now(_dt.timezone.utc)
        due = (Cohort.query.filter_by(status="scheduled")
               .filter(Cohort.start_at.isnot(None), Cohort.start_at <= now)
               .order_by(Cohort.sequence.asc()).first())
        if due:
            due.status = "active"
            due.activated_at = now
            db.session.flush()

    def _enforce_program():
        """The 130-day structure. Off unless ENFORCE_DEADLINES=1. Washes out the
        active cohort's stragglers when its window closes, and anyone idle past
        the inactivity threshold. Washout is terminal; badges already earned are
        kept, and the window clock starts at cohort activation."""
        if not ENFORCE_DEADLINES:
            return
        now = _dt.datetime.now(_dt.timezone.utc)
        active = _active_cohort()
        window_over = bool(active and active.activated_at and
                           (now - _aware(active.activated_at)).days >= PROGRAM_DAYS)
        for c in Candidate.query.filter_by(status="active").all():
            if window_over and c.cohort == active.name:
                _exit_candidate(c, "washed_out",
                                f"cohort window ended ({PROGRAM_DAYS} days)")
                continue
            rr = _board_range(c, c.current_board)
            last = _aware((rr.last_active_at if rr else None) or
                          (rr.created_at if rr else None) or c.created_at)
            if last and (now - last).days >= WASHOUT_IDLE_DAYS:
                _exit_candidate(c, "washed_out",
                                f"inactive {WASHOUT_IDLE_DAYS}+ days")

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
        _advance_cohorts(c.cohort)

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
            _notify(c, "graduation", "You are a Qwalora Ranger, Certified",
                    "You cleared all six boards. Your public certificate is at "
                    "%s/verify/%s" % (githuboauth.base_url(), c.handle))
            _exit_candidate(c, "graduated", "cleared the capstone")
        else:
            c.current_board = n + 1
            c.current_role = P.role_of(n + 1)
            nb = P.badge_for(n)[1]
            _notify(c, "promotion", "Board %d cleared - promoted to board %d" % (n, n + 1),
                    "You earned the %s badge. You are now a %s on board %d."
                    % (nb, P.ROLE_TITLES.get(P.role_of(n + 1), "ranger"), n + 1))
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
        return render_template("enroll.html",
                               cohort=request.args.get("cohort") or _active_cohort_name(),
                               org=request.args.get("org", ""))

    def _enrollment_decision(github_id):
        """Branch a (re)enrollment by the person's lifetime history, keyed on the
        immutable GitHub id. Returns (decision, message)."""
        prior = Candidate.query.filter_by(github_id=github_id).all()
        if not prior:
            return ("new", "")
        if any(p.status == "active" for p in prior):
            return ("blocked_active",
                    "You already have an active enrollment. Finish or withdraw it first.")
        if any(p.status == "graduated" for p in prior):
            return ("blocked_graduate",
                    "You have already graduated this track. Contact us about the advanced track.")
        # Only washed-out / withdrawn history remains: a fresh restart is allowed,
        # with brand-new scenarios (the ledger guarantees no repeat).
        return ("restart", "")

    @app.post("/enroll")
    def enroll():
        handle = (request.form.get("handle") or "").strip().lstrip("@")
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip()
        cohort = (request.form.get("cohort") or _active_cohort_name()).strip()
        org = (request.form.get("org") or "").strip() or None
        repo = (request.form.get("repo") or "").strip() or None
        if not (handle and name and email):
            return render_template("enroll.html", cohort=cohort,
                                   error="GitHub handle, name, and email are all required."), 400

        # Person key: the GitHub id. Until OAuth lands it is seeded from the
        # handle, so returning-student detection already works by handle.
        github_id = (request.form.get("github_id") or "").strip() or handle
        decision, msg = _enrollment_decision(github_id)
        if decision in ("blocked_active", "blocked_graduate"):
            return render_template("enroll.html", cohort=cohort, error=msg), 409
        # A brand-new handle in this cohort still can't collide (handle is unique);
        # a true cross-cohort restart lands with the OAuth + identity split.
        if Candidate.query.filter_by(handle=handle).first():
            return render_template("enroll.html", cohort=cohort,
                                   error=f"'{handle}' is already enrolled."), 409

        c = Candidate(handle=handle, name=name, email=email, cohort=cohort, org=org, repo=repo,
                      github_id=github_id, current_board=1, current_role=P.role_of(1))
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
        _touch(c, n)
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
            now = _dt.datetime.now(_dt.timezone.utc)
            rr.status, rr.detail = st, sdetail
            rr.last_checked_at = now
            if st == "deployed" and not rr.deployed_at:
                rr.deployed_at = now
        _touch(c, n)
        db.session.commit()
        return jsonify(ok=True, handle=c.handle, board=n, tier=P.tier_of(n),
                       range_status=rr.status, range_id=rr.ludus_range_id,
                       scenario_seed=_current_seed(c), detail=rr.detail,
                       mode=broker.mode()), 200

    def _create_report(c, body, board_str=None, role=None):
        """Create a report for the candidate's CURRENT board. Returns
        (report, None) or (None, (reason, status_code)). Shared by the API and
        the in-portal form, so both validate identically."""
        if not c.is_active:
            return None, (f"candidate is {c.status}, not accepting reports", 409)
        n = c.current_board
        board = (board_str or P.bstr(n)).strip()
        role = (role or c.current_role or P.role_of(n)).strip()
        if P.bint(board) != n:
            return None, (f"you are on {P.bstr(n)}; submit for that board", 409)
        if not (body or "").strip():
            return None, ("report body is required", 400)
        if os.environ.get("REPORTS_REQUIRE_RANGE", "1") != "0" and P.is_isolated(n):
            rr = _board_range(c, n)
            if rr is None or not rr.is_deployed:
                return None, ("deploy your lab before submitting a report", 409)
        r = Report(candidate_id=c.id, board=board, role=role, body=body.strip())
        db.session.add(r)
        _touch(c, n)
        db.session.commit()
        return r, None

    @app.post("/reports")
    def submit_report():
        data = request.get_json(silent=True) or request.form
        c, err = _auth_candidate(data)
        if err:
            return err
        r, rerr = _create_report(c, data.get("body") or "", data.get("board"), data.get("role"))
        if rerr:
            return jsonify(error=rerr[0], current_board=P.bstr(c.current_board)), rerr[1]
        return jsonify(ok=True, report_id=r.id, board=r.board, status=r.status), 201

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

    @app.post("/labs/dataset")
    def lab_dataset():
        """The ranger's seeded investigation surface for their current board,
        with the answer key stripped. Authed by the candidate token."""
        data = request.get_json(silent=True) or request.form
        c, err = _auth_candidate(data)
        if err:
            return err
        n = c.current_board
        if not scenarios.has_board(n):
            return jsonify(error="dataset for this board is not available yet", board=n), 501
        seed = _current_seed(c)
        if not seed:
            _ensure_seed(c, n)
            seed = _current_seed(c)
        _touch(c, n)
        db.session.commit()
        return jsonify(ok=True, board=n, seed=seed, kind=scenarios.kind(n),
                       dataset=scenarios.dataset(n, seed)), 200

    @app.post("/grade/submit")
    def grade_submit():
        """Server-side, answer-free grading: the ranger submits their analysis,
        the server re-derives the key from their seed and scores it. The key is
        never exposed; feedback is correctness flags only."""
        data = request.get_json(silent=True) or request.form
        c, err = _auth_candidate(data)
        if err:
            return err
        if not c.is_active:
            return jsonify(error=f"candidate is {c.status}"), 409
        n = c.current_board
        if not scenarios.has_board(n):
            return jsonify(error="grader for this board is not available yet", board=n), 501
        submission = data.get("submission")
        if isinstance(submission, str):
            import json as _json
            try:
                submission = _json.loads(submission)
            except ValueError:
                return jsonify(error="submission must be valid JSON"), 400
        if not isinstance(submission, dict):
            return jsonify(error="a submission object is required"), 400
        seed = _current_seed(c)
        score, per_alert = scenarios.grade(n, seed, submission)
        _record_objective(c, n, score)
        _touch(c, n)
        promoted = _evaluate_gate(c)
        db.session.commit()
        return jsonify(ok=True, board=n, kind=scenarios.kind(n),
                       score=score, passed=score >= P.PASS_BAR,
                       per_alert=per_alert, promoted=promoted,
                       current_board=c.current_board, status=c.status,
                       note="Report approval is also required to clear the board."), 200

    # --- admin ---------------------------------------------------------------
    @app.get("/admin/login")
    def admin_login():
        if not _auth_available():
            abort(503, "No admin sign-in is configured on this service.")
        return render_template("admin_login.html", nxt=request.args.get("next", "/admin"),
                               token_login=bool(admin_token and not token_disabled))

    @app.post("/admin/login")
    def admin_login_post():
        if not admin_token or token_disabled:
            return render_template("admin_login.html", nxt=request.form.get("next", "/admin"),
                                   token_login=False,
                                   error="Token sign-in is disabled. Use GitHub."), 403
        import hmac as _hmac
        if _hmac.compare_digest(request.form.get("token") or "", admin_token):
            session["admin"] = True
            return redirect(request.form.get("next") or url_for("admin"))
        return render_template("admin_login.html", nxt=request.form.get("next", "/admin"),
                               token_login=True, error="Wrong token."), 401

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
                "time": _ago(target.created_at), "rid": f"RGR-{c.cohort}-{target.id:02d}",
                "subject_line": f"{c.name.split()[0]} submitted {target.board} "
                                f"{ROLE_TITLES.get(target.role, target.role)} for review.",
                "participants": [_initials(c.name), "FK"], "participants_more": 0,
                "m_roles": 4, "m_boards": len(BOARDS), "m_flags": len(tags_for(target)),
                "m_signals": (len(evidence) if evidence else 0),
                "remeasure_label": (f"Program re-measured the repo · {len(evidence)} signals"
                                    if evidence else "Re-measurement runs at cohort sync"),
                "engine": "ed25519", "evidence": evidence, "sig": sig, "analysis": paras,
                "status_label": sl, "status_cls": scls, "status_dot": sdot,
                "cand_status": c.status,
                "cand_board": c.current_board,
                "cand_role": P.ROLE_TITLES.get(c.current_role or P.role_of(c.current_board), "-"),
                "is_current": (P.bint(target.board) == c.current_board and c.is_active),
                "badges": _badge_chain(c)["chain"], "certified": _badge_chain(c)["certified"]}

        title_map = {"pending": "Pending", "approved": "Approved",
                     "needs_changes": "Needs changes", "rejected": "Rejected", "all": "All reports"}
        vm = {"cohort": _active_cohort_name(), "broker": broker_status(),
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
                promoted_before = c.current_board
                if action == "approve" and n == c.current_board:
                    _evaluate_gate(c)
                # Notify on the decision (skip approve-that-promoted: the
                # promotion notice already covers it).
                if not (action == "approve" and c.current_board != promoted_before):
                    msg = {"approved": "Your %s report was approved." % r.board,
                           "rejected": "Your %s report was rejected." % r.board,
                           "needs_changes": "Your %s report needs changes." % r.board}[r.status]
                    if r.reviewer_notes:
                        msg += " Reviewer: " + r.reviewer_notes
                    _notify(c, "report", "Report %s - %s" % (r.status.replace("_", " "), r.board), msg)
            db.session.commit()
        return redirect(url_for("admin", status=request.form.get("return_status", "pending")))

    _RANGE_UI = {
        "deployed": ("Deployed", "pill-ok", "dot-ok"),
        "deploying": ("Deploying", "pill-amber", "dot-amber"),
        "queued_slot": ("Queued for a slot", "pill-amber", "dot-amber"),
        "configured": ("Configured", "pill-violet", "dot-violet"),
        "failed": ("Failed", "pill-amber", "dot-amber"),
        "destroyed": ("Destroyed", "pill", "dot"),
        "queued": ("Configured", "pill-violet", "dot-violet"),  # legacy
        "none": ("Not provisioned", "pill", "dot"),
    }

    def _cohort_rows():
        """All cohorts with live counts, newest sequence first, for the chooser
        and the header switcher."""
        out = []
        for co in Cohort.query.order_by(Cohort.sequence.desc()).all():
            base = Candidate.query.filter_by(cohort=co.name)
            out.append({
                "name": co.name, "status": co.status, "sequence": co.sequence,
                "total": base.count(),
                "active": base.filter_by(status="active").count(),
                "graduated": base.filter_by(status="graduated").count(),
                "start_at": co.start_at.date().isoformat() if co.start_at else None,
            })
        return out

    @app.get("/admin/cohorts")
    @admin_required
    def admin_cohorts():
        return render_template("admin_cohorts.html",
                               vm={"cohorts": _cohort_rows(),
                                   "active": _active_cohort_name()})

    @app.post("/admin/cohorts/new")
    @admin_required
    def admin_cohort_new():
        name = (request.form.get("name") or "").strip()
        if not name:
            return redirect(url_for("admin_cohorts"))
        if Cohort.query.filter_by(name=name).first():
            return redirect(url_for("admin_cohort", cohort=name))
        start = (request.form.get("start_at") or "").strip()
        start_at = None
        if start:
            try:
                start_at = _dt.datetime.fromisoformat(start)
            except ValueError:
                start_at = None
        seq = (db.session.query(db.func.max(Cohort.sequence)).scalar() or 0) + 1
        activate = request.form.get("activate") == "1" and not _active_cohort()
        co = Cohort(name=name, sequence=seq,
                    status=("active" if activate else "scheduled"),
                    start_at=start_at,
                    activated_at=(_dt.datetime.now(_dt.timezone.utc) if activate else None),
                    note=(request.form.get("note") or "").strip() or None)
        db.session.add(co)
        db.session.commit()
        return redirect(url_for("admin_cohort", cohort=name))

    @app.post("/admin/cohorts/<name>/activate")
    @admin_required
    def admin_cohort_activate(name):
        co = Cohort.query.filter_by(name=name).first_or_404()
        # Only one active at a time: demote any current active back to scheduled.
        for other in Cohort.query.filter_by(status="active").all():
            if other.id != co.id:
                other.status = "scheduled"
        co.status = "active"
        co.activated_at = co.activated_at or _dt.datetime.now(_dt.timezone.utc)
        co.completed_at = None
        db.session.commit()
        return redirect(url_for("admin_cohort", cohort=name))

    @app.post("/admin/cohorts/<name>/complete")
    @admin_required
    def admin_cohort_complete(name):
        co = Cohort.query.filter_by(name=name).first_or_404()
        co.status = "completed"
        co.completed_at = _dt.datetime.now(_dt.timezone.utc)
        db.session.flush()
        # Activating the next scheduled cohort, same rule as auto-advance.
        if not _active_cohort():
            nxt = (Cohort.query.filter_by(status="scheduled")
                   .order_by(Cohort.sequence.asc()).first())
            if nxt:
                nxt.status = "active"
                nxt.activated_at = _dt.datetime.now(_dt.timezone.utc)
        db.session.commit()
        return redirect(url_for("admin_cohorts"))

    @app.get("/admin/cohort")
    @admin_required
    def admin_cohort():
        # Default to the live (active) cohort; if none is live, don't default to
        # anything, send the operator to the chooser.
        cohort = (request.args.get("cohort") or "").strip()
        if not cohort:
            active = _active_cohort()
            if active:
                return redirect(url_for("admin_cohort", cohort=active.name))
            return redirect(url_for("admin_cohorts"))
        status = request.args.get("status", "active")
        org = (request.args.get("org") or "").strip()
        qtext = (request.args.get("q") or "").strip()
        base = Candidate.query.filter_by(cohort=cohort)
        counts = {k: base.filter_by(status=k).count()
                  for k in ("active", "graduated", "washed_out", "withdrawn")}
        counts["all"] = base.count()

        # Group summary: roll the cohort up by organization. For each org, how
        # many rangers, how many active, how far along, and how many need an
        # isolated range right now (board 5-6) vs have one deployed. This is the
        # view for running a sponsored batch and planning range capacity.
        orgs_present = sorted({c.org for c in base.all() if c.org})
        groups = []
        for oname in orgs_present:
            members = base.filter_by(org=oname).all()
            active = [m for m in members if m.status == "active"]
            iso = [m for m in active if P.is_isolated(m.current_board)]
            deployed = 0
            for m in iso:
                rr = _board_range(m, m.current_board)
                if rr and rr.is_deployed:
                    deployed += 1
            groups.append({
                "org": oname, "total": len(members),
                "active": len(active),
                "graduated": sum(1 for m in members if m.status == "graduated"),
                "iso_needed": len(iso), "iso_deployed": deployed,
                "avg_board": round(sum(m.current_board for m in active) / len(active), 1) if active else 0,
            })

        qry = base
        if status in ("active", "graduated", "washed_out", "withdrawn"):
            qry = qry.filter_by(status=status)
        if org:
            qry = qry.filter_by(org=org)
        if qtext:
            like = f"%{qtext}%"
            qry = qry.filter(db.or_(Candidate.name.ilike(like),
                                    Candidate.handle.ilike(like)))
        cands = qry.order_by(Candidate.current_board.desc(),
                             Candidate.handle.asc()).limit(300).all()
        rows = []
        for c in cands:
            bc = _badge_chain(c)
            rr = _board_range(c, c.current_board)
            rst = rr.status if rr else "none"
            rlabel, rpcls, rdot = _RANGE_UI.get(rst, ("None", "pill", "dot"))
            slabel, spcls, sdot = STATUS_UI.get(c.status, ("-", "pill", "dot"))
            rows.append({
                "cid": c.id, "ini": _initials(c.name), "name": c.name, "handle": c.handle,
                "org": c.org,
                "status": c.status, "status_label": slabel, "status_pcls": spcls, "status_dot": sdot,
                "board": c.current_board,
                "role_title": P.ROLE_TITLES.get(c.current_role or P.role_of(c.current_board), "-"),
                "tier": P.tier_of(c.current_board),
                "badges": bc["chain"], "certified": bc["certified"],
                "range_label": rlabel, "range_pcls": rpcls, "range_dot": rdot,
                "terminal": (c.status in Candidate.TERMINAL),
            })
        this_co = Cohort.query.filter_by(name=cohort).first()
        day = _cohort_day(this_co) if (this_co and this_co.status == "active") else None
        vm = {"cohort": cohort, "active_status": status, "q": qtext,
              "counts": counts, "rows": rows, "total": len(rows),
              "org": org, "orgs": orgs_present, "groups": groups,
              "cohorts": _cohort_rows(), "cohort_status": (this_co.status if this_co else "scheduled"),
              "is_active_cohort": bool(this_co and this_co.status == "active"),
              "program_days": PROGRAM_DAYS, "cohort_day": day,
              "days_left": (max(0, PROGRAM_DAYS - day + 1) if day else None),
              "enforce": ENFORCE_DEADLINES,
              "slots_used": _slots_used("primary"), "cap": MAX_CONCURRENT,
              "mode": broker.mode()}
        return render_template("admin_cohort.html", vm=vm)

    @app.get("/admin/ranges")
    @admin_required
    def admin_ranges():
        # Default to the live (active) cohort. If none is live and none is
        # chosen, don't default: show the empty state with the chooser.
        active = _active_cohort()
        cohort = (request.args.get("cohort") or "").strip() or (active.name if active else None)
        counts = {"deployed": 0, "deploying": 0, "queued_slot": 0, "configured": 0, "failed": 0}
        if not cohort:
            vm = {"cohort": None, "no_active": True, "cohorts": _cohort_rows(),
                  "broker": broker_status(), "mode": broker.mode(),
                  "template": broker.GOAD_TEMPLATE, "rows": [], "counts": counts, "total": 0,
                  "slots_used": _slots_used("primary"), "cap": MAX_CONCURRENT}
            return render_template("admin_ranges.html", vm=vm)
        # Ranges matter for active candidates; show them ordered by board.
        cands = (Candidate.query.filter_by(cohort=cohort, status="active")
                 .order_by(Candidate.current_board.desc(), Candidate.handle).limit(300).all())
        rows = []
        for c in cands:
            n = c.current_board
            rr = _board_range(c, n)
            st = rr.status if rr else "none"
            label, pcls, dot = _RANGE_UI.get(st, ("None", "pill", "dot"))
            key = "configured" if st in ("configured", "queued") else st
            if key in counts:
                counts[key] += 1
            rows.append({
                "cid": c.id, "ini": _initials(c.name), "name": c.name,
                "handle": c.handle, "ludus_user": c.ludus_user_id or "-",
                "board": n, "tier": P.tier_of(n),
                "role_title": P.ROLE_TITLES.get(c.current_role or P.role_of(n), "-"),
                "status": st, "label": label, "pcls": pcls, "dot": dot,
                "range_id": (rr.ludus_range_id if rr else None),
                "template": (rr.template if rr else None),
                "has_wg": bool(rr and rr.wireguard_config),
                "checked": _ago(rr.last_checked_at) if rr and rr.last_checked_at else "",
                "detail": (rr.detail if rr else "no range provisioned"),
            })
        this_co = Cohort.query.filter_by(name=cohort).first()
        vm = {"cohort": cohort, "no_active": False, "cohorts": _cohort_rows(),
              "cohort_status": (this_co.status if this_co else "scheduled"),
              "broker": broker_status(),
              "mode": broker.mode(), "template": broker.GOAD_TEMPLATE,
              "rows": rows, "counts": counts, "total": len(rows),
              "slots_used": _slots_used("primary"), "cap": MAX_CONCURRENT}
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

    def _wants_json():
        return (bool(request.headers.get("Authorization"))
                or "application/json" in request.headers.get("Accept", ""))

    @app.post("/admin/reconcile")
    @admin_required
    def admin_reconcile():
        # Full maintenance pass (same as the background worker): advance
        # in-flight deploys, reclaim stale ranges, fill freed slots.
        promoted = _maintenance()
        if _wants_json():
            return jsonify(ok=True, deployed_from_queue=promoted,
                           slots_used=_slots_used("primary"), cap=MAX_CONCURRENT)
        return redirect(url_for("admin_ranges"))

    @app.post("/admin/candidates/<int:cid>/exit")
    @admin_required
    def admin_exit(cid):
        c = Candidate.query.get_or_404(cid)
        reason = (request.form.get("reason") or "").strip()
        kind = (request.form.get("kind") or "withdrawn").strip()
        status = kind if kind in Candidate.TERMINAL else "withdrawn"
        _exit_candidate(c, status, reason or status)
        db.session.commit()
        if _wants_json():
            return jsonify(ok=True, handle=c.handle, status=c.status,
                           exit_reason=c.exit_reason)
        return redirect(request.form.get("return") or
                        url_for("admin_cohort", status=request.form.get("return_status", "active")))

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

    def _verify_record(c):
        """Re-derive each signed claim and check its Ed25519 signature, so the
        public page proves the credential rather than just displaying it."""
        badges = []
        for b in sorted(c.badges, key=lambda x: str(x.level)):
            claim = {"kind": "badge", "handle": c.handle, "cohort": c.cohort,
                     "level": b.level, "name": b.name, "role": b.role,
                     "issued_at": _iso(b.issued_at)}
            ok = bool(b.signature) and not b.revoked and signing.verify(claim, b.signature)
            badges.append({"level": b.level, "name": b.name, "role": b.role,
                           "issued_at": _iso(b.issued_at), "revoked": b.revoked,
                           "verified": ok})
        clearances = []
        for br in sorted(c.board_results, key=lambda x: x.board):
            if not br.cleared:
                continue
            claim = {"kind": "clearance", "handle": c.handle, "cohort": c.cohort,
                     "board": br.board, "role": P.role_of(br.board),
                     "objective_score": br.objective_score, "cleared_at": _iso(br.cleared_at)}
            ok = bool(br.signature) and signing.verify(claim, br.signature)
            clearances.append({"board": br.board, "name": P.badge_for(br.board)[1],
                               "role_title": P.ROLE_TITLES.get(P.role_of(br.board), "-"),
                               "objective_score": (round(br.objective_score, 1)
                                                   if br.objective_score is not None else None),
                               "cleared_at": _iso(br.cleared_at), "verified": ok})
        certified = any(b["level"] == "certified" and b["verified"] for b in badges)
        return {"badges": badges, "clearances": clearances, "certified": certified}

    @app.get("/verify/<handle>")
    def verify_page(handle):
        """Public, no-auth: verify a ranger's signed credentials in the open.
        Reveals only their own badges/clearances, no grades of others, no keys."""
        c = Candidate.query.filter_by(handle=handle.lstrip("@")).first()
        if not c:
            return render_template("verify.html", vm={"found": False, "handle": handle}), 404
        rec = _verify_record(c)
        all_ok = all(b["verified"] for b in rec["badges"]) and \
            all(cl["verified"] for cl in rec["clearances"]) and \
            (rec["badges"] or rec["clearances"])
        vm = {"found": True, "handle": c.handle, "name": c.name, "cohort": c.cohort,
              "status": c.status, "certified": rec["certified"],
              "badges": rec["badges"], "clearances": rec["clearances"],
              "all_ok": all_ok, "pubkey": signing.public_key_b64()}
        return render_template("verify.html", vm=vm)

    @app.get("/verify/<handle>/certificate")
    def verify_certificate(handle):
        c = Candidate.query.filter_by(handle=handle.lstrip("@")).first()
        if not c:
            abort(404)
        rec = _verify_record(c)
        if not rec["certified"]:
            return redirect(url_for("verify_page", handle=c.handle))
        cert = next((b for b in c.badges if b.level == "certified"), None)
        vm = {"name": c.name, "handle": c.handle, "cohort": c.cohort,
              "issued_at": _iso(cert.issued_at) if cert else "",
              "clearances": rec["clearances"], "pubkey": signing.public_key_b64()}
        return render_template("certificate.html", vm=vm)

    @app.get("/roster.json")
    @admin_required
    def roster_json():
        cohort = request.args.get("cohort") or _active_cohort_name()
        org = (request.args.get("org") or "").strip()
        q = Candidate.query.filter_by(cohort=cohort)
        if org:
            q = q.filter_by(org=org)
        cands = q.order_by(Candidate.handle).all()
        return jsonify(cohort=cohort, org=(org or None),
                       candidates=[c.roster_entry() for c in cands])

    # --- GitHub OAuth: the only way candidates get in -----------------------
    @app.get("/auth/github/login")
    def gh_login():
        if not githuboauth.enabled():
            abort(503, "GitHub sign-in is not configured.")
        import secrets as _secrets
        state = _secrets.token_urlsafe(24)
        session["oauth_state"] = state
        session["oauth_role"] = "reviewer" if request.args.get("role") == "reviewer" else "candidate"
        session["oauth_next"] = request.args.get("next", "")
        return redirect(githuboauth.authorize_url(state))

    @app.get("/auth/github/callback")
    def gh_callback():
        if not githuboauth.enabled():
            abort(503)
        if request.args.get("error"):
            return render_template("oauth_error.html",
                                   msg=request.args.get("error_description") or "sign-in was cancelled"), 400
        state = request.args.get("state")
        if not state or state != session.pop("oauth_state", None):
            return render_template("oauth_error.html", msg="sign-in session expired, please try again"), 400
        role = session.pop("oauth_role", "candidate")
        nxt = session.pop("oauth_next", "")
        token = githuboauth.exchange_code(request.args.get("code", ""))
        if not token:
            return render_template("oauth_error.html", msg="could not complete GitHub sign-in"), 400
        user = githuboauth.get_user(token)
        emails = githuboauth.get_emails(token)
        gid = str(user.get("id") or "")
        login = user.get("login") or ""
        name = user.get("name") or login
        if not gid or not login:
            return render_template("oauth_error.html", msg="could not read your GitHub profile"), 400

        if role == "reviewer":
            if gid not in githuboauth.reviewer_ids():
                return render_template("oauth_error.html",
                                       msg="this GitHub account is not authorized as a reviewer"), 403
            session["admin"] = True
            session["admin_login"] = login
            return redirect(nxt or url_for("admin"))

        # Candidate: enforce the identity bar before letting anyone in.
        ok, reason, email = githuboauth.identity_ok(user, emails)
        if not ok:
            return render_template("oauth_error.html", msg=reason), 403

        c = Candidate.query.filter_by(github_id=gid).first()
        if c is None:
            # Adopt a legacy row enrolled before OAuth (github_id was the handle).
            legacy = Candidate.query.filter_by(handle=login).first()
            if legacy is not None:
                legacy.github_id = gid
                c = legacy
            else:
                decision, msg = _enrollment_decision(gid)
                if decision in ("blocked_active", "blocked_graduate"):
                    return render_template("oauth_error.html", msg=msg), 409
                c = Candidate(handle=login, name=name, email=email,
                              cohort=_active_cohort_name(), github_id=gid,
                              current_board=1, current_role=P.role_of(1))
                db.session.add(c)
                db.session.flush()
                _provision_for_board(c, 1)
        db.session.commit()
        session["cand"] = c.id
        return redirect(url_for("candidate_me"))

    @app.get("/auth/logout")
    def auth_logout():
        session.pop("cand", None)
        return redirect(ranger_site)

    # --- candidate self-service --------------------------------------------
    def _current_candidate():
        cid = session.get("cand")
        return Candidate.query.get(cid) if cid else None

    _REPORT_UI = {"approved": ("Approved", "pill-ok", "dot-ok"),
                  "pending": ("In review", "pill-amber", "dot-amber"),
                  "needs_changes": ("Needs changes", "pill-amber", "dot-amber"),
                  "rejected": ("Rejected", "pill-amber", "dot-amber")}

    def _board_progress(c):
        """Per-board history: objective score, report outcome, clearance. The
        ranger's record across the whole ladder, for the dashboard."""
        results = {br.board: br for br in
                   BoardResult.query.filter_by(candidate_id=c.id).all()}
        rows = []
        for b in P.BOARD_PLAN:
            n = b["n"]
            br = results.get(n)
            state = "locked"
            if br and br.cleared:
                state = "cleared"
            elif n == c.current_board and c.is_active:
                state = "current"
            elif n < c.current_board or c.status == "graduated":
                state = "cleared"
            rows.append({
                "board": n, "name": b["badge"], "role_title": P.ROLE_TITLES.get(b["role"], b["role"]),
                "tier": P.tier_of(n), "state": state,
                "objective_score": (round(br.objective_score, 1) if br and br.objective_score is not None else None),
                "objective_passed": bool(br and br.objective_passed),
                "report_status": (br.report_status if br else None),
                "cleared": bool(br and br.cleared),
            })
        return rows

    def _me_vm(c):
        """The candidate dashboard view model. Shared by /me and the admin
        preview so both render exactly what the ranger sees."""
        n = c.current_board
        rr = _board_range(c, n)
        bc = _badge_chain(c)
        rst = rr.status if rr else "none"
        rlabel, rpcls, rdot = _RANGE_UI.get(rst, ("Not started", "pill", "dot"))
        br = _board_result(c, n, create=False)
        last_report = (Report.query.filter_by(candidate_id=c.id, board=P.bstr(n))
                       .order_by(Report.id.desc()).first())
        rep_status = last_report.status if last_report else None
        rlab, rpc, rdt = _REPORT_UI.get(rep_status, (None, None, None))
        return {
            "name": c.name, "handle": c.handle, "status": c.status,
            "board": n, "role_title": P.ROLE_TITLES.get(c.current_role or P.role_of(n), "-"),
            "tier": P.tier_of(n), "cohort": c.cohort,
            "badges": bc["chain"], "certified": bc["certified"],
            "range_status": rst, "range_label": rlabel, "range_pcls": rpcls, "range_dot": rdot,
            "has_wg": bool(rr and rr.wireguard_config),
            "seed": _current_seed(c), "token": c.token,
            "range_detail": (rr.detail if rr else ""),
            "preview": False,
            "progress": _board_progress(c),
            "cur_objective_score": (round(br.objective_score, 1) if br and br.objective_score is not None else None),
            "cur_objective_passed": bool(br and br.objective_passed),
            "cur_report_status": rep_status,
            "cur_report_label": rlab, "cur_report_pcls": rpc, "cur_report_dot": rdt,
            "cur_report_notes": (last_report.reviewer_notes if last_report else None),
            "report_open": (c.is_active and rep_status in (None, "needs_changes", "rejected")),
            "pass_bar": P.PASS_BAR,
            "notifications": [{"kind": nt.kind, "title": nt.title, "body": nt.body,
                               "when": _ago(nt.created_at), "read": nt.read}
                              for nt in (Notification.query.filter_by(candidate_id=c.id)
                                         .order_by(Notification.id.desc()).limit(8).all())],
            "unread": Notification.query.filter_by(candidate_id=c.id, read=False).count(),
        }

    def _demo_vm(n, graduated):
        """A synthetic dashboard for the admin demo preview: no real candidate,
        just the persona at board n (or graduated) so an operator can walk the
        whole ladder from SOC to capstone without enrolling anyone."""
        isolated = P.tier_of(n) == "isolated"
        rst = "deployed"
        rlabel, rpcls, rdot = _RANGE_UI.get(rst, ("Deployed", "pill-ok", "dot-ok"))
        chain = [{"level": str(b["n"]), "name": b["badge"], "role": b["role"],
                  "board": b["n"], "earned": (graduated or b["n"] < n)}
                 for b in P.BOARD_PLAN]
        personas = [{"n": b["n"], "role_title": P.ROLE_TITLES.get(b["role"], b["role"]),
                     "badge": b["badge"], "tier": P.tier_of(b["n"])} for b in P.BOARD_PLAN]
        return {
            "name": "Demo Ranger", "handle": "demo",
            "status": ("graduated" if graduated else "active"),
            "board": n, "role_title": P.ROLE_TITLES.get(P.role_of(n), "-"),
            "tier": P.tier_of(n), "cohort": "DEMO",
            "badges": chain, "certified": graduated,
            "range_status": rst, "range_label": rlabel, "range_pcls": rpcls, "range_dot": rdot,
            "has_wg": isolated, "seed": "demo-seed-b%d" % n, "token": "demo-preview-token",
            "range_detail": "Demo range (preview only)",
            "preview": True, "demo": True,
            "persona_board": n, "persona_graduated": graduated, "personas": personas,
            "progress": [{"board": b["n"], "name": b["badge"],
                          "role_title": P.ROLE_TITLES.get(b["role"], b["role"]),
                          "tier": P.tier_of(b["n"]),
                          "state": ("cleared" if (graduated or b["n"] < n)
                                    else ("current" if b["n"] == n else "locked")),
                          "objective_score": (100.0 if (graduated or b["n"] < n) else None),
                          "objective_passed": (graduated or b["n"] < n),
                          "report_status": ("approved" if (graduated or b["n"] < n) else None),
                          "cleared": (graduated or b["n"] < n)} for b in P.BOARD_PLAN],
            "cur_objective_score": None, "cur_objective_passed": False,
            "cur_report_status": None, "cur_report_label": None,
            "cur_report_pcls": None, "cur_report_dot": None, "cur_report_notes": None,
            "report_open": not graduated, "pass_bar": P.PASS_BAR,
            "notifications": [], "unread": 0,
        }

    @app.get("/admin/preview")
    @admin_required
    def admin_preview_demo():
        """Persona preview, independent of enrolled rangers. ?board=1..6 walks
        the ladder; ?state=graduated shows the certified end."""
        graduated = request.args.get("state") == "graduated"
        try:
            n = int(request.args.get("board", 1))
        except (TypeError, ValueError):
            n = 1
        n = max(1, min(P.LAST_BOARD, n))
        return render_template("candidate_me.html", vm=_demo_vm(n, graduated))

    @app.get("/me")
    def candidate_me():
        c = _current_candidate()
        if not c:
            if githuboauth.enabled():
                return redirect(url_for("gh_login"))
            abort(401)
        if c.is_active:
            _touch(c)
            db.session.commit()
        vm = _me_vm(c)
        vm["report_ok"] = request.args.get("report_ok") == "1"
        vm["report_error"] = request.args.get("report_error")
        resp = render_template("candidate_me.html", vm=vm)
        # Mark seen AFTER capturing the unread state for this render.
        if vm["unread"]:
            Notification.query.filter_by(candidate_id=c.id, read=False).update({"read": True})
            db.session.commit()
        return resp

    @app.post("/me/start")
    def candidate_start():
        c = _current_candidate()
        if not c:
            abort(401)
        if c.is_active:
            _provision_for_board(c, c.current_board, auto_deploy=True)
            _touch(c)
            db.session.commit()
        return redirect(url_for("candidate_me"))

    @app.post("/me/report")
    def candidate_report():
        """Submit the written report for the current board from the dashboard.
        Session-authed (the ranger is signed in), CSRF-protected."""
        c = _current_candidate()
        if not c:
            abort(401)
        _, rerr = _create_report(c, request.form.get("body") or "")
        if rerr:
            return redirect(url_for("candidate_me", report_error=rerr[0]))
        return redirect(url_for("candidate_me", report_ok="1"))

    @app.get("/me/wireguard")
    def candidate_wireguard():
        c = _current_candidate()
        if not c:
            abort(401)
        rr = _board_range(c, c.current_board)
        if not rr or not rr.wireguard_config:
            abort(404)
        rr.last_active_at = _dt.datetime.now(_dt.timezone.utc)
        db.session.commit()
        from flask import Response
        return Response(rr.wireguard_config, mimetype="text/plain",
                        headers={"Content-Disposition": "attachment; filename=qwalora-ranger.conf"})

    @app.get("/admin/preview/<int:cid>")
    @admin_required
    def admin_preview(cid):
        """Read-only preview of a ranger's own dashboard, so an operator can see
        exactly what a candidate sees. Candidate actions are disabled here; this
        never signs in as the candidate or changes anything on their behalf."""
        c = Candidate.query.get_or_404(cid)
        vm = _me_vm(c)
        vm["preview"] = True
        roster = (Candidate.query.filter_by(cohort=c.cohort)
                  .order_by(Candidate.handle).all())
        vm["preview_candidates"] = [
            {"id": o.id, "handle": o.handle, "board": o.current_board,
             "status": o.status, "current": o.id == c.id} for o in roster]
        vm["preview_cohort"] = c.cohort
        return render_template("candidate_me.html", vm=vm)

    # --- background maintenance scheduler -----------------------------------
    _LOCK_KEY = 913572  # arbitrary, stable advisory-lock id

    def _single_run_lock():
        """On Postgres, only one worker runs a tick: grab a session advisory
        lock, skip the tick if another worker holds it. SQLite/local has no
        cross-process workers, so always run."""
        try:
            if db.engine.dialect.name == "postgresql":
                return bool(db.session.execute(
                    db.text("SELECT pg_try_advisory_lock(:k)"), {"k": _LOCK_KEY}).scalar())
        except Exception:  # noqa: BLE001
            db.session.rollback()
            return False
        return True

    def _single_run_unlock():
        try:
            if db.engine.dialect.name == "postgresql":
                db.session.execute(db.text("SELECT pg_advisory_unlock(:k)"), {"k": _LOCK_KEY})
                db.session.commit()
        except Exception:  # noqa: BLE001
            db.session.rollback()

    def _scheduler_tick():
        with app.app_context():
            if not _single_run_lock():
                return
            try:
                _maintenance()
            except Exception:  # noqa: BLE001
                db.session.rollback()
            finally:
                _single_run_unlock()

    if ENABLE_SCHEDULER:
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            _sched = BackgroundScheduler(daemon=True, timezone="UTC")
            _sched.add_job(_scheduler_tick, "interval", seconds=RECONCILE_INTERVAL,
                           id="qwalora_maintenance", max_instances=1, coalesce=True,
                           next_run_time=_dt.datetime.now(_dt.timezone.utc))
            _sched.start()
            app.logger.info("maintenance scheduler started, every %ss", RECONCILE_INTERVAL)
        except Exception as e:  # noqa: BLE001
            app.logger.warning("maintenance scheduler not started: %s", e)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
