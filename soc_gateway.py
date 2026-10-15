"""Ranger /soc authenticated reverse-proxy gateway to the private OpenSearch
Dashboards.

Every /soc/* request is authenticated by Ranger's existing session and the
candidate's current authorization (active + Board 2). The gateway mints a
short-lived JWT server-side and injects it into the upstream Authorization
header; the token never reaches the browser, a URL, or storage. Client-supplied
authorization/identity/forwarding headers are stripped. Only the private
Dashboards service is reachable, under its /soc base path. Candidate role/index
provisioning is a separate, idempotent step (/soc/launch), never done on ordinary
proxy requests.

OpenSearch and Dashboards stay private; this gateway rides the portal's existing
public HTTPS. Security-relevant events are logged without tokens or secrets.
"""
from __future__ import annotations

import base64
import os
import time
import urllib.error
import urllib.request

from flask import Response, abort, redirect, request, session

from siem import authz, ranger_jwt
from siem.live import LiveCluster

DASH = os.environ.get("DASHBOARDS_URL", "http://dashboards.railway.internal:5601").rstrip("/")
OS_URL = os.environ.get("OPENSEARCH_URL", "https://opensearch.railway.internal:9200")
BASE = "/soc"
PROXY_TIMEOUT = int(os.environ.get("SOC_PROXY_TIMEOUT", "30"))
MAX_RESP = int(os.environ.get("SOC_MAX_RESP_BYTES", str(40 * 1024 * 1024)))
SIEM_BOARD = 2

# --- Admin "act-as" (candidate simulation) hard constraints -------------------
# act-as exists ONLY to let an authenticated Super Admin drive the real candidate
# SOC experience with a dedicated, non-real test identity during validation. It is
# never a path to impersonate a real candidate and is off unless explicitly enabled.
_ACTAS_HANDLE = "board2-test"               # the ONLY handle act-as may target
_ACTAS_MARKER = "soctest-board2-test"       # synthetic github_id marking the test candidate
_ACTAS_TTL = int(os.environ.get("RANGER_SOC_ACTAS_TTL", "1800"))  # session lifetime, seconds
_ACTAS_ENABLED = os.environ.get("RANGER_SOC_ACTAS_ENABLED", "").strip().lower() in (
    "1", "true", "yes", "on")

# Hop-by-hop headers never forwarded in either direction.
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host"}
# Client headers that must never reach upstream (identity/auth/forwarding/impersonation).
_STRIP_CLIENT = {"authorization", "securitytenant", "x-forwarded-for", "x-forwarded-host",
                 "x-forwarded-proto", "x-forwarded-port", "x-real-ip", "x-proxy-user",
                 "x-proxy-roles", "x-opaque-id", "jwt", "x-forwarded-user",
                 "x-forwarded-roles", "accept-encoding"}

_last_hit: dict[str, list] = {}  # naive per-candidate rate limiter


def _log(event, **kv):
    # Security audit, never includes the token or secrets.
    safe = {k: v for k, v in kv.items() if k not in ("token", "jwt", "password")}
    print(f"[soc-audit] {event} " + " ".join(f"{k}={v}" for k, v in safe.items()), flush=True)


def _jwt_priv():
    return base64.b64decode(os.environ["RANGER_JWT_PRIVATE_B64"])


def _ca_path():
    cab = os.environ.get("RANGER_CA_B64")
    if not cab:
        return None
    p = "/tmp/ranger-ca.pem"
    if not os.path.exists(p):
        with open(p, "wb") as f:
            f.write(base64.b64decode(cab))
    return p


def _admin_cluster():
    """Broker identity (portal holds the OpenSearch admin credential)."""
    return LiveCluster(OS_URL, os.environ.get("OPENSEARCH_ADMIN_USER", "admin"),
                       os.environ["OPENSEARCH_ADMIN_PASSWORD"], ca_path=_ca_path(), timeout=30)


def _rate_ok(key, limit=120, window=60):
    now = time.time()
    hits = [t for t in _last_hit.get(key, []) if now - t < window]
    hits.append(now)
    _last_hit[key] = hits[-limit:]
    return len(hits) <= limit


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # pass 3xx back to the browser rather than following server-side


_OPENER = urllib.request.build_opener(_NoRedirect)


def register(app, candidate_model, db):
    """Wire the /soc gateway onto the portal app. candidate_model is the Candidate
    ORM class; db is the SQLAlchemy handle."""

    def _current_candidate():
        cid = session.get("cand")
        if not cid:
            return None
        return candidate_model.query.get(cid)

    def _candidate_slug(c):
        return authz._slug(c.github_id or c.handle)

    _DEFCO = os.environ.get("DEFAULT_COHORT", "2026-A")

    def _actas_candidate():
        """Return the live act-as candidate for this admin session, or None.
        Enforces the short lifetime and the non-real-identity invariant; clears a
        stale or invalid impersonation so it cannot linger."""
        actas = session.get("soc_act_as")
        if not actas:
            return None
        if time.time() >= session.get("soc_act_as_exp", 0):
            _log("actas_expired", admin=session.get("soc_act_as_admin"), cand=actas)
            session.pop("soc_act_as", None)
            session.pop("soc_act_as_exp", None)
            session.pop("soc_act_as_admin", None)
            return None
        c = candidate_model.query.get(actas)
        # Defensive: the target must still be the dedicated synthetic test candidate.
        if not c or c.handle != _ACTAS_HANDLE or c.github_id != _ACTAS_MARKER:
            _log("actas_invalid_target", admin=session.get("soc_act_as_admin"), cand=actas)
            session.pop("soc_act_as", None)
            session.pop("soc_act_as_exp", None)
            session.pop("soc_act_as_admin", None)
            return None
        return c

    def _authorize():
        """Return (kind, candidate_or_None, subject, cohort) or abort. An
        authenticated admin may 'act as' the dedicated board2-test candidate (set via
        the admin-only /soc/admin/act-as route) so candidate-specific validation uses
        a real candidate identity, not the admin's. act-as never targets a real
        candidate and expires automatically."""
        if session.get("admin"):
            c = _actas_candidate()
            if c:
                return ("candidate", c, authz.user_name(_candidate_slug(c)), c.cohort or _DEFCO)
            return ("admin", None, "ranger_soc_admin", _DEFCO)
        c = _current_candidate()
        if not c:
            _log("deny", reason="no-session", path=request.path)
            abort(401)
        if c.status != "active":
            _log("deny", reason="status", status=c.status, cand=c.id)
            abort(403)
        if int(c.current_board or 0) != SIEM_BOARD:
            _log("deny", reason="board", board=c.current_board, cand=c.id)
            abort(403)
        return ("candidate", c, authz.user_name(_candidate_slug(c)), c.cohort or _DEFCO)

    def _provision(kind, cand, subject, cohort):
        """Idempotent: ensure the subject's role, roles-mapping, and (candidates)
        their seeded index exist. Separate from proxy requests."""
        cl = _admin_cluster()
        if kind == "admin":
            cl.put_role("ranger_soc_admin",
                        ["ranger-*", ".opendistro-alerting*", ".opensearch-sap*"],
                        allow_write=False,
                        cluster_perms=["cluster_monitor",
                                       "cluster:admin/opendistro/alerting/*",
                                       "cluster:admin/opensearch/securityanalytics/*"],
                        tenant_permissions=[{"tenant_patterns": ["__user__"],
                                             "allowed_actions": ["kibana_all_write"]}])
            cl.put_rolesmapping("ranger_soc_admin", users=[subject])
            return {"role": "ranger_soc_admin"}
        slug = _candidate_slug(cand)
        role = authz.role_name(slug)
        cl.put_role(role, [authz.candidate_index_pattern(cohort, slug)],
                    dls={"ranger.candidate_id": slug},
                    tenant_permissions=[{"tenant_patterns": ["__user__"],
                                         "allowed_actions": ["kibana_all_write"]}])
        cl.put_rolesmapping(role, users=[subject])
        idx = authz.index_name(cohort, slug, SIEM_BOARD)
        if not cl.index_exists(idx):
            from siem import enterprise, schema
            cl.create_index(idx, schema.INDEX_MAPPING)
            events, _truth = enterprise.generate(slug, SIEM_BOARD,
                                                 f"{cohort}-{slug}-b{SIEM_BOARD}", "B")
            for i in range(0, len(events), 1000):
                cl.bulk_index(idx, events[i:i + 1000])
            cl.refresh(idx)
        return {"role": role, "index": idx}

    @app.before_request
    def _actas_write_guard():
        """While an admin is impersonating the test candidate, the session may touch
        ONLY the candidate SOC experience (/soc/*) and the act-as controls. Every
        other portal route is refused, so the impersonated session can never modify
        candidate submissions, grading records, admission status, or qualification
        outcomes. SOC itself is candidate-scoped (per-candidate role + DLS + private
        tenant) and reaches none of those records."""
        if not session.get("soc_act_as"):
            return None
        # An expired impersonation imposes no further restriction; drop it so the
        # admin regains normal portal access.
        if time.time() >= session.get("soc_act_as_exp", 0):
            session.pop("soc_act_as", None)
            session.pop("soc_act_as_exp", None)
            session.pop("soc_act_as_admin", None)
            return None
        p = request.path
        if p == "/soc/admin/act-as-clear" or p == "/soc" or p.startswith("/soc/"):
            return None
        _log("actas_blocked_route", admin=session.get("soc_act_as_admin"),
             method=request.method, path=p)
        abort(403)

    @app.get("/soc/launch")
    def soc_launch():
        kind, cand, subject, cohort = _authorize()
        info = _provision(kind, cand, subject, cohort)
        _log("launch", kind=kind, subject=subject,
             actas_admin=session.get("soc_act_as_admin") if session.get("soc_act_as") else None,
             **{k: v for k, v in info.items() if k != "index"})
        return redirect(BASE + "/app/home")

    @app.route("/soc", methods=["GET"])
    def soc_root():
        _authorize()
        return redirect(BASE + "/app/home")

    @app.get("/soc/admin/act-as")
    def soc_act_as():
        # Admin-only (real GitHub Super Admin auth required): drive a candidate-scoped
        # SOC session as the dedicated, non-real Board 2 test candidate. Not a bypass;
        # short-lived, audited, write-guarded, and off unless explicitly enabled.
        if not session.get("admin"):
            abort(403)
        # (7) Disabled unless explicitly enabled for this validation.
        if not _ACTAS_ENABLED:
            _log("actas_disabled", admin=session.get("admin_login"))
            abort(404)
        # (2) Explicit per-use authorization, on top of the authenticated admin session.
        if request.args.get("authorize") != "yes":
            _log("actas_unauthorized", admin=session.get("admin_login"))
            abort(400)
        # (1)(5) Target is hardcoded to the dedicated synthetic test candidate; any
        # client-supplied handle is ignored, and a real account is never touched.
        handle = _ACTAS_HANDLE
        c = candidate_model.query.filter_by(handle=handle).first()
        if c and c.github_id != _ACTAS_MARKER:
            _log("actas_refused_real_account", admin=session.get("admin_login"), cand=c.id)
            abort(409)
        if not c:
            c = candidate_model(handle=handle, github_id=_ACTAS_MARKER,
                                status="active", current_board=SIEM_BOARD, cohort=_DEFCO)
            db.session.add(c)
            db.session.commit()
        else:
            c.status, c.current_board = "active", SIEM_BOARD
            db.session.commit()
        # (3) Short-lived. (6) Admin identity recorded for the whole impersonation.
        session["soc_act_as"] = c.id
        session["soc_act_as_exp"] = time.time() + _ACTAS_TTL
        session["soc_act_as_admin"] = session.get("admin_login") or str(session.get("admin"))
        _log("admin_act_as", admin=session["soc_act_as_admin"], cand=c.id,
             handle=handle, ttl=_ACTAS_TTL)
        return redirect(BASE + "/launch")

    @app.get("/soc/admin/act-as-clear")
    def soc_act_as_clear():
        if not session.get("admin"):
            abort(403)
        _log("admin_act_as_clear", admin=session.get("soc_act_as_admin"))
        session.pop("soc_act_as", None)
        session.pop("soc_act_as_exp", None)
        session.pop("soc_act_as_admin", None)
        return redirect("/admin")

    @app.route("/soc/<path:subpath>",
               methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    def soc_proxy(subpath):
        kind, cand, subject, cohort = _authorize()
        if not _rate_ok(subject):
            _log("rate_limited", subject=subject)
            abort(429)
        # Gateway-level CSRF defense for state-changing proxied actions. Dashboards
        # issues every API mutation with an osd-xsrf (legacy kbn-xsrf) header, which a
        # cross-site forgery cannot set without a CORS preflight the browser blocks;
        # combined with the SameSite=Lax session cookie (a cross-site POST carries no
        # session, so _authorize already fails), this enforces CSRF at the gateway, not
        # only upstream. The portal form-CSRF token does not apply here because the
        # Dashboards client cannot carry it.
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if not (request.headers.get("osd-xsrf") or request.headers.get("kbn-xsrf")):
                _log("csrf_missing", subject=subject, method=request.method, path=subpath)
                abort(403)
        token = ranger_jwt.mint(subject, _jwt_priv(), board=SIEM_BOARD, cohort=cohort, ttl=600)

        # Build upstream request: only ever the private Dashboards, under /soc.
        upstream = DASH + BASE + "/" + subpath
        if request.query_string:
            upstream += "?" + request.query_string.decode("latin-1")
        headers = {}
        for k, v in request.headers.items():
            lk = k.lower()
            if lk in _HOP or lk in _STRIP_CLIENT:
                continue
            headers[k] = v
        headers["Authorization"] = "Bearer " + token
        headers["securitytenant"] = "__user__"  # force the candidate's private tenant
        headers["Accept-Encoding"] = "identity"

        data = request.get_data() if request.method in ("POST", "PUT", "PATCH", "DELETE") else None
        up = urllib.request.Request(upstream, data=data, method=request.method, headers=headers)
        try:
            resp = _OPENER.open(up, timeout=PROXY_TIMEOUT)
        except urllib.error.HTTPError as e:
            resp = e
        except Exception as e:  # noqa: BLE001
            _log("upstream_error", subject=subject, err=str(e)[:120])
            abort(502)

        body = resp.read(MAX_RESP + 1)
        if len(body) > MAX_RESP:
            _log("response_too_large", subject=subject, path=subpath)
            abort(502)
        out_headers = []
        for k, v in resp.headers.items():
            lk = k.lower()
            if lk in _HOP or lk in ("content-encoding",):
                continue
            out_headers.append((k, v))
        out = Response(body, status=resp.status, headers=out_headers)
        out.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        out.headers["Pragma"] = "no-cache"
        out.headers["X-Content-Type-Options"] = "nosniff"
        out.headers["Referrer-Policy"] = "no-referrer"
        return out

    # Test-only session bootstrap. Disabled unless RANGER_SOC_TEST_KEY is set (never
    # in production). Lets an isolated test environment establish an authorized test
    # candidate session WITHOUT a production auth bypass: it still goes through the
    # same /soc authorization on every request.
    test_key = os.environ.get("RANGER_SOC_TEST_KEY")
    if test_key:
        @app.get("/soc-test/login")
        def soc_test_login():
            if request.args.get("key") != test_key:
                abort(404)
            handle = request.args.get("cand", "soc-test-a")
            c = candidate_model.query.filter_by(handle=handle).first()
            if not c:
                c = candidate_model(handle=handle, github_id="test-" + handle,
                                    status="active", current_board=SIEM_BOARD,
                                    cohort=os.environ.get("DEFAULT_COHORT", "2026-A"))
                db.session.add(c)
                db.session.commit()
            else:
                c.status = "active"
                c.current_board = SIEM_BOARD
                db.session.commit()
            session["cand"] = c.id
            _log("test_login", cand=c.id, handle=handle)
            return redirect("/soc/launch")

    _log("gateway_registered", dashboards=DASH, base=BASE, test_mode=bool(test_key),
         actas_enabled=_ACTAS_ENABLED, actas_ttl=_ACTAS_TTL)
