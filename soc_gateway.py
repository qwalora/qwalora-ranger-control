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

    def _authorize():
        """Return (kind, candidate_or_None, subject, cohort) or abort. An
        authenticated admin may 'act as' a dedicated test candidate (set via the
        admin-only /soc/admin/act-as route) so candidate-specific validation uses a
        real candidate identity, not the admin's."""
        if session.get("admin"):
            actas = session.get("soc_act_as")
            if actas:
                c = candidate_model.query.get(actas)
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

    @app.get("/soc/launch")
    def soc_launch():
        kind, cand, subject, cohort = _authorize()
        info = _provision(kind, cand, subject, cohort)
        _log("launch", kind=kind, subject=subject, **{k: v for k, v in info.items() if k != "index"})
        return redirect(BASE + "/app/home")

    @app.route("/soc", methods=["GET"])
    def soc_root():
        _authorize()
        return redirect(BASE + "/app/home")

    @app.get("/soc/admin/act-as")
    def soc_act_as():
        # Admin-only (real GitHub admin auth required): drive a candidate-scoped SOC
        # session as a dedicated Board 2 test candidate. Not a bypass; audited.
        if not session.get("admin"):
            abort(403)
        handle = request.args.get("handle", "board2-test")
        c = candidate_model.query.filter_by(handle=handle).first()
        if not c:
            c = candidate_model(handle=handle, github_id="soctest-" + handle,
                                status="active", current_board=SIEM_BOARD, cohort=_DEFCO)
            db.session.add(c)
            db.session.commit()
        else:
            c.status, c.current_board = "active", SIEM_BOARD
            db.session.commit()
        session["soc_act_as"] = c.id
        _log("admin_act_as", admin=session.get("admin_login"), cand=c.id, handle=handle)
        return redirect(BASE + "/launch")

    @app.get("/soc/admin/act-as-clear")
    def soc_act_as_clear():
        if not session.get("admin"):
            abort(403)
        session.pop("soc_act_as", None)
        _log("admin_act_as_clear", admin=session.get("admin_login"))
        return redirect(BASE + "/launch")

    @app.route("/soc/<path:subpath>",
               methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    def soc_proxy(subpath):
        kind, cand, subject, cohort = _authorize()
        if not _rate_ok(subject):
            _log("rate_limited", subject=subject)
            abort(429)
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

    _log("gateway_registered", dashboards=DASH, base=BASE, test_mode=bool(test_key))
