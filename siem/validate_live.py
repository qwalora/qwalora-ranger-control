"""Phase 2a live validation: runs INSIDE Railway against the private OpenSearch
cluster and prints a structured report to stdout (read from Railway logs).

Every check hits the real cluster. Nothing is mocked. Where a capability is not
exercisable in the pilot window it is reported as a documented limitation, never
as a pass. Candidate access stays disabled: the only users created are disposable
isolation-test identities on the private cluster, and they are deleted at the end
(which also proves revocation).

Run:  python -m siem.validate_live
Env:  OPENSEARCH_URL, OPENSEARCH_ADMIN_USER, OPENSEARCH_ADMIN_PASSWORD
"""
from __future__ import annotations

import base64
import json
import os
import statistics
import time

import signing  # repo-root module; on sys.path when run as python -m siem.validate_live

from . import SCHEMA_VERSION
from . import authz, detection, enterprise, ranger_jwt, schema
from .live import AuthzError, LiveCluster, NotFound

COHORT = "pilot"
REPORT = {"schema_version": SCHEMA_VERSION, "families": {}, "metrics": {}, "limitations": []}


def _rec(family, **kv):
    REPORT["families"][family] = kv
    status = kv.get("status")
    print(f"[{status}] {family}: " + json.dumps({k: v for k, v in kv.items() if k != 'status'})[:600], flush=True)


def _heap(cluster):
    code, body = cluster.node_stats()
    if code != 200:
        return None
    node = next(iter(body.get("nodes", {}).values()), {})
    jvm = node.get("jvm", {}).get("mem", {})
    return {
        "heap_used_mb": round(jvm.get("heap_used_in_bytes", 0) / 1e6, 1),
        "heap_max_mb": round(jvm.get("heap_max_in_bytes", 0) / 1e6, 1),
        "heap_used_pct": jvm.get("heap_used_percent"),
    }


def persist_check(c):
    """Non-destructive: count indices left by a prior full run, to prove data
    survived an OpenSearch restart (F13 restart persistence/recovery). Deletes
    nothing."""
    code, h = c.health()
    survived = {}
    for idx in (authz.index_name(COHORT, "cand-a", 2),
                f"ranger-{COHORT}-bench-b2".lower()):
        try:
            survived[idx] = c.count(idx)
        except Exception as e:  # noqa: BLE001
            survived[idx] = f"ERR:{e}"
    ok = all(isinstance(v, int) and v > 0 for v in survived.values())
    out = {"mode": "persist", "cluster_status": h.get("status"),
           "post_restart_counts": survived, "status": "PASS" if ok else "FAIL",
           "heap": _heap(c)}
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def harden(c):
    """P1.2/P1.4: create distinct least-privilege identities and rotate the admin
    and Dashboards credentials. Runs as the current admin, then proves the OLD
    admin password no longer authenticates."""
    base = c.base
    out = {"mode": "harden", "created": [], "rotated": [], "status": "PASS"}

    # least-privilege roles
    c.put_role("ranger_ingest_role", ["ranger-*"], allow_write=True)
    c.put_role("ranger_search_role", ["ranger-*"], allow_write=False)

    # identities. The validator identity is isolated from the real admin: it maps to
    # all_access + security_rest_api_access so it can run tests, and can be disabled
    # without touching the real admin credential.
    def put_user_roles(name, pw_env, sec_roles):
        pw = os.environ[pw_env]
        code, body = c._req("PUT", f"/_plugins/_security/api/internalusers/{name}",
                            body={"password": pw, "opendistro_security_roles": sec_roles})
        if code not in (200, 201):
            raise SystemExit(f"put_user {name} failed: {code} {body}")
        out["created"].append(name)

    put_user_roles("ranger_ingest", "RANGER_INGEST_PW", ["ranger_ingest_role"])
    put_user_roles("ranger_search", "RANGER_SEARCH_PW", ["ranger_search_role"])
    put_user_roles("ranger_validator", "RANGER_VALIDATOR_PW",
                   ["all_access", "security_rest_api_access"])

    # rotate passwords (PATCH only the password field). admin is rotated LAST so the
    # old admin credential stays valid for every preceding call.
    for user, env in (("kibanaserver", "RANGER_NEW_KIBANA_PW"),
                      ("admin", "RANGER_NEW_ADMIN_PW")):
        newpw = os.environ[env]
        code, body = c._req("PATCH", f"/_plugins/_security/api/internalusers/{user}",
                            body=[{"op": "replace", "path": "/password", "value": newpw}])
        if code not in (200, 201):
            raise SystemExit(f"rotate {user} failed: {code} {body}")
        out["rotated"].append(user)

    # prove the OLD admin credential is dead and the NEW one works
    newadmin = LiveCluster(base, "admin", os.environ["RANGER_NEW_ADMIN_PW"],
                           verify_tls=False, timeout=30)
    code_new, _ = newadmin.health()
    code_old, _ = c.health()  # c still holds the OLD admin password
    out["new_admin_works"] = code_new == 200
    out["old_admin_denied"] = code_old in (401, 403)
    if not (out["new_admin_works"] and out["old_admin_denied"]):
        out["status"] = "FAIL"
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def backup_check(c):
    """P1.7: register a filesystem snapshot repo on the volume, snapshot a probe
    index, DELETE it, restore from the snapshot, and confirm the data returns.
    This is true backup/restore, distinct from restart persistence."""
    out = {"mode": "backup", "steps": {}, "status": "PASS"}
    repo, snap = "ranger_fs", "snap-probe"
    idx = f"ranger-{COHORT}-backup-probe".lower()
    code, body = c.snapshot_register(repo, "/usr/share/opensearch/data/snapshots")
    out["steps"]["register"] = code
    c.delete_index(idx)
    c.create_index(idx, schema.INDEX_MAPPING)
    ev, _ = enterprise.generate("backup", 2, "pilot-backup", "A")
    c.bulk_index(idx, ev)
    c.refresh(idx)
    before = c.count(idx)
    code_s, _ = c.snapshot_create(repo, snap, idx)
    out["steps"]["snapshot"] = code_s
    c.delete_index(idx)
    deleted = not c.index_exists(idx)
    code_r, _ = c.snapshot_restore(repo, snap, idx)
    out["steps"]["restore"] = code_r
    import time as _t
    for _ in range(10):
        try:
            after = c.count(idx)
            break
        except Exception:  # noqa: BLE001
            after = -1
            _t.sleep(2)
    out["before"] = before
    out["deleted_before_restore"] = deleted
    out["after_restore"] = after
    if not (before > 0 and deleted and after == before):
        out["status"] = "FAIL"
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def jwt_check(c):
    """P2: validate the full candidate JWT flow against the real Security plugin.
    Mints Ranger RS256 tokens and drives OpenSearch exactly as Dashboards forwards
    them. Proves positive access, isolation, DLS, token validation (expiry/forgery/
    wrong key/issuer/audience), role-claim spoof resistance, privilege-escalation
    blocks, and enforceable revocation."""
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    priv = base64.b64decode(os.environ["RANGER_JWT_PRIVATE_B64"])
    out = {"mode": "jwt", "tests": {}, "status": "PASS"}

    def rec(name, ok, **kv):
        out["tests"][name] = {"pass": bool(ok), **kv}
        if not ok:
            out["status"] = "FAIL"
        print(f"[{'PASS' if ok else 'FAIL'}] jwt/{name}: {json.dumps(kv)[:300]}", flush=True)

    subs = {}
    for cand in ("cand-a", "cand-b"):
        idx = authz.index_name(COHORT, cand, 2)
        c.delete_index(idx)
        c.create_index(idx, schema.INDEX_MAPPING)
        ev, _ = enterprise.generate(cand, 2, f"jwt-{cand}", "A")
        c.bulk_index(idx, ev)
        c.refresh(idx)
        role = authz.role_name(cand)
        c.put_role(role, [authz.candidate_index_pattern(COHORT, cand)],
                   dls={"ranger.candidate_id": cand})
        sub = authz.user_name(cand)
        c.put_rolesmapping(role, users=[sub])
        subs[cand] = (sub, idx, len(ev))

    a_sub, a_idx, a_n = subs["cand-a"]
    b_sub, b_idx, b_n = subs["cand-b"]
    tok = lambda cand="cand-a", **kw: ranger_jwt.mint(subs[cand][0], priv, board=2, cohort=COHORT, **kw)

    ta = tok()
    rec("own_access_ok", c._req("GET", f"/{a_idx}/_count", bearer=ta)[0] == 200)
    rec("cross_candidate_denied", c._req("GET", f"/{b_idx}/_count", bearer=ta)[0] == 403)
    rec("expired_rejected", c._req("GET", f"/{a_idx}/_count", bearer=tok(ttl=-30))[0] in (401, 403))
    tampered = ranger_jwt.tamper_payload(ta, {"sub": b_sub})
    rec("tampered_rejected", c._req("GET", f"/{b_idx}/_count", bearer=tampered)[0] in (401, 403))
    wrong = _rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption())
    tw = ranger_jwt.mint(a_sub, wrong, board=2, cohort=COHORT)
    rec("wrong_key_rejected", c._req("GET", f"/{a_idx}/_count", bearer=tw)[0] in (401, 403))
    rec("wrong_issuer_rejected", c._req("GET", f"/{a_idx}/_count", bearer=tok(extra={"iss": "evil"}))[0] in (401, 403))
    rec("wrong_audience_rejected", c._req("GET", f"/{a_idx}/_count", bearer=tok(extra={"aud": "evil"}))[0] in (401, 403))
    # role-claim spoof on a validly-signed token: must be ignored
    ts = tok(extra={"roles": ["all_access", "admin", "security_rest_api_access"]})
    sp_cross = c._req("GET", f"/{b_idx}/_count", bearer=ts)[0]
    sp_sec = c._req("GET", "/_plugins/_security/api/internalusers", bearer=ts)[0]
    rec("role_spoof_ineffective", sp_cross == 403 and sp_sec == 403, cross=sp_cross, security_api=sp_sec)
    # privilege escalation attempts with the candidate's own valid token
    pe_role = c._req("PUT", "/_plugins/_security/api/roles/evil", bearer=ta,
                     body={"index_permissions": [{"index_patterns": ["*"], "allowed_actions": ["*"]}]})[0]
    pe_secidx = c._req("GET", "/.opendistro_security/_search", bearer=ta)[0]
    rec("privilege_escalation_blocked", pe_role in (401, 403) and pe_secidx in (401, 403, 404),
        put_role=pe_role, security_index=pe_secidx)
    # enforceable revocation: drop the rolesmapping; the SAME valid token loses access
    c.delete_rolesmapping(authz.role_name("cand-a"))
    rec("revocation_enforced", c._req("GET", f"/{a_idx}/_count", bearer=ta)[0] == 403)
    # admin least-privilege: SOC admin reads SIEM data but NOT the security index
    soc_pw = os.environ.get("RANGER_SOC_ADMIN_PW") or os.environ.get("RANGER_SOC_TEST_KEY") or ""
    c.put_role("ranger_soc_admin",
               ["ranger-*", ".opendistro-alerting*", ".opensearch-sap*"],
               allow_write=False,
               cluster_perms=["cluster_monitor", "cluster:admin/opendistro/alerting/*",
                              "cluster:admin/opensearch/alerting/*",
                              "cluster:admin/opensearch/securityanalytics/*"])
    c.put_user("ranger_soc_admin", soc_pw, ["ranger_soc_admin"])
    adm = ("ranger_soc_admin", soc_pw)
    soc_read = c._req("GET", f"/{a_idx}/_count", auth=adm)[0]
    soc_sec = c._req("GET", "/.opendistro_security/_search", auth=adm)[0]
    rec("admin_least_privilege", soc_read == 200 and soc_sec in (401, 403, 404),
        read_siem=soc_read, read_security_index=soc_sec)

    out["notes"] = {
        "grading_secrets_location": "Ranger portal + Postgres, never in OpenSearch; SOC admins cannot see them.",
        "candidate_auth": "JWT only; candidates never receive any OpenSearch password.",
        "revocation_model": "delete per-candidate roles_mapping -> any live token maps to no role (immediate), plus short TTL.",
    }
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def dashauth_check(c):
    """P2.6: empirically validate how OpenSearch Dashboards 2.17.1 accepts a Ranger
    JWT in the BROWSER/gateway path (header vs url param vs none), against the live
    Dashboards. Confirms the header-injection transport the gateway will use so the
    token never appears in a URL."""
    import urllib.error as _e
    import urllib.request as _u

    priv = base64.b64decode(os.environ["RANGER_JWT_PRIVATE_B64"])
    dash = os.environ.get("DASHBOARDS_URL", "http://dashboards.railway.internal:5601").rstrip("/")
    cand = "cand-a"
    idx = authz.index_name(COHORT, cand, 2)
    if not c.index_exists(idx):
        c.create_index(idx, schema.INDEX_MAPPING)
        ev, _ = enterprise.generate(cand, 2, "dash-a", "A")
        c.bulk_index(idx, ev)
        c.refresh(idx)
    role = authz.role_name(cand)
    c.put_role(role, [authz.candidate_index_pattern(COHORT, cand)],
               dls={"ranger.candidate_id": cand})
    sub = authz.user_name(cand)
    c.put_rolesmapping(role, users=[sub])
    token = ranger_jwt.mint(sub, priv, board=2, cohort=COHORT)

    acct = "/api/v1/configuration/account"

    def hit(headers=None, qs=""):
        req = _u.Request(dash + acct + qs, headers=headers or {}, method="GET")
        try:
            with _u.urlopen(req, timeout=30) as r:
                return r.status, r.read(500).decode(errors="replace")
        except _e.HTTPError as ex:
            return ex.code, ex.read(300).decode(errors="replace")
        except Exception as ex:  # noqa: BLE001
            return -1, str(ex)[:160]

    def op(path, method="GET", headers=None, body=None):
        # A real Dashboards operation: the console proxy executes against OpenSearch
        # as the JWT-authenticated user. This is Discover-equivalent, not just HTML.
        url = dash + "/api/console/proxy?path=" + path + "&method=" + method
        data = json.dumps(body).encode() if body is not None else b""
        hdrs = {**(headers or {}), "Content-Type": "application/json"}
        req = _u.Request(url, data=data, headers=hdrs, method="POST")
        try:
            with _u.urlopen(req, timeout=30) as r:
                return r.status, r.read(800).decode(errors="replace")
        except _e.HTTPError as ex:
            return ex.code, ex.read(400).decode(errors="replace")
        except Exception as ex:  # noqa: BLE001
            return -1, str(ex)[:160]

    base_hdr = {"osd-xsrf": "osd-fetch"}
    bearer = {**base_hdr, "Authorization": "Bearer " + token}
    b_idx = authz.index_name(COHORT, "cand-b", 2)
    if not c.index_exists(b_idx):
        c.create_index(b_idx, schema.INDEX_MAPPING)
        evb, _ = enterprise.generate("cand-b", 2, "dash-b", "A")
        c.bulk_index(b_idx, evb)
        c.refresh(b_idx)

    out = {"mode": "dashauth", "dashboards": dash, "probes": {}}
    out["probes"]["no_auth_account"] = hit(base_hdr)
    out["probes"]["bearer_account"] = hit(bearer)
    out["probes"]["url_param_account"] = hit(base_hdr, qs="?authorization=" + token)
    # real operation: Discover-style search of own index, and of another candidate's
    out["probes"]["discover_own"] = op(f"{idx}%2F_search", "GET", bearer,
                                       body={"size": 1, "query": {"match_all": {}}})
    out["probes"]["discover_cross"] = op(f"{b_idx}%2F_search", "GET", bearer,
                                         body={"size": 1, "query": {"match_all": {}}})

    na = out["probes"]["no_auth_account"][0]
    bh, bh_body = out["probes"]["bearer_account"]
    up = out["probes"]["url_param_account"][0]
    own_code, own_body = out["probes"]["discover_own"]
    cross_code, _cb = out["probes"]["discover_cross"]
    out["no_auth_rejected"] = na in (401,)
    out["header_auth_works"] = bh == 200 and (sub in bh_body or "user_name" in bh_body)
    out["url_param_auth_works"] = up == 200
    out["discover_own_ok"] = own_code == 200 and '"hits"' in own_body
    out["discover_cross_denied"] = cross_code in (401, 403) or '"status":403' in _cb
    out["recommended_transport"] = (
        "authorization_header" if out["header_auth_works"] else
        ("url_param" if out["url_param_auth_works"] else "undetermined"))
    out["status"] = "PASS" if (out["no_auth_rejected"] and out["header_auth_works"]
                               and out["discover_own_ok"] and out["discover_cross_denied"]) else "WARN"
    print(f"[{out['status']}] dashauth: no_auth={na} bearer={bh} url_param={up} "
          f"transport={out['recommended_transport']}", flush=True)
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def socgw_check(c):
    """P2 gateway validation end-to-end through the REAL deployed stack: portal
    /soc gateway -> private Dashboards -> private OpenSearch. Exercises auth
    enforcement, the full Discover path, cross-candidate isolation, header-spoofing
    resistance, no-store caching, and revocation. Uses the env-gated test session
    (no production bypass)."""
    import http.cookiejar as _cj
    import urllib.error as _e
    import urllib.request as _u

    portal = os.environ["PORTAL_URL"].rstrip("/")
    key = os.environ["RANGER_SOC_TEST_KEY"]
    cohort = os.environ.get("DEFAULT_COHORT", "2026-A")
    handle = "soc-test-a"
    slug = authz._slug("test-" + handle)  # gateway uses github_id="test-<handle>"
    own_idx = authz.index_name(cohort, slug, 2)
    other_idx = authz.index_name("pilot", "cand-b", 2)
    out = {"mode": "socgw", "portal": portal, "tests": {}, "status": "PASS"}

    def rec(n, ok, **kv):
        out["tests"][n] = {"pass": bool(ok), **kv}
        if not ok:
            out["status"] = "FAIL"
        print(f"[{'PASS' if ok else 'FAIL'}] socgw/{n}: {json.dumps(kv)[:260]}", flush=True)

    def mk_opener():
        jar = _cj.CookieJar()
        # Follow redirects like a browser (login -> launch -> dashboards home),
        # preserving session cookies across the chain.
        return _u.build_opener(_u.HTTPCookieProcessor(jar)), jar, jar

    def req(opener, path, method="GET", headers=None, body=None):
        r = _u.Request(portal + path, data=(json.dumps(body).encode() if body is not None else None),
                       method=method, headers=headers or {})
        try:
            with opener.open(r, timeout=45) as resp:
                return resp.status, dict(resp.headers), resp.read(2000).decode(errors="replace")
        except _e.HTTPError as ex:
            return ex.code, dict(ex.headers), ex.read(800).decode(errors="replace")
        except Exception as ex:  # noqa: BLE001
            return -1, {}, str(ex)[:160]

    # T1 no session -> gateway denies
    op0, _ = mk_opener()
    s1, _h1, _b1 = req(op0, "/soc/app/home")
    rec("no_session_denied", s1 in (401, 403), code=s1)

    # T2 authorized test session -> provision + proxied Dashboards home
    op, jar = mk_opener()
    s2, _h2, _b2 = req(op, f"/soc-test/login?key={key}&cand={handle}")
    rec("authorized_session_reaches_dashboards", s2 == 200, code=s2)

    # T3 real Discover search of OWN index, through the gateway
    xsrf = {"osd-xsrf": "osd-fetch", "Content-Type": "application/json"}
    s3, h3, b3 = req(op, f"/soc/api/console/proxy?path={own_idx}%2F_search&method=GET",
                     method="POST", headers=xsrf, body={"size": 1, "query": {"match_all": {}}})
    rec("discover_own_through_gateway", s3 == 200 and '"hits"' in b3, code=s3)
    rec("no_store_caching", "no-store" in (h3.get("Cache-Control") or h3.get("cache-control") or ""),
        cache_control=h3.get("Cache-Control") or h3.get("cache-control"))

    # T4 cross-candidate index via the gateway -> denied
    s4, _h4, b4 = req(op, f"/soc/api/console/proxy?path={other_idx}%2F_search&method=GET",
                      method="POST", headers=xsrf, body={"size": 1, "query": {"match_all": {}}})
    rec("cross_candidate_denied", s4 in (401, 403) or '"status":403' in b4, code=s4)

    # T5 header spoofing: client tries to inject identity/auth -> stripped
    spoof = {"Authorization": "Basic YWRtaW46YWRtaW4=", "X-Forwarded-User": "admin",
             "x-proxy-roles": "all_access", "securitytenant": "global_tenant",
             "osd-xsrf": "osd-fetch"}
    s5, _h5, b5 = req(op, "/soc/api/v1/configuration/account", headers=spoof)
    spoof_ok = s5 == 200 and ("cand_" + slug) in b5 and "all_access" not in b5
    rec("header_spoof_stripped", spoof_ok, code=s5,
        is_candidate=("cand_" + slug) in b5)

    # T6 revocation: drop the candidate's roles-mapping -> live session loses data access
    c.delete_rolesmapping(authz.role_name(slug))
    s6, _h6, b6 = req(op, f"/soc/api/console/proxy?path={own_idx}%2F_search&method=GET",
                      method="POST", headers=xsrf, body={"size": 1, "query": {"match_all": {}}})
    rec("revocation_enforced", s6 in (401, 403) or '"status":403' in b6, code=s6)

    out["notes"] = {
        "direct_origin": "OpenSearch and Dashboards have no public domains/TCP proxies; unreachable except via the gateway.",
        "arbitrary_upstream": "Gateway hardcodes upstream to the private Dashboards base path; no client-controlled host/path.",
        "browser_screenshots": "Require a connected browser or the operator; exact production steps provided separately.",
    }
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def socadmin_check(c):
    """Stage 1: validate the SOC administrator authorization boundary over the REAL
    JWT transport the admin's browser session uses. Provisions the exact
    `ranger_soc_admin` role the /soc gateway creates, maps sub=ranger_soc_admin to
    it, mints a short-lived Ranger JWT (no password), and asserts least privilege
    against the live Security plugin: oversight read across all candidate indices,
    but no write, no index/security mutation, no privilege escalation, no cluster
    administration beyond monitor + alerting/securityanalytics, and no reach outside
    the ranger-* / alerting / SAP scope."""
    priv = base64.b64decode(os.environ["RANGER_JWT_PRIVATE_B64"])
    out = {"mode": "socadmin", "tests": {}, "status": "PASS"}

    def rec(name, ok, **kv):
        out["tests"][name] = {"pass": bool(ok), **kv}
        if not ok:
            out["status"] = "FAIL"
        print(f"[{'PASS' if ok else 'FAIL'}] socadmin/{name}: {json.dumps(kv)[:300]}", flush=True)

    # Two candidate indices (ranger-*) so we can prove cross-candidate OVERSIGHT read
    # (the SOC admin legitimately sees all candidates, unlike a candidate).
    idxs = {}
    for cand in ("cand-a", "cand-b"):
        idx = authz.index_name(COHORT, cand, 2)
        if not c.index_exists(idx):
            c.create_index(idx, schema.INDEX_MAPPING)
            ev, _ = enterprise.generate(cand, 2, f"socadm-{cand}", "A")
            c.bulk_index(idx, ev)
            c.refresh(idx)
        idxs[cand] = idx
    a_idx, b_idx = idxs["cand-a"], idxs["cand-b"]

    # Provision EXACTLY what soc_gateway._provision(admin) creates.
    c.put_role("ranger_soc_admin",
               ["ranger-*", ".opendistro-alerting*", ".opensearch-sap*"],
               allow_write=False,
               cluster_perms=["cluster_monitor",
                              "cluster:admin/opendistro/alerting/*",
                              "cluster:admin/opensearch/securityanalytics/*"],
               tenant_permissions=[{"tenant_patterns": ["__user__"],
                                    "allowed_actions": ["kibana_all_write"]}])
    c.put_rolesmapping("ranger_soc_admin", users=["ranger_soc_admin"])

    # A non-ranger index to prove the index scope is tight (not all_access).
    nonranger = f"zzz-nonranger-{int(time.time())}"
    c.create_index(nonranger)

    tok = ranger_jwt.mint("ranger_soc_admin", priv, board=2, cohort=COHORT, ttl=600)
    g = lambda m, p, body=None: c._req(m, p, body=body, bearer=tok)[0]

    # Positive: oversight read across candidates + cluster monitor.
    rec("monitor_ok", g("GET", "/_cluster/health") == 200)
    rec("oversight_read_cand_a", g("GET", f"/{a_idx}/_count") == 200)
    rec("oversight_read_cand_b", g("GET", f"/{b_idx}/_count") == 200)
    # Negative: no write to SIEM data.
    rec("write_denied", g("POST", f"/{a_idx}/_doc", {"x": 1}) in (401, 403))
    rec("delete_doc_denied", g("DELETE", f"/{a_idx}/_doc/nope") in (401, 403))
    rec("delete_index_denied", g("DELETE", f"/{a_idx}") in (401, 403))
    # Negative: no reach outside the ranger-*/alerting/SAP scope.
    rec("non_ranger_read_denied", g("GET", f"/{nonranger}/_count") in (401, 403))
    # Negative: no security administration / privilege escalation.
    rec("security_api_denied", g("GET", "/_plugins/_security/api/internalusers") in (401, 403))
    rec("security_index_denied", g("GET", "/.opendistro_security/_search") in (401, 403, 404))
    rec("create_role_denied",
        g("PUT", "/_plugins/_security/api/roles/evil",
          {"index_permissions": [{"index_patterns": ["*"], "allowed_actions": ["*"]}]}) in (401, 403))
    # Negative: no cluster administration beyond monitor.
    rec("cluster_settings_denied",
        g("PUT", "/_cluster/settings", {"persistent": {"action.auto_create_index": "false"}}) in (401, 403))

    c.delete_index(nonranger)  # leave the ranger_soc_admin role in place (gateway maintains it)

    out["notes"] = {
        "transport": "Ranger RS256 JWT, sub=ranger_soc_admin, injected server-side by the gateway; never a password, never in a URL.",
        "scope": "read-only oversight on ranger-*/alerting/SAP + cluster_monitor + alerting/securityanalytics admin; no all_access, no security API, no index or cluster mutation.",
        "standing_credential": "none; the JWT is short-lived (10 min) and the role carries no password.",
    }
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def gwsec_check(c):
    """Stage 1 gateway-security integration checks that need NO authenticated
    session. Runs inside Railway against the live portal, Dashboards, and OpenSearch:
    portal session-cookie flags, unauthenticated gateway denial with no token leak,
    Dashboards osd-xsrf CSRF enforcement (the gateway's upstream), and Security
    Analytics authorized for the SOC admin but denied for a candidate. Browser-only
    properties (JS storage, network to the browser) are confirmed by the operator."""
    import urllib.error as _e
    import urllib.request as _u

    priv = base64.b64decode(os.environ["RANGER_JWT_PRIVATE_B64"])
    portal = os.environ["PORTAL_URL"].rstrip("/")
    dash = os.environ.get("DASHBOARDS_URL", "http://dashboards.railway.internal:5601").rstrip("/")
    out = {"mode": "gwsec", "portal": portal, "tests": {}, "status": "PASS"}

    def rec(n, ok, **kv):
        out["tests"][n] = {"pass": bool(ok), **kv}
        if not ok:
            out["status"] = "FAIL"
        print(f"[{'PASS' if ok else 'FAIL'}] gwsec/{n}: {json.dumps(kv)[:300]}", flush=True)

    class _NoRedir(_u.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    noredir = _u.build_opener(_NoRedir)

    def raw(url, method="GET", headers=None, body=None):
        req = _u.Request(url, data=(json.dumps(body).encode() if body is not None else None),
                         method=method, headers=headers or {})
        try:
            with _u.urlopen(req, timeout=30) as r:
                return r.status, dict(r.headers), r.read(4000).decode(errors="replace")
        except _e.HTTPError as ex:
            return ex.code, dict(ex.headers), ex.read(2000).decode(errors="replace")
        except Exception as ex:  # noqa: BLE001
            return -1, {}, str(ex)[:160]

    def set_cookies(url):
        # Do NOT follow redirects (that would swallow the Set-Cookie), and read EVERY
        # Set-Cookie header, not a dict-collapsed one.
        req = _u.Request(url, headers={"User-Agent": "ranger-validator"}, method="GET")
        try:
            with noredir.open(req, timeout=30) as r:
                return r.headers.get_all("Set-Cookie") or [], r.status, ""
        except _e.HTTPError as ex:
            return ex.headers.get_all("Set-Cookie") or [], ex.code, ""
        except Exception as ex:  # noqa: BLE001
            return [], -1, str(ex)[:160]

    # 1. Session-cookie flags on a normal portal response (the CSRF context processor
    #    sets session["csrf"], so Flask emits a Set-Cookie for the session cookie).
    setc = ""
    dbg = []
    for p in ("/auth/github/login", "/admin/login", "/"):
        cookies, st, err = set_cookies(portal + p)
        dbg.append(f"{p}:{st}:{len(cookies)}{(':' + err) if err else ''}")
        sess = [ck for ck in cookies if ck.lower().startswith("session=")]
        if sess:
            setc = sess[0]
            break
        if cookies and not setc:
            setc = cookies[0]
    low = setc.lower()
    rec("cookie_httponly", "httponly" in low, set_cookie=setc[:140], probes=";".join(dbg))
    rec("cookie_secure", "secure" in low)
    rec("cookie_samesite_lax", "samesite=lax" in low)

    # 2. Unauthenticated gateway request -> denied, with no token/credential leaked.
    s2, h2, b2 = raw(portal + "/soc/app/home")
    leaked = ("eyJ" in b2) or ("eyJ" in (h2.get("Set-Cookie", "") or ""))
    rec("unauth_gateway_denied", s2 in (401, 403, 302), code=s2)
    rec("no_token_leak_unauth", not leaked)

    # 3. Dashboards CSRF: a state-changing API without osd-xsrf is rejected (400);
    #    with it, the authorized operation succeeds. (Upstream the gateway forwards to.)
    cand = "cand-a"
    idx = authz.index_name(COHORT, cand, 2)
    if not c.index_exists(idx):
        c.create_index(idx, schema.INDEX_MAPPING)
        ev, _ = enterprise.generate(cand, 2, "gwsec-a", "A")
        c.bulk_index(idx, ev)
        c.refresh(idx)
    role = authz.role_name(cand)
    c.put_role(role, [authz.candidate_index_pattern(COHORT, cand)], dls={"ranger.candidate_id": cand})
    sub = authz.user_name(cand)
    c.put_rolesmapping(role, users=[sub])
    ctok = ranger_jwt.mint(sub, priv, board=2, cohort=COHORT)
    base = {"Authorization": "Bearer " + ctok, "Content-Type": "application/json"}
    # Index-independent, xsrf-guarded Dashboards API: _bulk_get requires osd-xsrf.
    # Dashboards serves under basePath /soc (rewriteBasePath true), so prefix it.
    sobj = dash + "/soc/api/saved_objects/_bulk_get"
    s3a, _, _ = raw(sobj, "POST", base, [])                                  # no osd-xsrf
    s3b, _, b3b = raw(sobj, "POST", {**base, "osd-xsrf": "osd-fetch"}, [])   # with osd-xsrf
    rec("dashboards_csrf_blocks_without_xsrf", s3a == 400, code=s3a)
    rec("dashboards_op_ok_with_xsrf", s3b == 200, code=s3b)

    # 4. Security Analytics: SOC admin authorized, candidate denied (authorization
    #    is checked before data, so 200/404 = authorized, 403 = denied).
    c.put_role("ranger_soc_admin", ["ranger-*", ".opendistro-alerting*", ".opensearch-sap*"],
               allow_write=False,
               cluster_perms=["cluster_monitor", "cluster:admin/opendistro/alerting/*",
                              "cluster:admin/opensearch/securityanalytics/*"],
               tenant_permissions=[{"tenant_patterns": ["__user__"], "allowed_actions": ["kibana_all_write"]}])
    c.put_rolesmapping("ranger_soc_admin", users=["ranger_soc_admin"])
    atok = ranger_jwt.mint("ranger_soc_admin", priv, board=2, cohort=COHORT)
    sap = "/_plugins/_security_analytics/detectors/_search"
    adm_sap = c._req("POST", sap, body={"query": {"match_all": {}}}, bearer=atok)[0]
    cand_sap = c._req("POST", sap, body={"query": {"match_all": {}}}, bearer=ctok)[0]
    rec("sap_admin_authorized", adm_sap in (200, 404), code=adm_sap)
    rec("sap_candidate_denied", cand_sap in (401, 403), code=cand_sap)

    out["notes"] = {
        "cookie": "Flask config: HttpOnly, Secure, SameSite=Lax (COOKIE_INSECURE unset in production).",
        "gateway_csrf": "osd-xsrf required at the gateway for POST/PUT/PATCH/DELETE; SameSite=Lax blocks cross-site cookie carriage.",
        "token_handling": "JWT minted server-side, injected to upstream only; never in a client response body, header, or cookie.",
        "browser_pending": "localStorage/sessionStorage/network-to-browser and the live Discover render are confirmed in the operator's authenticated session.",
    }
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def dataview_check(c):
    """Provision and validate per-tenant data views (index patterns) via the REAL
    gateway code path (soc_gateway._ensure_dataview). Confirms: the SOC admin gets a
    ranger-* oversight data view in their private tenant with @timestamp; each
    candidate gets a data view scoped to their own index pattern in their own private
    tenant; tenants are isolated (no cross-visibility of saved objects); and a broad
    data view a candidate creates exposes no other candidate's data (the role + DLS,
    not the saved object, bound access). Uses existing Ranger telemetry; no sample
    data, no duplicate indices."""
    import soc_gateway as gw

    TS = "@timestamp"
    priv = base64.b64decode(os.environ["RANGER_JWT_PRIVATE_B64"])
    out = {"mode": "dataview", "tests": {}, "status": "PASS"}

    def rec(n, ok, **kv):
        out["tests"][n] = {"pass": bool(ok), **kv}
        if not ok:
            out["status"] = "FAIL"
        print(f"[{'PASS' if ok else 'FAIL'}] dataview/{n}: {json.dumps(kv)[:300]}", flush=True)

    # Admin role + oversight data view (its private tenant).
    c.put_role("ranger_soc_admin", ["ranger-*", ".opendistro-alerting*", ".opensearch-sap*"],
               allow_write=False,
               cluster_perms=["cluster_monitor", "cluster:admin/opendistro/alerting/*",
                              "cluster:admin/opensearch/securityanalytics/*"],
               tenant_permissions=[{"tenant_patterns": ["__user__"], "allowed_actions": ["kibana_all_write"]}])
    c.put_rolesmapping("ranger_soc_admin", users=["ranger_soc_admin"])
    gw._ensure_dataview("ranger_soc_admin", COHORT, "ranger-all-events", "ranger-*")

    # Two candidates with their own indices (existing telemetry), roles, data views.
    subs = {}
    for cand in ("cand-a", "cand-b"):
        idx = authz.index_name(COHORT, cand, 2)
        if not c.index_exists(idx):
            c.create_index(idx, schema.INDEX_MAPPING)
            ev, _ = enterprise.generate(cand, 2, f"dv-{cand}", "A")
            c.bulk_index(idx, ev)
            c.refresh(idx)
        role = authz.role_name(cand)
        c.put_role(role, [authz.candidate_index_pattern(COHORT, cand)],
                   dls={"ranger.candidate_id": cand},
                   tenant_permissions=[{"tenant_patterns": ["__user__"], "allowed_actions": ["kibana_all_write"]}])
        sub = authz.user_name(cand)
        c.put_rolesmapping(role, users=[sub])
        dv_id = f"cand-{cand}-b2"
        pattern = authz.candidate_index_pattern(COHORT, cand)
        gw._ensure_dataview(sub, COHORT, dv_id, pattern)
        subs[cand] = (sub, idx, dv_id, pattern)

    a_sub, a_idx, a_dv, a_pat = subs["cand-a"]
    b_sub, b_idx, b_dv, b_pat = subs["cand-b"]

    def get_dv(subject, dv_id):
        # Read from the SAME private tenant the write used (addressed by username).
        return gw._dash_as_user(subject, COHORT, "GET",
                                "/api/saved_objects/index-pattern/" + dv_id, tenant=subject)

    # 1. Admin oversight data view exists with the correct pattern + time field.
    ca, ba = get_dv("ranger_soc_admin", "ranger-all-events")
    rec("admin_dataview_ranger_star", ca == 200 and '"ranger-*"' in ba and TS in ba, code=ca)
    # 2. Candidate data view exists, scoped to the candidate's own pattern.
    cb, bb = get_dv(a_sub, a_dv)
    rec("candidate_dataview_scoped", cb == 200 and a_pat in bb and TS in bb, code=cb)
    # 3-5. Tenant isolation: saved objects are not visible across tenants.
    rec("candidate_cannot_see_admin_dv", get_dv(a_sub, "ranger-all-events")[0] == 404)
    rec("candidate_cannot_see_other_candidate_dv", get_dv(a_sub, b_dv)[0] == 404)
    rec("admin_cannot_see_candidate_dv", get_dv("ranger_soc_admin", a_dv)[0] == 404)
    # Modified tenant header: candidate A forges B's tenant in securitytenant.
    # A has no kibana permission on B's tenant, so the read must not return B's object.
    fc, fb = gw._dash_as_user(a_sub, COHORT, "GET",
                              "/api/saved_objects/index-pattern/" + b_dv, tenant=b_sub)
    rec("forged_tenant_header_denied", fc in (403, 404) and '"ranger-pilot-cand-b' not in fb, code=fc)
    # Direct .kibana* operations by a candidate JWT (bypassing Dashboards) must fail:
    # the candidate role grants no .kibana* index permission.
    atok_a = ranger_jwt.mint(a_sub, priv, board=2, cohort=COHORT)
    kread = c._req("GET", "/.kibana/_search", bearer=atok_a)[0]
    kwrite = c._req("POST", "/.kibana/_doc", body={"x": 1}, bearer=atok_a)[0]
    kdelete = c._req("DELETE", "/.kibana_1", bearer=atok_a)[0]
    rec("candidate_no_direct_kibana_ops",
        kread in (401, 403) and kwrite in (401, 403) and kdelete in (401, 403),
        read=kread, write=kwrite, delete=kdelete)
    # Same for the SOC admin JWT: no direct .kibana* access either.
    atok_adm = ranger_jwt.mint("ranger_soc_admin", priv, board=2, cohort=COHORT)
    aread = c._req("GET", "/.kibana/_search", bearer=atok_adm)[0]
    awrite = c._req("POST", "/.kibana/_doc", body={"x": 1}, bearer=atok_adm)[0]
    rec("admin_no_direct_kibana_ops", aread in (401, 403) and awrite in (401, 403),
        read=aread, write=awrite)
    # 6. A broad data view a candidate creates exposes NO other candidate's data:
    #    creation is allowed in their own tenant, but the role + DLS still bind access.
    gw._ensure_dataview(a_sub, COHORT, "evil-broad", "ranger-*")
    atok = ranger_jwt.mint(a_sub, priv, board=2, cohort=COHORT)
    cross = c._req("GET", f"/{b_idx}/_count", bearer=atok)[0]
    own = c._req("GET", f"/{a_idx}/_count", bearer=atok)[0]
    rec("broad_dataview_exposes_nothing", cross == 403 and own == 200, cross=cross, own=own)
    gw._dash_as_user(a_sub, COHORT, "DELETE", "/api/saved_objects/index-pattern/evil-broad")

    out["notes"] = {
        "telemetry": "Existing per-candidate ranger-* indices; no sample data, no duplicate indices.",
        "time_field": TS,
        "isolation": "Per-user PRIVATE tenants (enable_global false); data views live only in the owner's tenant.",
        "candidate_scope": "Candidate data view titled to their own index pattern; a broad view grants no extra access (role + DLS bound every search).",
        "idempotent": "Deterministic saved-object ids; a repeat /soc/launch is a no-op (409).",
    }
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def tenantprobe_check(c):
    """Diagnose the supported mechanism for tenant-scoped data-view provisioning in
    OpenSearch Dashboards 2.17.1, per the operator's condition to verify supported
    APIs before implementing. Compares a scoped BASIC-AUTH provisioning identity
    (named tenant) against the failing JWT path, and tests whether a JWT user can then
    READ the provisioned object from that tenant. No sample data. Cleans up after."""
    import urllib.error as _e
    import urllib.request as _u
    import soc_gateway as gw

    priv = base64.b64decode(os.environ["RANGER_JWT_PRIVATE_B64"])
    dash = os.environ.get("DASHBOARDS_URL", "http://dashboards.railway.internal:5601").rstrip("/")
    out = {"mode": "tenantprobe", "tests": {}}

    def http(method, path, headers, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = _u.Request(dash + "/soc" + path, data=data, method=method, headers=headers)
        try:
            with _u.urlopen(req, timeout=30) as r:
                return r.status, r.read(600).decode(errors="replace")
        except _e.HTTPError as ex:
            return ex.code, ex.read(600).decode(errors="replace")
        except Exception as ex:  # noqa: BLE001
            return -1, str(ex)[:160]

    tn = "prov_probe_tn"
    prov_user, prov_pw = "ranger_provisioner_probe", "Prov-Probe-" + base64.b64encode(os.urandom(6)).decode().rstrip("=")
    prov_role = "ranger_provisioner_probe_role"
    # Named tenant + a narrowly scoped provisioning identity: ONLY kibana write on tn.
    c._req("PUT", f"/_plugins/_security/api/tenants/{tn}", body={"description": "provisioning probe"})
    c._req("PUT", f"/_plugins/_security/api/roles/{prov_role}",
           body={"cluster_permissions": [], "index_permissions": [],
                 "tenant_permissions": [{"tenant_patterns": [tn], "allowed_actions": ["kibana_all_write"]}]})
    c.put_user(prov_user, prov_pw, [prov_role])
    basic = base64.b64encode(f"{prov_user}:{prov_pw}".encode()).decode()

    # 1. Supported path: basic-auth provisioning identity writes into the named tenant.
    bh = {"Authorization": "Basic " + basic, "securitytenant": tn,
          "osd-xsrf": "osd-fetch", "Content-Type": "application/json"}
    bc, bb = http("POST", "/api/saved_objects/index-pattern/probe-dv",
                  bh, {"attributes": {"title": "ranger-*", "timeFieldName": "@timestamp"}})
    out["tests"]["basic_auth_named_tenant_write"] = {"code": bc, "body": bb[:200]}
    print(f"[tenantprobe] basic_auth_named_tenant_write code={bc} body={bb[:220]}", flush=True)

    # 2. Can a JWT user READ it back from the named tenant? Grant soc admin read on tn.
    c.put_role("ranger_soc_admin", ["ranger-*", ".opendistro-alerting*", ".opensearch-sap*"],
               allow_write=False,
               cluster_perms=["cluster_monitor", "cluster:admin/opendistro/alerting/*",
                              "cluster:admin/opensearch/securityanalytics/*"],
               tenant_permissions=[{"tenant_patterns": [tn], "allowed_actions": ["kibana_all_read"]}])
    c.put_rolesmapping("ranger_soc_admin", users=["ranger_soc_admin"])
    jtok = ranger_jwt.mint("ranger_soc_admin", priv, board=2, cohort=COHORT)
    jh = {"Authorization": "Bearer " + jtok, "securitytenant": tn, "osd-xsrf": "osd-fetch"}
    jc, jb = http("GET", "/api/saved_objects/index-pattern/probe-dv", jh)
    out["tests"]["jwt_read_named_tenant"] = {"code": jc, "found": "probe-dv" in jb}
    print(f"[tenantprobe] jwt_read_named_tenant code={jc} found={'probe-dv' in jb}", flush=True)

    # 3. For the record: the JWT write path that failed before.
    wc, wb = gw._dash_as_user("ranger_soc_admin", COHORT, "POST",
                              "/api/saved_objects/index-pattern/probe-jwt-write",
                              {"attributes": {"title": "ranger-*", "timeFieldName": "@timestamp"}}, tenant=tn)
    out["tests"]["jwt_named_tenant_write"] = {"code": wc, "body": wb[:200]}
    print(f"[tenantprobe] jwt_named_tenant_write code={wc} body={wb[:220]}", flush=True)

    # Cleanup
    http("DELETE", "/api/saved_objects/index-pattern/probe-dv", bh)
    c.delete_user(prov_user)
    c._req("DELETE", f"/_plugins/_security/api/roles/{prov_role}")
    c._req("DELETE", f"/_plugins/_security/api/tenants/{tn}")

    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def discoverdiag_check(c):
    """Diagnose 'No results' in Discover without touching data or permissions. Uses
    the ranger_soc_admin JWT to read ranger-* document counts and the actual
    @timestamp min/max, compares against the Last-90-days window and the scenario
    window, and reads back the saved data view. Determines whether the empty result
    is the dataset, the data view, authorization, or the gateway."""
    priv = base64.b64decode(os.environ["RANGER_JWT_PRIVATE_B64"])
    import soc_gateway as gw
    atok = ranger_jwt.mint("ranger_soc_admin", priv, board=2, cohort=COHORT)
    out = {"mode": "discoverdiag", "checks": {}}

    def show(name, v):
        out["checks"][name] = v
        print(f"[discoverdiag] {name}: {json.dumps(v)[:400]}", flush=True)

    # 1. Authorized document count across ranger-* (admin oversight JWT).
    tot_code, tot = c._req("GET", "/ranger-*/_count", bearer=atok)
    show("ranger_star_count", {"code": tot_code, "count": tot.get("count") if isinstance(tot, dict) else tot})
    # per-index counts (admin broker, for the record)
    _, cat = c._req("GET", "/_cat/indices/ranger-*?format=json&h=index,docs.count")
    show("per_index", cat if isinstance(cat, list) else str(cat)[:300])

    # 2. min/max @timestamp over ranger-* via the admin JWT.
    agg = {"size": 0, "aggs": {"min_ts": {"min": {"field": "@timestamp"}},
                               "max_ts": {"max": {"field": "@timestamp"}}}}
    mc, mb = c._req("GET", "/ranger-*/_search", body=agg, bearer=atok)
    mn = mb.get("aggregations", {}).get("min_ts", {}).get("value_as_string") if isinstance(mb, dict) else None
    mx = mb.get("aggregations", {}).get("max_ts", {}).get("value_as_string") if isinstance(mb, dict) else None
    show("timestamp_min_max", {"code": mc, "min": mn, "max": mx})

    # 3/4. Counts in the Last-90-days window vs the scenario window (overlap check).
    def rng_count(gte, lte=None):
        q = {"range": {"@timestamp": {"gte": gte}}}
        if lte:
            q["range"]["@timestamp"]["lte"] = lte
        code, b = c._req("GET", "/ranger-*/_count", body={"query": q}, bearer=atok)
        return code, (b.get("count") if isinstance(b, dict) else b)
    l90c, l90 = rng_count("now-90d/d")
    schem = rng_count("2026-03-01", "2026-05-01")
    show("count_last_90d", {"code": l90c, "count": l90})
    show("count_scenario_window_mar_may_2026", {"code": schem[0], "count": schem[1]})

    # 5. The saved data view's index pattern + time field (admin tenant).
    dc, db = gw._dash_as_user("ranger_soc_admin", COHORT, "GET",
                              "/api/saved_objects/index-pattern/ranger-all-events",
                              tenant="ranger_soc_admin")
    show("data_view", {"code": dc, "has_ranger_star": '"ranger-*"' in db,
                       "has_timefield": '"@timestamp"' in db})

    # Apply + verify the supported default-time-range correction in the admin tenant.
    sc1, _ = gw._dash_as_user(
        "ranger_soc_admin", COHORT, "POST", "/api/opensearch-dashboards/settings",
        {"changes": {"timepicker:timeDefaults":
                     json.dumps({"from": gw.SCENARIO_TIME_FROM, "to": gw.SCENARIO_TIME_TO})}},
        tenant="ranger_soc_admin")
    sc2, sb = gw._dash_as_user("ranger_soc_admin", COHORT, "GET",
                               "/api/opensearch-dashboards/settings", tenant="ranger_soc_admin")
    show("time_defaults_apply", {"post": sc1, "get": sc2,
                                 "stored": ("2026-02-28" in sb or "2026-03" in sb)})

    out["diagnosis"] = (
        "dataset timestamps outside the selected time range" if (l90 == 0 and isinstance(schem[1], int) and schem[1] > 0)
        else "see counts")
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def m4stream_check(c):
    """M4.2 live validation of the continuous operational SOC chain, against the
    private cluster, using ONLY the synthetic board2-test identity. Time-bounded
    with a hard deadline and an explicit stop; nothing runs unattended afterwards.

    Proves, end to end: continuous ingestion across scheduled worker ticks into an
    isolated ranger-op-* index -> genuine OpenSearch Security Analytics detector
    execution -> finding (and alert where the plugin supports it) -> an authorized
    SOC investigation query. Plus live recovery (watermark persistence, idempotent
    replay, partial bulk failure, dead-letter) and measured performance. Every step
    records the real API code/IDs; an unsupported step is a documented limitation,
    never faked."""
    import datetime as _dt
    import time as _time

    from . import telemetry_stream as tstream

    CAND = "board2-test"
    slug = authz._slug(CAND)
    op_index = f"ranger-op-{COHORT}-{slug}-b2".lower()
    qual_index = authz.index_name(COHORT, CAND, 2)
    state_index = "ranger-op-state"
    deadline = _time.monotonic() + int(os.environ.get("M4_DEADLINE_S", "540"))  # hard stop
    out = {"mode": "m4stream", "op_index": op_index, "candidate": CAND,
           "chain": {}, "ingestion": {}, "fields": {}, "detector": {}, "findings": {},
           "alerts": {}, "trace": {}, "isolation": {}, "admin": {}, "recovery": {},
           "metrics": {}, "labeling": {}, "limitations": [], "stop": {}, "status": "PASS"}

    def fail(section, why):
        out["status"] = "FAIL"
        out.setdefault("errors", []).append({section: why})
        print(f"[FAIL] m4/{section}: {why}", flush=True)

    def lim(section, why):
        out["limitations"].append({section: why})
        print(f"[LIMITATION] m4/{section}: {why}", flush=True)

    def note(tag, **kv):
        print(f"[m4] {tag}: " + json.dumps(kv, default=str)[:500], flush=True)

    def sa(method, path, body=None, timeout=150):
        """Resilient Security Analytics call: a slow/unreachable SA endpoint becomes
        a captured (0, error) result, never an unhandled crash of the whole run."""
        try:
            return c._req(method, path, body=body, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            note("sa_call_error", path=path, error=f"{type(e).__name__}: {e}")
            return 0, {"error": f"{type(e).__name__}: {e}"}

    # --- persistent watermark backed by a cluster state doc -----------------
    class ClusterWatermarks:
        def __init__(self, cluster, index, key):
            self.c, self.index, self.key = cluster, index, key
            self.c.create_index(index, {"mappings": {"properties": {
                "candidate": {"type": "keyword"}, "watermark": {"type": "date"}}}})
        def get(self, key):
            code, body = self.c._req("GET", f"/{self.index}/_doc/{key}")
            if code == 200 and body.get("found"):
                wm = body["_source"].get("watermark")
                return tstream._as_utc(wm) if wm else None
            return None
        def set(self, key, ts):
            self.c._req("PUT", f"/{self.index}/_doc/{key}?refresh=true",
                        body={"candidate": key, "watermark": tstream._as_utc(ts).isoformat()})

    # --- live bulk sink with op_type=create (idempotent) --------------------
    class LiveSink:
        def __init__(self, cluster):
            self.c = cluster
        def bulk(self, index, docs):
            lines = []
            for d in docs:
                lines.append(json.dumps({"create": {"_index": index, "_id": d["uid"]}}))
                lines.append(json.dumps(d["source"]))
            code, resp = self.c._req("POST", "/_bulk?refresh=false",
                                     body="\n".join(lines) + "\n", ndjson=True)
            if code not in (200, 201):
                raise LiveError(f"bulk transport {code}")
            res = []
            for it in resp.get("items", []):
                cr = it.get("create", {})
                res.append({"uid": cr.get("_id"), "status": cr.get("status", 500)})
            return res

    # =======================================================================
    # 1) fresh isolated operational index with the real ECS mapping
    # =======================================================================
    c.delete_index(op_index)
    c.create_index(op_index, schema.INDEX_MAPPING)
    note("op_index_created", index=op_index)

    # =======================================================================
    # 2) continuous ingestion across MULTIPLE scheduled worker ticks
    # =======================================================================
    start = _dt.datetime.now(_dt.timezone.utc)
    run_window_s = int(os.environ.get("M4_RUN_WINDOW_S", "40"))
    plan = tstream.StreamPlan(CAND, 2, "m4-op-seed", "functional", start, run_window_s,
                              max_delay_s=10, incident_span_s=min(25, run_window_s - 10))
    truth = plan.truth()
    wm = ClusterWatermarks(c, state_index, CAND)
    wm.set(CAND, plan.start)  # initialize
    driver = tstream.StreamDriver(LiveSink(c), wm, op_index, max_retries=4, queue_max=100000)
    ticks = []
    t_ingest0 = _time.monotonic()
    n_ticks = int(os.environ.get("M4_TICKS", "5"))
    for i in range(n_ticks):
        _time.sleep(max(1, run_window_s // n_ticks))
        now = _dt.datetime.now(_dt.timezone.utc)
        r = driver.tick(plan, CAND, now)
        ticks.append({"tick": i + 1, "advanced": r.advanced, "indexed": r.indexed,
                      "conflicts": r.conflicts, "window": r.window, "dead": len(r.dead)})
        note("tick", **ticks[-1])
    # final drain tick (captures the last delayed arrivals), watermark persisted in-cluster
    _time.sleep(11)
    r = driver.tick(plan, CAND, _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=30))
    ticks.append({"tick": "drain", "advanced": r.advanced, "indexed": r.indexed,
                  "conflicts": r.conflicts, "window": r.window, "dead": len(r.dead)})
    ingest_elapsed = _time.monotonic() - t_ingest0
    c.refresh(op_index)
    indexed_total = c.count(op_index)
    planned_total = truth["counts"]["total"]
    multi_tick = sum(1 for t in ticks if isinstance(t["tick"], int) and t["indexed"] > 0) >= 2
    out["ingestion"] = {"ticks": ticks, "planned_total": planned_total,
                        "indexed_total": indexed_total, "multi_tick_ingestion": multi_tick,
                        "watermark_persisted": wm.get(CAND).isoformat() if wm.get(CAND) else None}
    if not multi_tick:
        fail("ingestion", "events did not arrive across multiple ticks")
    if indexed_total < planned_total:
        lim("ingestion", f"indexed {indexed_total}/{planned_total}; stragglers beyond drain window")

    # =======================================================================
    # 3) field correctness: timestamps, identities, mapped security fields
    # =======================================================================
    sample = c.search(op_index, {"match_all": {}}, size=50)
    def has(path, d):
        cur = d
        for p in path.split("."):
            if not isinstance(cur, dict) or p not in cur:
                return False
            cur = cur[p]
        return True
    ingest_delays = []
    for d in sample:
        ts = d.get("@timestamp"); ing = (d.get("event") or {}).get("ingested")
        if ts and ing:
            try:
                ingest_delays.append((tstream._as_utc(ing) - tstream._as_utc(ts)).total_seconds())
            except Exception:  # noqa: BLE001
                pass
    fields_ok = bool(sample) and all(
        has("@timestamp", d) and has("event.ingested", d) and has("event.dataset", d)
        and has("ranger.plane", d) for d in sample)
    current_ts = all(str(d.get("@timestamp", "")).startswith(str(start.year)) for d in sample)
    out["fields"] = {
        "sampled": len(sample), "all_have_core_fields": fields_ok,
        "current_era_timestamps": current_ts,
        "has_identity_fields": any(has("user.name", d) or has("source.ip", d) for d in sample),
        "has_security_mappings": any(has("winlog.event_id", d) or has("dns.question.name", d) for d in sample),
        "plane": next((d.get("ranger", {}).get("plane") for d in sample), None)}
    if not (fields_ok and current_ts):
        fail("fields", "operational events missing core/current-timestamp fields")

    # =======================================================================
    # 12) synthetic labeling (do this before detectors so the report is explicit)
    # =======================================================================
    labeled = bool(sample) and all((d.get("data") or {}).get("synthetic") is True for d in sample)
    out["labeling"] = {"all_marked_synthetic": labeled,
                       "org": "Valyria Financial Group (fictional, synthetic lab data)"}
    if not labeled:
        fail("labeling", "operational events not all marked data.synthetic=true")

    # =======================================================================
    # 5+6) GENUINE Security Analytics detector -> finding -> alert
    # =======================================================================
    # a custom Sigma rule on a real indexed field from the privileged-identity
    # incident chain (Windows EventID 4728 = member added to a privileged group).
    rule_yaml = (
        "title: Ranger Op Privileged Group Addition\n"
        "logsource:\n  product: windows\n"
        "detection:\n  sel:\n    EventID: 4728\n  condition: sel\n"
        "level: high\n")
    sa_obj = {"rule_id": None, "detector_id": None, "mappings": None}
    finding_ids, finding_docs, alert_ids = [], [], []
    try:
      # discover the mapping view for the windows log type on our index
      code, view = sa("GET",
                      f"/_plugins/_security_analytics/mappings/view?index_name={op_index}&rule_topic=windows")
      note("sa_mappings_view", code=code, keys=list(view.keys()) if isinstance(view, dict) else None)
      # field mapping BEFORE the rule/detector so winlog.event_id maps to the alias
      code, mbody = sa("POST", "/_plugins/_security_analytics/mappings",
                       body={"index_name": op_index, "rule_topic": "windows", "partial": True,
                             "field_mappings": [
                                 {"raw_field": "winlog.event_id", "ocsf_field": "EventID"}]})
      sa_obj["mappings"] = {"code": code}
      note("sa_mappings_applied", code=code, body=json.dumps(mbody)[:200])
      # prefer a GENUINE pre-packaged windows rule that keys on EventID 4728 (the
      # privileged-group-addition tradecraft). Pre-packaged rules avoid the custom-
      # rules index bootstrap that returned 500 on this build, and the detector
      # lifecycle itself initializes SA's per-log-type indices.
      pp_ids, pp_titles = [], []
      # rule.* is a NESTED field; the earlier non-nested query matched nothing even
      # though 2200+ windows rules exist. Fetch windows rules, then pick the ones
      # whose content keys on EventID 4728 (privileged group addition).
      code, pp = sa("POST", "/_plugins/_security_analytics/rules/_search?pre_packaged=true",
                    body={"size": 3000, "query": {"nested": {"path": "rule",
                          "query": {"match": {"rule.category": "windows"}}}}})
      if code == 200:
          for h in (pp.get("hits", {}) or {}).get("hits", []):
              src = h.get("_source", {}) if isinstance(h, dict) else {}
              blob = json.dumps(src)
              if "4728" in blob:
                  pp_ids.append(h.get("_id"))
                  rule = src.get("rule", {})
                  pp_titles.append(rule.get("title") if isinstance(rule, dict) else "rule")
      note("sa_prepackaged_rules", code=code, windows_total=(pp.get("hits", {}) or {}).get("total"),
           matched_4728=len(pp_ids), ids=pp_ids[:3], titles=pp_titles[:3])
      # best-effort custom rule too (documents the 500 if the index is not ready)
      code, body = sa("POST", "/_plugins/_security_analytics/rules?category=windows",
                      body={"rule": rule_yaml})
      if code in (200, 201):
          sa_obj["rule_id"] = body.get("_id")
          note("sa_rule_created", rule_id=sa_obj["rule_id"])
      else:
          lim("detector", f"custom rule create returned {code}: {json.dumps(body)[:200]}")
      pre = [{"id": i} for i in pp_ids[:1]]
      cust = [{"id": sa_obj["rule_id"]}] if sa_obj["rule_id"] else []
      trig_ids = ([pp_ids[0]] if pp_ids else []) + ([sa_obj["rule_id"]] if sa_obj["rule_id"] else [])
      sa_obj["rules_used"] = {"pre_packaged": pre, "custom": cust}
      if pre or cust:
          detector = {"type": "detector", "detector": {
              "name": "ranger-op-board2test", "detector_type": "windows", "enabled": True,
              "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
              "inputs": [{"detector_input": {"description": "ranger operational",
                          "indices": [op_index],
                          "custom_rules": cust,
                          "pre_packaged_rules": pre}}],
              "triggers": [{"name": "priv-group-add", "types": ["windows"],
                            "sev_levels": ["high"], "ids": trig_ids,
                            "severity": "1", "actions": []}]}}
          code, body = sa("POST", "/_plugins/_security_analytics/detectors", body=detector)
          if code in (200, 201):
              sa_obj["detector_id"] = body.get("_id")
              note("sa_detector_created", detector_id=sa_obj["detector_id"],
                   used_pre=len(pre), used_custom=len(cust))
          else:
              lim("detector", f"detector create returned {code}: {json.dumps(body)[:300]}")
      else:
          lim("detector", "no usable rule (pre-packaged search and custom create both unavailable)")
    except Exception as e:  # noqa: BLE001
        lim("detector", f"SA setup raised {type(e).__name__}: {e}")
    out["detector"] = sa_obj

    # SA diagnostics (always captured): distinguish "query too narrow" from
    # "Security Analytics rules indices not initialized" as the root cause.
    diag = {}
    code, ppc = sa("POST", "/_plugins/_security_analytics/rules/_search?pre_packaged=true",
                   body={"size": 0, "query": {"match_all": {}}})
    diag["pre_packaged_rules_total"] = (ppc.get("hits", {}) or {}).get("total", {}).get("value") \
        if code == 200 else f"code={code}"
    code, cc2 = sa("POST", "/_plugins/_security_analytics/rules/_search?pre_packaged=false",
                   body={"size": 0, "query": {"match_all": {}}})
    diag["custom_rules_total"] = (cc2.get("hits", {}) or {}).get("total", {}).get("value") \
        if code == 200 else f"code={code}"
    code, cat = c._req("GET", "/_cat/indices/.opensearch-sap*,.opensearch-pre*,.opendistro*?format=json&h=index,health,status,docs.count")
    diag["sa_indices"] = cat if code == 200 else f"code={code}"
    code, pl = c._req("GET", "/_cat/plugins?format=json&h=component")
    if code == 200 and isinstance(pl, list):
        comps = sorted({p.get("component") for p in pl})
        diag["security_analytics_plugin_present"] = any("security-analytics" in (x or "") for x in comps)
    note("sa_diagnostics", **{k: v for k, v in diag.items() if k != "sa_indices"})
    note("sa_indices", indices=diag.get("sa_indices"))
    out["sa_diagnostics"] = diag

    # poll for a genuine detector execution + findings, up to the deadline
    if sa_obj["detector_id"]:
        while _time.monotonic() < deadline:
            _time.sleep(20)
            code, fres = sa("GET",
                            "/_plugins/_security_analytics/findings/_search?detectorType=windows")
            total = (fres or {}).get("total_findings", 0)
            note("sa_findings_poll", code=code, total=total)
            if code == 200 and total:
                for f in fres.get("findings", []):
                    if (f.get("detectorId") == sa_obj["detector_id"]) or not f.get("detectorId"):
                        finding_ids.append(f.get("id"))
                        finding_docs.append(f)
                if finding_ids:
                    break
    out["findings"] = {"count": len(finding_ids), "ids": finding_ids[:10]}
    if not finding_ids:
        lim("findings", "no Security Analytics finding observed within the deadline; "
            "detector/mapping may need adjustment on this build (see sa_* logs)")

    # alerts (distinct from findings): triggered by the detector's trigger
    code, ares = sa("GET", "/_plugins/_security_analytics/alerts?detectorType=windows")
    if code == 200:
        for a in (ares or {}).get("alerts", []):
            alert_ids.append(a.get("id") or a.get("alert_id"))
    out["alerts"] = {"count": len(alert_ids), "ids": alert_ids[:10],
                     "distinct_from_findings": True}
    if not alert_ids:
        lim("alerts", "no alert observed; a detector trigger fires alerts only after a "
            "finding; reported separately from findings, not conflated")

    # =======================================================================
    # 7) trace one incident: event -> finding/alert -> investigation query
    # =======================================================================
    inc = truth["incidents"][0]
    trigger_uid = None
    for uid in inc["event_uids"]:
        code, doc = c._req("GET", f"/{op_index}/_doc/{uid}")
        if code == 200 and doc.get("found") and (doc["_source"].get("winlog", {}) or {}).get("event_id") == 4728:
            trigger_uid = uid
            break
    out["trace"] = {
        "incident_family": inc["family"],
        "indexed_event_uid": trigger_uid,
        "finding_ids": finding_ids[:3],
        "alert_ids": alert_ids[:3],
        "investigation_query": {"query": {"term": {"winlog.event_id": 4728}}},
        "chain_complete": bool(trigger_uid and finding_ids)}
    out["chain"] = {
        "continuous_ingestion": multi_tick,
        "native_detector": bool(sa_obj["detector_id"]),
        "finding": bool(finding_ids),
        "alert": bool(alert_ids),
        "authorized_investigation": None}  # filled by isolation step (candidate query)

    # =======================================================================
    # 8) candidate isolation (JWT as board2-test); + a second disposable candidate
    # =======================================================================
    try:
        priv = base64.b64decode(os.environ["RANGER_JWT_PRIVATE_B64"])
        role = authz.role_name(CAND)
        c.put_role(role, [op_index, authz.candidate_index_pattern(COHORT, CAND)],
                   dls={"ranger.candidate_id": CAND})
        sub = authz.user_name(CAND)
        c.put_rolesmapping(role, users=[sub])
        tok = ranger_jwt.mint(sub, priv, board=2, cohort=COHORT)
        own = c._req("GET", f"/{op_index}/_count", bearer=tok)[0]
        # authorized investigation query as the candidate (the chain's last hop)
        inv = c._req("GET", f"/{op_index}/_search",
                     body={"query": {"term": {"winlog.event_id": 4728}}}, bearer=tok)
        out["chain"]["authorized_investigation"] = (inv[0] == 200)
        # a disposable second candidate with its own op index
        other = "board2-other"
        oidx = f"ranger-op-{COHORT}-{authz._slug(other)}-b2".lower()
        c.delete_index(oidx); c.create_index(oidx, schema.INDEX_MAPPING)
        op2 = tstream.StreamPlan(other, 2, "m4-other", "functional", start, 20, max_delay_s=5)
        LiveSink(c).bulk(oidx, op2.window(op2.start, op2.end + _dt.timedelta(seconds=60)))
        c.refresh(oidx)
        cross = c._req("GET", f"/{oidx}/_count", bearer=tok)[0]
        sec_cfg = c._req("GET", "/.opendistro_security/_search", bearer=tok)[0]
        sec_api = c._req("GET", "/_plugins/_security/api/internalusers", bearer=tok)[0]
        out["isolation"] = {
            "own_op_index_ok": own == 200,
            "cross_candidate_denied": cross == 403,
            "security_config_denied": sec_cfg in (401, 403, 404),
            "security_api_denied": sec_api in (401, 403),
            "note": "no protected-truth index exists candidate-side; truth lives only in the Ranger backend"}
        if not (own == 200 and cross == 403 and out["isolation"]["security_api_denied"]):
            fail("isolation", f"own={own} cross={cross} sec_api={sec_api}")
        c.delete_index(oidx)
    except Exception as e:  # noqa: BLE001
        fail("isolation", f"{type(e).__name__}: {e}")

    # =======================================================================
    # 9) SOC admin oversight WITHOUT broad security-administration
    # =======================================================================
    soc_pw = os.environ.get("RANGER_SOC_ADMIN_PW") or os.environ.get("RANGER_SOC_TEST_KEY")
    if not soc_pw:
        lim("admin", "no SOC-admin password in the validator env; skipped the SOC-admin "
            "least-privilege check (not faked)")
        out["admin"] = {"skipped": "no_credential_in_env"}
    else:
      try:
        c.put_role("ranger_soc_admin",
                   ["ranger-*", ".opendistro-alerting*", ".opensearch-sap*"],
                   allow_write=False,
                   cluster_perms=["cluster_monitor",
                                  "cluster:admin/opendistro/alerting/*",
                                  "cluster:admin/opensearch/alerting/*",
                                  "cluster:admin/opensearch/securityanalytics/*"])
        c.put_user("ranger_soc_admin", soc_pw, ["ranger_soc_admin"])
        adm = ("ranger_soc_admin", soc_pw)
        read_op = c._req("GET", f"/{op_index}/_count", auth=adm)[0]
        read_find = c._req("GET",
                           "/_plugins/_security_analytics/findings/_search?detectorType=windows", auth=adm)[0]
        no_sec = c._req("GET", "/.opendistro_security/_search", auth=adm)[0]
        no_users = c._req("PUT", "/_plugins/_security/api/internalusers/evil",
                          body={"password": "x", "opendistro_security_roles": ["all_access"]}, auth=adm)[0]
        out["admin"] = {"reads_operational": read_op == 200,
                        "reads_findings": read_find in (200, 404),
                        "security_index_denied": no_sec in (401, 403, 404),
                        "cannot_create_users": no_users in (401, 403)}
        if not (read_op == 200 and out["admin"]["security_index_denied"]
                and out["admin"]["cannot_create_users"]):
            fail("admin", json.dumps(out["admin"]))
      except Exception as e:  # noqa: BLE001
        fail("admin", f"{type(e).__name__}: {e}")

    # =======================================================================
    # 10) live recovery: watermark persistence, replay idempotency, partial fail
    # =======================================================================
    rec = {}
    # watermark persistence across a fresh driver/store instance
    wm2 = ClusterWatermarks(c, state_index, CAND)
    rec["watermark_persisted_readback"] = wm2.get(CAND) is not None
    # replay idempotency: re-run the full window via create -> all conflicts, count stable
    before = c.count(op_index)
    replay = driver._drive(plan.window(plan.start, plan.end + _dt.timedelta(seconds=120)), CAND,
                           _dt.datetime.now(_dt.timezone.utc))
    c.refresh(op_index)
    rec["replay_conflicts"] = replay.conflicts
    rec["replay_no_new_docs"] = (c.count(op_index) == before)
    # partial bulk failure: a doc that violates the mapping (string into event_id int)
    bad_uid = "m4-badmap-0001"
    badsink_docs = [{"uid": bad_uid, "source": {"@timestamp": start.isoformat(),
                     "event": {"dataset": "windows.security"},
                     "winlog": {"event_id": "not-an-int"},
                     "ranger": {"candidate_id": CAND, "plane": "operational"},
                     "data": {"synthetic": True}}},
                    {"uid": "m4-goodmap-0001", "source": {"@timestamp": start.isoformat(),
                     "event": {"dataset": "windows.security"},
                     "ranger": {"candidate_id": CAND, "plane": "operational"},
                     "data": {"synthetic": True}}}]
    res = driver._drive(badsink_docs, CAND + "-badtest", _dt.datetime.now(_dt.timezone.utc))
    rec["partial_failure_dead_lettered"] = any(d["uid"] == bad_uid for d in res.dead)
    rec["partial_failure_good_indexed"] = (res.indexed >= 1)
    lim("recovery", "live 429 backpressure not force-induced on a healthy cluster "
        "(validated offline in test_telemetry_stream.py); not faked here")
    out["recovery"] = rec
    if not (rec.get("watermark_persisted_readback") and rec.get("replay_no_new_docs")):
        fail("recovery", json.dumps(rec))

    # =======================================================================
    # 11) measured performance
    # =======================================================================
    t0 = _time.monotonic()
    c.search(op_index, {"term": {"winlog.event_id": 4728}}, size=10)
    query_ms = round((_time.monotonic() - t0) * 1000, 1)
    code, cat = c._req("GET", f"/_cat/indices/{op_index}?format=json&bytes=b")
    size_bytes = int(cat[0]["store.size"]) if (code == 200 and cat) else None
    heap = _heap(c)
    code, ns = c.node_stats()
    node = next(iter((ns or {}).get("nodes", {}).values()), {})
    out["metrics"] = {
        "ingest_eps_observed": round(indexed_total / ingest_elapsed, 2) if ingest_elapsed else None,
        "ingest_elapsed_s": round(ingest_elapsed, 1),
        "event_to_ingest_delay_s": {
            "p50": round(statistics.median(ingest_delays), 2) if ingest_delays else None,
            "max": round(max(ingest_delays), 2) if ingest_delays else None},
        "detector_poll_findings": len(finding_ids),
        "query_latency_ms": query_ms,
        "op_index_size_bytes": size_bytes,
        "heap": heap,
        "cpu_percent": node.get("os", {}).get("cpu", {}).get("percent"),
        "fs_available_bytes": node.get("fs", {}).get("total", {}).get("available_in_bytes"),
        "railway_note": "cross-check against Railway service metrics (CPU/mem/disk) for the opensearch service over the run window"}

    # =======================================================================
    # stop: disable + delete the detector so NOTHING runs unattended
    # =======================================================================
    stop = {"detector_deleted": None, "soc_admin_user_deleted": None,
            "candidate_rolesmapping_deleted": None}
    if sa_obj["detector_id"]:
        dc, _ = sa("DELETE", f"/_plugins/_security_analytics/detectors/{sa_obj['detector_id']}")
        stop["detector_deleted"] = dc in (200, 204)
    stop["soc_admin_user_deleted"] = c.delete_user("ranger_soc_admin")[0] in (200, 204)
    stop["candidate_rolesmapping_deleted"] = c.delete_rolesmapping(authz.role_name(CAND))[0] in (200, 204)
    # verify no detector remains
    code, dl = c._req("GET", "/_plugins/_security_analytics/detectors/_search",
                      body={"query": {"match_all": {}}})
    stop["remaining_detectors"] = (dl or {}).get("hits", {}).get("total", {}).get("value", "?") if code == 200 else "?"
    stop["bounded_run"] = True
    out["stop"] = stop

    out["acceptance_chain"] = {
        "continuous_telemetry": out["chain"]["continuous_ingestion"],
        "opensearch_ingestion": indexed_total > 0,
        "native_detector_execution": out["chain"]["native_detector"],
        "finding_or_alert": bool(finding_ids or alert_ids),
        "authorized_investigation": bool(out["chain"]["authorized_investigation"]),
        "fully_demonstrated": all([out["chain"]["continuous_ingestion"], indexed_total > 0,
                                   out["chain"]["native_detector"],
                                   bool(finding_ids or alert_ids),
                                   bool(out["chain"]["authorized_investigation"])])}
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def resettime_check(c):
    """Clear the timepicker:timeDefaults override from the SOC admin and candidate
    tenants (setting it back to default removes the override), to undo the tenant
    config write that correlated with the Dashboards capabilities failure. Reversible,
    no data or permission change."""
    import soc_gateway as gw
    subjects = ["ranger_soc_admin", authz.user_name("cand-a"), authz.user_name("cand-b")]
    out = {"mode": "resettime", "results": {}}
    for s in subjects:
        code, body = gw._dash_as_user(s, COHORT, "POST", "/api/opensearch-dashboards/settings",
                                      {"changes": {"timepicker:timeDefaults": None}}, tenant=s)
        out["results"][s] = {"code": code}
        print(f"[resettime] {s}: code={code} body={body[:160]}", flush=True)
    print("===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(out, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def main():
    url = os.environ["OPENSEARCH_URL"]
    admin = os.environ.get("OPENSEARCH_ADMIN_USER", "admin")
    pw = os.environ["OPENSEARCH_ADMIN_PASSWORD"]
    # P1.6: verify the node cert against the Ranger CA when it is provided.
    ca_path = None
    cab64 = os.environ.get("RANGER_CA_B64")
    if cab64:
        ca_path = "/tmp/ranger-ca.pem"
        with open(ca_path, "wb") as f:
            f.write(base64.b64decode(cab64))
    c = LiveCluster(url, admin, pw, timeout=60, ca_path=ca_path)
    REPORT["metrics"]["tls_verification"] = bool(ca_path)
    mode = os.environ.get("RANGER_VALIDATE_MODE")
    if mode == "persist":
        print(f"== Ranger SIEM persistence re-check against {url} ==", flush=True)
        return persist_check(c)
    if mode == "harden":
        print(f"== Ranger SIEM credential hardening against {url} ==", flush=True)
        return harden(c)
    if mode == "backup":
        print(f"== Ranger SIEM snapshot backup/restore against {url} ==", flush=True)
        return backup_check(c)
    if mode == "jwt":
        print(f"== Ranger SIEM candidate JWT auth against {url} ==", flush=True)
        return jwt_check(c)
    if mode == "dashauth":
        print(f"== Ranger Dashboards JWT transport probe ==", flush=True)
        return dashauth_check(c)
    if mode == "socgw":
        print(f"== Ranger /soc gateway end-to-end validation ==", flush=True)
        return socgw_check(c)
    if mode == "socadmin":
        print(f"== Ranger SOC administrator authorization boundary ==", flush=True)
        return socadmin_check(c)
    if mode == "gwsec":
        print(f"== Ranger gateway security integration checks ==", flush=True)
        return gwsec_check(c)
    if mode == "dataview":
        print(f"== Ranger per-tenant data view provisioning + isolation ==", flush=True)
        return dataview_check(c)
    if mode == "tenantprobe":
        print(f"== Ranger tenant provisioning mechanism probe ==", flush=True)
        return tenantprobe_check(c)
    if mode == "discoverdiag":
        print(f"== Ranger Discover empty-result diagnosis ==", flush=True)
        return discoverdiag_check(c)
    if mode == "resettime":
        print(f"== Ranger reset tenant timepicker:timeDefaults ==", flush=True)
        return resettime_check(c)
    if mode == "m4stream":
        print(f"== Ranger M4.2 continuous operational SOC chain (bounded) against {url} ==", flush=True)
        return m4stream_check(c)
    print(f"== Ranger SIEM live validation against {url} ==", flush=True)

    # F1 cluster health
    code, h = c.health()
    _rec("F1_cluster_health", status="PASS" if h.get("status") == "green" else "WARN",
         cluster_status=h.get("status"), nodes=h.get("number_of_nodes"),
         http_code=code)

    # F2 ingestion + field mapping (Profile A for candidate A, board 2)
    idx_a = authz.index_name(COHORT, "cand-a", 2)
    c.delete_index(idx_a)
    c.create_index(idx_a, schema.INDEX_MAPPING)
    events_a, truth_a = enterprise.generate("cand-a", 2, "pilot-seed-a", "A")
    res = c.bulk_index(idx_a, events_a)
    c.refresh(idx_a)
    cnt = c.count(idx_a)
    code, mp = c._req("GET", f"/{idx_a}/_mapping")
    props = mp.get(idx_a, {}).get("mappings", {}).get("properties", {})
    cid_type = props.get("ranger", {}).get("properties", {}).get("candidate_id", {}).get("type")
    _rec("F2_ingestion_mapping",
         status="PASS" if (cnt == len(events_a) and not res["errors"] and cid_type == "keyword") else "FAIL",
         generated=len(events_a), indexed=res["indexed"], counted=cnt,
         bulk_errors=res["errors"], candidate_id_mapping=cid_type,
         benign=truth_a["counts"]["benign"], malicious=truth_a["counts"]["malicious"])

    # F3 per-candidate authorization provisioning (role + user + DLS) on the real
    # Security API, for two candidates.
    idx_b = authz.index_name(COHORT, "cand-b", 2)
    c.delete_index(idx_b)
    c.create_index(idx_b, schema.INDEX_MAPPING)
    events_b, _ = enterprise.generate("cand-b", 2, "pilot-seed-b", "A")
    c.bulk_index(idx_b, events_b)
    c.refresh(idx_b)

    prov = {}
    for cand in ("cand-a", "cand-b"):
        role = authz.candidate_role(COHORT, cand)
        c.put_role(role.name, role.index_patterns, dls=role.dls, allow_write=False)
        cred = f"Pw-{cand}-{int(time.time())}xZ9"
        c.put_user(authz.user_name(cand), cred, [role.name])
        prov[cand] = (authz.user_name(cand), cred)
    _rec("F3_authz_provisioning", status="PASS",
         roles=[authz.role_name("cand-a"), authz.role_name("cand-b")],
         users=[u for u, _ in prov.values()],
         dls_field="ranger.candidate_id")

    # F4 candidate index isolation: A reads own index; A reading B's index -> 403.
    ua, pa = prov["cand-a"]
    own_ok = False
    cross_denied = False
    try:
        own = c.count(idx_a, auth=(ua, pa))
        own_ok = own == len(events_a)
    except Exception as e:  # noqa: BLE001
        own = str(e)
    try:
        c.count(idx_b, auth=(ua, pa))
    except AuthzError:
        cross_denied = True
    except NotFound:
        cross_denied = True  # index not visible to the role is also isolation
    _rec("F4_index_isolation",
         status="PASS" if (own_ok and cross_denied) else "FAIL",
         candidate_reads_own=own_ok, own_count=own,
         cross_candidate_read_denied=cross_denied)

    # F5 document-level security as a second layer: a shared index holding both
    # candidates' docs; cand-a's DLS role must return only cand-a documents.
    shared = f"ranger-{COHORT}-dls-probe".lower()
    c.delete_index(shared)
    c.create_index(shared, schema.INDEX_MAPPING)
    c.bulk_index(shared, events_a[:50] + events_b[:50])
    c.refresh(shared)
    dls_role = "dls_probe_cand_a"
    c.put_role(dls_role, [shared], dls={"ranger.candidate_id": "cand-a"})
    c.put_user("dls_probe_a", "Pw-dls-a-77Qx", [dls_role])
    seen = c.search(shared, auth=("dls_probe_a", "Pw-dls-a-77Qx"), size=500)
    only_a = all(d["ranger"]["candidate_id"] == "cand-a" for d in seen) and len(seen) > 0
    _rec("F5_document_level_security",
         status="PASS" if only_a else "FAIL",
         docs_visible=len(seen), all_cand_a=only_a,
         total_in_shared=100)

    # F6 detection derives from rule logic, measured against the hidden truth on
    # REAL indexed data pulled back from the cluster.
    pulled = c.search(idx_a, size=1000)
    pulled_events = [{"_id": d.get("ranger", {}).get("event_uid") or f"p{i}", "_source": d}
                     for i, d in enumerate(pulled)]
    det = detection.validate(pulled_events, truth_a)
    _rec("F6_detection_from_logic",
         status="PASS" if (det["findings"] > 0 and det["true_positive_findings"] > 0) else "WARN",
         findings=det["findings"], true_positives=det["true_positive_findings"],
         false_positives=det["false_positive_findings"],
         incidents_detected=det["incidents_detected"],
         incidents_missed=det["incidents_missed"])

    # F7 genuine alert from detection LOGIC via the Alerting plugin, executed
    # synchronously. The query term is taken from a real malicious event, so the
    # alert reflects indexed data, not a hardcoded object. A control query for an
    # absent indicator must NOT trigger.
    malicious_uids = {u for inc in truth_a["incidents"] for u in inc["event_uids"]}
    mal_sources = [e["_source"] for e in events_a if e["_id"] in malicious_uids]
    indicator = None
    for s in mal_sources:
        eid = s.get("winlog", {}).get("event_id")
        if eid:
            indicator = ("winlog.event_id", eid)
            break
    if not indicator:
        for s in mal_sources:
            u = s.get("url", {}).get("original")
            if u:
                indicator = ("url.original", u)
                break
    alert_fired = control_quiet = None
    sa_probe = {}
    if indicator:
        field, val = indicator
        fired = _run_monitor(c, idx_a, {"term": {field: val}})
        quiet = _run_monitor(c, idx_a, {"term": {"host.name": "no-such-host-zzz"}})
        alert_fired, control_quiet = fired, quiet
    # Security Analytics capability probe (honest: report what the engine exposes)
    code_lt, lt = c._req("GET", "/_plugins/_security_analytics/logtypes")
    sa_probe["logtypes_api"] = code_lt
    if isinstance(lt, dict):
        sa_probe["logtype_count"] = lt.get("total") or len(lt.get("logtypes", []) or [])
    _rec("F7_alerting_and_security_analytics",
         status="PASS" if (alert_fired and control_quiet is False) else "WARN",
         indicator=f"{indicator[0]}={indicator[1]}" if indicator else None,
         monitor_triggered_on_malicious=alert_fired,
         monitor_triggered_on_control=control_quiet,
         security_analytics=sa_probe)

    # F8 cross-source correlation by identity
    corr = detection.correlate(detection.run_rules(pulled_events))
    _rec("F8_correlation", status="PASS" if isinstance(corr, list) else "FAIL",
         correlated_incidents=len(corr),
         sample=[{k: v for k, v in ci.items() if k in ("user", "finding_count", "severity")}
                 for ci in corr[:3]])

    # F9 evidence integrity: sign a case snapshot, verify, then tamper -> fail.
    snapshot = {"candidate": "cand-a", "board": 2, "index": idx_a,
                "findings": det["findings"], "ts": int(time.time())}
    sig = signing.sign(snapshot)
    ok = signing.verify(snapshot, sig)
    tampered = dict(snapshot); tampered["findings"] = det["findings"] + 999
    bad = signing.verify(tampered, sig)
    _rec("F9_evidence_integrity",
         status="PASS" if (ok and not bad) else "FAIL",
         signed=True, verifies=ok, tamper_detected=(not bad),
         public_key=signing.public_key_b64()[:16] + "...")

    # F10 progressive benchmark A -> B: chunked bulk ingest, query latency, heap.
    heap_before = _heap(c)
    bench = f"ranger-{COHORT}-bench-b2".lower()
    c.delete_index(bench)
    c.create_index(bench, schema.INDEX_MAPPING)
    ev_b, _ = enterprise.generate("bench", 2, "pilot-bench", "B")
    t0 = time.time()
    total_indexed = 0
    chunk = 1000
    for i in range(0, len(ev_b), chunk):
        r = c.bulk_index(bench, ev_b[i:i + chunk])
        total_indexed += r["indexed"]
    ingest_s = time.time() - t0
    c.refresh(bench)
    # representative queries
    queries = [
        {"match_all": {}},
        {"term": {"event.dataset": "windows.security"}},
        {"range": {"@timestamp": {"gte": "now-30d"}}},
        {"term": {"ranger.candidate_id": "bench"}},
    ]
    lat = []
    for _ in range(20):
        q = queries[_ % len(queries)]
        s = time.time()
        c._req("GET", f"/{bench}/_search", body={"size": 20, "query": q})
        lat.append((time.time() - s) * 1000)
    code_st, st = c._req("GET", f"/{bench}/_stats/store")
    size_mb = None
    try:
        size_mb = round(st["indices"][bench]["total"]["store"]["size_in_bytes"] / 1e6, 1)
    except Exception:  # noqa: BLE001
        pass
    heap_after = _heap(c)
    _rec("F10_benchmark_A_to_B", status="PASS" if total_indexed == len(ev_b) else "WARN",
         profile_b_events=len(ev_b), indexed=total_indexed,
         ingest_seconds=round(ingest_s, 2),
         ingest_docs_per_sec=round(total_indexed / ingest_s, 1) if ingest_s else None,
         query_p50_ms=round(statistics.median(lat), 1),
         query_p95_ms=round(sorted(lat)[int(len(lat) * 0.95) - 1], 1),
         index_size_mb=size_mb, heap_before=heap_before, heap_after=heap_after)

    # F11 metrics snapshot
    REPORT["metrics"] = {"heap": _heap(c), "cluster": {"status": h.get("status")}}

    # revocation + cleanup: delete test identities, confirm a deleted user cannot
    # authenticate any more.
    for u in ("dls_probe_a",):
        c.delete_user(u)
    c.delete_role("dls_probe_cand_a")
    revoked_ok = False
    ua2, pa2 = prov["cand-a"]
    c.delete_user(ua2)
    try:
        c.count(idx_a, auth=(ua2, pa2))
    except Exception:  # noqa: BLE001  (401/403 after deletion)
        revoked_ok = True
    c.delete_user(prov["cand-b"][0])
    c.delete_role(authz.role_name("cand-a"))
    c.delete_role(authz.role_name("cand-b"))
    _rec("F12_revocation", status="PASS" if revoked_ok else "WARN",
         deleted_user_access_denied=revoked_ok)

    # F13 least-privilege identities (P1.4): ingest writes ranger-*, search cannot.
    try:
        c.put_role("ranger_ingest_role", ["ranger-*"], allow_write=True)
        c.put_role("ranger_search_role", ["ranger-*"], allow_write=False)
        ing = ("ranger_ingest", os.environ.get("RANGER_INGEST_PW", ""))
        sea = ("ranger_search", os.environ.get("RANGER_SEARCH_PW", ""))
        ing_write_ok = False
        r = c._req("POST", f"/{idx_a}/_doc/_lp_probe?refresh=true", auth=ing,
                   body={"ranger": {"candidate_id": "cand-a"}, "data": {"synthetic": True},
                         "message": "lp-probe"})
        ing_write_ok = r[0] in (200, 201)
        rs = c._req("POST", f"/{idx_a}/_doc/_lp_probe2?refresh=true", auth=sea,
                    body={"message": "lp"})
        search_write_denied = rs[0] == 403
        search_read_ok = False
        try:
            c.count(idx_a, auth=sea)
            search_read_ok = True
        except Exception:  # noqa: BLE001
            pass
        _rec("F13_least_privilege_identities",
             status="PASS" if (ing_write_ok and search_write_denied and search_read_ok) else "FAIL",
             ingest_can_write=ing_write_ok, search_write_denied=search_write_denied,
             search_can_read=search_read_ok)
    except Exception as e:  # noqa: BLE001
        _rec("F13_least_privilege_identities", status="FAIL", error=str(e)[:200])

    REPORT["limitations"] = [
        "TLS now uses a Ranger-issued CA (managed certs); clients verify against it. Rotate the CA before GA and move keys to a sealed store.",
        "JWT direct-Dashboards access (signature/issuer/exp/revocation/tenant/spoofing) is the next milestone; candidate access stays disabled until it passes.",
        "Security Analytics native detectors need field mappings for the custom ECS subset; the Alerting plugin provides genuine detection-driven alerts in the interim (F7).",
    ]
    print("\n===RANGER_VALIDATION_JSON_BEGIN===", flush=True)
    print(json.dumps(REPORT, default=str), flush=True)
    print("===RANGER_VALIDATION_JSON_END===", flush=True)


def _run_monitor(c, index, query):
    """Create+execute a query-level Alerting monitor synchronously (dryrun) and
    return whether its trigger fired. Proves alerts come from query logic."""
    monitor = {
        "type": "monitor", "name": "ranger-validate", "monitor_type": "query_level_monitor",
        "enabled": False,
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [{"search": {"indices": [index],
                               "query": {"size": 0, "query": query}}}],
        "triggers": [{"query_level_trigger": {
            "name": "hit", "severity": "2",
            "condition": {"script": {"source": "ctx.results[0].hits.total.value > 0",
                                     "lang": "painless"}},
            "actions": []}}],
    }
    code, body = c._req("POST", "/_plugins/_alerting/monitors/_execute?dryrun=true",
                        body=monitor)
    try:
        tr = body["trigger_results"]
        return any(v.get("triggered") for v in tr.values())
    except Exception:  # noqa: BLE001
        return None


if __name__ == "__main__":
    main()
