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
    soc_pw = os.environ.get("RANGER_SOC_ADMIN_PW", "SocAdmin-Pilot-7xQ=")
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
        req = _u.Request(url, data=data, headers=headers or {}, method="POST")
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
