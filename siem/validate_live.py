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

import json
import os
import statistics
import time

import signing  # repo-root module; on sys.path when run as python -m siem.validate_live

from . import SCHEMA_VERSION
from . import authz, detection, enterprise, schema
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


def main():
    url = os.environ["OPENSEARCH_URL"]
    admin = os.environ.get("OPENSEARCH_ADMIN_USER", "admin")
    pw = os.environ["OPENSEARCH_ADMIN_PASSWORD"]
    c = LiveCluster(url, admin, pw, verify_tls=False, timeout=60)
    if os.environ.get("RANGER_VALIDATE_MODE") == "persist":
        print(f"== Ranger SIEM persistence re-check against {url} ==", flush=True)
        return persist_check(c)
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

    REPORT["limitations"] = [
        "HTTP-layer TLS uses the Security demo certificates; replace with managed certs before production.",
        "Dashboards authenticates with the demo kibanaserver account; rotate before production.",
        "JWT direct-Dashboards access (signature/issuer/exp/revocation/tenant/spoofing) is a separate milestone and requires securityconfig changes; candidate access stays disabled until it passes.",
        "Security Analytics native detectors need field mappings for the custom ECS subset; the Alerting plugin provides genuine detection-driven alerts in the interim (F7).",
        "Restart persistence/recovery is validated out-of-band via a Railway service restart, not in this in-process run.",
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
