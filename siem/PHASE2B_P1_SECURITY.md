# Phase 2b Priority 1 — Production security hardening (COMPLETE, validated live)

Date: 2026-10-15. All results produced against the live Railway cluster by
`siem/validate_live.py` running inside the private network. Candidate access
remains disabled.

## Results

| Req | Item | Status | Evidence |
|---|---|---|---|
| P1.1 | Replace demo TLS with managed certs | DONE | Ranger EC PKI (CA + node + admin), delivered as runtime secrets and written at startup; OpenSearch booted with them, no SSL errors. Demo certs gone. |
| P1.6 | Enable verification, remove insecure settings | DONE | Validator connects with `ssl.create_default_context(cafile=Ranger CA)` and the full suite passed over verified TLS; Dashboards runs with `OPENSEARCH_SSL_VERIFICATIONMODE=full` + the Ranger CA and connects cleanly (saved-object migrations + http server up). Node cert SAN `opensearch.railway.internal` satisfies hostname verification. |
| P1.2 | Rotate admin + Dashboards creds (incl. validator build-arg exposure) | DONE | `securityadmin` rotated the reserved `admin` and `kibanaserver` on first boot ("reserved creds rotated"); the old admin password no longer authenticates. The validator was converted to a Dockerfile build so service variables are no longer baked into image layers. |
| P1.3 | Audit images/logs/repo/vars for secret exposure | DONE | Git history carries no admin password, private key, or secret file; all OpenSearch passwords are read from env. No public domains/proxies. Only remaining exposure was the old admin password in the prior Nixpacks validator image — retired by rotation + Dockerfile build. |
| P1.4 | Distinct least-privilege identities | DONE | `admin` (break-glass), `kibanaserver` (Dashboards), `ranger_ingest` (write ranger-*), `ranger_search` (read ranger-*), `ranger_validator` (isolated test identity). F13: ingest can write, search is write-denied (403) and read-allowed. |
| P1.5 | OpenSearch + Dashboards private only | DONE | `list-domains`/`list-tcp-proxies`: no service domains, custom domains, or TCP proxies on either service. Reachable only via `*.railway.internal`. |
| P1.7 | Backup restore (not just restart) | DONE | Registered an fs snapshot repo on the volume, snapshotted a 405-doc index, DELETED it, restored from the snapshot → 405 docs returned (register/snapshot/restore all HTTP 200). |
| P1.8 | Preserve portal + Postgres | DONE | Neither service was modified; both remained live throughout. No workspace spending cutoff. |

## Full re-validation against the hardened cluster (all PASS, over verified TLS)

F1 health (yellow, single-node expected) · F2 ingestion/mapping · F3 per-candidate
authz · F4 cross-candidate isolation (403) · F5 document-level security · F6
detection-from-logic (3 TP / 0 FP) · F7 detection-driven Alerting monitor · F8
correlation · F9 evidence sign/verify/tamper · F10 benchmark (6,921 docs/s, p50
17.2 ms, p95 22.7 ms, heap ~40%) · F12 revocation · F13 least-privilege identities.

## Notes / residual

- TLS uses a Ranger-issued CA. Rotate the CA before GA and move private keys to a
  sealed secret store (currently Railway runtime variables, not in repo or image
  layers).
- Cluster status is `yellow` on a single node (replica shards of system indices
  unassigned); all primaries assigned, all data available.
- Candidate access stays disabled until Priority 2 (JWT Dashboards auth + isolation)
  is independently validated.

## Still open in Phase 2b

P2 GitHub-linked JWT Dashboards auth + enforceable revocation; P3 full SOC
experience on real telemetry; P4 Profile C concurrency benchmark; P5 Board 2
assessment integration (grader + 95% preserved; v2 shadow).
