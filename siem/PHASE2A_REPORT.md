# Qwalora Ranger — Phase 2a Railway Live Validation Pilot: final report

Date: 2026-10-15. Environment: Railway project `qwalora-ranger`, `production`,
region `us-west2`. All results below are from the **live** cluster, produced by
`siem/validate_live.py` running inside Railway's private network against
`opensearch.railway.internal`. Nothing is mocked.

## 1. What was provisioned

- **opensearch-5IDf** — single-node OpenSearch 2.17.1, Security plugin enabled,
  1 GB JVM heap, on a 10 GB persistent volume, private endpoint
  `opensearch.railway.internal:9200` (TLS). Custom pinned image (commit `6603a72`)
  whose only change over stock is a root entrypoint that fixes Railway volume
  ownership then drops to uid 1000 — OpenSearch runs non-root.
- **dashboards** — OpenSearch Dashboards 2.17.1 (stock image), private endpoint
  `dashboards.railway.internal:5601`, connected to OpenSearch over the private
  network as the restricted `kibanaserver` account. Security Analytics, Alerting,
  and Security dashboards plugins loaded.
- **siem-validator** — one-shot validation runner (pinned commit), restart NEVER.
- `portal` and `Postgres` were not modified.

No public domains on any SIEM service. No candidate OpenSearch users in steady
state. **No workspace-wide spending cutoff** was configured (per your directive),
so nothing can take down `portal`/`Postgres`; spend is observed via metrics.

## 2. Validation results (all against the live cluster)

| # | Family | Result | Evidence |
|---|---|---|---|
| F1 | Cluster health | PASS | status green, 1 node, HTTP 200 |
| F2 | Ingestion + field mapping | PASS | 404 generated = 404 indexed = 404 counted, 0 bulk errors, `ranger.candidate_id` mapped as `keyword` |
| F3 | Per-candidate authorization | PASS | per-candidate security role + internal user provisioned via the real Security API, DLS on `ranger.candidate_id` |
| F4 | **Candidate index isolation** | PASS | candidate A reads its own 404 docs; **A reading B's index is denied (403)** |
| F5 | **Document-level security** | PASS | in a shared index of 100 docs, A's DLS role returns only A's 48 docs |
| F6 | Detection from logic | PASS | 3 findings, 3 true positives, 0 false positives on real indexed data |
| F7 | Detection-driven alert | PASS | real Alerting monitor fires on malicious `winlog.event_id=4728`, stays quiet on the control query — alert comes from query logic, not a hardcoded object |
| F8 | Cross-source correlation | PASS | 1 correlated incident by identity (`davos.tully8`, 2 findings, escalated critical) |
| F9 | Evidence integrity | PASS | Ed25519 sign + verify succeed; a tampered snapshot fails verification |
| F10 | Progressive benchmark A→B | PASS | see metrics below |
| F12 | Revocation | PASS | a deleted candidate user can no longer authenticate/read |
| F13 | Restart persistence/recovery | PASS | after a Railway restart, pre-restart indices re-counted exactly (404 and 8,012); see §4 |

The validation left small test indices on the cluster (`ranger-pilot-*`, ~2 MB
total); they are harmless, carry only synthetic data, and are overwritten on the
next validation run or can be dropped before handover.

## 3. Measured performance, resource, and cost (actuals)

**Benchmark (Profile B = 8,012 events, single candidate, single-node 1 GB heap):**
- Ingestion: **1.3 s** for 8,012 docs = **~6,140 docs/sec** (chunked bulk, 1k/chunk).
- Query latency over representative queries: **p50 20.5 ms, p95 33.9 ms**.
- Index size: **2.1 MB** for 8,012 events (≈ 0.26 KB/event).
- JVM heap: 363.8 MB (33%) before → **722.4 MB (67%)** of 1,073.7 MB after the full
  Profile B ingest + query pass. Cluster stayed green throughout.

**Reading of the capacity question (the WORKLOAD_PLAN open item):** the earlier
worry that a 1 GB heap could not carry Profile B is **not borne out for data
volume** — a full Profile B single-candidate workload peaks at ~67% heap with
sub-35 ms p95 queries, and the data footprint is trivial (2.1 MB). The real
variable is **concurrent analytical load across many candidates**, which this pass
did not stress (it is single-threaded). Storage is a non-issue: even 50 candidates
at Profile B is ~100 MB, far under the 10 GB volume.

**Cost (actual Railway metrics, no caps set per your directive):** usage-based.
Measured over the pilot hour:
- OpenSearch: RAM ~1.6 GB steady, 2.0 GB peak during the benchmark; CPU ~0.03 vCPU
  average, 0.60 vCPU peak; volume 0.21 GB used of 10 GB.
- Dashboards: RAM ~0.19 GB steady, 0.56 GB peak; CPU ~0.004 vCPU average.

At Railway's rates (RAM $10/GB-mo, vCPU $20/vCPU-mo, volume $0.15/GB-mo) and the
steady footprint, projected SIEM cost is **~$22–28/month** (OpenSearch ≈ $16 RAM +
$1.50 volume + a few $ CPU; Dashboards ≈ $2–5). This is **under your $40 notify
threshold.** The number rises with sustained concurrent query load (more resident
RAM/CPU on OpenSearch); that is the trigger I will flag if it approaches $40. No
workspace spending cutoff is set, so nothing here can interrupt `portal`/`Postgres`.

## 4. Restart persistence/recovery (F13)

OpenSearch was restarted via Railway. After restart, the indices written before the
restart were re-counted without re-ingesting — **data survived exactly**:

- `ranger-pilot-cand-a-b2`: **404** docs (unchanged)
- `ranger-pilot-bench-b2`: **8,012** docs (unchanged)
- Heap after restart: 515 MB (47%). Result: **PASS**.

Cluster status reads `yellow` post-restart: on a single node the replica shards of
the auto-created system indices (Security, Alerting, Security-Analytics, `.kibana`)
cannot be placed, so they show unassigned. All primary shards are assigned and all
data is readable; this is expected single-node behavior, not data loss. Setting
`number_of_replicas: 0` on those index templates makes it report green and is a
cosmetic follow-up.

## 5. Honest limitations (documented, not worked around)

1. **TLS certificates are the Security demo certs** on the HTTP layer. Transport and
   HTTP are encrypted, but these certs are well-known and must be replaced with
   managed certs before production.
2. **Dashboards uses the demo `kibanaserver` account.** Rotate before production.
3. **The admin password was passed as a Railway service variable** and, for the
   Nixpacks-built validator, is baked into that image's build args. Rotate the admin
   credential after the pilot; prefer a sealed secret and a dedicated broker account.
4. **JWT direct-to-Dashboards candidate access is not yet enabled.** It requires
   security-config changes (authc JWT domain, issuer/key, claim validation) and its
   own test battery (signature, issuer, `aud`/`iss`/`exp`, revocation, role mapping,
   tenant separation, spoofing resistance). Until that battery passes,
   **candidate access stays disabled** — which satisfies your item 10. The
   backend-brokered path (the preferred one) is validated and working now.
5. **Security Analytics native detectors** need field mappings between the custom
   ECS subset and SA log types; the `logtypes` probe returned 400 on this version's
   path. Genuine detection-driven alerting is proven via the Alerting plugin (F7) in
   the interim; native SA detectors are a follow-up, documented rather than faked.
6. **Concurrency was not stress-tested.** Profile C (bounded concurrent load) is the
   next benchmark; only it can set the safe concurrent-candidate ceiling.

## 6. Production resource recommendation

- Data volume does not require more heap. **Keep 1 GB heap for the pilot and early
  cohorts.** Revisit only against a Profile C concurrency benchmark, not preemptively.
- When concurrency is tested and if p95 or heap pressure rises, the first lever is
  **2 GB heap / 4 GB container** (est. +$15–20/mo), brought back to you with the
  concurrency numbers before any change — not applied preemptively.
- Before any candidate access: replace demo certs, rotate admin + `kibanaserver`,
  and complete the JWT test battery.

## 7. What did not change

The existing Board 2 grader and the **95% qualification threshold are unchanged.**
An extended rubric (v2) is proposed in `BOARD2_RUBRIC_V2.md` as a flagged, versioned,
shadow-gradable option for your separate approval; it is not active and does not
alter v1 grading.
