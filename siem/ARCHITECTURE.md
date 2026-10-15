# Ranger Phase 2: Shared SOC / OpenSearch SIEM

Architecture, resource sizing, cost, and security design for the Boards 1 to 4
operational SIEM. **This is the review-and-approve deliverable. No paid
infrastructure is provisioned until this architecture, sizing, cost, and security
design are approved.** Ludus and GOAD are out of scope for Phase 2 (Phase 3).

Status of execution: the Ranger-side components (schema, telemetry generator,
authorization model, credential mapping, ingestion pipeline) are built and
unit-tested in this repository against an in-process fake OpenSearch. They have
**not** been validated against a live OpenSearch cluster, because that requires the
approved node. Nothing here claims live-cluster verification.

## 1. Audit of the existing backend and hosting

- **Control plane:** Flask + Flask-SQLAlchemy + gunicorn, Postgres, APScheduler
  worker, on Railway. GitHub OAuth is the only candidate authentication. Candidate
  lifecycle is pending -> active -> graduated/withdrawn/washed_out (+ rejected);
  `status == "active"` is the admission gate, `current_board` the board gate.
- **Evidence:** board clearances and certificates are Ed25519-signed and publicly
  verifiable. Evidence lives in Postgres, independent of any SIEM.
- **Boards 1 to 4 today:** `scenarios.generate_boardN(seed)` produces a
  per-candidate dataset that is a pure function of the candidate's scenario seed.
  `public_boardN(scenario)` is the investigation surface with the answer key
  stripped; the hidden `_key` (verdict, technique, IOCs) stays server-side.
  `score_boardN` re-derives the answer from the seed, so grading is answer-free and
  there is no stored answer to leak.
- **What Phase 2 changes:** the same per-candidate public events are ingested into a
  per-candidate OpenSearch index so candidates investigate with real OpenSearch
  queries instead of a static JSON view. **The answer key is never ingested.**
  Grading, identity, admission, and board authorization stay in the Ranger backend
  unchanged.

## 2. Target architecture

```
                         GitHub OAuth (unchanged)
                                 |
   Candidate ---- HTTPS ----> Ranger portal (Railway) ----+   admin cred (secret)
      |                         | Postgres (state, seeds, |   held ONLY here
      |                         | evidence, answer keys)  |
      |                         +-- SIEM broker ----------+----TLS---> OpenSearch
      |                              (mints scoped creds,            Security plugin
      |                               seeds telemetry,               (VPS, always-on)
      |                               enforces board/cohort)              |
      |                                                                   |
      +------------------ HTTPS (scoped credential) --------> OpenSearch Dashboards
                                                              (investigation UI)
```

- **OpenSearch** (single node): indexing and search. Runs the Security plugin for
  authentication, TLS, and index/document-level authorization.
- **OpenSearch Dashboards**: the investigation interface candidates log in to.
- **SIEM broker** (new code in the Ranger backend, `siem/`): the only component that
  holds the OpenSearch admin credential. It mints per-candidate scoped roles and
  short-lived users, seeds normalized telemetry into the candidate's index, and
  enforces that a candidate is active, approved, and on the right board before any
  access is granted.
- **Isolation boundary:** one index per candidate-board
  (`ranger-<cohort>-<candidate>-b<N>`); each candidate's OpenSearch role grants read
  on only that index pattern. Document-level security on `candidate_id` is applied as
  a second layer. This is enforced by the OpenSearch Security plugin at the REST API
  layer, not only in Dashboards.

Boards 1 to 4 share the one OpenSearch node; Boards 5 to 6 are separate Ludus/GOAD
ranges in Phase 3 and are not part of this.

## 3. Resource sizing (small cohort)

The sizing is driven by OpenSearch's JVM baseline, not by data volume: a Ranger
candidate's dataset is tiny (Board 1 is ~12 to 16 events; the Board 3 corpus is at
most a few thousand small documents).

| Dimension | Estimate | Basis |
|---|---|---|
| OpenSearch JVM heap | 2 GB | heap <= 50% RAM; 2 GB is a sound single-node floor |
| OpenSearch + Dashboards RAM | 4 to 6 GB host | 2 GB heap + OS page cache + Dashboards (Node, ~0.5 to 1 GB) |
| vCPU | 2 to 4 | bursty seeding and interactive search, not streaming ingest |
| Index storage | < 1 GB of candidate data | 25 candidates x ~5,000 docs x ~1 KB ~= 125 MB; allocate 20 GB for indices + translog + margin |
| Snapshots | +10 GB | daily snapshot repository on the same volume or object storage |
| Ingestion volume | bursty, tiny | seeding happens on board access, not continuously |

Recommended node: **4 vCPU / 8 GB RAM / 80 GB SSD.** 8 GB gives the 2 GB heap room
plus page cache and Dashboards headroom; 80 GB SSD is far more than the data needs
and covers snapshots and growth. Retention: candidate indices are deleted on board
completion and at cohort end; evidence persists in Postgres independently.

Scaling thresholds (documented triggers, not auto-scaling): raise heap to 4 GB (node
to 16 GB RAM) past ~50 concurrent candidates or if heap pressure exceeds 75%
sustained; add a second data node only if a single node cannot hold the working set
in page cache, which is far beyond the initial cohort.

## 4. Hosting: Railway vs a VPS (revised after checking both)

Two things in the first draft of this section were wrong, and correcting them
changes the recommendation to **run OpenSearch on Railway**, not a VPS.

**Correction 1: Railway can run OpenSearch reliably.** My objection was that
OpenSearch needs the `vm.max_map_count = 262144` sysctl, which Railway does not let
you set. But in **single-node mode** (`discovery.type=single-node`) OpenSearch
**skips the production bootstrap checks**, so that sysctl and the `memlock`/`nofile`
ulimits are not required. Single node is exactly our design (one small shared node
for Boards 1 to 4). Published Railway OpenSearch templates confirm this: they boot,
keep their index on a Railway volume across redeploys, run the Security plugin for
authentication, and run OpenSearch + Dashboards together. The two real Railway
quirks both have known fixes: Railway mounts the volume as root (an entrypoint takes
ownership and drops to the `opensearch` user), and Railway terminates TLS at its edge
and speaks HTTP internally (so OpenSearch's HTTP-layer TLS is turned off while the
Security plugin's transport encryption and authentication stay on).

**Correction 2: the VPS is not cheaper any more.** My ~16 USD/month VPS figure was
stale. After Hetzner's June 2026 reprice, a current 4 vCPU / 8 GB instance is about
**39 USD/month** (the cheaper 8 GB CX/CAX lines showed as unavailable in mid-2026).
That is at parity with Railway for this workload, not below it.

**Revised recommendation: run OpenSearch + Dashboards on Railway**, in the existing
qwalora-ranger workspace next to the portal and Postgres, because at cost parity the
single-provider option is simpler and, in one respect, more secure:

- The OpenSearch REST API stays on **Railway's private network**: the broker (portal)
  and Dashboards reach it internally, and the API need not be exposed publicly at all.
  Only Dashboards is a public surface, behind Railway's edge TLS. A VPS puts a public
  server on the internet to harden, patch, firewall, and monitor.
- One provider, one bill, one control plane, one secret store. No OS patching, no
  Let's Encrypt lifecycle, no second attack surface.
- The Security plugin (authentication + index/document-level roles) does the candidate
  isolation regardless of HTTP-layer TLS, so isolation is unaffected by the edge-TLS model.

We do **not** use the convenience templates as-is: the two-service one disables the
Security plugin, and we require it on. The build is two Railway services (OpenSearch
and Dashboards) from **pinned official images** with a small entrypoint for volume
ownership, the **Security plugin enabled**, single-node, a persistent volume, the API
private, and Dashboards the only edge-TLS surface.

The honest tradeoff that would favor a VPS: a mandate for **end-to-end HTTP-layer TLS
with our own certificates** (Railway's edge-TLS model means plaintext on its private
network internally), or a future need for a **multi-node** cluster. For synthetic
telemetry with no real secrets and a single small node, neither applies now. The VPS
stays documented as the fallback if either requirement emerges.

## 5. Projected monthly cost (actual rates, October 2026)

Railway bills actual usage: RAM at 10 USD/GB-month, vCPU at 20 USD/vCPU-month, volume
at 0.15 USD/GB-month, egress at 0.05 USD/GB (Pro plan 20 USD/month per workspace, with
20 USD of usage credit). OpenSearch at a 2 GB heap sits around 2.5 GB resident;
Dashboards adds ~0.7 GB; CPU is bursty (seeding on board access, interactive search),
so average vCPU is low.

| Component | Host | Est. USD/month |
|---|---|---|
| OpenSearch RAM (~2.5 GB) | Railway | ~25 |
| OpenSearch Dashboards RAM (~0.7 GB) | Railway | ~7 |
| vCPU (bursty, ~0.3 to 0.5 avg) | Railway | ~6 to 10 |
| Volume (10 GB) | Railway | ~1.5 |
| Egress (mostly private network) | Railway | ~1 to 3 |
| **Phase 2 SIEM on Railway (incremental)** | | **~40 to 47 USD/month** |
| Membership context: same on a 4 vCPU / 8 GB VPS | Hetzner, flat | ~39 to 42 plus self-managed ops |

Either option lands near 40 USD/month; the existing portal + Postgres (~10 to 25) are
unchanged. Total Phase 2 stays well inside the 300 USD/month budget with headroom for
the Phase 3 GOAD host. OpenSearch is stateful and continuously holds its JVM heap, so
it does not cleanly scale to zero; a small always-on node is the honest model, and it
is cheap enough that always-on is correct. Rates are current list as of October 2026,
to confirm at provisioning, not quotes.

## 6. Candidate isolation model

- **Index per candidate-board:** `ranger-<cohort>-<candidate_id>-b<board>`. Primary
  isolation.
- **OpenSearch role per candidate:** read-only on exactly that index pattern, no
  cluster privileges, no write. Defense in depth: document-level security restricting
  to `candidate_id == <id>`.
- **Role mapping:** the candidate's minted OpenSearch user maps only to their role.
- **Credential mapping (Ranger-managed):** on authorized board access, the SIEM
  broker calls the OpenSearch Security API (with the admin credential held only in
  the Ranger backend) to ensure the candidate's role, user, and role mapping exist,
  then issues the candidate a short-lived, scoped credential for Dashboards/API.
  GitHub OAuth remains the candidate's Ranger identity; `github_id` maps to the
  OpenSearch user. Credentials are rotated and revoked on any status change
  (withdrawn, washed out, graduated, rejected) and on board change.
- **No shared admin credential ever reaches a candidate or the frontend.** Dashboards
  private tenants separate saved objects but are **not** relied on for data isolation.

The isolation tests (Section 9) assert, against the Security model, that candidate A
reads only A's index and that a direct REST query for B's index is denied for A, at
the API layer, not only in Dashboards.

## 7. Telemetry

Normalized to an Elastic Common Schema (ECS) aligned shape so one query language
spans sources. Sources and the Ranger board they primarily serve:

- **Linux security** (Board 1, 2, 4): SSH auth success/failure, sudo/privilege,
  service and process events, file permission changes, sysadmin events.
- **Windows and identity** (Board 1, 4): logon (4624) and failed logon (4625),
  privileged logon (4672), group membership change (4728/4732), process creation
  (4688) where a suitable dataset exists.
- **Network** (Board 2, 4): DNS queries, suspicious connection patterns, HTTP
  requests, intrusion indicators, firewall allow/deny.
- **Investigation scenarios** (all): credential misuse, unauthorized access,
  suspicious privilege activity, host persistence, abnormal network communication,
  and multi-event incident timelines that correlate across the above.

Every event carries a documented origin, schema version, time context, and scenario
association, and is tagged `data.synthetic: true` with the generator version in
`ranger.provenance`. **Synthetic events are clearly identified as synthetic and are
never claimed to be observed on a live production system.** The existing per-seed
generators feed this; the answer key is never included.

## 8. Security

TLS on the OpenSearch transport and REST layers and on Dashboards; Security plugin
authentication required on every request; least-privilege service identities (the
broker's admin credential is the only privileged one and lives only in the Ranger
backend secret store); candidate-specific read-only authorization; the ingestion
endpoint is internal to the broker and never exposed to candidates; secrets in
Railway's secret store, never in the frontend or the repo; OpenSearch audit logging
enabled; administrative interfaces not exposed publicly without auth and network
restriction; and documented data retention and deletion (candidate indices deleted on
completion and cohort end).

## 9. Verification plan (runs against the approved node)

The tests in `siem/tests/` run today against an in-process fake OpenSearch to prove
the Ranger-side logic. The same suites run against the real node once provisioned:

- **Telemetry:** events indexed; searches return expected records; timestamps and
  mappings correct; datasets seed repeatably; duplicate ingestion handled; reset and
  reseed predictable.
- **Isolation:** A reads A; A cannot read B; B cannot read A; direct REST queries
  enforce the same; Dashboards cannot bypass index authorization.
- **Ranger integration:** unapproved candidates get no SOC access; approved
  candidates get board-scoped access; revoked candidates lose access; evidence stays
  linked to the correct candidate and board.
- **Infrastructure:** data persists across restarts; health checks detect failure;
  backup and recovery work; storage and memory measured; ingestion failures reported.

Live-cluster results will be recorded with the same signed-evidence discipline used
elsewhere. **Phase 2 is not complete until approved candidates investigate real
indexed events in an isolated cluster and Ranger enforces authorization and binds
evidence to the correct candidate and board.**

## 10. Decision required before provisioning

Approve, with any changes: (a) OpenSearch + Dashboards as the platform; (b) hosting
it on **Railway** (single-node, Security plugin on, pinned images, API on the private
network, Dashboards behind edge TLS) rather than a VPS, since at ~40 USD/month the two
are at cost parity and Railway is the simpler, single-provider option; (c) the
~40 to 47 USD/month incremental Phase 2 operating cost; (d) the isolation and
credential-mapping model above. On approval, the two services are provisioned on
Railway and the built components are validated against the live cluster. The VPS
remains the documented fallback only if end-to-end HTTP-layer TLS or a multi-node
cluster becomes a hard requirement.
