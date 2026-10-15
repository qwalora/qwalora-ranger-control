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

## 4. Hosting: Railway suitability and the VPS alternative

**Railway is not suitable for the OpenSearch data node**, for concrete reasons:

- OpenSearch requires `vm.max_map_count = 262144`, a host-level kernel sysctl.
  Railway runs managed containers and does not expose host sysctl control, so
  OpenSearch fails its bootstrap checks in production mode. Disabling bootstrap
  checks or forcing single-node discovery to get around this produces an unreliable
  indexer, which the brief explicitly warns against.
- JVM memory locking (`bootstrap.memory_lock`) and guaranteed high-IOPS persistent
  volumes are not dependable under Railway's shared, memory-limited model.

**Keep the Ranger portal and Postgres on Railway** (they are small and already run
well there). **Run OpenSearch + Dashboards on a modest dedicated VPS** where kernel
settings, a mounted persistent volume, TLS, and the Security plugin are fully under
our control. A Hetzner CX32 (4 vCPU / 8 GB / 80 GB, about 16 USD/month) or
equivalent meets the sizing with margin.

## 5. Projected monthly cost

| Component | Host | Est. USD/month |
|---|---|---|
| Ranger portal | Railway, always-on | 5 to 15 |
| Postgres | Railway | 5 to 10 |
| OpenSearch + Dashboards node (4 vCPU / 8 GB / 80 GB) | VPS (Hetzner CX32 class), always-on | 16 to 20 |
| Snapshots / volume / egress | VPS provider | 2 to 6 |
| **Phase 2 baseline total** | | **~28 to 51 USD/month** |

Comfortably inside the 300 USD/month combined budget, leaving headroom for the
Phase 3 GOAD host. OpenSearch is stateful and continuously ingesting at the JVM
level, so it does not cleanly scale to zero; the honest model is a small always-on
node, which is cheap enough that always-on is the right call. These are current-list
estimates to confirm at provisioning, not quotes.

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

Approve, with any changes: (a) OpenSearch + Dashboards as the platform; (b) the
dedicated VPS (Hetzner CX32 class, ~16 to 20 USD/month) rather than Railway for the
OpenSearch node; (c) the ~28 to 51 USD/month Phase 2 operating cost; (d) the
isolation and credential-mapping model above. On approval, the node is provisioned
and the built components are validated against it.
