# Board 2 Enterprise SOC: workload plan and envelope sizing (for approval)

The directive raises Board 2 to a financial-sector-grade SOC investigation. This
plan finalizes the workload and assesses, honestly, whether the already-approved
pilot envelope carries it. **No paid provisioning happens until you approve.**
This container cannot run OpenSearch, so the live benchmark and Security Analytics
feature verification run only after provisioning is approved.

## What is built and proven offline (no cluster)

- **Enterprise telemetry generator** (`siem/enterprise.py`): a coherent fictional
  financial org (identities, service accounts, tiered admins, assets, five business
  apps, five network segments) across eleven data sources, with diurnal timestamps,
  plausible source/destination relationships, heavy benign noise generated
  independently of the incident truth, and realistic imperfections (delayed and
  out-of-order arrival, partial observability).
- **Five scenario families** with hidden server-side truth models (privileged-identity
  compromise, data exfiltration, compromised service identity, endpoint lateral
  movement, detection failure). Truth labels, techniques, and verdicts are returned
  to the Ranger backend only; they are never written to a candidate index.
- **Sigma detection + correlation** (`siem/detection.py`) with an offline evaluator.
  On a reference Profile B dataset (8,013 events, 13 malicious in 8,000 benign across
  8 sources): findings derive from rule logic, the non-gapped incidents are detected,
  and the detection-failure incident is a **genuine false negative** the candidate
  must find. 24 SIEM tests pass.

## Three workload profiles

| Profile | Benign events / candidate | Incidents | Span | Purpose |
|---|---|---|---|---|
| A Functional | ~400 | 1 | 2 days | dev, grading regression, authorization and isolation tests |
| B Enterprise Investigation | ~8,000 (scalable) | 3 | 14 days | the required Board 2 experience |
| C Stress Benchmark | ~40,000 | 5 | 30 days | bounded burst to find the safe ceiling; never continuous |

Data size is small: Profile B is ~8 MB/candidate (~200 MB for 25 candidates). Storage
is not the constraint. The constraints are heap and query concurrency.

## Honest envelope sizing assessment

The approved pilot envelope is OpenSearch 2 GB RAM / 1 vCPU / **1 GB heap** + 10 GB
volume, Dashboards 1 GB / 0.5 vCPU.

- **Sufficient on the approved envelope:** Profile A, the full ingestion/mapping
  pipeline, candidate isolation, JWT auth, persistence and recovery. These are what
  the first provisioning validates.
- **At risk on a 1 GB heap:** Profile B as a live experience with the **OpenSearch
  Security Analytics** plugin running detectors + correlation **and** several
  candidates issuing analytical queries at once. Security Analytics is heavier than
  plain search (scheduled detector queries, findings/alerts/correlation indices), and
  1 GB is the documented floor for light workloads. Concurrent aggregations on a 1 GB
  heap risk GC pauses and circuit-breaker trips.

I will **not assume** the ceiling. The plan measures it:

**Phase 2a (within the approved envelope, no limit increase, no new spend):**
provision at the approved 1 GB-heap envelope, run functional validation (ingestion,
isolation, JWT, persistence, recovery), then a **progressive benchmark** that scales
the Profile B dataset size and query concurrency step by step until pressure appears,
recording at each step: total generated, indexed, rejected and duplicate events,
ingestion throughput, search latency (p50/p95), CPU, memory, index size, JVM heap
usage and GC, disk watermarks, and recovery behavior. A system that silently drops
telemetry fails this gate.

**Decision point after 2a:** if the benchmark shows 1 GB cannot carry the target
Board 2 Profile B experience (the likely outcome), I report the measured safe dataset
size and concurrency and recommend a bump to **OpenSearch 2 GB heap / 4 GB RAM** (est.
**+$15 to $20/month**, bringing the SIEM to ~$45 to $53/month incremental). That
increase requires your explicit approval before it is applied; the limits are not
raised without it.

## Security Analytics feature support

Pinned OpenSearch 2.17.x includes Security Analytics with Sigma rule import, detectors,
findings/alerts, and the correlation engine. Each is verified against the deployed
version at provisioning; if any specific capability is missing or incompatible, it is
documented as a limitation, not replaced with fake functionality.

## Candidate access and JWT validation plan

Both the backend-brokered path (preferred) and Dashboards-via-JWT are enforced at the
OpenSearch Security layer. "A JWT with a role claim" is not treated as secure by
itself; before candidate access is enabled the following are tested against the real
cluster: the token signature and the trusted issuer/key (OpenSearch trusts only
Ranger's issuer and key), `aud`/`iss`/`exp` claim validation, short expiry, revocation
(a broker-maintained `jti` denylist plus short TTL), `backend_role` to index/DLS role
mapping, index-level authorization, document-level security, saved-object tenant
separation, direct-API restriction, and header/role spoofing resistance (forged token,
wrong issuer, expired, replayed, and altered-claim tokens must all be rejected). No
shared admin credential is exposed. **Candidate access is not enabled until
cross-candidate isolation passes against the real cluster.**

## Ranger case management and evidence

Ranger owns case management and grading. The case workspace (built in the Ranger
backend, not a Dashboards imitation) holds incident notes, a constructed timeline,
evidence references (event_uids plus the exact queries used), asset/identity
association, ATT&CK techniques, impact, containment and remediation recommendations,
and stated confidence and limitations. On submission, Ranger takes an **immutable
snapshot signed with the existing Ed25519 evidence capability**. Hidden answers and
grading logic stay in the protected backend; the answer key is never in indexed
telemetry. Credit is for demonstrated competence against the Board 2 rubric, not for
running queries or opening alerts.

## Grader compatibility (flagged for your decision)

The existing `score_board2` grades the current hunting submission shape. The enterprise
case report, queries, and timelines are a richer deliverable. Per your instruction,
this is a **compatibility gap to confirm before changing the rubric**: either the
enterprise surface enriches the investigation while grading stays on the existing
answer-free model, or the rubric is extended, which needs your approval. I will not
change the grading rubric without it.

## Approval requested

1. Approve provisioning **Phase 2a at the already-approved 1 GB-heap envelope**
   (~$27 to $33/month, no new spend) to run functional validation and the progressive
   benchmark.
2. Acknowledge that a heap/RAM bump for the full Profile B experience (est.
   +$15 to $20/month) will be brought back to you with the benchmark data before any
   limit is raised.
3. Confirm the grader-compatibility direction (enrich vs extend the rubric).
