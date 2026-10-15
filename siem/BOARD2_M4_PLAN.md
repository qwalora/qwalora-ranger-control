# Board 2 Milestone 4 — Continuous SOC Operations: implementation plan (approved with corrections)

Status: **architecture conditionally approved**; development, offline validation, and a
**bounded live streaming pilot on synthetic test identities** using the existing Railway
services are authorized. The 25-candidate workload is **not** authorized yet, and no new
paid infrastructure or material resource expansion happens without a separate cost
review. General candidate access and act-as stay disabled. The M3 enterprise grader
stays shadow-only; `PASS_BAR = 95.0` is preserved; candidate qualification is never
driven by the new grader.

Goal: a genuinely functioning enterprise SOC training environment with continuously
arriving telemetry, authentic OpenSearch detections, realistic incidents, and
measurable operational performance. Not a dashboard with moving numbers.

This revision folds in the eight review corrections.

---

## 1. Workload model (corrected)

**Correction absorbed.** The earlier aggregate figure was wrong: aggregate peak is
`N_candidates × peak_EPS_per_candidate`, so 25 candidates at 2 peak EPS each is
**50 aggregate peak EPS**, not 6–7. The 0.25 EPS average is a functional smoke-test
rate only and is **not** represented as a validated enterprise workload.

Three benchmark profiles. The EPS values below are **proposed targets**; expected
event counts, storage growth, and resource requirements are **modeled estimates to be
replaced by measured numbers** from the Phase-2a benchmark before any cohort sizing is
recommended. Event size assumed ~1 KB ECS-normalized (to be measured).

| Profile | Peak EPS / cand | Avg EPS / cand (diurnal) | Events / cand / day | ~Storage / cand / day | Purpose |
|---|---|---|---|---|---|
| **Functional** | 0.5 | 0.1 | ~8.6k | ~9 MB | low-rate ingestion + recovery/backpressure testing; smoke only, NOT an enterprise workload |
| **Operational** | 8 | 2 | ~173k | ~170 MB | realistic multi-source activity with a meaningful investigation workload (the training target) |
| **Stress** | 25 | 8 | ~690k | ~675 MB | bounded burst to find the safe ceiling for concurrency, detectors, and query pressure; never continuous |

Aggregate peak EPS = `N × peak`. Example planning points (to be validated, not
provisioned): Operational at 10 candidates = 80 peak EPS; at 25 = 200 peak EPS.
Storage is now a real driver (Operational ≈ 170 MB/cand/day), so ISM rollover + delete
and volume sizing are first-class (see §6, §10). The benchmark reports measured EPS,
indexed/rejected/dup counts, index size growth, heap/GC, CPU, and query latency per
profile; a profile that silently drops telemetry fails its gate.

## 2. Genuine OpenSearch detections (corrected)

**Correction absorbed.** The live SOC experience uses **actual OpenSearch Security
Analytics** detectors, findings, and alerts where supported and validated against the
pinned 2.17.x cluster. `detection.py` is retained for offline validation, test
comparison, and grading support only; Ranger-generated alert records are **never**
presented as native detector output.

Mandatory demonstration (Phase M4.2), end to end on a synthetic test identity:

```
indexed security event  ->  Security Analytics detector execution  ->  finding/alert
                                                                          ->  candidate investigation
```

Concretely: import Sigma rules as detectors against the candidate's operational index;
confirm a seeded malicious event triggers a detector run that writes a finding/alert to
the candidate-scoped findings/alerts indices; confirm the finding is visible in the
candidate investigation surface and carries no hidden-truth field. Any Security
Analytics capability that is missing or incompatible on the deployed version is
documented as a limitation, never faked. Detectors run against the real cluster; this
part cannot be validated in the offline container and is gated on the live pilot.

## 3. Operational metrics (corrected)

**Correction absorbed.** Each metric has an explicit formula, timestamp source, and
denominator. Case submission time is **not** labeled remediation time. No metric
exposes hidden scenario truth. A metric with no valid underlying measurement is marked
**unavailable**, never defaulted or invented.

| Metric | Formula | Timestamp / source | Denominator / scope | Truth-safe? |
|---|---|---|---|---|
| Ingestion rate (EPS) | indexed docs / window seconds | bulk responses + `_cat/indices` doc counts over time | per candidate index, per tick | yes |
| Ingestion latency | `event.ingested − @timestamp` (p50/p95) | the two timestamps already on every doc | per candidate index | yes (no truth) |
| Detection latency | `finding.timestamp − triggering_event.@timestamp` | Security Analytics finding doc + its mapped event | per detector finding | yes (finding is not truth) |
| Time to acknowledge (TTA) | `analyst_ack_ts − finding.timestamp` | finding doc + Ranger case action log (candidate ack) | per acknowledged finding | yes |
| Investigation duration | `case.submitted_at − case.started_at` | Ranger `cases` table | per case | yes (labeled investigation time, NOT remediation) |
| Detector execution failures | failed detector runs / total runs | Security Analytics detector run history / job errors | per detector, per interval | yes |
| Telemetry source health | sources seen in window / expected sources; last-seen age | per-source last `@timestamp` from the candidate index | per candidate, per source | yes |

Remediation/MTTR is **not** reported in M4 because there is no authentic remediation
action to timestamp; it is marked unavailable rather than aliased to submission time.
Any metric whose inputs are absent (e.g., no findings yet) renders as "unavailable",
not zero.

## 4. Two data planes (corrected, preserved)

| Plane | Timestamps | Determinism | Index | Drives qualification? |
|---|---|---|---|---|
| **Qualification** | fixed scenario anchor (2026-03-01…) | deterministic, versioned (`SCENARIO_VERSION`), reproducible from seed | `ranger-<cohort>-<slug>-b2` | yes (existing `score_board2`; M3 grader shadow-only) |
| **Operational** | **current wall-clock**, continuously arriving | deterministic in content given (seed, engagement_start); timestamps track real time | `ranger-op-<cohort>-<slug>-b2` (distinct) | **no** |

The operational stream writes only to the distinct `ranger-op-*` index and never
touches qualification evidence, grades, hidden truth, or the signed M3 records. The
qualification generator (`enterprise.generate`) is unchanged and stays the reproducible
source of record for grading.

## 5. Safe stream recovery (corrected)

- **Persistent watermark** per (candidate, plane) in Postgres: the arrival-time boundary
  already streamed. Advanced only after a window is fully processed (indexed or
  dead-lettered), so nothing is silently lost.
- **Deterministic event ids**: uid = hash(seed, profile, engagement_start, sequence),
  stable across replays.
- **Idempotent indexing**: bulk `op_type=create`; a replayed uid returns 409
  version-conflict, treated as already-indexed (no duplicate).
- **Retry controls**: per-doc failed items retried with bounded exponential backoff.
- **Bounded queue + backpressure**: on 429 / circuit-breaker the watermark does not
  advance and emission slows; a bounded pending set caps in-flight work; the driver
  never drops to relieve pressure.
- **Dead-letter / error visibility**: a doc that keeps failing past max retries is
  recorded in a visible dead-letter channel (with reason), and the watermark still
  advances past the window so the stream is not wedged; the dead-letter is re-drivable.
- **Validated offline** (M4.1) against: partial bulk failure, worker interruption
  mid-window, delayed and out-of-order arrival, duplicate delivery, and backpressure.

## 6. Candidate isolation (corrected, preserved)

- A candidate reads only their own operational index, their own qualification index, and
  their own findings/alerts; enforced by index-level authz + DLS + saved-object tenant
  separation (the Stage-1 model, extended to the `ranger-op-*` and findings indices).
- No cross-candidate findings, saved objects, index queries, or incident metadata are
  reachable. Verified against the real cluster before any multi-identity pilot step.
- General candidate access and act-as remain disabled by their existing flags; the
  stream itself is gated by a new `RANGER_TELEMETRY_STREAM` (default off).

## 7. Pilot scope (corrected)

- Authorized: development, offline validation, and a **bounded live streaming pilot
  using synthetic test identities** (the existing `board2-test`) on the existing
  Railway services. The 25-candidate workload is not activated.
- Benchmark actual detector activity, query latency, heap, CPU, storage, indexing
  health, and Railway consumption **before** recommending cohort concurrency.
- No new paid infrastructure or material resource expansion without a separate cost
  review. Storage growth (operational plane) may require a larger volume; that is a
  cost-review item, surfaced with measured numbers, not provisioned unilaterally.

## 8. Implementation sequence (reviewable milestones)

- **M4.1 (offline, this milestone):** streaming adapter over `enterprise.py`, the three
  workload profiles, persistent watermarks, and the idempotent bulk driver with
  retry/bounded-queue/dead-letter/backpressure — plus the full recovery test suite. No
  cluster, no spend.
- **M4.2 (live pilot, synthetic identity):** continuous event arrival into a
  `ranger-op-*` index and a **genuine Security Analytics detector → finding/alert →
  investigation** chain, demonstrated on `board2-test`. Isolation re-verified.
- **M4.3 (metrics):** operational metrics computed and validated against the underlying
  data per §3, with unavailable-state handling.
- **M4.4 (measure + recommend):** measured performance per profile, projected Railway
  cost, and a recommended initial candidate concurrency, brought back for approval.

Across all milestones: grader stays shadow-only, `PASS_BAR = 95.0` preserved, candidate
access and act-as disabled, operational plane isolated from qualification.

## 9. OpenSearch capacity and estimated cost (modeled; to be measured)

Operational storage dominates: at ~170 MB/cand/day, a 3-day engagement is ~520 MB/cand,
so 10 candidates ≈ 5 GB and 25 ≈ 13 GB — the latter exceeds the current 10 GB volume,
making ISM retention and volume sizing explicit cost-review inputs. Heap pressure from
continuous detectors + concurrent analytical queries is expected to need the 2 GB-heap /
4 GB-RAM OpenSearch tier (as the Phase-2a note anticipated). Modeled monthly cost stays
in the ~$75–110 range for a bounded pilot and remains under the $300 ceiling; a larger
volume, a second node, or Security Analytics at cohort scale are the overage triggers,
each surfaced with benchmark data before provisioning.

## 10. What is NOT done without further approval

Activating continuous ingestion for real candidates; the 25-candidate workload;
enabling candidate access or act-as; any new paid infrastructure or material resource
expansion; enabling the enterprise grader for qualification; lowering or bypassing the
95% bar.
