# Board 2+ M4.3 — Cohort-shared operational SOC: architecture & integration (for approval)

Planning and architecture only. No implementation, no candidate access, no
unattended ingestion until this is reviewed and approved. M3 grading stays
shadow-only; the 95% qualification standard is unchanged; act-as stays disabled.
Ranger remains the authoritative control plane for authorization, assignments,
evidence, signing, and qualification across all six boards.

This design aligns the operational SOC with the original six-board program and
replaces the per-candidate operational test (M4.2) with a cohort-shared SOC, while
keeping formal qualification per-candidate, deterministic, and independently graded.

## 0. What the existing code already gives us (grounding)

- `program.py` — six boards: 1-4 `shared` tier (SOC roles), 5-6 `isolated` tier
  (Ludus/GOAD red-team ranges). `PASS_BAR = 95.0`.
- `models.Candidate` — `cohort` (data/batch axis) and `org` (employer axis,
  explicitly orthogonal to cohort), `current_board`, `status`.
- `models.ScenarioAssignment` — per-person seed ledger `(github_id, board, cohort,
  seed)`, unique per `(github_id, board, seed)`; guarantees a returning ranger never
  repeats a world. This stays the **qualification** assignment mechanism.
- `models.CohortScenarioPlan` — admin-declared `(cohort, board, coverage,
  difficulty, variant)`; today a statement of intent. M4.3 promotes it to the
  anchor for a cohort **operational scenario package**.
- `models.Case` — already carries `plane` (`qualification` | `operational`) and
  `workflow` (`qualification` | `assigned` | `practice`), `seed`,
  `scenario_version`. The two-plane split is already modeled.
- `siem/enterprise.generate(candidate_id, board, seed, profile)` — the world is a
  pure function of `(board, seed, profile)`; `candidate_id` only labels
  `ranger.candidate_id` on docs and never alters structure. **So one seed yields one
  shared world** — a cohort can share a world by sharing a seed, and different
  cohorts get different worlds from different seeds, with no generator change.
- `siem/authz.py` — index-per-candidate-board, per-candidate role, DLS on
  `ranger.candidate_id`. M4.3 adds a parallel cohort-scoped model for the shared
  operational plane; the qualification model is untouched.
- `siem/telemetry_stream.py` (M4.1) + `score_board2` + Ed25519 signing + M3 shadow
  grader — reused as-is.

## 1. Two planes, made explicit by index + access

| | Qualification plane (unchanged) | Operational plane (new, cohort-shared) |
|---|---|---|
| Purpose | the graded exam, independently evaluated | collaborative live SOC, ungraded |
| Index | `ranger-<cohort>-<slug>-b<board>` (per candidate) | `ranger-op-<cohort>-b<board>` (per cohort, shared) — alias to the active version |
| World seed | per-person, from `ScenarioAssignment` | per-cohort **package seed** (shared) |
| Timestamps | fixed scenario anchor, deterministic | continuous, current wall-clock (M4.1 stream) |
| Access | candidate-only, DLS `candidate_id` | cohort team, cohort backend-role, no DLS |
| Findings | none (answer-free grading) | shared cohort findings/alerts + team queue |
| Grading | `score_board2`, 95% bar (M3 grader shadow-only) | not graded |
| Truth | recomputed from seed server-side, never indexed | recomputed from package seed, never indexed |

Separation of shared operational evidence from private qualification (point 6,
mandatory 7): different indices, different seeds, different access models, different
lifecycles. A candidate's qualification world is never shared; the cohort
operational world is never graded.

## 2. Cohort operational scenario package (scenario-assignment model)

New model `CohortScenario` (promotes `CohortScenarioPlan`'s intent to a reproducible
package):

```
CohortScenario:
  cohort            (fk cohort name)
  board             1..4            # boards 1-4 use the shared SOC
  scenario_version  int             # versioned, bumped on refresh
  package_seed      str             # the SHARED world seed (cohort-level, not per person)
  profile           A|B|C           # fixes benign volume + incident count + span
  difficulty        intro|standard|advanced
  family_mix        [str]           # incident families, fixed cardinality for parity
  status            draft|active|retiring|retired
  activated_at, retired_at
  unique(cohort, board, scenario_version)
```

- The shared operational world for a cohort+board is
  `enterprise.generate(cohort_key, board, package_seed, profile)` — deterministic,
  versioned, reproducible (mandatory 4). `candidate_id` on the shared docs is set to
  a cohort marker (e.g., `cohort:<name>`), not a person.
- Different cohorts have different `package_seed` → distinct incidents, timelines,
  identities/assets, benign patterns, detection challenges (mandatory 2).
- Per-candidate **qualification** assignment keeps using `ScenarioAssignment`
  (unchanged): each candidate still gets a unique, never-repeated private world
  (mandatory 7, point 9).

### Scenario versioning strategy (mandatory 6)

- A refresh publishes a new `CohortScenario` row (new `package_seed`, bumped
  `scenario_version`) into a new versioned index `ranger-op-<cohort>-b<board>-v<N>`.
- The stable read alias `ranger-op-<cohort>-b<board>` points at the active version.
  Detectors are re-created against the new index; the alias cuts over atomically.
- The previous version is set `retiring`: kept read-only until its in-flight
  operational cases close, then `retired` and deleted. Rotating never breaks an open
  investigation and never exposes hidden truth (truth is recomputed from
  `package_seed` server-side, never written to any index) (mandatory 6).
- Independent validation (mandatory 4): an offline validator regenerates a package
  from `(cohort, board, package_seed, profile, scenario_version)` and asserts
  determinism and the difficulty contract below.

### Difficulty parity (mandatory 5)

A per-board **difficulty contract**: every cohort package for a board must use the
same `profile` and the same `family_mix` cardinality and shape (e.g., Board 2 =
3 incidents including exactly one detection-failure), so only specifics vary across
cohorts, not complexity. The validator checks parity (incident count, family
classes, benign volume band) across a board's cohort packages.

## 3. Cohort access-control model (point 2, mandatory 1 & 3)

- Identity: GitHub OAuth → Ranger candidate (unchanged). OpenSearch access via the
  existing per-candidate JWT (M4.2), now carrying a **cohort backend-role** claim.
- `cohort_<cohort>_soc` role: read-only on `ranger-op-<cohort>-b*`, the cohort's
  findings/alerts indices, and the cohort saved-object tenant. No telemetry write,
  no security API, no cross-cohort pattern. Cross-cohort isolation is by index
  pattern (no DLS needed because the whole cohort shares the world) (mandatory 3).
- Each candidate still ALSO holds their private qualification role
  (`cand_<slug>`, DLS `candidate_id`) for their qualification index only.
- Org boundary (point 2): `Candidate.org` stays orthogonal — used for enrollment and
  reporting, never to widen data access. The data boundary is the cohort. Least
  privilege = cohort-read + own-qualification-read, nothing else.
- SOC-admin least privilege (validated in M4.2) unchanged: reads operational +
  findings, denied the security index, cannot create users.

## 4. Shared findings + team investigation queue (point 3, 4, 5)

One detector set per cohort op index (not per candidate) → shared cohort
findings/alerts. Ranger overlays a collaborative workflow (Ranger is authoritative):

```
TeamInvestigation:                         InvestigationNote / InvestigationAction:
  cohort, board                              investigation_id (fk)
  finding_id (native SA finding)             candidate_id (author)
  incident_ref (server-side correlation)     kind: note | action | status_change
  status: new|claimed|investigating|          body / action_type / from->to
          resolved|dismissed                  created_at           (append-only, audited)
  claimed_by (candidate_id|null)
  severity, disposition
  version  (optimistic-concurrency token)
  created_at, updated_at
```

- Team queue = the cohort's findings/alerts joined to `TeamInvestigation` status.
- Candidate-specific assignments/notes/actions/audit (point 4): claims, notes, and
  actions are attributable, timestamped, append-only rows; status changes are logged
  as `status_change` entries. Nothing is destructively overwritten.
- Conflict handling (point 5): a **claim** is single-winner compare-and-set on
  `TeamInvestigation.version` (first writer wins; a stale claim/disposition write
  returns 409 with the current owner). Notes/actions are append-only so they never
  conflict. Status transitions are validated by a small state machine (same pattern
  as `case_contract.CASE_TRANSITIONS`). Concurrent analysts both contribute notes;
  disposition has one owner at a time, visibly.

## 5. /case integration with native OpenSearch findings (point 7)

- An operational case is opened **from a finding**: `Case{plane:"operational",
  workflow:"practice"|"assigned", index_name: ranger-op-<cohort>-b<board>,
  source_finding_id}`. The candidate's evidence citations reference the native
  `finding_id` plus the underlying `event_uid`s.
- The existing `case_contract.verify_evidence` already checks each cited `event_uid`
  exists, is in scope, and reproduces in the **authorized index** — now the cohort op
  index. `preserve_and_sign` signs the evidence record (finding + event refs) with
  the existing Ed25519 capability. No new evidence system.
- Qualification cases are unchanged: `plane:"qualification"`, per-candidate index,
  per-person seed, graded by `score_board2`; the M3 enterprise grader stays
  shadow-only. Collaborative operational cases are never graded and never feed
  qualification (point 9, mandatory 7).

## 6. Program alignment (all six boards)

- Boards 1-4: this cohort-shared SOC on the single OpenSearch cluster (shared tier).
- Boards 5-6: dedicated Ludus/GOAD per-candidate ranges (isolated tier) — unchanged;
  the shared-SOC model does not apply, but Ranger stays the control plane for
  authz, assignment, evidence, signing, and qualification.
- All six: Ranger authoritative; OpenSearch/Ludus are execution substrates only.

## 7. Cost & capacity: sharing vs per-candidate duplication (point 8, mandatory 8)

Sharing collapses N per-candidate operational indices and N detector sets into **one
per cohort+board**. Detector load (the real heap driver) scales with **cohorts**,
not candidates.

| | Per-candidate (M4.2 shape) | Cohort-shared (M4.3) |
|---|---|---|
| Op indices (25 candidates, 1 cohort, board 2) | 25 | 1 |
| Detector sets executing | 25 | 1 |
| Shared-world storage | 25 x world | 1 x world |
| Heap pressure scales with | candidates | cohorts |

One OpenSearch deployment is reused for all cohorts (mandatory 8): isolation is
index-per-cohort + cohort role, not a cluster per cohort. Modeled monthly cost stays
in the prior ~$75-110 envelope for a few cohorts on the 2 GB-heap tier; the overage
trigger is many concurrent cohorts or Profile C at scale, surfaced with measured
numbers before provisioning. Qualification indices remain per-candidate but are
small, deterministic, and short-lived.

## 8. Integration contracts (summary)

- Package: `CohortScenario(cohort, board, scenario_version, package_seed, profile,
  difficulty, family_mix, status)` → shared world via `enterprise.generate`.
- Index + alias: `ranger-op-<cohort>-b<board>-v<N>` with alias
  `ranger-op-<cohort>-b<board>`; cohort findings/alerts indices.
- Access: `cohort_<cohort>_soc` role (cohort op + findings read); candidate JWT
  carries cohort backend-role + keeps the private qualification role.
- Collaboration: `TeamInvestigation` + `InvestigationNote/Action` (append-only,
  versioned claims).
- Case link: `Case.plane="operational"`, `source_finding_id`; evidence cites
  `finding_id` + `event_uid`; signed via existing Ed25519.
- Qualification: `ScenarioAssignment` + `score_board2` + 95% bar + M3 shadow grader,
  all unchanged.

## 9. Security boundaries (must hold)

1. Cohort isolation across telemetry, alerts, findings, cases, and collaborative
   notes (index pattern + cohort role) (mandatory 3).
2. Qualification isolation per candidate (DLS `candidate_id`), never shared (point 6,
   mandatory 7).
3. Hidden scenario truth never indexed in either plane; recomputed server-side.
4. Least privilege: cohort-read + own-qualification-read only; SOC-admin cannot
   touch the security index or create users; broker holds the only admin credential.
5. Act-as disabled; general candidate access disabled; M3 grader shadow-only; 95%
   bar unchanged.
6. Collaborative operational work is never graded and never alters qualification
   evidence, grades, or truth (point 9).

## 10. Migration strategy (point 10)

From the current per-candidate operational test to cohort-shared, without touching
qualification or security boundaries. Reviewable, flag-gated, reversible:

1. Add `CohortScenario` + the cohort op index/alias + `cohort_<cohort>_soc` role and
   field mappings, behind `RANGER_COHORT_SOC` (default off). No candidate access.
2. Generate and validate one cohort package offline (determinism + difficulty
   parity); stand up detectors against the shared index; confirm findings on a
   synthetic cohort of test identities (M4.2 harness, cohort-scoped).
3. Re-point the `/case` operational workflow at the cohort index behind the flag;
   add `TeamInvestigation`/notes/actions + the queue UI.
4. Verify cohort isolation (cross-cohort read denied) and that the qualification
   plane is byte-for-byte unchanged.
5. Delete the per-candidate operational indices (`ranger-op-<cohort>-<slug>-b*`);
   qualification indices are untouched throughout.
6. One OpenSearch deployment throughout; no cluster duplication (mandatory 8).

## 11. Remaining blockers / not without approval

- No implementation, no candidate access, no unattended/continuous shared ingestion
  until this architecture is approved and (for ingestion) the M4 workload+cost plan
  is approved.
- Continuous shared detector execution is an always-on workload: needs the cost
  review and the 2 GB-heap tier confirmation before activation.
- Open from earlier: the Dashboards TLS/`verificationMode` item; the SA custom-rule
  `500` on this build (pre-packaged rules suffice, custom rules would need it
  resolved); off-site snapshots for true DR need a bucket (cost review).
- M3 grader stays shadow-only; 95% bar unchanged; act-as disabled.

Deliver for approval: this architecture, the integration contracts (§8), the security
boundaries (§9), the migration strategy (§10), and the blockers (§11). Implementation
does not begin until the revised architecture is reviewed and approved.
