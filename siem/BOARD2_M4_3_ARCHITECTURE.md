# Board 2+ M4.3 — Cohort-shared operational SOC: architecture & integration (revised for approval)

Planning and architecture only. No implementation, no candidate access, no
continuous/unattended ingestion until this revision receives final approval. M3
grading stays shadow-only; the 95% qualification standard is unchanged; act-as stays
disabled. Ranger remains the authoritative control plane for authorization,
assignments, evidence, signing, and qualification across all six boards.

Approved direction: Boards 1-4 shared operational SOC per cohort; different cohorts
get isolated operational scenario packages; individual qualification stays separately
assigned, deterministic, and independently graded; Boards 5-6 are dedicated advanced
environments integrated later through the existing control plane.

This revision resolves the six review requirements: meaningful scenario diversity,
real SOC team operations, strict qualification boundaries, safe scenario rotation,
enterprise continuity, and migration + validation. It ends with a complete two-cohort
worked example.

## 0. Grounding in the existing code (unchanged facts)

- `program.py`: boards 1-4 `shared` tier, 5-6 `isolated` (Ludus/GOAD); `PASS_BAR=95.0`.
- `Candidate.cohort` (data/batch axis) and `.org` (employer axis, orthogonal).
- `ScenarioAssignment`: per-person seed ledger, no-repeat per `(github_id, board)`.
  Stays the qualification assignment mechanism.
- `CohortScenarioPlan`: admin-declared `(cohort, board, coverage, difficulty,
  variant)`. Promoted here to a reproducible `CohortScenario` package.
- `Case`: already has `plane` (`qualification`|`operational`), `workflow`
  (`qualification`|`assigned`|`practice`), `seed`, `scenario_version`, `index_name`.
- `enterprise.py`: a coherent Valyria Financial topology (identities, service
  accounts, tiered admins, hosts, 5 business apps, 5 segments, external benign/sus),
  benign generated independently of incidents, hidden truth returned to the backend
  only. `generate()` is a pure function of `(board, seed, profile)`.
- `telemetry_stream.py` (M4.1), `score_board2`, Ed25519 signing, M3 shadow grader:
  reused as-is.

## 1. Two-layer generation model (resolves req 1 + req 5)

The review's core point: a different seed alone is not meaningful diversity, and
every incident must unfold inside one coherent enterprise, not a new world. The
revision splits generation into two layers:

```
  Layer A - ENTERPRISE FOUNDATION  (persistent, shared by ALL cohorts)
     Valyria Financial topology + baseline behaviours. Versioned enterprise_version.
     Identities, service accounts, tiered admins, hosts, business services, network
     segments, trust relationships, and benign baseline activity.
            |
            v  instantiated against the foundation
  Layer B - SCENARIO PACKAGE  (per cohort, declarative + seeded)
     A ScenarioSpec that chooses attacker objective, incident kill-chain sequence,
     targeted identities/assets, detection gaps, benign look-alike decoys, expected
     investigation path, and response decisions. Deterministic from (spec, seed).
```

Layer A is the stable enterprise every cohort investigates in. Layer B is what
varies per cohort and is explicitly validated and calibrated. Incidents are injected
into the SAME Valyria enterprise; the foundation (people, assets, services, normal
behaviour) persists across scenarios and cohorts (req 5).

## 2. Meaningful scenario diversity (req 1)

A `ScenarioSpec` is declarative, not just a seed. Each cohort package pins concrete,
semantically different choices on every axis the review named:

| Diversity axis | How it varies per cohort (examples, not identifiers) |
|---|---|
| Attacker objective | cardholder-data theft vs trading-position tampering vs payroll fraud vs IP exfiltration |
| Incident sequence (kill chain) | phishing->OAuth token theft->API abuse->DNS exfil vs service-account off-hours logon->sudo->DB tamper |
| Affected systems/identities | payment-gateway + svc-web + web-payments vs db-trading + svc-sql + trading-platform |
| Detection gaps | DNS-exfil channel uncovered vs service-account-wrong-host rule missing vs impossible-travel not alerting |
| Benign explanations (decoys) | quarter-close bulk export by finance vs scheduled DBA maintenance window vs legit admin break-glass |
| Investigation path | correlate sign-in anomaly->API->DNS vs baseline svc normal-hosts->anomaly->DB audit |
| Response decisions | revoke token + block domain vs disable account + restore dataset vs rotate creds + isolate host |

The generator change: incident families stop being a blind `r.sample(...)`. A
`ScenarioSpec` selects the family sequence, targets, gap set, and decoy set
explicitly; the seed only randomizes instance details (names, times, IPs) WITHIN the
chosen structure. Two cohorts therefore differ in substance, not just identifiers
and timestamps.

### Difficulty calibration (req 1 + req 5 parity)

A calibration harness (same pattern as the M3 calibration suite) scores every cohort
package on explicit complexity dimensions and asserts they fall in the board's parity
band:

- incident count and kill-chain depth (steps to reconstruct),
- benign-to-malicious ratio and decoy count (noise/ambiguity),
- number of data sources that must be correlated,
- detection-gap count (how much is un-alerted and must be hunted),
- attribution fan-out (identities/assets to tie together).

A package is `active`-eligible only if its calibration vector is within the board's
tolerance of the reference package. This is validated offline, independently, before
activation.

## 3. Enterprise continuity (req 5)

Layer A is a versioned, persistent foundation defined once and reused:

- **Identities**: the `enterprise.PEOPLE` set (per-department employees), service
  accounts (`svc-sql`, `svc-backup`, `svc-web`, `svc-scan` with normal hosts and
  patterns), and tiered admins (`adm.tier0/servers/helpdesk`). Stable across cohorts.
- **Assets**: `HOSTS` with segment assignments (dc01/dc02 identity, app-core/db-core/
  db-trading datacenter, web-portal/web-payments dmz, workstations corp, vpn-gw
  remote).
- **Business services**: `BUSINESS_APPS` (core-banking, trading-platform,
  customer-portal, payment-gateway, hr-workday).
- **Network relationships**: `SEGMENTS` and the plausible source/destination
  patterns already in the generator.
- **Baseline behaviours**: diurnal business-hours logons, DNS to benign externals,
  web app traffic, failed-auth noise, legitimate service automation, legitimate
  privileged admin - generated independently of incidents.

`enterprise_version` versions the foundation; a cohort package references a specific
`enterprise_version` so the world a case saw is reproducible. Incidents are overlaid
on this foundation, never replacing it. A candidate who learns Valyria's normal
behaviour in one scenario carries that mental model forward, exactly like a real SOC.

## 4. Two planes, indices, and access (condensed from the approved v1)

| | Qualification plane (unchanged) | Operational plane (cohort-shared) |
|---|---|---|
| Index | `ranger-<cohort>-<slug>-b<board>` per candidate | `ranger-op-<cohort>-b<board>-v<N>` per cohort, pinned version; alias `ranger-op-<cohort>-b<board>` -> active version |
| World | per-person seed (`ScenarioAssignment`) | foundation(`enterprise_version`) + cohort `ScenarioSpec` + `package_seed` |
| Timestamps | fixed scenario anchor | continuous current (M4.1 stream) |
| Access | candidate-only, DLS `candidate_id` | `cohort_<cohort>_soc` role, cohort indices only |
| Findings | none (answer-free) | shared cohort findings/alerts + team queue |
| Grading | `score_board2`, 95% (M3 grader shadow-only) | never graded |
| Truth | recomputed from seed, never indexed | recomputed from (spec, seed), never indexed |

## 5. Scenario-assignment model + versioning

```
CohortScenario (promotes CohortScenarioPlan):
  cohort, board(1..4)
  scenario_version   int            # bumped on refresh
  enterprise_version int            # which Layer-A foundation
  spec_id            str            # ScenarioSpec selected (objective, families, gaps, decoys)
  package_seed       str            # randomizes instance details within the spec
  profile            A|B|C
  difficulty         intro|standard|advanced
  calibration        json           # the validated complexity vector
  status             draft|active|retiring|retired
  activated_at, retired_at
  unique(cohort, board, scenario_version)
```

- Shared operational world = `generate_operational(enterprise_version, spec_id,
  package_seed, profile)` into `ranger-op-<cohort>-b<board>-v<scenario_version>`.
- Per-candidate qualification still uses `ScenarioAssignment` (unchanged), a
  different seed and a private index per person.

## 6. Cohort access-control model

- Identity: GitHub OAuth -> Ranger candidate. OpenSearch via per-candidate JWT (M4.2)
  carrying a cohort backend-role claim.
- `cohort_<cohort>_soc`: read-only on `ranger-op-<cohort>-b*` and the cohort's
  findings/alerts indices and saved-object tenant. No telemetry write, no security
  API, no cross-cohort pattern. Cross-cohort isolation by index pattern.
- Each candidate also keeps their private `cand_<slug>` role (DLS `candidate_id`) for
  their qualification index only.
- `org` never widens access; the cohort is the data boundary. Least privilege =
  cohort-op-read + own-qualification-read.

## 7. Real SOC team operations (req 2)

### Roles (within a cohort)

| Role | Capabilities |
|---|---|
| Analyst | read cohort telemetry + findings; triage; claim an unclaimed investigation; add notes/actions; propose disposition |
| Lead (rotating) | assign/reassign ownership; approve escalation; require peer review; close/dismiss |
| Peer reviewer | review a `peer_review` investigation; approve or send back |
| SOC admin | read-only oversight (M4.2 least privilege); never telemetry write, never security index |

Roles are Ranger-side attributes on cohort membership, enforced server-side; they are
not OpenSearch security roles (OpenSearch sees only cohort-read).

### TeamInvestigation state machine

```
new -> triaged -> claimed -> investigating -> { escalated -> investigating,
                                                peer_review -> { investigating, resolved } }
                                            -> resolved -> closed
any -> dismissed (false positive)   (Lead only; requires reason)
```

```
TeamInvestigation:
  cohort, board, scenario_version            # pinned to the version that produced the finding
  finding_id (native SA finding), incident_ref
  status, severity, disposition
  owner (candidate_id | null), version (optimistic-concurrency token)
  created_at, updated_at

InvestigationNote / InvestigationAction  (append-only, audited):
  investigation_id, candidate_id (author), kind: note|action|status_change
  body | action_type | from_status->to_status
  created_at
```

### Permissions + concurrency controls

- Claim/own/assign/close/dismiss/escalate: gated by role, applied as compare-and-set
  on `TeamInvestigation.version`; a stale write returns 409 with the current owner and
  version. Single-winner claims; no lost updates.
- Notes and actions are append-only, attributable, timestamped: they never conflict
  and form the audit trail. Status changes are logged as `status_change` entries.
- Transitions validated by the state machine above (same pattern as
  `case_contract.CASE_TRANSITIONS`).

### Workflows

- **Triage**: findings land `new`; an Analyst triages severity and either claims or
  the Lead assigns. **Ownership**: one owner at a time (CAS). **Escalation**: owner or
  Lead moves to `escalated` with a reason. **Handoff**: reassign ownership (logged).
  **Peer review**: before closure a Lead can require `peer_review`; a reviewer approves
  or sends back. **Closure**: `resolved -> closed` with disposition + response actions
  recorded; `dismissed` for false positives.

### Integration with the existing `/case` workflow (no duplication)

The collaborative triage/queue layer is new; the investigation **documentation** reuses
the existing `/case` engine unchanged:

- From a `TeamInvestigation`, a member opens an operational `Case`
  (`plane="operational"`, `workflow="assigned"|"practice"`, `source_finding_id`,
  `index_name = ranger-op-<cohort>-b<board>-v<N>`). The case's draft/verify/submit/
  preserve_and_sign flow is the existing `case_contract` path; evidence cites the
  native `finding_id` plus `event_uid`s, verified against the pinned cohort index and
  signed with the existing Ed25519 capability.
- `score_board2` and the M3 grader are NOT invoked on operational cases. The case
  engine is reused for structure and evidence integrity, not for grading.

## 8. Strict individual qualification boundaries (req 3)

- Qualification is a separate `Case` (`plane="qualification"`) on a separate
  per-candidate index with a separate per-person seed and a DIFFERENT world than the
  cohort operational scenario. Operational findings/notes therefore reveal nothing
  about a candidate's private qualification incidents: different world, different
  truth.
- Grading reads ONLY qualification cases and the protected truth recomputed from the
  per-person seed. Collaborative operational work cannot satisfy or influence an
  individual's qualification: no operational case, note, finding, or teammate action
  is an input to `score_board2` or the M3 grader.
- Protected assessment answers are never in any index (operational or qualification);
  truth is recomputed server-side. Teamwork cannot leak answers because the answers
  are not present to leak, and the qualification world differs from the shared one.
- All existing standards preserved: `score_board2`, 95% bar, per-candidate signed
  objective result, M3 grader shadow-only.

## 9. Safe scenario rotation (req 4)

- **Case-to-version binding is immutable.** Every `Case` and `TeamInvestigation`
  stores `scenario_version` and the concrete versioned index
  `ranger-op-<cohort>-b<board>-v<N>`, never the moving alias. An active case always
  reads its pinned dataset.
- **Controlled alias transition.** The alias `ranger-op-<cohort>-b<board>` points at
  the active version for NEW work (new findings, new cases). Publishing a refresh:
  create `-v<N+1>`, generate + validate it, stand up detectors on it, then move the
  alias atomically. No open case switches datasets, because cases bind to `-v<N>`, not
  the alias.
- **Open cases across rotation.** The old version is set `retiring`: kept read-only,
  its detectors stopped, but the index retained while any `-v<N>`-bound case or
  investigation is open. On close, the case's evidence record (M3 `preserve_and_sign`
  with embedded `_source` snapshots) makes it independently verifiable offline even
  after the index is deleted. A version becomes `retired` and its index is deleted
  only when no bound case is open; its signed evidence records persist in Postgres.
- **No silent dataset switch, ever.** A query path that would read the alias for an
  existing case is rejected; cases resolve their pinned index explicitly.

## 10. Cost & capacity for multiple cohorts (req 6)

Detectors execute once per active cohort version, not per candidate. Load scales with
active cohort-versions, not headcount.

| Scenario | Op indices (active) | Detector sets | Shared-world storage |
|---|---|---|---|
| 1 cohort, 25 candidates, board 2 | 1 | 1 | 1x world |
| 3 cohorts x boards 1-4, 25 each | 12 (3 x 4) | 12 | 12x world |
| During a board-2 refresh (overlap) | +1 transient (`-v<N>` retiring) | +1 transient | +1 transient |

Modeled (to be measured): Profile B shared world ~8 k events (~8 MB) per cohort-board;
12 active worlds ~100 MB; detector heap is the driver and scales with the ~12 active
detector sets, well within the 2 GB-heap tier for a small number of cohorts. Overage
triggers (many concurrent cohorts, Profile C, or long rotation overlaps) are surfaced
with measured numbers before provisioning. One OpenSearch deployment throughout; no
cluster per cohort.

## 11. Migration path + validation (req 6)

Flag-gated (`RANGER_COHORT_SOC`, default off), reversible, qualification untouched:

1. Add `CohortScenario` + `ScenarioSpec` registry + `enterprise_version`; add the
   versioned op index/alias and `cohort_<cohort>_soc` role + field mappings. No
   candidate access.
2. Generate + validate one cohort package offline (determinism, difficulty parity,
   diversity-axis coverage); stand up detectors on `-v1`; confirm findings on a
   synthetic cohort of test identities (M4.2 harness, cohort-scoped).
3. Add `TeamInvestigation` + notes/actions + the queue; wire `/case` operational
   workflow to the pinned cohort index.
4. Verify cohort isolation, team permissions, concurrent updates, version pinning,
   evidence verification, and qualification separation (tests below).
5. Delete the per-candidate operational pilot indices (`ranger-op-<cohort>-<slug>-b*`);
   qualification indices untouched.
6. One OpenSearch deployment throughout.

### Validation tests (offline + bounded live, synthetic identities)

| Test | Asserts |
|---|---|
| cohort isolation | cohort-B JWT cannot read cohort-A op/findings/alerts indices (403); no cross-cohort saved objects |
| team permissions | Analyst cannot close/dismiss; Lead can; reviewer can only approve/return; SOC admin read-only |
| concurrent case updates | two claims on one investigation -> one 201, one 409; notes from both appended; no lost update |
| scenario version pinning | after an alias cutover, an open `-vN` case still reads `-vN`; new cases read `-vN+1` |
| evidence verification | operational case evidence (finding_id + event_uid) verifies against the pinned index; signed record self-verifies offline after the index is retired |
| qualification separation | operational findings/notes never appear as grader inputs; grading reads only the per-person qualification world; 95% math unchanged |
| difficulty parity | two cohort packages for a board fall within the calibration tolerance band |
| diversity | two cohort packages differ on every diversity axis (objective, sequence, targets, gaps, decoys), not only identifiers |

## 12. Worked example - two cohorts (complete)

Shared Valyria foundation (`enterprise_version = 1`) for both: same people, service
accounts, admins, hosts, business apps, segments, and benign baseline.

### Cohort 2026-A - operational package `payment-data-exfiltration`
- scenario_version 1, index `ranger-op-2026-a-b2-v1`, Profile B, difficulty standard.
- Objective: steal cardholder data from the payment gateway.
- Sequence: phishing -> OAuth token theft for `svc-web` -> `payment-gateway` API bulk
  export -> DNS exfiltration over `dns-tunnel.xyz`.
- Affected: `web-payments`, `payment-gateway`, `svc-web`.
- Detection gap: DNS-exfil channel not covered by a rule (must be hunted).
- Benign decoy: quarter-close legitimate bulk export by `finance` (looks like exfil).
- Investigation path: risky-sign-in -> API export volume -> DNS TXT beaconing.
- Response: revoke `svc-web` token, block the domain, rotate the gateway key.
- Team: analysts triage the shared findings queue; `aria.stark` claims the OAuth
  finding, `jon.snow` claims the DNS finding, the Lead links them into one
  investigation, requires peer review, then closes with disposition
  `confirmed_incident` and the response actions. All notes/actions audited.

### Cohort 2026-B - operational package `trading-position-tampering`
- scenario_version 1, index `ranger-op-2026-b-b2-v1`, Profile B, difficulty standard.
- Objective: tamper with trading positions via a compromised service identity.
- Sequence: `svc-sql` off-hours interactive logon on a wrong host -> sudo to root ->
  ad-hoc `trading.positions` write -> cover-up.
- Affected: `db-trading`, `trading-platform`, `svc-sql`.
- Detection gap: service-account-on-wrong-host rule missing.
- Benign decoy: a scheduled DBA maintenance window (also off-hours).
- Investigation path: baseline `svc-sql` normal hosts -> spot the anomalous host ->
  DB audit of the write.
- Response: disable `svc-sql`, restore the dataset, add the wrong-host rule.
- Team: 2026-B analysts investigate THEIR queue only; they cannot see 2026-A's
  telemetry, findings, or notes (cohort isolation), and vice versa.

### Independent individual qualification (both cohorts)
- Each candidate in either cohort is separately assigned a private qualification case
  (`plane="qualification"`), on their own index `ranger-<cohort>-<slug>-b2`, from a
  per-person seed in `ScenarioAssignment` - a DIFFERENT world than their cohort's
  operational scenario.
- That case is graded by `score_board2` at the 95% bar (M3 grader shadow-only),
  producing the signed per-candidate objective result. No teammate's work, note, or
  operational finding is an input. `aria.stark` passing Board 2 depends only on
  `aria.stark`'s own qualification case.

Net: both cohorts investigate the same Valyria enterprise with substantively
different incidents, collaborate within their own cohort, stay isolated from the other
cohort, and each candidate still qualifies alone on a private, deterministic, graded
scenario.

## 13. Security boundaries (must hold)

1. Cohort isolation across telemetry, alerts, findings, cases, and notes.
2. Qualification isolation per candidate (DLS), never shared.
3. Hidden truth never indexed in either plane; recomputed server-side.
4. Least privilege: cohort-read + own-qualification-read; SOC admin cannot touch the
   security index or create users; broker holds the only admin credential.
5. Act-as disabled; general candidate access disabled; M3 grader shadow-only; 95% bar
   unchanged.
6. Collaborative operational work never graded and never alters qualification
   evidence, grades, or truth.
7. Cases bind to an immutable scenario version + dataset; no silent dataset switch.

## 14. Remaining blockers / not without approval

- No implementation, no candidate access, no continuous/unattended shared ingestion
  until this revision is approved and (for ingestion) the M4 workload+cost plan is
  approved.
- Continuous shared detector execution is an always-on workload: cost review + 2 GB
  heap tier confirmation before activation.
- Open from earlier: Dashboards TLS/`verificationMode`; SA custom-rule `500` on this
  build (pre-packaged rules suffice); off-site snapshot bucket for DR (cost review).
- M3 grader shadow-only; 95% bar unchanged; act-as disabled.

## 15. Ranger Cohort Provisioning & Lifecycle Orchestration (foundational)

Cohorts C, D, E, and beyond must be stood up and torn down by an administrator
through the existing portal, with no code change, no manual seed assignment, no
manual OpenSearch configuration, and no developer intervention for routine
provisioning. This is foundational, not a later manual workaround. It is grounded in
the existing models: `Cohort` (already has `scheduled|active|completed`, `sequence`,
auto-advance), `CohortScenarioPlan`, `ScenarioAssignment`, `RangeRequest` (an
idempotent status/slot-accounting lifecycle analog with broker messages and poll
timestamps), `AdminUser`, GitHub OAuth identity, `authz`, and `Case`.

### 15.1 Models (extend existing, do not fork)

```
Cohort (extend):
  + lifecycle: draft|scheduled|provisioning|validating|active|suspended|retiring|retired
  + start_at, end_at (schedule), capacity_max (max concurrent analysts)
  + enterprise_version, board_set (default 1..4)
  (keeps name, sequence, auto-advance)

ScenarioCatalogEntry (NEW - the validated, versioned catalog; req 2, 13):
  spec_id, family, enterprise_version, scenario_version
  profile, difficulty, calibration(json), diversity_axes(json)
  status: authored|validated|approved|deprecated
  reuse_policy: {cooldown_cohorts:int, max_concurrent_uses:int}
  authored_by, validated_at, approved_by, approved_at

CohortScenario (from §5; the per-cohort binding):
  cohort, board, scenario_version, enterprise_version, spec_id, package_seed,
  profile, difficulty, calibration, status: draft|active|retiring|retired

CohortMembership (NEW; team membership, req 4/11):
  cohort, candidate_id, soc_role: analyst|lead|reviewer, added_by, added_at, removed_at

CohortProvisioningJob (NEW; idempotent orchestration, modeled on RangeRequest; req 4,8):
  cohort, board, kind: provision|suspend|resume|retire|rotate
  state: queued|running|succeeded|failed|rolling_back|rolled_back
  steps(json): [{name, status: pending|ok|failed|skipped|rolled_back, detail, attempts}]
  cursor(int), attempts, last_error, created_by, created_at, updated_at
```

### 15.2 Administrator lifecycle through the portal (req 1)

Admin actions (portal routes, gated by the new orchestrator capability in §15.7):
create a cohort (draft), schedule it (start/end, capacity), configure it (board set,
scenario selection or auto), activate (triggers provisioning), suspend (stop
ingestion + detectors, keep data), resume, and retire (teardown + reclamation). Each
action records an audit entry and, where it changes infrastructure, enqueues a
`CohortProvisioningJob`. No action requires a code change.

### 15.3 Scenario catalog + selection (req 2, 3, 13)

- The catalog holds versioned `ScenarioCatalogEntry` rows. Only `approved` entries are
  eligible for automated assignment; `authored`/`validated` are not.
- Promotion pipeline (req 13): author a ScenarioSpec -> `validated` (offline:
  determinism, difficulty calibration within the board band, diversity-axis coverage,
  no hidden-truth leakage) -> `approved` (admin sign-off, the only step that unlocks
  auto-assignment) -> `deprecated` (retired from selection, existing cohorts keep
  their pinned version).
- Auto-selection for a new cohort+board (req 3): from `approved` entries, pick one
  that (a) matches the board difficulty band (parity), (b) differs materially on the
  diversity axes (§2) from entries used by recent sibling cohorts, (c) satisfies the
  reuse policy (cohort cooldown + max concurrent uses), (d) is compatible with the
  cohort `enterprise_version`. Selection is deterministic and logged; an administrator
  may override with a manual selection. Materially-different-from-siblings is enforced
  by comparing diversity-axis vectors, not seeds.

### 15.4 Idempotent provisioning workflow (req 4, 5)

A `CohortProvisioningJob` executes ordered, individually idempotent steps under the
existing `pg_try_advisory_lock` single-run guard (reused from the scheduler). Each
step is create-if-absent and re-runnable:

1. resolve/validate the selected `ScenarioCatalogEntry` (approved + parity).
2. create the versioned op index `ranger-op-<cohort>-b<board>-v<N>` (if absent).
3. apply field mappings (keyword `winlog.event_data.*`, as M4.2 proved necessary).
4. generate the shared world from (enterprise_version, spec_id, package_seed, profile)
   and bulk-load it (idempotent via `op_type=create`).
5. create the least-privilege cohort role `cohort_<cohort>_soc` + rolesmapping +
   saved-object tenant (if absent).
6. create native SA detectors on the op index + wire findings/alerts access.
7. enroll `CohortMembership` rows (analysts/leads from the admin's roster).
8. run readiness validation (§15.5); only on all-green does the cohort go `active`.

Failure handling (req 8): a failed step records `last_error`, retries with bounded
backoff up to a cap, then the job goes `failed`; an admin (or policy) triggers
`rolling_back`, which undoes exactly what this job created (reverse order: drop
detectors, role, mappings, index, memberships) to a clean state, leaving no partial
cohort. Every step transition is appended to an audit log. Jobs are resumable: a
re-run continues from `cursor` and is safe because each step is idempotent.

### 15.5 Pre-activation validation gates (req 5)

Before `validating -> active`: provisioning success (all steps ok), permissions
(cohort JWT reads its op/findings only; cross-cohort 403; SOC admin read-only; no
security-index access), detector execution (a synthetic trigger yields a finding, as
in M4.2), scenario readiness (expected incident families present, calibration vector
within band, no hidden truth indexed), and resource capacity (heap/CPU/storage within
the budget for the number of active cohort-versions). A gate failure blocks activation
and surfaces the reason; nothing half-active is exposed.

### 15.6 Multiple active cohorts + independent lifecycles (req 6, 7, 9)

- Many cohorts active at once; isolation by index pattern + `cohort_<cohort>_soc`
  role; each cohort's provisioning, suspend/resume, rotation, and retire run
  independently via their own jobs.
- Case/investigation binding to an immutable `scenario_version` + concrete `-v<N>`
  index (from §9); provisioning or rotation never changes an active case's dataset.
- Capacity + lifecycle management (req 9): cohort `capacity_max` caps concurrent
  analysts; the active schedule (start/end) drives ingestion start/stop; detectors are
  created on provision, stopped on suspend/retire; retention keeps a retiring version's
  index until its bound open cases close; signed evidence records persist in Postgres
  regardless; resource reclamation deletes retired indices and removes the cohort role
  once no bound case is open. Reuses the `RangeRequest`-style idle/TTL + reconcile
  worker pattern already in the scheduler.

### 15.7 Permission separation (req 11)

Three distinct capabilities, enforced server-side and surfaced as separate portal
areas:

| Capability | Who | Can do |
|---|---|---|
| Cohort Orchestrator | provisioning admin | create/schedule/configure/activate/suspend/resume/retire cohorts; promote/approve catalog entries; trigger jobs. Does NOT hold the OpenSearch admin credential (the broker performs OS changes on the job's behalf). |
| SOC Analyst / Lead / Reviewer | cohort member | read cohort telemetry/findings; triage; investigate; notes/actions; (Lead) own/assign/close; (Reviewer) peer review |
| SOC Admin | oversight | read-only oversight of operational data + findings (M4.2 least privilege); never telemetry write, never the security index, never provisioning |

The orchestrator can mutate provisioning but not investigate or grade; analysts/leads
can investigate but not provision; SOC admin is read-only. None can read another
cohort's data. Qualification grading remains a separate backend path.

### 15.8 Boards 5-6 adapter contract (req 12; not provisioned now)

An abstract `EnvironmentProvisioner` interface decouples lifecycle from substrate:

```
EnvironmentProvisioner:
  provision(cohort|candidate, board, spec) -> job
  validate(target) -> readiness
  suspend(target) / resume(target)
  retire(target) -> reclamation
  status(target)
```

- `SharedSocProvisioner` (boards 1-4): the OpenSearch implementation in §15.4.
- `LudusRangeProvisioner` (boards 5-6): a FUTURE implementation over the existing
  `RangeRequest` seam (per-candidate GOAD ranges, slot accounting, WireGuard). Defined
  as a contract only; not implemented or provisioned now. Ranger stays the control
  plane for authz, assignment, evidence, signing, and qualification on all boards.

### 15.9 Preserved invariants (req 10)

Individual qualification assignments (`ScenarioAssignment`), hidden truth (recomputed,
never indexed), signed evidence (Ed25519), shadow-only enterprise grading, and
`PASS_BAR = 95.0` are all unchanged by orchestration. Provisioning touches only the
operational plane and cohort access; it never writes qualification indices, truth, or
grades.

### 15.10 Worked example - Cohort 2027-C lifecycle (req 14)

1. **Create**: an orchestrator admin creates `2027-C` (draft), schedules it
   (start 2027-01-05, end 2027-03-01, capacity 20), board set 1-4,
   `enterprise_version 1`, scenario mode = auto.
2. **Select**: for board 2, Ranger auto-selects an `approved` catalog entry whose
   diversity-axis vector differs from the entries used by sibling cohorts C/D/E and
   whose calibration is within the board-2 parity band and reuse cooldown; it records
   the choice (e.g., `payroll-fraud-ach-diversion`, scenario_version 1). Admin may
   override.
3. **Provision**: activation enqueues a `CohortProvisioningJob`. Steps run idempotently:
   create `ranger-op-2027-c-b2-v1`, apply mappings, generate + load the shared world,
   create `cohort_2027-c_soc` role + tenant, create detectors, enroll the analyst
   roster as `CohortMembership`. A transient detector-create failure retries, then
   succeeds; every step is audited.
4. **Validate**: gates pass (isolation: a 2027-C JWT cannot read 2026-A/B; detector
   fires a synthetic finding; scenario families present; heap/storage within budget).
   Cohort -> `active`.
5. **Operate**: enrolled analysts investigate the 2027-C shared SOC (team queue,
   claims, notes, peer review, closure); each candidate is independently assigned a
   private qualification case (separate index/seed/world) graded at 95%, untouched by
   the team work.
6. **Rotate (optional)**: a refresh publishes `-v2`, validates it, moves the alias for
   new work; open `-v1` cases stay pinned to `-v1` until they close.
7. **Retire**: at end of schedule the admin retires 2027-C: a retire job stops
   ingestion + detectors, sets the version `retiring` (index read-only, kept while any
   bound case is open), preserves signed evidence, then on no-open-cases deletes the
   op indices and removes `cohort_2027-c_soc` (reclamation). Qualification results and
   their signed evidence persist. Audit shows the full lifecycle.

No code change, manual seed assignment, or manual OpenSearch configuration was needed
at any step.

## 16. Proposed M4.3 implementation milestones (for approval)

Each milestone is independently testable, flag-gated, reversible, and stops for
review. No candidate access, no act-as, no unattended ingestion, no paid
infrastructure, no cohort activation until the specific milestone is approved. Offline
milestones need no cluster; live milestones use the existing Railway services with
synthetic identities and a bounded, verified-stop run (the M4.2 pattern).

| Milestone | Scope | Primary tests | Infra |
|---|---|---|---|
| M4.3.1 Scenario catalog + specs | `ScenarioSpec`, two-layer generator (foundation + spec), `ScenarioCatalogEntry`, calibration + promotion (authored->validated->approved) | determinism; difficulty parity band; diversity-axis coverage; no-truth-leak; only approved are selectable | offline |
| M4.3.2 Cohort lifecycle + portal + permissions | extend `Cohort`; `CohortMembership`; orchestrator vs analyst vs SOC-admin capabilities; portal CRUD + state machine | state transitions; permission separation; audit entries; no infra side effects | portal only |
| M4.3.3 Idempotent orchestrator | `CohortProvisioningJob`; step engine (create-if-absent, retry, rollback, resume) under the advisory lock; audit | idempotent re-run; forced step failure -> rollback to clean; resume from cursor; full audit | dry-run + bounded live |
| M4.3.4 Shared operational plane | cohort index/alias, mappings, `cohort_<cohort>_soc` role, detectors, findings; `TeamInvestigation` + notes/actions + queue; `/case` operational wiring | cohort isolation; team permissions; concurrent-claim 409; finding->case->evidence verify | bounded live, synthetic |
| M4.3.5 Rotation + retention | versioned rotation, alias cutover, case-version pinning, retiring/retired lifecycle, evidence preservation, reclamation | pinned case never switches dataset; evidence verifies offline after retire; reclamation leaves nothing | bounded live, synthetic |
| M4.3.6 Auto-selection + multi-cohort | catalog auto-select with diversity + reuse policy; multiple active cohorts; capacity/schedule | two cohorts differ on every axis; cross-cohort isolation; capacity enforced; workload within budget | bounded live, synthetic |
| M4.3.7 Boards 5-6 adapter contract | `EnvironmentProvisioner` interface + `LudusRangeProvisioner` stub over the `RangeRequest` seam (no provisioning) | contract conformance tests; stub raises not-implemented; no Ludus calls | offline |

Sequencing: 4.3.1 and 4.3.2 first (offline/portal, no infra), then 4.3.3 (orchestrator
on a synthetic cohort), then 4.3.4 and 4.3.5 (the shared plane + rotation), then 4.3.6
(auto-selection + multi-cohort), with 4.3.7 as an offline contract stub at any point.
Continuous shared ingestion stays OFF until its workload+cost plan is separately
approved.

## Deliverable summary

Deliver for final approval: this revised architecture, the scenario-diversity +
calibration model (§2), the enterprise continuity model (§3), the SOC team operations
model (§7), the qualification boundaries (§8), the rotation + case-pinning model (§9),
the multi-cohort workload (§10), the migration + validation tests (§11), the
two-cohort worked example (§12), the cohort provisioning + lifecycle orchestration
layer (§15), and the proposed M4.3 implementation milestones (§16). Implementation
begins only after final approval, milestone by milestone.
