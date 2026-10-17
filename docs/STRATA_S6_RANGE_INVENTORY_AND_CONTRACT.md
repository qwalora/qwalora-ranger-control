# STRATA S6 - Range inventory, Ludus contract, and the §9 attestation boundary

Repository: `qwalora/qwalora-ranger-control`
Branch: `feature/strata-s6-goad-ranges` (from accepted base `f50ff20`)
Scope of this document: the mandated section-2 inspection and section-3 Ludus contract, plus the
Phase-1 implementation (the real-vs-mock attestation boundary, §9). The uploaded S6 brief was
TRUNCATED mid-section-13, so the remaining scope (scenario families, capstone rubric, lifecycle UI,
mission briefs, cost model, broader evidence contract) is deferred until the rest of the brief is
provided. No merge, no deploy, no production infrastructure.

Boards 5 (Raider) and 6 (Vanguard) are the two `isolated`-tier boards (`program.py` BOARD_PLAN):
board 5 -> template `goad` -> `ludus/goad-range.yml`; board 6 -> `goad-capstone` ->
`ludus/capstone-range.yml`.

## Section 2 - Inventory (real / mock / documented-unimplemented / unverifiable)

- **Ludus broker (`broker.py`)**: full live lifecycle CODE exists (`ensure_user`, `set_range_config`,
  `deploy_range`, `range_status`, `wireguard_config`, `destroy_range`) but is UNVERIFIABLE without a
  Ludus host. Live iff `LUDUS_API_URL` is set; otherwise MOCK, which is the only exercised path.
  Mock `range_status` returns `deployed` unconditionally. No retry/backoff. `LUDUS_VERIFY_TLS` is
  documented in the README but UNIMPLEMENTED (the broker uses plain urllib). No shutdown/resume
  function (only destroy).
- **Range lifecycle / concurrency (`models.RangeRequest`, `app.py` `_try_deploy`, `_reconcile`,
  `_expire_ranges`, `_maintenance`)**: REAL and exercised in mock; reserve-before-launch against
  `MAX_CONCURRENT`, queue park, idle/max-age reclamation, per-host accounting, PG advisory lock. Real
  timing UNVERIFIABLE without a host.
- **Board 5/6 grading (`scenarios.py`)**: REAL. Flags are `QR{board}{sha256("board{b}:{seed}:{oid}")
  [:16]}`; the same function feeds the grader and the range role. `_score_flags` awards an objective's
  points on exact token match. The 95% bar and the human report-approval gate apply. There is NO
  per-objective critical-failure gate for 5/6 (only the 95% sum). Flags are never emitted in any
  public/dataset projection.
- **Evidence binding for 5/6**: WEAK / documented-only before this change. The signed objective and
  clearance records did not bind cohort/attempt/scenario/range/objective, and did not record
  real-vs-mock. S3/S4/S5 scenario governance (catalog, bindings, pinned contracts) is scoped to
  boards 1/3/4 (and board 2's separate case path); boards 5/6 used the legacy seed-only path with no
  binding.
- **Candidate experience (`strata_missions.py`, `/labs/*`, `templates/admin_ranges.html`)**: REAL
  (mock-exercised). Mission briefs, WireGuard delivery (mock WG clearly labelled not-live), readiness
  polling, admin view with a "mock mode" banner. `environment_availability()` reports mock ->
  unavailable but was DISPLAY-ONLY (not enforced in grading).
- **Latent defect (to fix in a later phase)**: the `qwalora_flags` Ansible role's ACL lock uses fixed
  `qwalora_svc_account`/`qwalora_asrep_account` defaults while `scenarios.py` seed-randomizes the
  service / AS-REP accounts, so a seed picking a different account would mismatch the role's lock. The
  live preflight would catch it, but only against the two fixed names.

## Section 3 - Ludus/GOAD compatibility contract

Verified against the current Ludus docs and the published Ludus operation surface (the broker's REST
paths themselves remain UNVERIFIED against a running node, so the real adapter stays disabled until
confirmed):

- Operations that exist: user management; range config get/set; template/role install (operator-run
  `ludus ansible role add`); `deploy` (with tags/limit); range status; range logs; deployment abort;
  connection-info / WireGuard retrieval; **power on/off** (per-VM or all; power-off is a
  destructive-flagged stop); destroy.
- **No true suspend/resume.** Only power off/on (Proxmox stop/start), which preserves VM disks. So the
  S6 lifecycle must model "suspend" as power-off and "resume" as power-on, and a rebuild as
  destroy+deploy. The system must not claim snapshot-suspend.
- Broker gaps to close before enabling a real adapter: pin exact REST paths to the installed Ludus
  version's spec; implement `LUDUS_VERIFY_TLS`; add retry/backoff and typed error handling; add
  power-off/on and a technical-validation probe (expected hosts/domains/services/reachability) so a
  broker-reported `deployed` is not trusted on its own.

## §9 - The real-vs-mock attestation boundary (PHASE 1, implemented)

Finding: before this change, no real-vs-mock attestation existed. A mock range (which reports
`deployed` unconditionally) could structurally drive a real Board 5/6 objective award and promotion;
the only barrier was flag secrecy, not a reality gate. The `/grade` CI callback could even write a
passing 5/6 score with no flags and no range, on the CI token alone.

Implemented (additive, fail-closed, preserves all accepted S1-S5 tests):

- `strata_range_attestation.py`: builds and Ed25519-signs a range attestation binding
  handle/cohort/board/attempt/scenario-ref/range-id/status and the real-vs-mock posture. `range_is_real`
  requires a genuinely live broker AND a deployed/validated range; a mock broker or absent/non-deployed
  range is never real. A deterministic TEST override (`RANGER_ENV` in {test,ci} AND
  `RANGER_S6_ATTEST_TEST=1`) simulates an attested real range for offline tests only, inert elsewhere -
  the same pattern S5 uses for authorized-test activation.
- `_record_objective` (app.py): on isolated boards, records the signed attestation and sets
  `objective_passed` to False whenever the range is not real, regardless of score. A simulated range
  never yields an isolated-board award.
- `_evaluate_gate` (app.py): on isolated boards, re-verifies a real attestation before promotion
  (defense in depth), mirroring the board-2 `verify_authorized_clearance` chokepoint.
- `/grade` CI callback: refuses isolated boards (5/6) with 409, closing the raw-score hole.
- `/grade/submit` response: `passed` now reflects the ACTUAL recorded award, so a correct score
  against a mock range truthfully reports no credit.
- `models.BoardResult.range_attestation` (additive column + ensure_schema ALTER): stores the signed
  attestation.
- `siem/tests/test_strata_s6_attestation.py`: proves end-to-end through the real routes that a mock
  range awards no isolated-board objective and no promotion; that an attested real range (test
  override) awards and, with report approval, promotes exactly once; that the CI callback refuses
  boards 5/6; and that the attestation is signed and tamper-evident.

## §14 - Boards 5/6 under S3/S4 scenario governance (implemented)

Boards 5 (Raider) and 6 (Vanguard) now run under the same cohort scenario-governance machinery as
boards 1/3/4: `goad-redteam` / `goad-capstone` spec validators with GOAD inventory feasibility checks;
materially-diverse scenario families (`siem/board_variants.py` VARIANTS[5]/[6], ≥2 divergent axes);
catalog build/approve/calibrate (advanced band); cohort portfolios; randomized, immutably-pinned
assignment; reproducible replay; candidate-safe projection (no flags leak); and non-transfer of one
candidate's answers to another's pinned world. The provisioner plants flags for the pinned
`ScenarioBinding` seed + family `gen_params`, so the live range matches exactly what the grader scores
and the ACL locks reference the approved accounts (closes the §17 latent defect). The governed grade
path STILL passes through the §9 attestation chokepoint: a correct submission against a mock range
earns no objective. Covered by `test_strata_s6_families.py` and `test_strata_s6_governance.py`.

## §15 - Hardened Ludus adapter (implemented; live path category-D unverified)

`broker.py` closes the section-3 gaps:
- **Typed errors**: `LudusError` base + `LudusTimeout` / `LudusUnavailable` (retryable), `LudusAuthError`
  (401/403), `LudusNotFound` (404), `LudusConflict` (409), `LudusProtocolError` (bad shape / TLS).
- **TLS**: `LUDUS_VERIFY_TLS` honored (verify ON by default; explicit opt-out is surfaced in
  `broker_status()`), optional `LUDUS_CA_BUNDLE` for a private CA. An SSL error under verification is a
  hard, non-retryable trust failure, never masked.
- **Bounded retry/backoff**: only IDEMPOTENT calls (status/config/wireguard GETs) are retried, only on
  retryable typed errors, with capped exponential backoff + full jitter (`LUDUS_RETRIES`,
  `LUDUS_TIMEOUT`). Writes (user/range create, deploy, destroy) are never silently retried.
- **Idempotency**: `ensure_user` treats 409 as reuse; `destroy_range` treats 404 as already-gone.
- **Power off/on**: `power_off` = Proxmox stop (disks preserved), `power_on` = start. There is NO
  snapshot-suspend; the module never claims one.
- **Technical-validation probe**: `verify_range(candidate, expected)` inspects the live range detail
  (VMs present, count, powered-on, deployed state) so a broker-reported `deployed` is not trusted on
  its own. It NEVER passes a mock range, and NEVER passes while the adapter is unverified: an operator
  who has confirmed the REST paths against their installed Ludus version sets
  `LUDUS_ADAPTER_VERIFIED=1`; until then the probe is fail-closed (code present, not trusted).
  `strata_range_attestation.technical_validation` delegates to this probe behind that gate, so no
  real-range objective credit is possible until the adapter is confirmed on a live host.

Honesty: the exact Ludus REST paths remain UNVERIFIED against a running node (category D). The live
adapter is present but gated off; mock is still the only exercised path. Covered (offline, mocked
transport) by `test_strata_s6_lifecycle.py`.

## §16 - Range lifecycle state machine + evidence-preservation guards (implemented)

`range_lifecycle.py` is a PURE state machine (no I/O): states
`configured/queued_slot/deploying/deployed/suspended/failed/destroyed`, legal transitions, slot
accounting (a **suspended** range is powered off, so it FREES its concurrency slot while its disks and
planted evidence persist), and the policy decisions reclamation uses. `app.py` executes them:
- Submitting an isolated objective opens an **evidence hold** (`RangeRequest.evidence_hold_until`,
  additive column + ensure_schema ALTER; `RANGE_EVIDENCE_HOLD_HOURS`, default 72h).
- `_expire_ranges` consults `reclaim_decision`: while the evidence window is open it **suspends**
  (power-off) instead of destroying, preserving the candidate's evidence - even for a max-age reclaim.
  After the window closes, idle/age reclamation destroys as before (cost stays bounded).
- Re-entering a suspended board **resumes** (power-on → deployed, same range id) rather than rebuilding
  (destroy+deploy would discard evidence); if the host is at cap it stays suspended and the candidate
  retries, never silently rebuilt.
- `teardown_allowed` refuses an explicit destroy during an open evidence window.

Covered by `test_strata_s6_lifecycle.py` (pure transitions/guards + integration: hold-on-submit,
suspend-under-hold then destroy-after, resume-not-rebuild, suspended-frees-a-slot).

## §18 - Board 6 capstone rubric (implemented)

Board 6 (Vanguard) is now graded by a DISTINCT, VERSIONED capstone rubric (`CAPSTONE_RUBRIC_VERSION
= b6-capstone-v1`), not board 5's flat points sum. A set of MANDATORY end-to-end milestones
(`child_da, trust_abuse, parent_ea, forest_persist, cross_forest, crown`) must all be demonstrated;
missing any is a CRITICAL FAILURE that caps the effective score below the 95 bar regardless of points
(OSCP-style must-complete gating). The weights make the gate load-bearing: the final crown-jewel exfil
is low-point but mandatory, so a candidate can earn >=95 points on the rest of the chain and still fail
by never capturing the crown. The versioned rubric is carried on the generated world and surfaced in
the candidate brief (`public_board6`), flag-free. Board 5 is unchanged. `scenarios.score_board6`
delegates to `score_capstone`; covered by `test_strata_s6_capstone.py` (versioning + distinctness,
full-pass, the crown gate, each mandatory individually required, brief exposure without flag leak,
reproducibility).

## §19 - Board 5/6 mission briefs + status surfaces (implemented)

Both isolated boards carry an approved, versioned, candidate-safe ten-section mission brief
(`strata_missions.py`, boards 5 and 6) with genuinely distinct content (Raider single-domain red-team
vs Vanguard multi-forest capstone). Updated for consistency with the rest of S6:
- Board 6's submission/evaluation now disclose the §18 capstone rubric truthfully - the mandatory
  end-to-end milestones and the critical-failure gate that caps a high-point-but-incomplete attempt -
  without leaking any solution, command, or attack path.
- Both briefs now state the §9/§13 reality: objective credit is awarded only against a real, validated
  isolated range (a simulated/unvalidated environment records no credit), and clearance also requires
  report approval.
- Both briefs explain the §16 lifecycle to the candidate: a range suspended to free capacity preserves
  its disks and progress and resumes from the board workspace.
- The candidate/admin range-status surface renders the new `suspended` state (`_RANGE_UI`), alongside
  the existing deployed/deploying/queued/configured/failed/destroyed.

## §20 - Cost and capacity model (implemented)

`docs/STRATA_S6_COST_AND_CAPACITY.md` models the boards 5/6 range operating cost and concurrency
capacity: per-board GOAD VM footprints, the capacity math tied to the real controls
(`MAX_CONCURRENT_RANGES`, idle/age caps, the §16 evidence-hold suspend behaviour), labeled monthly
estimates (~$50-70/mo for the S6 ranges, well inside the $300/mo combined target, with a second GOAD
host named as the likely overage trigger requiring approval), and honest trade-offs (no scale-to-zero
for an active range; suspend saves RAM not the host bill; resume cheap vs rebuild expensive). All
figures are labeled estimates; range timings are category-D unverified without a live host.

## Deferred to later phases

Still outstanding: the comprehensive acceptance suite + handoff (§21).
Categories D (actual Ludus/Proxmox provisioning + REST-path confirmation) and E (candidate acceptance)
remain UNVERIFIED without a live host and must not be claimed as done. No merge, deploy, live Ludus
provisioning, paid infrastructure, or candidate activation is in scope.
