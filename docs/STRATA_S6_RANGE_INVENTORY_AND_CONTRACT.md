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

## Deferred to later phases (pending the truncated brief, sections 14+)

Scenario families for boards 5/6 under the S3/S4 governance model (schema/structural/feasibility/
diversity/calibration/approval/versioning/candidate-safe projection); a separately versioned capstone
rubric with board-6 objectives independent of board 5; the full range-provisioning lifecycle with an
independent technical-validation probe and the §9 state machine; the stronger evidence contract
(section 8) binding range instance + window; admin range-management controls (approve/queue/
suspend=power-off/resume=power-on/rebuild/reclaim) with evidence-preservation guards; distinct Board
5/6 mission briefs and deliverables; the operational cost model; and the `qwalora_flags` ACL account
fix. None of these are started; they depend on the acceptance/test/restriction sections not present in
the uploaded brief.
