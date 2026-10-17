# STRATA S6 - Engineering handoff (Raider / Vanguard isolated ranges)

Repository: `qwalora/qwalora-ranger-control`
Branch: `feature/strata-s6-goad-ranges` (base `f50ff20`)
Status: implementation complete through section 21, **awaiting engineering acceptance**. No merge, no
deploy, no live Ludus provisioning, no paid infrastructure, no candidate activation.

## 1. What this delivers

Boards 5 (Raider) and 6 (Vanguard) are the two `isolated`-tier STRATA boards: genuine qualification
environments backed by isolated Ludus/GOAD ranges, graded on cryptographic proof-of-action flags,
under the same answer-free, signed, governed model as the rest of STRATA. The work closed the
Phase-1 attestation gap and built out the range governance, lifecycle, grading, briefs, cost model,
and acceptance.

| Section | Delivered |
|---|---|
| 9 / 13 | Real-vs-mock range attestation boundary (Ed25519-signed, verified at the gate; mock/simulated/unavailable never creditable; CI callback refuses 5/6) |
| 14 | Boards 5/6 under S3/S4 scenario governance (spec validators, materially-diverse families, catalog/approval/calibration, cohort portfolios, immutable pinning, non-transfer, candidate-safe projection) |
| 15 | Hardened Ludus adapter (typed errors, TLS verify, bounded retry/backoff, idempotency, power off/on, technical-validation probe behind the adapter-verified gate) |
| 16 | Range lifecycle state machine + evidence-preservation guards (suspend=power-off frees slot, resume=power-on, rebuild=destroy+deploy; evidence hold suspends instead of destroying) |
| 17 | Flag-planting pinned to the approved scenario accounts (ACL lock matches the grader) |
| 18 | Distinct, versioned Board 6 capstone rubric (mandatory end-to-end milestones + critical-failure gate) |
| 19 | Board 5/6 ten-section mission briefs + candidate/admin status surfaces reconciled with 9/16/18 |
| 20 | Range cost and capacity model (labeled estimates, ~$300/mo combined target, honest trade-offs) |
| 21 | This handoff + the acceptance suite |

## 2. Evidence categories A-E

- **A - Unit / logic (VERIFIED, offline).** Attestation signing/verification, lifecycle state machine
  and guards, capstone rubric, broker typed errors / TLS / retry classification, verify_range
  fail-closed. Suites: `test_strata_s6_attestation.py` (units), `test_strata_s6_lifecycle.py`,
  `test_strata_s6_capstone.py`, `test_strata_s6_families.py`.
- **B - Integration through the real routes (VERIFIED, offline, mock broker).** `/labs/dataset`,
  `/labs/start`, `/grade/submit`, `/grade`, `/admin/reconcile`: mock range earns no credit;
  attested-real (test override) awards + promotes once; governed assignment pins + replays;
  suspend-under-hold then destroy-after; resume keeps the range. Suites:
  `test_strata_s6_attestation.py`, `test_strata_s6_governance.py`, `test_strata_s6_lifecycle.py`,
  `test_strata_s6_flag_placement.py`.
- **C - Acceptance gate (VERIFIED, offline).** The consolidated negative+positive contract run:
  `test_strata_s6_acceptance.py` (8 negative, 5 positive). Plus the full S1-S5 regression stays green
  (the S6 additions are additive and change no accepted behaviour).
- **D - Actual Ludus/Proxmox (UNVERIFIED).** The live adapter's REST paths, deploy/resume/power
  timings, and the technical-validation probe against a real range are NOT confirmed. The adapter is
  present but gated off (`LUDUS_ADAPTER_VERIFIED` unset), so no real-range credit is possible. Requires
  a Ludus host.
- **E - Candidate acceptance (UNVERIFIED).** No candidate has run a real range end to end. Requires
  category D first, then a pilot.

**Boards 5/6 must not be called operational, and a simulated range must never be presented as
qualification proof, until D and E are satisfied on a live host with human report approval.**

## 3. Running the acceptance suite

```
python -m pytest siem/tests/test_strata_s6_acceptance.py \
                 siem/tests/test_strata_s6_attestation.py \
                 siem/tests/test_strata_s6_governance.py \
                 siem/tests/test_strata_s6_lifecycle.py \
                 siem/tests/test_strata_s6_capstone.py \
                 siem/tests/test_strata_s6_families.py \
                 siem/tests/test_strata_s6_flag_placement.py \
                 siem/tests/test_strata_s6_closure.py -q
```
Each S6 suite creates a Flask app (and its SQLAlchemy singleton) per test, so the slot/reclaim-
sensitive lifecycle and closure suites must run in their OWN process - sharing one interpreter with
many other app-creating suites lets a prior app's DB/session singleton skew global range-slot
accounting (a known test-harness characteristic, not a product defect; every suite is green in its own
process). `siem/tests/run_s6_acceptance.sh` runs each suite in a separate process, which is how CI
should run them. The PG-backed suites skip without an authorized PG test server (expected).

Offline acceptance totals: 11 S6 suites green, in per-file runs AND as one combined process in
forward and reversed order (80 passed, 1 PG-only skip each). The S1-S5 suites the S6 additions touch
stay green. Category C (PostgreSQL transactional concurrency) is prepared but UNVERIFIED without an
authorized PG server (its test skips); categories D (real Ludus/Proxmox) and E (candidate acceptance)
remain unverified without a live host.

## 4. Go-live checklist (category D/E, operator, gated on separate approval)

1. Stand up a Ludus host sized per `STRATA_S6_COST_AND_CAPACITY.md` (~64 GB, `MAX_CONCURRENT=2`).
2. Install the GOAD and `goad-capstone` templates and the `qwalora_flags` role on the host.
3. Set `LUDUS_API_URL` + `LUDUS_API_KEY` (and `LUDUS_CA_BUNDLE` if a private CA). Keep
   `LUDUS_VERIFY_TLS=1`.
4. **Confirm the broker's REST paths against the installed Ludus version** (user/config/deploy/status/
   wireguard/poweroff/poweron/destroy and the range-detail shape `verify_range` reads). Only after
   confirming, set `LUDUS_ADAPTER_VERIFIED=1`. Until this is set, `technical_validation` fails closed
   and no real-range objective credit can be awarded.
5. Deploy one range, run `verify_range` against it, and confirm the expected VMs/power/state.
6. Pilot a single candidate end to end (category E) with human report approval before any cohort
   activation.

## 4a. Final integrity closure (reviewer items 1-7)

A focused integrity closure was applied after the first acceptance review; no redesign, no new
milestone.

1. **Pinned generation contract at deploy.** `_try_deploy` provisions governed boards 5/6
   EXCLUSIVELY from `strata_assignment.resolve(binding)` (the integrity-verified pinned seed +
   gen_params), with no legacy-seed fallback; a missing/revoked/mismatched/tampered binding fails
   closed. `/labs/dataset`, config, flag planting, grading and attestation now share the identical
   pinned contract. Proven by a variant-revision test: a live variant edit after assignment does not
   change the candidate's world or grade.
2. **Complete real-range probe contract.** `broker.PROBE_CONTRACT` enumerates all mandatory checks,
   split into Ludus-direct (VM inventory, power, state, ownership, window) and guest/scenario
   (domains/trusts/roles, service reachability, account/ACL, flag-placement preflight, segmentation/
   isolation). `verify_range` records every check, treats any missing/unknown result as NOT a pass,
   and requires all-true. MODE_REAL stays non-creditable until the adapter is confirmed AND the full
   contract (including a guest-probe not yet implemented) verifies.
3. **Evidence-preservation on every destructive path.** A single `_retire_range` helper is the only
   teardown path; `_expire_ranges`, `_teardown_ranges`, `_promote`, `_exit_candidate` and the admin
   teardown route all route through it. An open evidence window SUSPENDS (preserves disks + the
   DB-resident signed record) instead of destroying, even on advance/graduate/remove/timeout; a
   forced legally-required teardown confirms the signed record is persisted before destroying.
4. **Broker-op confirmation.** `_retire_range` and `_resume_range` change DB status / free or take a
   slot ONLY after the broker confirms the remote op; a failed/partial/unconfirmed op leaves the
   range in place (no phantom capacity). Resume uses reserve-before-launch to prevent concurrent
   oversubscription. Proven with a fault-injecting broker through the real Flask route.
5. **Full attestation binding.** Attestation v3 binds candidate github id, cohort+pathway,
   board+attempt, ScenarioBinding id, spec id+version, content hash, pinned gen-contract hash,
   technical-validation results, assessment window+expiry, rubric version and signing-key version.
   The governed gate re-verifies all of it (`require_full_binding`), rejecting missing fields, missing
   expiry, stale range state, foreign/superseded/unrelated attestations. Proven: a genuine but
   unrelated signed attestation cannot qualify another attempt.
6. **Corrected capacity model.** `STRATA_S6_COST_AND_CAPACITY.md` section 2 fixes the arithmetic: a
   64 GB host holds 2 Raider OR 1 capstone (not 2 capstones), distinguishes theoretical RAM from
   provisioned capacity, and names the bigger/second host as the approval-gated overage.
7. **Acceptance strengthened.** `test_strata_s6_closure.py` proves items 1-5 through integrated
   Flask/broker/assignment paths.

## 4b. Post-closure correctness pass (second review)

1. **Suspended-range retention cleanup.** `_cleanup_suspended()` (run in `_maintenance`) reclaims the
   DISKS of suspended ranges once past retention (`RANGE_SUSPENDED_RETENTION_HOURS`, default 24h after
   the evidence hold ends): never while a hold is open; only after the signed record is confirmed
   persisted; destruction via the broker, recorded only once absence is CONFIRMED; retried safely.
   Covered by `test_strata_s6_retention.py` (hold-open preserve, past-retention destroy, missing
   evidence withheld, interrupted-then-confirmed, exit→cleanup, repeated-maintenance idempotent,
   retention-disabled).
2. **Accepted vs confirmed broker state.** `broker.power_off/power_on/destroy_range` return
   `(confirmed, detail, outcome)` with outcomes `confirmed/accepted/pending/failed/unknown`. A slot is
   freed on power-off only when VMs are confirmed stopped; a range is marked destroyed only when
   absence is confirmed; resume reaches deployed only when VMs are confirmed running. Uncertain states
   stay conservative and retryable and never auto-resend the destructive request. Verified against a
   fault-injecting double; true confirmation cadence/paths need a real Ludus host (category D).
3. **Atomic, RAM-weighted capacity.** `_admit()` takes a per-host `pg_advisory_xact_lock` and checks a
   RAM-WEIGHTED budget (Raider 1 unit, capstone 2; host capacity in units), so a count of two never
   implies RAM for any two ranges (two capstones are refused on a 2-unit host). The weighted policy is
   verified offline (`test_strata_s6_capacity.py`); the transactional-concurrency guarantee requires a
   PostgreSQL server and is UNVERIFIED offline (that test skips, never claims a pass).
4. **Governance required for real credit.** `_record_objective` credits a MODE_REAL isolated range
   ONLY under governance with a valid approved binding (`_governed_credit_ok`): portfolios enabled, an
   un-revoked ScenarioBinding, an integrity-verified pinned contract, and an approved catalog entry.
   A disabled portfolio flag, legacy-only seed, or revoked/unapproved binding earns no real credit.
   The offline `test_fixture` path is preserved and, being inert outside test/ci, is never a
   production bypass. Covered by `test_strata_s6_real_credit.py`.

**Test-harness root cause (resolved).** The combined run was order-dependent because (a) `ADMIN_TOKEN`
was set via `setdefault` at import, so import order fixed the process-wide token and `/admin/reconcile`
returned 401, and (b) two lifecycle tests mutated app module globals (`MAX_CONCURRENT`, reclaim
thresholds) without restoring them. Fixes: each suite sets its admin token explicitly per app; an
autouse fixture snapshots/restores those globals; plus session hygiene (in-memory StaticPool, per-test
`drop_all`, and a test client that expires the outer session after each request). The full combined
single-process run now passes deterministically in forward and reversed order (80 passed, 1 PG-only
skip each). Per-file execution (`run_s6_acceptance.sh`) remains the CI strategy.

## 4c. Final capacity and remote-state safety (third review)

1. **PG advisory lock fails closed.** `_host_lock` no longer swallows a PostgreSQL lock error. On
   Postgres a failed `pg_advisory_xact_lock` acquisition raises and `_admit` REFUSES admission (no
   unlocked fallback). SQLite keeps an explicit local no-op path (single writer), never presented as
   proof of PostgreSQL atomicity.
2. **Uncertain transitions keep counting.** An accepted-but-unconfirmed power-on no longer drops the
   reservation to `suspended`. A new slot-occupying `resuming` state holds the capacity until the
   transition definitively resolves; `_poll_resuming` resolves it READ-ONLY (confirmed running ->
   deployed; confirmed stopped / definitive failure -> suspended; pending/unknown -> stay resuming),
   and never re-issues the power operation. Interrupted initial deploys behave the same: an `unknown`
   status probe keeps the range `deploying` (counted), resolved on a later poll - `range_status`
   returns `unknown` (not `failed`) on a transient probe error.
3. **Tri-state VM power.** `broker._vm_power_states` classifies each VM as running / stopped / unknown
   from explicit recognized fields only; absent or unrecognized fields are UNKNOWN. Power-off is
   confirmed only when every VM is explicitly stopped; power-on only when every VM is explicitly
   running; any unknown, missing or opposite VM yields PENDING/FAILED, never a false confirmation.
   `confirm_power` is a read-only tri-state probe reused by power_off/power_on and `_poll_resuming`.
4. **Real PG concurrency test.** The connection-local TEMP-table test is replaced by one that drives
   the ACTUAL `/labs/start` admission path from concurrent threads against a real, disposable
   PostgreSQL database, asserting the PERSISTED weighted capacity is never exceeded (one capstone on a
   2-unit host, the other queues). It requires `RANGER_PG_TEST_URL` + `RANGER_PG_TEST_DISPOSABLE=1` +
   `RANGER_TEST_ALLOW_DB_MUTATION` and SKIPS transparently otherwise (category C remains UNVERIFIED
   offline, never claimed as passed).
5. **Repeated reconciliation recovery.** `test_strata_s6_remote_state.py` proves repeated maintenance
   recovers accepted-but-unconfirmed resumes and deploys with no phantom capacity (the `resuming`/
   `deploying` range keeps counting), no duplicate power operations (power-on issued exactly once,
   resolution is read-only), and no premature evidence deletion.

## 5. Restrictions (unchanged)

The 95% bar and mandatory human report approval are unchanged. No PARALLAX. No production deployment,
live Ludus provisioning, new paid infrastructure, candidate activation, production migration, or merge
is authorized by this work; those are separate, explicitly-approved steps. Commits on this branch are
authored by the maintainer with no third-party attribution, per repository policy.
