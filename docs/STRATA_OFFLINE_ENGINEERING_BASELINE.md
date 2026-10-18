# STRATA — Offline Engineering Baseline

Authoritative frozen record of the consolidated STRATA engineering work (F4 through S6, plus the
S5.1 real-OpenSearch validation suite) integrated for the `main` development baseline.

## State labels (do not conflate)

- **MERGED** — code incorporated into `main`.
- **OFFLINE ACCEPTED** — validated to the level offline execution + integration tests support.
- **LIVE VALIDATED** — tested against actual authorized infrastructure.
- **PRODUCTION READY** — all release gates passed.
- **DEPLOYED** — actually deployed to the target environment.

## Current status of this baseline

| Label | Status |
|---|---|
| MERGED | **PENDING** — integration branch `integration/strata-offline-baseline` is prepared and tested; the merge into `main` is HELD at the mandatory deployment-safety gate (see below). |
| OFFLINE ACCEPTED | **YES** — full offline suite + combined S6 + disposable-PostgreSQL concurrency pass. |
| LIVE VALIDATED | **NO** — real OpenSearch and real Ludus/GOAD validation outstanding. |
| PRODUCTION READY | **NO** — live validation and release gates outstanding. |
| DEPLOYED | **NO** — no production deployment performed or authorized by this work. |

## Integration composition

Integration branch: `integration/strata-offline-baseline` (built from `origin/main` = `d1df8b1`).

History-preserving merges (no squash, no rebase, no force):

| Milestone | Source branch | Head SHA | In baseline |
|---|---|---|---|
| main (prior default) | `main` | `d1df8b1` | base (wholly contained in S6) |
| F4 bounded forensic processing | `review/f4-bounded-forensic-processing` | `4210db1` | yes (ancestor of S6) |
| F5 candidate workbench | `feature/f5-candidate-workbench` | `ef3b345` | yes (ancestor of S6) |
| S1/S2 readiness | `feature/strata-readiness-s1-s2` | `b66ae35` | yes (ancestor of S6) |
| S3/S4 cohort diversity + governance | `feature/strata-s3-s4-cohort-diversity` | `04f4662` | yes (ancestor of S6) |
| S5 Board 2 qualification | `feature/strata-s5-board2-qualification` | `f50ff20` | yes (ancestor of S6) |
| S5.1 real-OpenSearch validation | `feature/strata-s5-real-opensearch-validation` | `f8acc27` | yes (merged additively) |
| S6 Boards 5/6 GOAD ranges | `feature/strata-s6-goad-ranges` | `d33a986` | yes (merge base of the integration) |

Ancestry verified: F4, F5, S1/S2, S3/S4, S5 and `main` are all ancestors of S6, so merging S6 pulls
them in without duplication. S5.1 diverges from S5 (merge-base `f50ff20`) and is purely additive
(9 new files: CI workflow, OpenSearch test harness/compose/scripts, `test_strata_s5_real_opensearch.py`,
`_ostest.py`, `ci_check_junit.py`, two validation docs) — no edits to shared code, so no conflicts.

Aggregate change vs prior `main`: 98 files, +23,971 / -269 (the full F4–S6 + S5.1 body).

## What was built (by milestone)

- **F4** — bounded forensic processing and evidence persistence.
- **F5** — candidate workbench, scenario eligibility, case compatibility.
- **S1/S2** — candidate mission improvements.
- **S3/S4** — scenario governance, approved catalogs, cohort diversity, pinned (integrity-verified)
  assignment contracts.
- **S5** — authoritative Board 2 qualification: signed-citation path, full-payload integrity,
  evidence re-verification, evaluator authorization, activation gate, 95% objective standard,
  mandatory human report approval.
- **S5.1** — real OpenSearch 2.17.1 validation suite, disposable-node safety boundary, local test
  runner + docker-compose, GitHub Actions workflow (read-only), and validation docs. Real-cluster
  tests remain visibly distinct from FakeCluster tests and fail closed when no authorized node exists.
- **S6** — Board 5 Raider and Board 6 Vanguard: GOAD templates, per-seed flag placement, capstone
  rubric and mandatory milestones with critical-failure veto, range lifecycle, RAM-weighted host
  capacity with atomic PostgreSQL admission, Ed25519 range attestation with real-vs-mock boundary,
  evidence-preserving retirement, suspended-range retention, conservative remote-state reconciliation,
  async-safe power operations, complete expected-VM-inventory confirmation, ambiguous-dispatch vs
  definitive-failure classification, and a config-must-apply-before-deploy gate.

## What was tested (this baseline, offline environment)

| Suite | Backend | Result |
|---|---|---|
| Full repository suite | SQLite in-memory | 237 passed, 23 skipped, exit 0 (~6m37s) |
| Combined S6 (forward) | SQLite in-memory | 104 passed, 4 skipped |
| Combined S6 (reversed) | SQLite in-memory | 104 passed, 4 skipped (order-independent) |
| Combined S6 | disposable PostgreSQL 16 | 108 passed, 0 skipped |
| PG concurrency races (deploy/deploy, resume/resume, deploy/resume, deploy/reconcile) | disposable PostgreSQL 16 | 4 passed, 8/8 clean repeated runs; `postgresql` dialect + live `pg_advisory_xact_lock` confirmed |

The 23 skipped in the full offline suite are infrastructure-gated tests that fail closed without
authorized disposable backends (PostgreSQL concurrency variants, and the 12 S5.1 real-OpenSearch
tests). None are false passes.

Security/correctness audit (static, on the integrated tree): no private keys, API tokens, or
hardcoded secrets in tracked files (only a public CA certificate `siem/dashboards/ca.pem`, 0 private
keys); all sensitive values sourced from environment variables, not the repository. Governance and
qualification invariants present in the integrated tree: 95% pass bar, `require_full_binding`
attestation gate, governed real-credit gate, signed-citation Board 2 path, RAM-weighted admission,
`pg_advisory_xact_lock`, the S6 ambiguous-dispatch classifier, and the config-apply-before-deploy gate.

## Remaining limitations / live validation gates

- **Real OpenSearch 2.17.1 validation — UNVERIFIED.** No container runtime (docker daemon down) and
  the egress allowlist blocks OpenSearch artifacts in the offline environment, so a disposable node
  could not be stood up here. The S5.1 suite skipped fail-closed (12 skipped, explicit reason). Run
  via the S5.1 GitHub Actions workflow against a disposable OpenSearch node (the branch recorded that
  path as CI billing-locked), or a locally provisioned disposable node.
- **Real Ludus / GOAD validation — UNVERIFIED.** Boards 5/6 ran against the mock broker only. The
  live adapter (`set_range_config`, `deploy_range`, `confirm_power`, `range_status`, ambiguous-dispatch
  classification against genuine node faults) and the `qwalora_flags` role need a real `ludus_goad`
  install.
- **Real PostgreSQL concurrency — VERIFIED on a disposable local cluster only.** Production-topology
  validation (managed PG, independent connections) remains a separate gate.

## Required migrations

Schema changes are additive and applied idempotently at app startup via `db.create_all()` (checkfirst)
plus `ensure_schema(db)` (idempotent `ALTER`s for post-launch columns, e.g.
`RangeRequest.evidence_hold_until`). No destructive migration. No production migration is authorized by
this work; any production schema change must be run as a reviewed additive migration against a
disposable database first.

## Production activation restrictions (preserved, default-off)

The main-branch merge (when authorized) must not activate: Board 2 live qualification, Board 5/6
candidate access, Ludus/GOAD infrastructure, new cohort enrollment, live OpenSearch destructive tests,
test-only grade authorization, production schema migrations, or any experimental PARALLAX service.
All existing fail-closed defaults are preserved.

## Deployment-safety finding (why the merge is HELD)

The Railway `portal` service (project `qwalora-ranger`, environment `production`, domain
`portal.qwalora.com`) is connected to this repository and **auto-deploys branch `main`** (every
recorded deployment: `reason: deploy`, `branch: main`). On boot the app runs `db.create_all()` +
`ensure_schema()` against the production PostgreSQL. `main` is **unprotected** (no required checks or
reviews). Therefore a merge into `main` would immediately and silently trigger a production deploy and
schema-init.

Per the engineering directive, the merge is held before this trigger. Required safeguard (needs
separate explicit authorization — not performed here): pause/disable the `portal` service's
auto-deploy-on-`main` (or gate it behind a manual/approved deploy) in Railway, confirm it, then merge
during a controlled window and verify no unintended production change occurred. No production
integration was disabled, modified, or disconnected by this work.

## Candidate pilot requirements

Before any candidate pilot: live OpenSearch and live Ludus/GOAD validation complete; production
deploy performed under the controlled safeguard above; qualification/award authority and candidate
enrollment explicitly enabled by a separate authorized step; human report approval staffed.

## Rollback references

- Prior `main` HEAD: `d1df8b1` (restore target if a merged baseline must be reverted).
- The integration is a pair of `--no-ff` merge commits on `integration/strata-offline-baseline`;
  reverting the merge commit on `main` (after any future merge) cleanly removes the baseline.
- Railway: the `portal` service's last SUCCESS deployment (`72951d90`, commit `7b441e7`) is
  `canRollback: true` as an independent rollback path.

## Freeze

With this baseline recorded, STRATA new functionality is frozen. Only separately approved
infrastructure validation, security repairs, and release-readiness work may modify it.
