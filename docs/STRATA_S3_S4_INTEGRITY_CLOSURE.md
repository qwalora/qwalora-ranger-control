# STRATA S3/S4 integrity closure - review response

Branch `feature/strata-s3-s4-cohort-diversity` (same review branch). Follows the engineering review of `fcb84b2`, which accepted the variant library, ScenarioSpec extensions, randomized-assignment direction and two-cohort test foundation and returned six integrity gaps. All six are closed below. No merge, deploy, production flag change, live migration, paid infrastructure, or PARALLAX. The 95 percent objective standard is unchanged.

## Changed files
- `siem/schema.py` - opaque `scenario_ref` replaces the seed in normalized telemetry; strict allowlisted candidate projection.
- `strata_assignment.py` - fail-closed portfolio resolution; real version pinning (immutable generation contract + integrity hash); admin-authorized portfolio configuration stored in a dedicated column.
- `strata_catalog.py` - approval authorization hardened (persisted, authorized AdminUser only; sponsors read-only); board-2 simulation now tests the candidate projection.
- `models.py` - `ScenarioBinding.gen_contract` + `gen_hash` (version pinning); `CohortScenarioPlan.portfolio_json` (portfolio stored without clobbering admin notes); `ensure_schema` ALTER entries for all three.
- `app.py` - seed removed from `/labs/dataset`, `/grade/submit`, `/me`, status and the dashboard view models (opaque `case_ref` instead); Board 2 refused at `/grade/submit` and the `/grade` CI callback; `_record_objective` refuses Board 2 as a server-side chokepoint; `/labs/dataset` resolves the cohort portfolio fail-closed.
- `siem/case_contract.py` - the signed preservation record no longer embeds the seed (opaque ref instead); `PRESERVATION_VERSION` 2 -> 3.
- `case_routes.py` - passes the opaque ref (not the seed) into the preservation record meta.
- `templates/candidate_me.html` - shows the opaque case reference, not the seed.
- `siem/tests/test_strata_s3_s4.py` - existing acceptance tests updated to the hardened APIs; six new gap-regression tests plus a real-PostgreSQL concurrency test.

## Gap 1 - protect the generator seed (both paths)
The seed is the generator's reproducibility key; with the public generator code it could reconstruct hidden truth. It is now removed from every candidate-reachable surface and from indexed telemetry.
- Normalized events carry `ranger.scenario_ref` (an opaque, non-invertible sha256-derived id over candidate_id+board+seed), never `ranger.scenario_seed`. `schema.case_ref()` is the single derivation. The seed (>= 96 bits) cannot be recovered from the digest.
- `/labs/dataset` (legacy and portfolio paths), `/grade/submit`, `/me`, the range-status response and both dashboard view models now return an opaque `case_ref`; the raw `seed`/`variant` are gone from candidate JSON.
- The signed preservation record stores `scenario_ref`, not the seed. Server-side replay uses the seed held on `ScenarioAssignment`/`ScenarioBinding`/`Case` (backend only), never a value read from a document.
- Tests: `test_gap1_no_seed_in_legacy_or_portfolio_routes` (recursively asserts the real seed never appears in either route's response), `test_gap1_normalized_event_has_no_seed_and_opaque_ref`, plus recursive no-leak checks in the dataset/route tests.

## Gap 2 - close the Board 2 objective-grading bypass
Board 2 (`CASE_BOARD`) is in the legacy generator registry, so `/grade/submit` and the `/grade` CI callback previously graded it generically and recorded objective credit, bypassing the signed-citation `/case` workflow and its clearance gate.
- `/grade/submit` refuses Board 2 (409) before any grading; the `/grade` CI callback refuses Board 2 (409); `_record_objective` raises for Board 2 as a server-side chokepoint so no generic path can award Board 2 objective credit or drive clearance.
- Board 2 clearance flows only through the signed-citation case workflow (existing behavior preserved). No stored historical result is modified.
- Test: `test_gap2_board2_generic_grade_route_cannot_bypass` - a Flask-route regression (not only a unit test of `strata_assignment.grade`) proving the candidate submission and the CI callback both 409 and record no objective credit / no clearance.

## Gap 3 - remove Board 2 hidden truth from candidate projections
`candidate_view()` returned raw generated events. `generate()` already stripped `_malicious`, but the projection was a denylist and `_source` still carried the provenance block.
- New strict ALLOWLIST (`schema.project_candidate_events`): only analyst-relevant ECS fields survive; the whole `ranger.*` block (ref, candidate_id, generator metadata) and any sibling label (`_malicious`, `_key`) are dropped by construction. `candidate_view()` routes Board 2 through it.
- Catalog `simulate()` for Board 2 now asserts the projected view carries none of the truth tokens.
- Tests: `test_gap3_board2_candidate_view_allowlist_strips_truth` (recursive over the whole response incl. `_source`, and a poisoned-event defensive case).

## Gap 4 - cohort portfolio fails closed
`cohort_portfolio()` returned `None` on missing/malformed config, which let selection expand across the whole eligible catalog.
- `resolve_portfolio(..., required=True)` raises on missing/empty/malformed; the candidate route uses it and `assign(require_portfolio=True)`, returning 409 and creating no binding rather than falling back to the generic path. Empty portfolios are rejected; wrong-board/unknown/revoked/unapproved ids are rejected at both set and assign time.
- Portfolios are stored in the dedicated `CohortScenarioPlan.portfolio_json` column, so saving one never overwrites admin `notes`/coverage.
- Test: `test_gap4_cohort_portfolio_fails_closed` (missing -> 409 + no binding; malformed -> raises; notes preserved; cross-board rejected).

## Gap 5 - real version pinning
`resolve()` regenerated from whatever `board_variants.gen_params()` returns in the live code, so editing a variant would change an existing assignment's world.
- Each binding pins an immutable generation contract (`gen_contract`: board, variant, spec version, content hash and the exact gen_params) with an integrity hash (`gen_hash`). `resolve()` generates from the pinned contract and verifies the hash; a tampered contract fails closed. A legacy binding with no contract uses live params only if the live spec still hashes to the pinned `content_hash`, else fails closed.
- Test: `test_gap5_version_pin_replay_before_and_after_revision` - binds, captures the world, simulates a variant revision (live hash changes), proves the existing binding still replays its original world and grades correctly, proves a drifted legacy binding fails closed, and proves a tampered contract fails its integrity check.

## Gap 6 - approval and concurrency guarantees
- Approval is authorized only for an administrator that is PERSISTED in `AdminUser` with an authorizing role, re-read from the database (not trusted from the passed object). An unpersisted/forged `AdminUser`, a bare string, an invented reviewer dict, and a read-only sponsor are all rejected. Portfolio configuration (`set_cohort_portfolio`) is gated the same way.
- Concurrency/no-repeat/uniqueness are now verified against a REAL, authorized, disposable PostgreSQL database (`_pgtest.isolated_pg_database`, the existing positive-authorization + sentinel safety boundary), using independent threads with their own connections - not only SQLite threading.
- Tests: `test_gap6_admin_authorization_is_real`; `test_concurrent_assignment_idempotent_postgres` (8 concurrent assigns -> exactly one binding on PG); the SQLite idempotency test is retained.

## Test evidence
- Offline full suite: 97 passed, 6 skipped (was 90/5). pyflakes clean on all changed modules (two pre-existing warnings in `case_routes.py` predate this work and are unrelated).
- S3/S4 suite with the authorized local PostgreSQL test server: 18 passed (the PG concurrency test runs and passes rather than skipping).
- The PostgreSQL concurrency test uses the dedicated-test-instance authorization boundary (opt-in + dedicated URL + loopback + sentinel database + production-DB refusal) and a disposable per-run database; it SKIPs with an explicit reason when no authorized server is configured (fail-closed), so production concurrency is never claimed from a SQLite run.

## Schema compatibility
`ScenarioBinding.gen_contract`/`gen_hash` and `CohortScenarioPlan.portfolio_json` are additive. `create_all` provisions them offline and on a fresh disposable PG database; `ensure_schema` carries idempotent ALTERs for a deployed database. Already-indexed enterprise telemetry written under the old schema carried `ranger.scenario_seed`; no destructive live cleanup is performed here. Re-indexing or dropping those historical indices so no document retains the seed is a release-gated operational step (candidate indices are disposable between cohorts by design). New generation writes only `scenario_ref`.

## Unchanged / still release-gated
95 bar unchanged. No merge/deploy/flag flip/live migration/paid infra. Board 2 live per-candidate OpenSearch ingestion of a bound variant via `/soc` remains a release gate. Boards 5/6 remain non-operational. A successful offline/local-PG run is not live candidate validation.

Stop for final S3/S4 engineering acceptance.
