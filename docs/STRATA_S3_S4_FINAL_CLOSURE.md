# STRATA S3/S4 final integration closure - review response (2)

Branch `feature/strata-s3-s4-cohort-diversity`, on top of `bc395b8` (the six accepted security corrections, all preserved). Responds to the final-integration review. No merge, deploy, flag change, candidate activation, production migration, new infrastructure, or PARALLAX. The 95 percent objective standard is unchanged.

## Issue 1 - Board 2 legitimate qualification progression

### Traced
`/case` assigns a version-pinned `Case` (seed, index, scenario) -> candidate drafts, verifies citations, and submits -> the submission's evidence is Ed25519-signed and preserved -> a reviewer may add feedback; the SHADOW grader (`RANGER_SHADOW_GRADER`, default off) may compute a comparison score but, by its own contract, NEVER writes an objective grade or clearance. No code path sets `BoardResult.objective_passed` for Board 2, and `_evaluate_gate()` requires it. So a Board 2 candidate currently cannot pass Board 2 or advance to Board 3.

### Classification
This is a **blocking release dependency**, intentionally deferred to the live Board 2 qualification milestone, not an oversight. It is kept default-off: there is deliberately no flag that turns it on here, and the shadow grader is **not** silently promoted to live grading (`score_board2_enterprise` documents itself as shadow-only and never drives qualification). The dependency is now documented in code at `_evaluate_gate` / `_record_objective` (the full trace and the conditions below) and proven by test.

Any future objective-award path MUST require, together: (1) an authenticated authorized reviewer/principal; (2) a verified Ed25519 signature over the preserved evidence record; (3) citations re-verified `reference_valid` against the candidate's pinned authorized scenario index; (4) protected grading truth recomputed server-side from the pinned (scenario, seed), never stored or exposed; (5) the real enterprise grader at the unchanged 95% standard; (6) the existing subjective review gate (report approval) still applied by `_evaluate_gate`.

### Evidence
`test_issue1_board2_progression_gate_is_blocking_release_dependency` - a Board 2 candidate with an APPROVED report (subjective gate satisfied) still cannot be cleared: `/grade/submit` and the `/grade` CI callback both 409, `objective_passed` stays false, the board is not cleared, and `current_board` stays 2. The generic-bypass negative test (`test_gap2_...`) is retained.

## Issue 2 - bind catalog approval to the authenticated caller

`_is_authorized_admin()` previously accepted a dict carrying an existing reviewer's GitHub id, so a known id could confer authority. That path is removed. Authority is now bound to Ranger's established authentication context (no new auth system):
- Inside an HTTP request (the production path), authority comes ONLY from the authenticated admin session (`session['admin']`, set solely by the GitHub-OAuth reviewer flow when the signed-in id is in the reviewer set). The passed argument is ignored - supplying a known reviewer's id (dict, string, or even a persisted `AdminUser` object) does not authorize an unauthenticated caller.
- Outside any request (bootstrap, jobs, tests), a trusted server-side principal must be passed explicitly: a persisted `AdminUser` with an authorizing role, re-read from the database. A dict/string/unpersisted object is rejected.

The admin session now also records `admin_gid` so the authenticated principal resolves to its `AdminUser`. Both catalog promotion (`approve`) and cohort-portfolio changes (`set_cohort_portfolio`) use this.

### Evidence
`test_issue2_approval_requires_authenticated_session_not_github_id` - in a request with no admin session, approval via the real reviewer's id (dict), the id (string), and the persisted `AdminUser` object are all rejected and the entry stays `calibrated`; a portfolio change is likewise rejected; with an authenticated admin session, approval proceeds. The non-request authorization tests (`test_gap6_...`, `test_unauthorized_catalog_change_rejected`) are retained.

## Release notes

### (a) Legacy 64-bit seeds -> keyed opaque reference
Correction: not all legacy seeds have >= 96 bits. The `secrets.token_hex(8)` assignment path minted 64-bit seeds, which are within offline brute-force reach against a bare SHA-256 of the opaque reference. The scenario reference is therefore now a **keyed MAC** (HMAC-SHA256 under a server secret, `RANGER_REF_KEY` or `SECRET_KEY`), not a bare digest: without the key, neither a 64-bit legacy seed nor any seed can be recovered from the published reference. The reference is a correlator only (nothing is looked up by it), so keying is free operationally and key rotation is safe. Evidence: `test_release_note_a_scenario_ref_is_keyed`.

### (b) Generation-contract hash is keyed, not a bare digest
Recorded: a stored SHA-256 contract hash detects accidental change but is not tamper-proof against a privileged database writer who can alter both the contract and its digest. The pinned contract's integrity value is therefore a **keyed HMAC** under the server secret, so a database-only writer cannot forge a matching value for an altered contract without the key. Residual limitation: if the server secret itself is compromised the guarantee degrades; that is a broader-compromise case, not a database-only writer. Evidence: `test_release_note_b_gen_contract_mac_is_keyed_tamper_evident` (a keyless forged contract + recomputed plain digest fails closed).

## Preserved
All six original security corrections and all existing S3/S4 tests are intact.

## Test evidence
- Offline full suite: 101 passed, 6 skipped (was 97/6; +4 new tests, the PG concurrency test skips offline).
- S3/S4 suite against the authorized local PostgreSQL test server: 22 passed (PG concurrency runs).
- pyflakes clean on all changed modules (two pre-existing `case_routes.py` warnings predate this work).
- Known, pre-existing: a full suite run WITH the PG env shows 2 failures in `test_f4_review_boundaries` / `test_forensic_f4` ("working outside of application context"); verified by stashing to clean `bc395b8`/`fcb84b2` that these fail identically there - a pre-existing cross-test ordering artifact in the forensic PG suites (they skip offline, pass in isolation), unrelated to S3/S4.

## Still release-gated
95 bar unchanged. No merge/deploy/flag/candidate-activation/migration/infra/PARALLAX. Board 2 live objective grading (Issue 1) and live `/soc` per-candidate ingestion of a bound variant remain blocking release dependencies; boards 5/6 remain non-operational. The additive columns still require a production migration. A local-PG run is not live candidate validation.

Stop for final acceptance.
