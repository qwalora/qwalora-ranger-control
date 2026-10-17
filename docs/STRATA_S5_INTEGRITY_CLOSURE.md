# STRATA S5 - engineering integrity closure (review response)

Branch `feature/strata-s5-board2-qualification`, on top of `db327f4` (the accepted S5 implementation). Responds to the S5 integrity review; all six code-level gaps closed on the same branch. S3/S4 security corrections, S5 architecture, F5 isolation and the unchanged 95% standard preserved. Not merged; production qualification remains disabled.

## Gap 1 (CRITICAL) - generate from the pinned contract, not live params

`strata_board2.generate_world()` previously read generation parameters from `board_variants.gen_params()`, bypassing the pinned `ScenarioBinding.gen_contract`. Now it loads the binding, validates that the binding matches the assignment's full identity (github_id, board, attempt, seed, spec_id, spec_version, content_hash, variant_id), and obtains the generation inputs **only** from the integrity-verified pinned contract via `strata_assignment.resolve()` (which verifies the keyed contract MAC and fails closed on tamper/drift). Evidence: `test_gap1_pinned_contract_survives_variant_revision` - after editing the live variant's families, an existing assignment still produces byte-for-byte identical event ids and identical incident-family truth; a tampered pinned contract raises `Board2ProvisionError` (fail closed).

**Corrected claim:** the prior delivery said generation used the pinned contract. In fact `resolve_assignment` validated the contract but `generate_world` re-derived parameters from live `gen_params`. That is now actually the case.

## Gap 2 (CRITICAL) - cryptographically bind the full submission

`decide()` previously verified the signed preservation record but graded `CaseSubmission.payload` independently, so a payload edited after signing was not detected. `case_contract.preserve_and_sign()` now binds a canonical SHA-256 of the **whole** payload (`payload_sha256`) and the `attempt` into the signed record (`PRESERVATION_VERSION` 3 -> 4). At grading time `_check_submission_binding()` recomputes the digest from the stored payload and verifies it, and also verifies `case_id`, `index`, `scenario_version` and `rubric_version` from the record (not only candidate/cohort/board/scenario_ref), plus finalized status. A cached idempotent decision is trusted only after its own signature re-verifies. Evidence: `test_gap2_payload_modified_after_signing_fails_closed` (edit conclusions/analyst_conclusion after signing -> `QualificationEvidenceError`) and `test_gap2_record_case_or_version_mismatch_fails_closed`.

**Corrected claim:** the prior delivery implied the signed submission bound the investigation; in fact only the cited snapshots + metadata were signed. The full payload is now bound.

## Gap 3 (CRITICAL) - integrity metadata out of candidate-readable documents

The qualification-index meta document (holding `variant_id`, `spec_id`, fingerprint, family-revealing data) was stored in the candidate's own index under `ranger.candidate_id = slug`, so the candidate's DLS role could read it. The meta is now stored in a protected system index `.ranger-qualmeta` (keyed by the qualification index name) that is **not matched by any candidate role pattern** (`ranger-<cohort>-<slug>-b*`) and is read only with the broker credential; the candidate index contains **no** meta document and the events carry no variant/spec/family. Evidence: `test_gap3_candidate_role_cannot_read_variant_or_fingerprint` uses the candidate's actual scoped role to attempt reads: the candidate search returns only events (no variant/spec/fingerprint/`qual`), the system meta index raises `AuthzError` under the candidate role, and the broker can still read the meta server-side.

## Gap 4 (HIGH) - provisioning fails closed

`provision()` is now an explicit state machine over the protected system meta: **new** (no index, no meta) -> create + ingest; **verified-complete** (meta matches + status complete + document inventory matches) -> reuse; **verified-incomplete** (meta matches, status incomplete) -> converge (idempotent upsert); **foreign/mismatched** (meta fingerprint differs) -> reject; **unknown** (index exists but no system-meta claim) -> reject without writing/deleting/reindexing; **corrupted** (bad status, or complete with a document-count mismatch) -> reject. The incomplete claim is written to the system meta **before** ingest so a crash leaves a verifiable same-assignment incomplete index (retryable), and completion is stamped only after the full inventory is confirmed. Evidence: `test_provision_idempotent_and_refuses_foreign_and_unknown_index`, `test_provision_converges_after_interrupted_ingest`, `test_provision_rejects_corrupted_completion_record`.

## Gap 5 (HIGH) - hardened activation + principal identity

- Production activation is fail-closed when `RANGER_ENV` is missing or unrecognized (it must equal `production`), and additionally requires `RANGER_B2_QUAL_ACTIVE`, a `deployment_id` matching `RANGER_DEPLOYMENT_ID`, and calibration + shadow-run evidence in the signed activation.
- A signed **test** activation authorizes grading only inside an explicitly permitted isolated test env (`RANGER_ALLOW_TEST_QUAL`) and never when the process declares itself production.
- The internal-service evaluator identity is no longer an arbitrary `{"service","trusted":true}` dict; it must present a token matching `RANGER_EVALUATOR_TOKEN` (a secret set only in the trusted service context), else the service path is unavailable (fail closed).

Evidence: `test_gap5_activation_and_principal_hardening` and `test_authorized_gate_closed_without_activation`.

## Gap 6 (HIGH) - the real candidate-to-reviewer HTTP chain

`test_gap6_full_candidate_to_reviewer_http_chain` drives the actual routes end to end: candidate session (`/soc-test/login`) -> `/soc/launch` provisioning through the S5 binding -> candidate queries their own telemetry under their scoped role -> `/case` (pinned to the binding) -> `/case/<id>/draft` -> `/case/<id>/verify` -> `/case/<id>/submit` (signed preservation) -> reviewer `/admin/cases/submission/<id>/qualify` (test-only authorized award) -> separate human report approval -> Board 2 clearance -> exactly-once Board 3 promotion (a second qualify does not re-award or double-promote). Only infrastructure boundaries are injected: the OpenSearch double (`soc_gateway.set_cluster_factory`, `case_routes.set_reader_factory`); the qualifying submission is produced through the candidate HTTP routes, not constructed directly. The service-level tests are retained.

## Changed files
- `strata_board2.py` - pinned-contract generation (`_resolve_pinned`, `generate_world`); system-meta index + fail-closed `provision()` state machine; `read_index_meta` reads the protected index.
- `strata_qualification.py` - full-payload + case_id/index/version binding in `_check_submission_binding`; cached-decision signature re-verification; hardened `assert_gate_open` (deployment identity, RANGER_ENV fail-closed, permitted-test flag) and token-bound service principal; `build_activation` carries `deployment_id`.
- `siem/case_contract.py` - `payload_digest()`, `payload_sha256` + `attempt` in the signed record, `PRESERVATION_VERSION = 4`.
- `case_routes.py` - submit meta carries `attempt`.
- `soc_gateway.py` - `set_cluster_factory` injection hook.
- `siem/tests/test_strata_s5_board2.py` - gap regressions + the full HTTP chain; service tests retained.

## Test evidence and result classes
- **SQLite (A, unit/logic) + fake-OpenSearch (C-double)**: the S5 suite. Run counts in the handoff message.
- **Real PostgreSQL (B)**: `test_concurrent_authorized_decision_is_idempotent_postgres` against the authorized disposable instance (skips with reason otherwise).
- **Fake OpenSearch vs actual OpenSearch**: all OpenSearch-layer behavior here runs against `FakeCluster` (the in-process `LiveCluster` double), explicitly distinguished; **actual** OpenSearch ingestion/search/DLS validation against a live 2.17.1 node remains a separate requirement (E), not claimed here.
- **End-to-end (D)**: the full HTTP chain in isolation (SQLite + fake OpenSearch), positive and the negative gates.

## Migration
Additive, unchanged from the S5 delivery: `scenario_bindings`, `qualification_decisions`, `cases.binding_id/content_hash/variant_id`, plus the operational use of a `.ranger-qualmeta` system index (created on demand by the broker; no migration). `PRESERVATION_VERSION` is now 4 - historical records signed under v2/v3 still verify under their own version; new records bind the full payload. A production migration script lands with the activation change (release-gated).

## Remaining limitations / blockers
Unchanged from the S5 delivery section K: live OpenSearch validation on a disposable node; written activation + real-cohort shadow run with reviewer adjudication; production-safe `SECRET_KEY`/`RANGER_REF_KEY`/`RANGER_SIGNING_KEY` and a MAC/signing key-version + rotation scheme (with old-key verification for historical records); a signed production `ActivationAuthorization` naming the deployment; re-index/drop of historical telemetry carrying `ranger.scenario_seed`; candidate access stays disabled. The pre-existing full-PG forensic test-order failures (shared-fixture app-context isolation gap) are unchanged and still out of S5 scope.

## Stop conditions honored
No merge/deploy/Railway/prod-migration/activation/candidate-access/new-service/S6/PARALLAX; 95 bar and S1/S2 unchanged.

Stop for review.
