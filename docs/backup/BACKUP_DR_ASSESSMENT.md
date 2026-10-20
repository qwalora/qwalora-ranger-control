# Qwalora Ranger — PostgreSQL Backup & Disaster-Recovery Assessment (Sprint 1B)

Scope: backup and recovery for the Ranger PostgreSQL system of record (STRATA + PARALLAX candidate
records, research experiments/investigations, signed evidence and adjudications, audit-chain events
and checkpoints, program entitlements, drafts/submissions, qualification artifacts). Branch
`feat/sprint-1b-backup-dr` off the accepted baseline `b0f1588`. All development and tests use
synthetic data and a disposable PostgreSQL; no live database, service, or infrastructure was touched.

Important: a successful disposable-DB test is not a verified production recovery capability. Production
recovery readiness is explicitly NOT claimed here (no live backup has been restored and verified).

## 1. Existing capability assessment

Mechanisms already present in the baseline and validated on disposable PostgreSQL:
- `scripts/pg_backup.py` — encrypted logical backup: `pg_dump -Fc` streamed into `age` with a PUBLIC recipient (the running service can create but not decrypt backups). DB password via a 0600 `PGPASSFILE`, never on argv; fail-closed if no age recipient (never writes plaintext); SHA-256 sidecar + JSON manifest; structured logs with the DB URL redacted. Exit codes 0/2/3.
- `scripts/pg_backup_prune.py` — Grandfather-Father-Son retention (keep N daily / M weekly / K monthly), dry-run by default, never deletes the newest, refuses if retention would delete everything.
- `scripts/pg_restore_verify.py` — restores into an ISOLATED disposable DB (refuses production-like names), and verifies ciphertext SHA-256 before decrypt, schema consistency, row-count parity, the Ed25519 hash-chained audit trail, and (new in 1B) every research-evidence/investigation/reviewer-adjudication signature, plus qualification isolation via core-table parity. Exit codes 0/2/3/4.
- `scripts/backup_healthcheck.py` — read-only dead-man's-switch: newest manifest exists, age within window, ciphertext SHA matches, optional min bytes. Exit codes 0/2/3/4.
- `deploy/backup-runner/` — a prepared (NOT deployed) Railway cron image chaining backup -> offsite upload (S3-compatible) -> healthcheck -> prune, failing closed with no offsite target. Installs `age`, `awscli`, and `postgresql-client-18` with a build-time assertion that `pg_dump >= 18`.

Encryption: `age` X25519 public-key, decryption identity held separately/offline. Backup schedule/retention: the runner README specifies daily `0 7 * * *`; retention via GFS prune plus bucket lifecycle. Offsite storage: supported by the runner (`RANGER_BACKUP_S3_URL` + `AWS_*`), not yet provisioned. Integrity: SHA-256 + versioned manifest (now `manifest_version: 1` with `schema_tables`). PostgreSQL version: nonprod server is `postgres-ssl:18`; the runner pins client 18 (pg_dump major must be >= server major, and the restore target must be the same major). Signing-key dependency: restore verification re-verifies Ed25519 signatures and therefore requires the SAME signing key material (`RANGER_SIGNING_KEY`/`RANGER_SIGNING_KEYS`) that produced the records; 1B adds a guard that refuses to verify under a derived key. Operational failure conditions (all fail closed): no recipient, SHA mismatch, decrypt/auth failure, schema drift, count mismatch, any signature failure, missing signing key, and (runner) no offsite target.

Status: Implemented and tested on disposable PostgreSQL. NOT operationally validated (not scheduled/enabled, no offsite destination provisioned, no live restore drill).

## 2. Proposed production backup architecture

Two independent layers:
- Layer 1 — Railway-managed PostgreSQL backups (volume snapshots / PITR): the platform baseline, low-RPO but coupled to the Railway account/region and not independently portable or verifiable. Confirm it is enabled and note its retention.
- Layer 2 — independent encrypted logical backups (the scripts, via the backup-runner cron): age-encrypted `pg_dump`, pushed to an access-controlled offsite object store with versioning and object-lock. This protects against account/region/platform loss and ransomware, and is the layer whose integrity the restore-verify tool can prove end to end.

Both layers are warranted: Railway-managed backups alone are not a defensible DR posture for signed research evidence, because they are platform-coupled and cannot be independently integrity-verified or restored into a neutral environment. The independent encrypted offsite backup is required.

Capabilities provided: automated daily schedule; age public-key encryption (decryption key offline); SHA-256 + versioned manifests including a schema fingerprint; GFS retention plus bucket lifecycle; backup-failure alerting via the dead-man's-switch healthcheck wired to a Railway webhook or an external monitor; protection from accidental deletion via object-lock/versioned bucket and the prune's dry-run-default + never-delete-newest guards; and a documented operator recovery runbook (`RECOVERY_RUNBOOK.md`).

## 3. Tested backup & restore implementation

The implementation is the scripts above plus Sprint 1B enhancements on this branch:
- `pg_backup.py`: records `manifest_version` and a `schema_tables` fingerprint (public base tables) in the manifest, best-effort and never logging row data.
- `pg_restore_verify.py`: adds schema-consistency verification against the manifest, per-row re-verification of all research/investigation/adjudication Ed25519 signatures (not just the audit chain), a fail-closed guard requiring explicit signing-key material, qualification-isolation parity (`unit_results`, `badges`, `parallax_research_runs` added to the core tables), and fails closed (not silently downgrades) on a broken checkpoint stream.
Evidence: `siem/tests/test_backup_dr_sprint1b.py` plus the existing backup suites (see §9).

## 4. Recovery validation report

On disposable PostgreSQL with real `age` and `pg_dump`/`pg_restore` (PG16), a seeded database (candidates, program memberships, a signed PARALLAX trial + investigation + reviewer adjudication, and audit events) was backed up and restored into an isolated database, and verification confirmed: ciphertext SHA-256 match; schema fidelity (33 tables, no drift); row-count parity across the core tables; audit-chain integrity; research-evidence and reviewer-adjudication signatures all re-verified (3/3 research runs); candidate entitlements intact; and qualification isolation (0 `qualification_decisions`, 0 `unit_results` of kind `qualification_decision`, 0 `badges`, 0 `board_results`). Every corruption path fails closed (truncation, wrong identity, invalid manifest, schema drift, missing signing key, tampered research record). This validates the mechanism, not a production recovery.

## 5. RPO / RTO feasibility (provisional; require measured validation + business approval)

- RPO 24h: met by a daily logical backup (worst case 24h of logical-backup loss); Railway PITR, if enabled, reduces effective RPO to minutes. Feasible.
- RTO 4h: the restore path (fetch artifact, decrypt, `pg_restore`, verify) completed in seconds on the current small dataset in testing; comfortably within 4h now. RTO grows with database size and must be re-measured as research/audit volume grows. Feasible now.
Both targets remain proposed engineering objectives until a measured live isolated restore drill and business sign-off confirm them.

## 6. Operational recovery runbook
See `docs/backup/RECOVERY_RUNBOOK.md`.

## 7. Required Railway and offsite-storage configuration (authorization-gated; not provisioned here)
- A Railway cron service built from `deploy/backup-runner/` (schedule `0 7 * * *`), on the private network with read access to `parallax-postgres` via its `DATABASE_URL`.
- An offsite S3-compatible bucket with versioning and object-lock (immutability window >= retention), plus least-privilege credentials: the runner gets write/put only (no delete, no read); a separate restore-only principal gets read.
- Environment variable NAMES (no values here): `RANGER_BACKUP_AGE_RECIPIENT` (public), `RANGER_BACKUP_S3_URL`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (write-only principal), optional `AWS_ENDPOINT_URL_S3`, `RANGER_BACKUP_DEST`, `RANGER_BACKUP_MAX_AGE_HOURS`, `RANGER_BACKUP_KEEP_DAILY/WEEKLY/MONTHLY`. The age PRIVATE identity is stored offline / in a separate secret store and NEVER placed on the runner.

## 8. Cost and retention considerations
Logical dumps are small at current data volume (well under 1 GB) and grow with research runs and audit events. GFS defaults (7 daily / 4 weekly / 3 monthly ≈ 14 artifacts) plus a bucket lifecycle keep storage cost negligible at current size; object-lock adds minimal cost; egress is incurred only on restore. Re-estimate when the dataset grows materially.

## 9. Release-gate evidence matrix

| Requirement (§4) | Status | Evidence |
|---|---|---|
| PostgreSQL data restores successfully | Implemented and tested | `test_backup_restore.py::test_backup_restore_roundtrip...`; `test_backup_dr_sprint1b.py::test_roundtrip_reverifies_research_and_adjudication_signatures` |
| Schema and migrations remain consistent | Implemented and tested | manifest `schema_tables` + `verify_schema`; `test_schema_incompatibility_fails_closed` |
| Research evidence signatures verify | Implemented and tested | `_verify_research_runs`; roundtrip (3/3 runs); `test_tampered_research_record_fails_verification` |
| Reviewer adjudication signatures verify | Implemented and tested | adjudication run re-verified in `_verify_research_runs`; roundtrip |
| Audit-chain integrity remains valid | Implemented and tested | `verify_signatures` (verify_chain + verify_events); `test_parallax_recovery_pg.py` |
| Candidate entitlements remain intact | Implemented and tested | row-count parity + sample_records; roundtrip |
| STRATA qualifications do not change | Implemented and tested | core-table parity (`qualification_decisions`, `board_results`, `unit_results`, `badges`) |
| PARALLAX research issues no qualification | Implemented and tested | `test_qualification_isolation_after_restore` |
| Historical signing-key verification available | Implemented and tested | kid-aware per-row verify; `test_verification_detects_wrong_signing_key`; `test_missing_signing_key_fails_closed` |
| Corrupted / incomplete / invalid-manifest / encryption-auth / missing-key fail closed | Implemented and tested | `test_backup_dr_sprint1b.py` (tamper, truncate, invalid manifest, wrong identity, missing key) |
| Idempotency / safe failure | Implemented and tested | `test_restore_verify_is_idempotent`; prune dry-run; recovery rollback tests |
| Scheduled offsite backups actually running | Requires infrastructure authorization + live drill | `deploy/backup-runner` prepared, not deployed |
| Railway-managed PITR enabled/configured | Not verified | not inspectable via current tooling |
| Measured RPO/RTO from a real backup | Requires a live isolated restore drill | not performed |

## 10. Decisions requiring your authorization
- B1: provision the Railway cron backup service from `deploy/backup-runner/` (schedule, private-network access).
- B2: provision the offsite S3-compatible bucket with versioning + object-lock, and least-privilege write-only runner credentials plus a separate read-only restore principal.
- B3: generate and store the age keypair — the PUBLIC recipient on the runner, the PRIVATE identity offline / in a separate secret store (never on the runner); this is key material, so it is created by you, not here.
- B4: confirm/enable Railway-managed PostgreSQL PITR and record its retention.
- B5: ratify RPO (24h) and RTO (4h) as policy after a measured live drill.
- B6: authorize a live isolated restore drill: restore an ACTUAL nonprod backup into a disposable database and run `pg_restore_verify.py`. This never touches the live database.
- B7: confirm the signing-key material that must remain available to verify restored historical records (ties to Sprint 1A: `legacy:696697820b69d289` for current nonprod records).

## Final assessment (status categories)
- Implemented and tested: the backup/prune/restore-verify/healthcheck scripts and all 31 backup/DR tests on disposable PostgreSQL, including every fail-closed path and the new research/adjudication signature + schema + qualification-isolation checks.
- Configured but not operationally validated: the backup-runner cron service spec and schedule, manifests, and healthcheck wiring (defined in-repo, not deployed).
- Requires infrastructure authorization: the cron service, offsite bucket, IAM/credentials, and age recipient provisioning (B1 to B3).
- Requires a live isolated restore drill: restoring a real nonprod backup and passing verification (B6); measured RPO/RTO (B5).
- Not verified: Railway-managed PITR enablement/configuration, real offsite durability, and production recovery readiness.

Production recovery readiness is NOT claimed. It is established only after a real backup has been restored into an isolated environment and the restored research evidence and audit chain have passed verification (B6).
