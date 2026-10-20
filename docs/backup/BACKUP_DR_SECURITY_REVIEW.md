# Qwalora Ranger — Sprint 1B Backup & DR: Independent Security & Recovery Review

Branch `feat/sprint-1b-backup-dr`. Independent review of the complete backup/recovery implementation,
with defects fixed and adversarial tests added on the same branch. Disposable PostgreSQL and synthetic
data only; no live service, database, variable, signing key, or offsite infrastructure was touched.
Ranger is NOT classified disaster-recovery ready (no live isolated restore drill has been performed).

## 1. Security review findings

Cryptographic protection: encryption happens before anything leaves the host (pg_dump is streamed
into age; only ciphertext touches disk); the runner uploads only `*.dump.age`, `*.sha256`,
`*.manifest.json`; no recipient fails closed before any dump; manifests expose only table names, a
redacted DB identifier, byte size, SHA-256, and core-table counts (no research payload, no secrets);
the private age identity is never on the runner. One robustness defect found and fixed (D8).

Offsite storage: the upload is `aws s3 cp --recursive` from a local directory, which is write-only
compatible (it does not list or read the destination). Object-lock + versioning make stored backups
immutable, which is the primary protection if the runner is compromised. Object-lock and the GFS
pruner are in tension, so the pruner must operate only on the runner's local mirror and offsite
retention must be enforced by a bucket lifecycle aligned to the lock window. The job previously could
report success without confirming the offsite object was durable; fixed with a post-upload size check
(D9).

Restore integrity: after the fixes, `pg_restore_verify.py` re-verifies the ciphertext SHA before
decrypt, schema consistency against the manifest, core-table count parity (with a manifest-count
fallback), the governance audit chain, checkpoint integrity, every research-evidence / investigation
/ reviewer-adjudication signature, researcher-ownership (signed id vs column, and investigation to
evidence ownership), and refuses to verify without explicit signing-key material. False-positive and
bypass paths found and fixed (D1-D6).

Operational safety: the destination guard requires an explicitly disposable name and refuses
production-like names (a live name such as `railway` is refused because it does not match the
disposable pattern); restore recreates the isolated target each run (idempotent); `pg_restore
--exit-on-error` reports partial failures; PostgreSQL major-version incompatibility is now enforced
(D7).

## 2. Confirmed defects and fixes (all fixed on this branch)

| ID | Severity | Defect | Fix |
|---|---|---|---|
| D1 | Medium | Restore verified only the audit chain, not research-evidence/investigation/adjudication signatures (§4 requirement unmet) | `_verify_research_runs`: per-row canonical-hash + Ed25519 re-verification of every research record |
| D2 | Medium | No schema-consistency check across restore | manifest `schema_tables` + `verify_schema` (fail closed on drift) |
| D3 | Medium | Missing signing key silently synthesized a derived key, risking a false-positive verify | `_require_signing_key` (fail closed if no explicit key) |
| D4 | Medium | A broken checkpoint stream was silently downgraded to the chain result | fail closed on `verify_events` error; add `assess()` checkpoint-status gate (allow only ok / no_checkpoint) |
| D5 | Low-Med | Empty/partial restore with no live source reference verified as success | manifest `row_counts` used as the parity reference when no source is supplied |
| D6 | Low | Signed-record `researcher_id` vs column mismatch, and investigation to evidence ownership, were not checked | ownership checks added to `_verify_research_runs` |
| D7 | Low | pg_restore/pg_dump major-version incompatibility not enforced | version check: fail closed if pg_restore major < backup's pg_dump major |
| D8 | Low | pg_dump stderr via a pipe could deadlock on large stderr while waiting on age | route pg_dump stderr to a temp file |
| D9 | Medium (op) | Backup job could report success before confirming the offsite object was durable | post-upload HeadObject size check in the runner (fail closed), flag-controlled |

## 3. Exact test results

Full backup/DR suite on disposable PostgreSQL with real age + pg_dump/pg_restore: **36 passed, 0
failed, 0 skipped** (`test_backup_restore.py` 5, `test_backup_prune.py` 5, `test_backup_healthcheck.py`
6, `test_parallax_recovery_pg.py` 6, `test_backup_dr_sprint1b.py` 14). New/adversarial coverage in
`test_backup_dr_sprint1b.py`: research+adjudication signature re-verify after restore; truncated
ciphertext (age auth failure); wrong age identity; invalid manifest (healthcheck); schema
incompatibility; missing signing key; tampered research record; qualification isolation after
restore; restore idempotency; tampered SHA-256 sidecar; broken audit checkpoint (tail truncation);
restore-destination-must-be-disposable; manifest-count shortfall; researcher_id column mismatch.

## 4. Residual risk register

| ID | Risk | Mitigation / status |
|---|---|---|
| RR1 | A compromised runner (write-only creds + public recipient) can upload junk NEW objects, though it cannot destroy history under object-lock | alert on object-count/size anomalies; the dead-man's-switch healthcheck; object-lock preserves history |
| RR2 | Durable-upload verification needs HeadObject (not pure write-only) | `RANGER_BACKUP_VERIFY_UPLOAD=1` (recommended) needs HeadObject; set `=0` to keep write-only and accept the weaker aws-cp exit-code signal |
| RR3 | Incomplete multipart uploads leave orphaned parts (cost, confusion) | bucket lifecycle `AbortIncompleteMultipartUpload` |
| RR4 | Restore verification depends on the signing key; losing it makes historical signatures unverifiable | back up signing key(s) separately, offline; keep historical kids trusted (Sprint 1A pin) |
| RR5 | RPO/RTO measured only for restore+verify on a tiny dataset; transfer and app-recovery phases unmeasured | measure all four phases in a live drill |
| RR6 | Railway-managed PITR enablement/retention not verifiable via current tooling | operator confirms in the Railway console |
| RR7 | Entire subsystem validated on disposable PG only | a live isolated restore drill is required before DR-ready |

## 5. Minimum viable nonproduction backup architecture
Daily Railway cron runner (private network, read on `parallax-postgres`) -> age public-key encryption
-> write to an offsite S3-compatible bucket with versioning + object-lock -> post-upload size
confirmation -> dead-man's-switch healthcheck -> local-mirror GFS prune. The age private identity is
offline; offsite retention is a bucket lifecycle aligned to the object-lock window; Railway-managed
PITR is the complementary low-RPO layer.

## 6. Required external storage permissions (least privilege)
- Backup runner (write path): `s3:PutObject` on the backup prefix (covers multipart part uploads);
  `s3:AbortMultipartUpload` for cleanup. No `s3:DeleteObject`, no `s3:ListBucket`, no `s3:GetObject`
  for a pure write-only runner.
- Durable-upload verification (if `RANGER_BACKUP_VERIFY_UPLOAD=1`): add `s3:GetObject`/HeadObject on
  the prefix. This is the documented trade-off against pure write-only.
- Restore principal (separate identity, used only during a drill/recovery): `s3:GetObject` and
  `s3:ListBucket` on the prefix; nothing else.
- Retention/immutability: bucket-level object-lock + lifecycle (expiration >= lock window;
  `AbortIncompleteMultipartUpload`); not granted to the runner.

## 7. Recovery-key custody procedure
- age keypair: generated by the owner. PUBLIC recipient goes on the runner (`RANGER_BACKUP_AGE_RECIPIENT`).
  PRIVATE identity is stored offline / in a dedicated secret store, released only to restore operators;
  never on the runner. Rotating the recipient re-keys future backups only; keep prior identities to
  decrypt historical backups.
- signing key(s): `RANGER_SIGNING_KEY` / `RANGER_SIGNING_KEYS` are required to verify restored evidence,
  so they are a recovery dependency and are backed up separately, offline. Keep every historical kid in
  a trusted state; current nonprod records are signed under `legacy:696697820b69d289` (Sprint 1A).

## 8. Operator authorization checklist
- A1 provision the offsite bucket with versioning + object-lock (choose governance vs compliance mode) and a retention window; add a lifecycle rule (expiration >= lock; abort incomplete multipart).
- A2 create two IAM principals: write-only runner (+HeadObject if upload verification is on) and a read-only restore principal.
- A3 generate the age keypair; public recipient to the runner, private identity offline.
- A4 provision/confirm the signing-key custody (offline backup; historical kids trusted).
- A5 deploy the Railway cron backup service from `deploy/backup-runner/` (schedule, private-network DB access).
- A6 confirm/enable Railway-managed PITR and record retention.
- A7 ratify RPO (24h) / RTO (4h) after a measured live drill.
- A8 authorize the first live isolated restore drill (§10).

## 9. Safe deployment and rollback sequence
Deploying this changes no portal, database, or signing key: it is a new cron service plus its env.
Order: (1) A1-A4 infrastructure and keys; (2) deploy the cron runner (A5); (3) observe the first run
-> upload -> post-upload verify -> healthcheck succeed; (4) run a live isolated restore drill (§10)
before declaring DR-ready. Rollback: disable or delete the cron service (no data impact); the scripts
are inert until the runner invokes them; nothing in the portal or the live database is affected. No
merge to main and no push to the deployed portal branch is involved.

## 10. Criteria for authorizing the first real isolated recovery drill
All must hold, and the drill never touches the live database:
- a real nonprod backup exists offsite and passes `backup_healthcheck.py` (exit 0);
- an isolated target database with a disposable name is available;
- the age PRIVATE identity and the signing key(s) that signed the records are available to the drill operator;
- `pg_restore_verify.py` on that backup returns exit 0 (ciphertext SHA, schema, counts, audit chain, checkpoint, research + adjudication signatures, researcher ownership, and qualification isolation all pass);
- the measured transfer + restore + verify (+ app-recovery) time is recorded against the RTO target.
Only after a passing drill, with business RPO/RTO sign-off, is Ranger moved toward disaster-recovery ready.
