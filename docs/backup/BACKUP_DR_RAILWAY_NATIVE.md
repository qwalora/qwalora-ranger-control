# Qwalora Ranger — Railway-Native Backup & Recovery Architecture

Branch `feat/sprint-1b-backup-dr`. Adapts the completed Sprint 1B backup/recovery implementation to a
Railway-first architecture per the infrastructure decision (no external storage provider). Research,
design, and non-deploying code adaptation only: no bucket, service, volume, environment, variable,
or key was created or changed; the accepted baseline `b0f1588` is unchanged. Railway capabilities are
from current official docs and must be re-confirmed at provisioning.

## Verified Railway capabilities (not assumed)

Storage Buckets: private, S3-compatible object storage on Tigris, encrypted at rest, $0.015/GB-month
with free egress and free unlimited API operations; each environment gets its own isolated bucket and
credentials; virtual-hosted-style endpoint (e.g. `https://t3.storageapi.dev`); deletion is staged with
a 52-hour restore window, then permanent.
- Supported S3 ops: Put, Get, Head, Delete, List/ListV2, Copy, presigned URLs, object tagging, multipart.
- NOT supported: server-side encryption (customer), object versioning, Object Lock, bucket lifecycle.
- Credentials: one full-access S3 credential set per bucket (`ACCESS_KEY_ID`/`SECRET_ACCESS_KEY`/`ENDPOINT`/`BUCKET`/`REGION=auto`); granular per-operation keys are NOT offered.
- Buckets are reachable over public networking only (private, credential-gated, TLS); no private-network access.

PostgreSQL PITR: when enabled, the Postgres image archives every WAL segment to a Railway-managed
bucket via pgBackRest, with weekly full + daily differential base backups; the last 4 full backups are
kept (~4-week window); no separate fee (pay bucket storage + egress); restore is to a NEW service, so
the source database is never modified. Single-node by default (convert to HA for automatic failover).
Volume backups also restore in place or to a new service.

Sources: Railway Storage Buckets (https://docs.railway.com/storage-buckets), PITR
(https://docs.railway.com/volumes/point-in-time-recovery), Back Up and Restore Postgres
(https://docs.railway.com/guides/postgres-backups-restores).

## 1. Railway-native backup architecture

Two complementary Railway-hosted layers:
- Layer 1 (primary, platform-managed): Railway PITR on `parallax-postgres`. Continuous WAL archiving gives a low RPO within the ~4-week window, and restore-to-new-service is inherently isolated. Minimal operational overhead. Limitation: platform-coupled (same provider/account as the DB), ~4-week retention, and not independently verifiable or portable.
- Layer 2 (independent logical, reuses the Sprint 1B runner): a Railway Cron service runs the existing encrypted logical backup (`pg_dump -Fc` streamed into age with a PUBLIC recipient), uploads the ciphertext + `.sha256` + `.manifest.json` to a Railway Storage Bucket via its S3 endpoint, then runs mandatory upload verification, the freshness healthcheck, and a GFS bucket prune. This yields portable, tamper-evident, signed-evidence-verifiable logical dumps that are restore-verified into a disposable database, extending retention (GFS monthly) beyond the PITR window and surviving logical corruption.

Both layers live on Railway. True immutability (Object Lock/WORM) and an off-platform copy are
intentionally deferred until contractual requirements justify an external provider.

## 2. Minimum required Railway services and storage
Existing (unchanged): `parallax-portal`, `parallax-postgres`, `parallax-inference`,
`qwalora-ranger-control`. New (authorization-gated, not created here): enable PITR on
`parallax-postgres` (uses a Railway-managed bucket); one Storage Bucket (e.g. `ranger-nonprod-backups`)
in `parallax-nonprod`; one Cron service (the backup runner) in `parallax-nonprod`. Restore drills use
either PITR restore-to-new-service or a disposable PostgreSQL target; no permanent extra service is
required.

## 3. Compatibility assessment (runner vs Railway Buckets)
- Works with no functional change: upload (PutObject), mandatory verification (HeadObject on the object and both sidecars, size match), large dumps (multipart), and the new GFS bucket prune (List/Delete). The verifier compares object SIZE, not ETag, so Railway/Tigris ETag semantics are irrelevant.
- Object Lock not supported: backups are NOT immutable. Compensating controls: unique timestamped keys (no accidental overwrite), the 52-hour bucket-deletion grace, client-side age encryption, and SHA-256 + signed-record verification that makes any tampering fail the restore. True WORM is deferred (external provider).
- Versioning not supported: mitigated by unique keys (a key is never reused); the verifier records a version id only if present.
- Server-side encryption not supported: compensated by client-side age encryption (the provider never sees plaintext); Railway also encrypts at rest at the platform level.
- Lifecycle not supported: retention is handled by `scripts/bucket_prune.py` (new; reuses the proven GFS keep logic), dry-run by default, apply-gated, never deletes the newest, refuses to delete everything.
- Granular credentials not supported: one full-access credential per bucket, so write-only vs read-only separation is not possible. Mitigation: per-environment bucket isolation (Railway gives each environment its own bucket + credentials) and tight custody of the single credential. Documented as SP4.
- AWS CLI checksum caveat: set `AWS_REQUEST_CHECKSUM_CALCULATION=when_required` and `AWS_RESPONSE_CHECKSUM_VALIDATION=when_required` on the runner (or pin the CLI) and verify uploads at the pilot.
- "No public database endpoints" preserved: the database connection stays on the private network; only the bucket is reached over public TLS, credential-gated, with age-encrypted artifacts.

## 4. Revised backup runner configuration (Railway variable mapping; names only)
Map the bucket's Railway-provided variables to the runner's AWS-standard names:
- `AWS_ACCESS_KEY_ID` <- bucket `ACCESS_KEY_ID`; `AWS_SECRET_ACCESS_KEY` <- bucket `SECRET_ACCESS_KEY`
- `AWS_ENDPOINT_URL_S3` <- bucket `ENDPOINT`; `AWS_REGION`/`AWS_DEFAULT_REGION` <- bucket `REGION` (`auto`)
- `RANGER_BACKUP_S3_URL` = `s3://$BUCKET/pg/`
- `RANGER_BACKUP_AGE_RECIPIENT` = PUBLIC age recipient
- `RANGER_BACKUP_REQUIRE_VERIFY=1` (mandatory offsite verification; non-disableable)
- `RANGER_BACKUP_PRUNE_APPLY=1` (retention must actually delete, since there is no lifecycle) and `RANGER_BACKUP_KEEP_DAILY/WEEKLY/MONTHLY`
- `AWS_REQUEST_CHECKSUM_CALCULATION=when_required`, `AWS_RESPONSE_CHECKSUM_VALIDATION=when_required`
- `DATABASE_URL` = a read-only PG role over the private network to `parallax-postgres`
- `RANGER_BACKUP_DEST=/tmp/ranger-backups`, `RANGER_BACKUP_MAX_AGE_HOURS=26`
The runner's local prune and the new bucket prune both run in `deploy/backup-runner/entrypoint.sh`;
the bucket prune is the only offsite retention and is apply-gated. Note: because Railway credentials
are full-access and there is no lifecycle, the runner credential must be able to delete (it performs
the GFS bucket prune); this is inherent to the Railway model and recorded as SP4.

## 5. Recovery and rollback runbook (Railway-native)
Recovery (never overwrites the operational database):
- Fast path (platform): Railway PITR restore of `parallax-postgres` to a NEW service at a chosen timestamp; verify the new service read-only (admin evidence verifier / signature checks); promote only by a deliberate cutover.
- Portable path (independent): download the latest age-encrypted logical backup from the bucket; run `scripts/pg_restore_verify.py` into a disposable PostgreSQL target (name must match the disposable guard); require exit 0 across schema, counts, audit chain, checkpoint, research + adjudication signatures, and qualification isolation.
Rollback of the backup pilot: disable or delete the Cron service and (optionally) the bucket (52-hour
grace); disabling PITR stops WAL archiving. No change to the portal, the live database, or any data.

## 6. Security and single-provider risk register
| ID | Severity | Risk | Mitigation / status |
|---|---|---|---|
| SP1 | High | No off-platform copy: a Railway account/region/platform failure or account compromise could lose the DB and its backups together | Accepted for launch per decision; add an external immutable copy when contracts require |
| SP2 | High | No Object Lock: backups are deletable by anyone holding bucket credentials or a compromised runner (no WORM/ransomware protection) | Credential custody, unique keys, 52h delete grace, PITR as a second copy, alert on object-count drops; external WORM deferred |
| SP3 | Medium | No versioning: overwriting a key loses history | Unique timestamped keys (never reused); verifier has no version dependency |
| SP4 | Medium | No granular credentials: one full-access key does upload, prune/delete, and restore-read | Per-environment bucket isolation; tight custody; nonprod pilot scope |
| SP5 | Medium | PITR window ~4 weeks | Logical GFS backups extend effective retention (monthly) but are not immutable |
| SP6 | Low-Med | Bucket is public-networking-only | TLS + credential-gated + age-encrypted artifacts; DB stays private |
| SP7 | Info | PITR and logical backups both on Railway-managed storage (correlated failure) | Consider a different bucket region for the logical copy for partial independence |

## 7. Cost estimate (verified Railway pricing: bucket $0.015/GB-mo, free egress, free API ops; PITR no separate fee)
- Bucket (logical GFS backups, ~14 artifacts): small ~0.3 GB ≈ $0.005/mo; moderate ~7 GB ≈ $0.11/mo; high ~70 GB ≈ $1.05/mo. Egress and API operations free.
- PITR: no separate fee; pays bucket storage for compressed WAL + base backups (weekly full + daily diff, 4 full retained). For a low-write research DB, [estimate] roughly $0.05-0.50/mo now, scaling with write volume.
- Cron compute: a short daily job, billed by usage; negligible (cents/mo) within the plan.
- Total nonprod pilot: roughly < $1-2/mo at current scale; a few dollars/mo at high growth. Railway's free egress and free API operations make this cheaper to operate than an external provider at this scale, at the cost of the single-provider risks above.

## 8. Step-by-step nonproduction validation plan (no provisioning performed here)
1. Enable PITR on a nonprod `parallax-postgres`; confirm WAL archiving and a base backup appear.
2. Create the Storage Bucket (auth-gated) and the Cron runner with the §4 variable mapping.
3. First run: backup -> age-encrypt -> upload -> mandatory verify (object + both sidecars, sizes match) -> healthcheck -> bucket prune (dry-run, then apply) all succeed; confirm an induced failure exits nonzero and alerts.
4. PITR restore-to-new-service drill; verify the new service read-only; never touch the live DB.
5. Logical restore-verify into a disposable PostgreSQL target; require every release-gate check PASS (schema, counts, audit chain, checkpoint, research + adjudication signatures, qualification isolation).
6. Measure RPO/RTO; owner sign-off; only then is the Railway-native backup posture accepted.

## 9. Explicit changes requiring approval
- B1 enable Railway PITR on `parallax-postgres`.
- B2 create one Storage Bucket in `parallax-nonprod`.
- B3 create one Cron backup-runner service in `parallax-nonprod` and set its variables (§4).
- B4 create the read-only PostgreSQL backup role (`ranger_backup_ro`).
- B5 generate the age keypair (public recipient on the runner; private identity offline) and keep the signing key(s) in offline custody for restore verification.
- B6 authorize the PITR restore drill and the logical restore-verify drill.
Nothing is created until B1-B6 are approved. No external storage provider is involved.

## Code changes in this adaptation (tested)
- `scripts/bucket_prune.py` (new): GFS retention for a bucket without lifecycle, reusing `pg_backup_prune.select_keep`; injectable list/delete for provider-agnostic testing; dry-run default, apply-gated, never-delete-newest, refuse-all.
- `deploy/backup-runner/entrypoint.sh`: runs the bucket prune when `RANGER_BACKUP_S3_URL` is set (Railway mode).
- Tests: `siem/tests/test_bucket_prune.py` (6). Full backup/DR + verify + bucket-prune suite: 51 passed, 0 failed, 0 skipped on disposable PostgreSQL. The encrypted backup + mandatory verification implementation is otherwise unchanged and provider-agnostic, so it runs against Railway Buckets without modification.
