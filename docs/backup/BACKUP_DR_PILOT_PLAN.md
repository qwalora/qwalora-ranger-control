# Qwalora Ranger — Sprint 1B Backup/DR: Release-Gate Finalization & Nonproduction Pilot Plan

Branch `feat/sprint-1b-backup-dr`. Approval-gated design for a nonproduction recovery pilot. No
storage, Railway service, credential, live database, variable, or recovery key was created or
changed. Values marked [proposal] are proposed engineering defaults, not approved configuration.
Ranger is not disaster-recovery ready until a live isolated restore drill passes (§6, §9).

## 1. Mandatory upload verification (implemented this sprint)

The runner now delegates post-upload confirmation to `scripts/backup_upload_verify.py`, which:
- confirms the newest backup OBJECT and BOTH integrity sidecars (`.sha256`, `.manifest.json`) are visible offsite at their expected byte sizes, recording any returned ETag/version-id/checksum;
- never accepts upload-command success alone as delivery;
- is MANDATORY and non-disableable for a production/readiness job: with `RANGER_BACKUP_REQUIRE_VERIFY=1` (or a production/ambiguous environment marker), `RANGER_BACKUP_VERIFY_UPLOAD=0` fails closed (exit 2) instead of skipping;
- distinguishes remote visibility (a HeadObject success proves the object is present and the right size) from provider durability (the provider's replication SLA, not proven by this check);
- exits nonzero on any failure, which is the alerting signal (the Railway cron run fails).
Negative tests: `siem/tests/test_backup_upload_verify.py` (9) covers all-three-verified, missing sidecar, size mismatch, object-not-visible, incomplete local set, production-cannot-disable, production-marker-requires, non-production-may-skip, ambiguous-env-requires.

## 2. Storage-provider recommendation

Primary (recommended): **Backblaze B2**. It implements real Object Lock (governance and compliance
modes) through its S3-compatible API, with versioning and server-side encryption, is independent of
Railway, and has low, predictable storage cost. Alternative: **AWS S3**, the most mature option
(compliance-mode WORM, SSE-S3/SSE-KMS, lifecycle, additional SHA-256 checksums, broad cross-region),
at higher restore-egress cost. A lower-egress option to evaluate is Cloudflare R2, which added
bucket-level locks in 2025, but its lock semantics differ from AWS per-object Object Lock and must be
validated for enforced per-version retention before being relied on.

Do not assume Object Lock merely because a provider exposes an S3 API. Verify at provisioning:
(a) Object Lock is actually enforced (a compliance-mode retention cannot be shortened or deleted,
even by an admin, until expiry), (b) versioning is on, (c) SSE is enabled. Differences between AWS S3
and S3-compatible implementations that matter here: Object Lock enforcement (AWS compliance mode is
true WORM; some providers offer governance-only or bucket-level locks); checksum algorithms (AWS
returns `x-amz-checksum-sha256`; many compatible providers return only ETag, and ETag is not an MD5
for multipart uploads, so never treat ETag as a content hash); SSE-KMS availability (AWS; fewer
compatible providers); IAM/permission model (AWS IAM JSON vs B2 application keys vs R2 API tokens);
and VersionId/ListObjectVersions semantics. Our integrity guarantee does not depend on the provider
checksum: the manifest SHA-256 and the restore-verify re-checks are authoritative.

Sources: Backblaze B2 Object Lock docs (https://www.backblaze.com/docs/cloud-storage-object-lock);
Backblaze B2 S3-compatible Object Lock (https://www.backblaze.com/docs/cloud-storage-enable-object-lock-with-the-s3-compatible-api);
Cloudflare R2 bucket locks changelog (https://developers.cloudflare.com/changelog/2025-03-06-r2-bucket-locks).

## 3. Permission matrix (minimum required; do not create these here)

| Role | Required actions | Must NOT have |
|---|---|---|
| Backup runner | `s3:PutObject` (covers multipart UploadPart/Complete), `s3:AbortMultipartUpload` (orphan cleanup), and `s3:GetObject` (HeadObject maps to GetObject) for the mandatory post-upload verify. On B2: an app key scoped to the bucket with write + read, no delete. | `s3:DeleteObject`/`DeleteObjectVersion`, `s3:PutObjectRetention`/`PutObjectLegalHold`, `s3:PutLifecycleConfiguration`, `s3:ListBucket` (not needed: `cp` reads the local dir). |
| Restore operator | `s3:GetObject`, `s3:GetObjectVersion`, `s3:ListBucket`/`ListBucketVersions`, `s3:GetObjectRetention`/`GetObjectLegalHold`. | any `Put`/`Delete`. |
| Storage administrator | bucket create, `s3:PutBucketVersioning`, `s3:PutObjectLockConfiguration` (default retention + mode), `s3:PutLifecycleConfiguration` (expiration >= lock window + AbortIncompleteMultipartUpload), key/policy management; `s3:DeleteObject*` only after retention expiry. | nothing routine; the only role that may delete, and only post-retention. |

GFS pruning cannot delete protected versions: the runner holds no delete permission and no S3
retention/lock permission, and `pg_backup_prune.py` runs ONLY against the runner's local mirror (it
is never given bucket credentials). Offsite expiration is enforced solely by the bucket lifecycle,
whose expiration window is set >= the Object Lock retention, so no object version can be removed
before its lock expires. This is verified operationally by confirming the runner credential has no
delete action and that prune receives no S3 target.

## 4. Recovery-key custody procedure (no real keys generated here)

- Generation (owner, offline): create an age keypair (`age-keygen`). The PUBLIC recipient (`age1...`) is non-secret; the PRIVATE identity is a secret.
- Runner holds only the PUBLIC recipient (`RANGER_BACKUP_AGE_RECIPIENT`); it can encrypt but never decrypt.
- Private identity custody: stored offline / in a dedicated secret store (e.g., a hardware-backed secret or an offline vault), released only to restore operators, never on the runner and never in the repo.
- Recovery-access testing: during each drill, confirm the private identity can decrypt the latest backup in the isolated environment (this is exercised by `pg_restore_verify.py`).
- Historical signing-key dependency: `RANGER_SIGNING_KEY`/`RANGER_SIGNING_KEYS` are required to verify restored evidence, so they are backed up separately, offline, and every historical kid is kept in a trusted state (current nonprod records: `legacy:696697820b69d289`, Sprint 1A).
- Authority separation: the backup-upload authority (write+get S3 key + public age recipient) is distinct from the restore-decryption authority (read-only S3 key + private age identity + signing key); no single principal holds both.
- Loss-of-key contingencies: losing the private age identity makes existing encrypted backups undecryptable (data is not corrupted, but unrecoverable from those backups) — hence offline, redundant custody and periodic recovery-access testing; losing the signing key makes historical signatures unverifiable (records still restore, but their integrity cannot be proven) — hence separate offline backup of signing material; rotating the age recipient re-keys only future backups, so prior identities are retained to read historical backups.

## 5. Nonproduction pilot architecture (exact; [proposal] where open)

- Railway service: a Cron service built from `deploy/backup-runner/Dockerfile` in `parallax-nonprod`, private networking to `parallax-postgres.railway.internal`, no public domain. [proposal] schedule `0 7 * * *` (daily 07:00 UTC).
- Backup job env (names only): `DATABASE_URL` (a read-only PG role), `RANGER_BACKUP_AGE_RECIPIENT` (public), `RANGER_BACKUP_S3_URL`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (runner write+get key), `AWS_ENDPOINT_URL_S3` (provider endpoint), `RANGER_BACKUP_REQUIRE_VERIFY=1`, `RANGER_BACKUP_DEST=/tmp/ranger-backups`, `RANGER_BACKUP_MAX_AGE_HOURS=26`, `RANGER_BACKUP_KEEP_DAILY=7`/`WEEKLY=4`/`MONTHLY=3`.
- PostgreSQL read-only backup permission: [proposal] a dedicated role `ranger_backup_ro` with `CONNECT`, `USAGE` on schemas, and `pg_read_all_data` (PostgreSQL 14+) so `pg_dump` can read every table/sequence without ownership or superuser. No write/DDL.
- Offsite bucket: [proposal] `ranger-nonprod-backups` with versioning ON, Object Lock in compliance mode with a [proposal] 30-day default retention (ransomware window), SSE enabled.
- Retention: local GFS prune (7/4/3); bucket lifecycle [proposal] expire noncurrent/locked versions at 100 days (>= longest GFS window and > the 30-day lock), plus AbortIncompleteMultipartUpload after 1 day.
- Monitoring and failure alerts: the cron run exits nonzero on any backup, upload-verify, or healthcheck failure → wire a Railway webhook to the team alert channel; [proposal] also register an external dead-man's-switch (a monitor pinged only on success) so a runner that never starts is detected.
- Isolated restore target: a disposable PostgreSQL database with a name matching the restore-guard pattern (e.g., `ranger_restore_drill_<ts>`), never the live database; created and dropped per drill.
- Verification procedure: run `scripts/pg_restore_verify.py <artifact>` against the isolated target with the private age identity and the signing key present; require exit 0.
- Expected monthly cost: see §(cost) below.
- Rollback: disable or delete the Cron service; no data impact; the portal and live database are untouched; the scripts are inert until the runner invokes them.

## 6. Release-gate validation (objective PASS/FAIL)

| Check | PASS criterion |
|---|---|
| Backup completion | `pg_backup.py` exit 0; artifact + `.sha256` + `.manifest.json` present; `manifest.recipients >= 1` |
| Offsite object verification | `backup_upload_verify.py` exit 0 (all 3 files visible offsite, sizes match); production mode enforced (not skippable) |
| Successful isolated restoration | `pg_restore_verify.py` exit 0 into a disposable target |
| Schema + row-count integrity | `verify_schema` ok (no drift) AND counts parity (0 mismatches vs manifest/source) |
| Ed25519 evidence + adjudication signatures | `research_ok` true (0 of N research runs fail hash/signature/ownership) |
| Governance audit-chain + checkpoint | `chain_ok` true, `events_ok` true, checkpoint status in {ok, no_checkpoint} |
| Historical-key compatibility | restore verifies under the original signing kid; a wrong/missing key fails (negative control) |
| STRATA/PARALLAX qualification isolation | restored `qualification_decisions`/`unit_results`(qual)/`badges`/`board_results` equal source and the PARALLAX research path introduced none |
| Recovery time | measured transfer + restore + verify (+ app recovery) <= RTO ([proposal] 4h) |
| Recoverable data age | newest good backup age <= RPO ([proposal] 24h) and `backup_healthcheck.py` exit 0 |
| Retention + encryption controls | Object Lock enforced (verified), versioning on, SSE on, lifecycle expiration >= lock window, runner has no delete right |

## Monthly cost estimate (assumptions)
Assumptions: current compressed logical dump is small (tens of MB now; model growth to ~1-5 GB each);
GFS retains ~14 artifacts. Backblaze B2 storage ~$6/TB/mo: 14 × ~1 GB ≈ $0.08/mo now, ≈ $0.42/mo at 5
GB each; restore egress free up to 3× stored/day; class B/C transactions negligible → effectively
< $1/mo at current scale. AWS S3 Standard ~$0.023/GB/mo: 14 GB ≈ $0.32/mo; a full restore egress at
$0.09/GB ≈ $1.26 per restore; Object Lock free → < $2/mo at current scale. Railway Cron compute runs
only minutes/day → negligible within the existing plan. Pilot total is effectively a few dollars per
month; re-estimate as the dataset grows.

## 7-9 Authorization checklist and execution sequence

Owner authorization checklist (no action taken here):
- A1 provision the offsite bucket with versioning + Object Lock (verify enforcement) + SSE; add the lifecycle rule (expiration >= lock; abort incomplete multipart).
- A2 create three scoped credentials per the §3 matrix (runner write+get, restore read-only, admin).
- A3 generate the age keypair (public recipient to the runner; private identity offline) and confirm signing-key offline custody.
- A4 create the PostgreSQL read-only backup role.
- A5 deploy the Cron runner from `deploy/backup-runner/` with `RANGER_BACKUP_REQUIRE_VERIFY=1` and the [proposal] schedule/retention.
- A6 wire failure alerting (Railway webhook + external dead-man's-switch).
- A7 authorize the first live isolated restore drill (§6 all PASS).
- A8 ratify RPO/RTO after the measured drill; confirm/enable Railway-managed PITR as the complementary layer.

Proposed execution sequence:
1. A1-A4 (storage, credentials, keys, PG role). 2. A5 deploy the runner. 3. Observe the first run: backup -> encrypt -> upload -> mandatory offsite verify -> healthcheck -> local prune all succeed. 4. A6 confirm an induced failure raises an alert. 5. A7 run the isolated restore drill and confirm every §6 gate PASSes. 6. Record measured RPO/RTO. 7. A8 owner sign-off; only then is Ranger moved toward disaster-recovery ready.
