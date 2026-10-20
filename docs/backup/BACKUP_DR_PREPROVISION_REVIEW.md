# Qwalora Ranger — Sprint 1B Nonproduction Backup Pilot: Preprovisioning Review

Branch `feat/sprint-1b-backup-dr` @ `563d463`. Research, validation, and preparation only. Nothing is
provisioned: no bucket, credential, key, Railway service, or PostgreSQL role was created, and the
accepted Ranger baseline (`b0f1588`) is unchanged. Provider capabilities and prices are from current
official documentation and must be re-confirmed at provisioning time.

## 1. Verified provider compatibility report

Backblaze B2 (primary), verified against official docs:
- S3-compatible Object Lock: supported via the S3 API; the bucket must be created with Object Lock enabled (it cannot be added to an existing bucket).
- Compliance-mode immutability: supported (governance and compliance modes); compliance-mode retention cannot be shortened or deleted, even by an account admin, until expiry.
- Versioning: supported and required for Object Lock; each upload is a new version.
- Retention + lifecycle: default retention is set at the bucket (or per object); B2 lifecycle rules cannot remove a version still under lock, so lifecycle expiry must be set at or beyond the lock window.
- Server-side encryption: SSE-B2 (AES-256, provider-managed) and SSE-C supported. Our data is already client-side age-encrypted, so SSE is defense-in-depth; enable SSE-B2.
- HeadObject and uploads: HeadObject and PutObject are supported through the S3 API; HeadObject requires the key's read capability. Our verifier uses HeadObject (ContentLength) only.
- Multipart: supported (5 MB minimum part, like S3); the AWS CLI auto-multiparts above ~8 MB. Our verifier compares object SIZE, not ETag, so B2's multipart ETag semantics (ETag is not an MD5 for multipart, same as S3) do not affect verification.
- Regions: multiple regions are available (US West, US East, EU Central). [proposal] use a region distinct from Railway's `us-west2` for geographic independence; confirm data-residency constraints for research data before choosing EU.
- Pricing: see §5.

AWS S3 (fallback): the most mature option — compliance-mode Object Lock, versioning, SSE-S3/SSE-KMS,
lifecycle, additional SHA-256 checksums, broad cross-region — at higher egress cost. Suitable as a
drop-in via `AWS_ENDPOINT_URL_S3` unset (native) and standard IAM (see §3).

Incompatibilities with the existing backup runner: none at the protocol level. One operational
compatibility RISK to resolve at provisioning: recent AWS CLI v2 versions send request integrity
checksums (CRC32) by default, which some S3-compatible providers reject and which can fail uploads
against B2 depending on versions. Mitigation: set `AWS_REQUEST_CHECKSUM_CALCULATION=when_required` and
`AWS_RESPONSE_CHECKSUM_VALIDATION=when_required` in the runner environment (or pin a known-good AWS CLI
version in `deploy/backup-runner/Dockerfile`, which currently installs awscli unpinned via apt). This
is the single must-verify item for the runner against B2. Everything else (encrypt-before-upload,
`aws s3 cp` with a custom endpoint, size-based HeadObject verification, no reliance on ETag/checksum)
is provider-robust.

Sources: Backblaze B2 Object Lock (https://www.backblaze.com/docs/cloud-storage-object-lock);
S3-compatible app keys (https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys);
IAM/ACL mapping (https://www.backblaze.com/docs/cloud-storage-map-iam-policies-and-s3-acls-to-backblaze-b2-access-controls);
pricing (https://www.backblaze.com/cloud-storage/pricing).

## 2. Exact pilot infrastructure specification (configuration matrix; [proposal] where open)

| Item | Specification |
|---|---|
| Storage provider / region | Backblaze B2; [proposal] `us-east` (distinct from Railway us-west2) |
| Bucket | [proposal] `ranger-nonprod-backups`, private, Object Lock ENABLED at creation, versioning ON |
| Object Lock | compliance mode, default retention [proposal] 30 days |
| Encryption | SSE-B2 (AES-256) ON (data also client-side age-encrypted) |
| Lifecycle | expire versions at [proposal] 100 days (>= lock window and >= longest GFS); abort incomplete multipart after 1 day |
| Runner credential | B2 app key, bucket-scoped: `readFiles` + `writeFiles` (no `deleteFiles`, no `listBuckets`) |
| Restore credential | B2 app key, bucket-scoped: `readFiles` + `listFiles` (no write/delete) |
| Age recipient | PUBLIC recipient on the runner (`RANGER_BACKUP_AGE_RECIPIENT`); private identity offline |
| Railway service | Cron service from `deploy/backup-runner/Dockerfile`, `parallax-nonprod`, private networking to `parallax-postgres.railway.internal`, no public domain |
| Railway variables (names) | `DATABASE_URL` (read-only role), `RANGER_BACKUP_AGE_RECIPIENT`, `RANGER_BACKUP_S3_URL`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (runner key), `AWS_ENDPOINT_URL_S3` (B2 S3 endpoint), `AWS_REQUEST_CHECKSUM_CALCULATION=when_required`, `AWS_RESPONSE_CHECKSUM_VALIDATION=when_required`, `RANGER_BACKUP_REQUIRE_VERIFY=1`, `RANGER_BACKUP_DEST=/tmp/ranger-backups`, `RANGER_BACKUP_MAX_AGE_HOURS=26`, `RANGER_BACKUP_KEEP_DAILY=7`/`WEEKLY=4`/`MONTHLY=3` |
| PostgreSQL backup role | [proposal] `ranger_backup_ro`: CONNECT + USAGE + `pg_read_all_data` (PG14+); no write/DDL |
| Backup schedule | [proposal] `0 7 * * *` (daily 07:00 UTC) |
| Alerting | Railway webhook on nonzero cron exit + external dead-man's-switch pinged only on success |
| Restore environment | disposable PostgreSQL DB, name matching the restore guard (e.g., `ranger_restore_drill_<ts>`), never the live DB |

## 3. Least-privilege permission policies

Backblaze B2 (capability model, bucket-scoped):
- Runner: `readFiles`, `writeFiles`. (`readFiles` enables HeadObject/GetObject for the mandatory verify.) NOT `deleteFiles`, NOT bypass-governance.
- Restore operator: `readFiles`, `listFiles`. No write/delete.
- Storage admin: account master key (or a key with `writeBuckets`, `deleteFiles`, and bypass-governance) used ONLY to create the bucket with Object Lock, set retention/lifecycle, and (post-retention) clean up. Not used by the runner.

AWS S3 fallback (IAM JSON intent):
- Runner: Allow `s3:PutObject`, `s3:AbortMultipartUpload`, `s3:GetObject` on `arn:aws:s3:::<bucket>/<prefix>/*`; explicit Deny `s3:DeleteObject*`, `s3:PutObjectRetention`, `s3:PutObjectLegalHold`.
- Restore: Allow `s3:GetObject`, `s3:GetObjectVersion`, `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetObjectRetention` on the bucket/prefix; no Put/Delete.
- Admin: bucket create, `s3:PutBucketVersioning`, `s3:PutObjectLockConfiguration`, `s3:PutLifecycleConfiguration`; delete only after retention expiry.

GFS pruning cannot destroy immutable backups: the runner holds no delete and no lock permission, and `pg_backup_prune.py` runs only against the local mirror (it is never given bucket credentials). Offsite expiry is lifecycle-only, with expiry >= the Object Lock window.

## 4. Recovery-key custody requirements
- age keypair generated offline by the owner; PUBLIC recipient on the runner; PRIVATE identity offline / in a dedicated secret store, released only to restore operators, never on the runner or in the repo.
- Signing key(s) (`RANGER_SIGNING_KEY`/`RANGER_SIGNING_KEYS`) are required to verify restored evidence; backed up separately, offline; all historical kids kept trusted (current nonprod: `legacy:696697820b69d289`).
- Backup-upload authority (write+read B2 key + public recipient) is separate from restore-decryption authority (read-only B2 key + private identity + signing key); no single principal holds both.
- Periodic recovery-access testing: each drill confirms the private identity decrypts the latest backup in the isolated environment.
- Loss contingencies: lost private age identity => existing backups undecryptable (hence redundant offline custody); lost signing key => restored evidence unverifiable (hence separate offline backup); recipient rotation re-keys only future backups (retain prior identities).

## 5. Monthly cost model (three scenarios; verified published pricing, assumptions noted)

Assumptions: GFS retains ~14 artifacts (7 daily + 4 weekly + 3 monthly). Daily backup. B2 storage
$6.95/TB/mo (~$0.00695/GB/mo), egress free up to 3x stored then $0.01/GB, Class A/B/C free
(pay-as-you-go), Class D $0.004/10k (first 2,500/day free), first 10 GB storage free. AWS S3 Standard
list: storage $0.023/GB/mo, egress $0.09/GB, PUT $0.005/1k, GET $0.0004/1k, Object Lock free (verify
at provisioning). Railway Cron compute is minutes/day, negligible within the existing plan.

| Scenario | Per-dump | Retained (~14x) | B2 storage | B2 requests/egress | AWS storage | AWS requests/egress | Railway |
|---|---|---|---|---|---|---|---|
| Current (small) | ~20 MB | ~0.3 GB | ~$0 (under 10 GB free) | free (Class A/B/C free; a restore << 3x) | ~$0.01/mo | PUT/GET ~$0; restore egress ~$0.002 | negligible |
| Moderate | ~500 MB | ~7 GB | ~$0.05/mo (near free tier) | free | ~$0.16/mo | ~$0; restore egress ~$0.045/restore | negligible |
| High-growth | ~5 GB | ~70 GB | ~$0.49/mo | free (egress allowance 3x=210 GB/day) | ~$1.61/mo | ~$0; restore egress ~$0.45/restore | negligible |

Net: the pilot costs a fraction of a dollar per month on B2 across all three scenarios (a couple of
dollars on AWS at high growth), dominated by storage; retrieval is free on B2 within the 3x
allowance and a per-restore egress charge on AWS. Re-estimate if retention or dump size grows beyond
these assumptions.

## 6. Risks and unresolved dependencies
- RD1: AWS CLI checksum default vs B2 (set the two checksum env vars or pin the CLI); the single must-verify runner-compat item.
- RD2: Object Lock must be enabled at bucket creation on B2 (cannot be added later).
- RD3: region / data-residency decision for research data (owner).
- RD4: Railway Cron service support for the schedule, private-network reach to `parallax-postgres`, and secret injection (verify in Railway).
- RD5: the `ranger_backup_ro` role must be created on the live nonprod DB (an admin action, not done here).
- RD6: external dead-man's-switch monitor selection.
- RD7: age private identity + signing-key offline custody must exist before any restore is possible.
- RD8: no live restore drill has run; Ranger is not DR-ready until one passes all §6 gates (see the pilot plan).

## 7. Step-by-step pilot execution plan
1. Provision the B2 bucket with Object Lock enabled, versioning on, SSE-B2, default retention [proposal] 30 days, and the lifecycle rule (expiry [proposal] 100 days + abort incomplete multipart). Verify Object Lock is actually enforced.
2. Create the three scoped B2 keys per §3; create the `ranger_backup_ro` PostgreSQL role.
3. Generate the age keypair (public recipient recorded; private identity to offline custody); confirm signing-key offline custody.
4. Deploy the Railway Cron runner from `deploy/backup-runner/` with the §2 variables, including `RANGER_BACKUP_REQUIRE_VERIFY=1` and the checksum env vars.
5. Trigger one run manually; confirm the chain succeeds: backup -> encrypt -> upload -> mandatory offsite verify (object + both sidecars, sizes match) -> healthcheck -> local prune.
6. Induce a failure (e.g., wrong endpoint) and confirm a nonzero exit raises the alert and the dead-man's-switch flags a missed run.
7. Run the isolated restore drill: `pg_restore_verify.py` on the latest backup into a disposable DB; require every §6 release-gate PASS; record measured transfer + restore + verify time.
8. Owner reviews results, ratifies RPO/RTO, confirms Railway-managed PITR as the complementary layer, and only then classifies Ranger DR-ready.

## 8. Operations requiring explicit owner authorization (none performed here)
A1 create the B2 bucket + Object Lock + lifecycle + SSE; A2 create the three B2 keys; A3 create the
`ranger_backup_ro` PostgreSQL role; A4 generate the age keypair and establish offline custody of the
private identity and the signing key; A5 deploy the Railway Cron runner and set its variables; A6
wire alerting + the external dead-man's-switch; A7 authorize and run the first isolated restore drill;
A8 ratify RPO/RTO and confirm PITR. No bucket, credential, key, Railway service, or PostgreSQL role
is created until these are authorized.
