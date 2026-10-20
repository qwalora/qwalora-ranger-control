# Qwalora Ranger - Stage 2 encrypted logical backup: readiness report

Branch `feat/sprint-1b-backup-dr` (non-deploying). Read-only preparation only: no Railway service,
role, key, variable, or deployment was created or changed by this work. Implementation reviewed at
`c9c8cd96` plus the Railway-native adaptation. Companion documents:
`BACKUP_DR_ROLE_PERMISSIONS.md` (backup-role privilege verification + read-only test procedure) and
`BACKUP_DR_KEY_CUSTODY.md` (recovery-key generation and custody).

## Verified state (control-plane evidence)
- PARALLAX portal operational: `/healthz` returns `{"status":"ok","db":true}`.
- Portal deployment `eb9e925e` = commit `b0f1588f66754a8748fcfee240b9479968e8ec73` (`b0f1588`),
  branch `feature/parallax-p1-architecture-foundations`. Unchanged.
- PITR enabled on `parallax-postgres` (deployment `3475da91`): `stanza-create` ok, first full base
  backup `20261020-041432F` complete (33.3 MB, 1552 files), continuous WAL archiving healthy,
  retention full=4 / diff=14 (~4-week window). Archive repo = Railway-managed `Postgres-PITR` bucket
  (`0455c0e3...`, region sjc).
- `ranger-nonprod-backups` (`c618866e...`, region iad / US-East) present and separate from the PITR
  bucket.
- The post-PITR 41-check research-integrity audit is PENDING (not run from a cloud container with no
  private-network DB path). It is NOT represented as complete.

## 1. Configuration already verified (read-only)
- Runner image `deploy/backup-runner/Dockerfile`: `python:3.12-slim` + `postgresql-client-18`
  (server 18.6; a build-time assertion fails the build if `pg_dump` < 18) + `age` + `awscli`.
  `RANGER_PG_BIN=/usr/lib/postgresql/18/bin`.
- Run chain `entrypoint.sh`: `pg_backup.py` (`pg_dump -Fc --no-owner --no-privileges --no-password`
  streamed into `age -r <PUBLIC>`; only ciphertext touches disk; fails closed with no recipient) ->
  `aws s3 cp` (uploads only `*.dump.age`, `*.sha256`, `*.manifest.json`) -> `backup_upload_verify.py`
  (mandatory) -> `backup_healthcheck.py` -> `pg_backup_prune.py` (local) -> `bucket_prune.py`
  (offsite, gated).
- Bucket compatibility: verification compares object SIZE via HeadObject (not ETag), multipart
  handles large dumps, path-style endpoint. Correct for Railway/Tigris. The logical bucket (iad) is
  region-separate from the DB (us-west2) and the PITR archive (sjc), improving SP7 independence.
- Mandatory remote verification `backup_upload_verify.py`: confirms the newest encrypted object AND
  both sidecars (`.sha256`, `.manifest.json`) are visible offsite at expected byte sizes;
  `RANGER_BACKUP_VERIFY_UPLOAD=0` fails closed under a production/readiness marker. Non-disableable.
- Role compatibility: `--no-owner --no-privileges` means the dump needs only read access, so a
  least-privilege read-only role suffices (no ownership or superuser). See
  `BACKUP_DR_ROLE_PERMISSIONS.md`.
- Deployed-code compatibility: the store/audit functions used by verification exist at `b0f1588`; the
  runner is independent of portal code and reads only the DB.

## 2. Remaining dependencies
- An age keypair: public recipient (`age1...`) for the runner; private identity generated and kept
  offline (never on the runner, never in Railway, never in chat). See `BACKUP_DR_KEY_CUSTODY.md`.
- A read-only PostgreSQL role (`ranger_backup_ro`) in the live DB.
- Bucket S3 credentials mapped to `AWS_*` on the runner (Railway provides on bucket attach).
- A private-network `DATABASE_URL` for that role (Railway variable reference to `parallax-postgres`,
  resolvable only inside `parallax-nonprod`).
- Failure alerting (Railway webhook on cron failure, or `backup_healthcheck.py` as an independent
  monitor).

## 3. Required owner actions
- Generate the age keypair offline and share only the `age1...` recipient (procedure in
  `BACKUP_DR_KEY_CUSTODY.md`). Claude will not generate keys.
- Authorize creation of `ranger_backup_ro` + grants via a DB channel (SQL in
  `BACKUP_DR_ROLE_PERMISSIONS.md`).
- Approve the provisioning sequence in section 10.

## 4. Private PostgreSQL connectivity
The runner lives in `parallax-nonprod`, so it reaches `parallax-postgres` over Railway private
networking (`postgres.railway.internal:5432`) using the `ranger_backup_ro` `DATABASE_URL`. No public
DB endpoint is introduced; only the bucket is reached over public TLS, credential-gated, with
age-encrypted artifacts.

## 5. Backup role privileges (summary; detail in companion doc)
A login role with `CONNECT` plus membership in the built-in `pg_read_all_data` role is necessary and
sufficient for `pg_dump -Fc --no-owner --no-privileges` of the whole database, with two caveats to
verify at the DB: Row-Level Security (a non-BYPASSRLS role can silently under-dump) and large objects
(if any exist). See `BACKUP_DR_ROLE_PERMISSIONS.md`.

## 6. Mandatory remote verification (confirmed)
Non-disableable: the run does not report success until the newest `*.dump.age` and both sidecars are
confirmed present offsite at expected sizes; a production/readiness marker makes
`RANGER_BACKUP_VERIFY_UPLOAD=0` fail closed. Keep `RANGER_BACKUP_REQUIRE_VERIFY=1` on the runner.

## 7. Pruning stays disabled (pilot)
Do NOT set `RANGER_BACKUP_PRUNE_APPLY`. For the pilot also set `RANGER_BACKUP_BUCKET_PRUNE=0` so the
offsite prune step does not run even in dry-run. The sample README defaults
`RANGER_BACKUP_PRUNE_APPLY=1`; that is explicitly overridden off for Stage 2. No automatic deletion of
bucket objects will be configured.

## 8. age-recipient provisioning without exposing private keys
Only the public recipient is placed on the runner (`RANGER_BACKUP_AGE_RECIPIENT`, or a recipients
file). The private identity is never a runner variable, never committed, never printed; the runner is
cryptographically incapable of decrypting its own output. Full procedure in
`BACKUP_DR_KEY_CUSTODY.md`.

## 9. Executable via Railway tools vs requires owner / DB channel
- Possible through Railway tools when later authorized (no service shell needed): create the Cron
  service from the Dockerfile, set runner variables, surface/attach bucket credentials. NOT done now
  (no service, no variable change, no deploy this stage).
- Requires a PostgreSQL channel (service shell or authorized SQL), so it waits for the owner: creating
  `ranger_backup_ro` and grants, and running the pending 41-check audit. The Railway MCP has no
  shell / `psql` exec.
- Owner's own machine: age keypair generation and offline escrow.

## 10. Proposed rollback-ready Stage 2 execution sequence (for later authorization)
1. Owner generates the age keypair offline; shares only the `age1...` recipient. Rollback: discard;
   nothing deployed.
2. Create `ranger_backup_ro` + grants. Rollback: `DROP ROLE ranger_backup_ro;` (no data touched).
3. Create the Cron service from `deploy/backup-runner/Dockerfile`, schedule `0 7 * * *`, region
   `parallax-nonprod`, auto-deploy off until variables are set. Rollback: delete the service (no
   effect on portal/DB).
4. Set runner variables: `DATABASE_URL` (ro role, private ref), `RANGER_BACKUP_AGE_RECIPIENT`,
   `RANGER_BACKUP_S3_URL=s3://ranger-nonprod-backups/pg/`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/
   `AWS_ENDPOINT_URL_S3`/`AWS_REGION`, `RANGER_BACKUP_REQUIRE_VERIFY=1`, `RANGER_BACKUP_BUCKET_PRUNE=0`,
   `RANGER_BACKUP_MAX_AGE_HOURS=26`, `AWS_REQUEST_CHECKSUM_CALCULATION=when_required`,
   `AWS_RESPONSE_CHECKSUM_VALIDATION=when_required`. Do NOT set `RANGER_BACKUP_PRUNE_APPLY`.
5. One manual off-schedule run: backup -> encrypt -> upload -> mandatory verify -> healthcheck
   succeed; confirm three objects in the bucket. Rollback: delete the test objects (52h grace),
   disable the service.
6. Logical restore-verify drill into a disposable PostgreSQL target (never the live DB); require
   `pg_restore_verify.py` exit 0; owner sign-off.

## Security safeguards (summary)
Public-key-only encryption with fail-closed recipient check; mandatory non-disableable upload
verification; least-privilege read-only role; private-network DB only, no public endpoint; signing
keys untouched and evidence integrity verified at restore; pruning disabled (no deletion possible in
the pilot); secrets only in Railway's secret store with the age identity escrowed offline; unique
timestamped keys, 52h bucket-deletion grace, SHA-256 + signed-record verification. Single-provider
risks SP1-SP7 remain as documented in `BACKUP_DR_RAILWAY_NATIVE.md`; SP7 is partially mitigated by the
region split (logical iad, PITR sjc, DB us-west2).

## Operational costs
Bucket storage $0.015/GB-month, free egress and free API operations: empty ~ $0; ~0.3 GB ~ $0.005/mo;
~7 GB ~ $0.11/mo. Cron compute: a short daily job, a few cents/mo. PITR bills as bucket storage for
WAL + base backups; for this low-write DB, sub-dollar/mo. Total nonprod Stage 2 well under $1-2/mo at
current scale.

## What can be completed now without a service shell
This read-only inspection and the three readiness documents; age keypair generation (owner, offline);
and, after authorization, the service/variable/bucket steps via Railway tools. Waiting on the owner or
an authorized execution channel: the `ranger_backup_ro` role and grants, the pending 41-check audit,
and all actual provisioning, first backup, and restore drill.
