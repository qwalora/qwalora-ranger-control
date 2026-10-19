# parallax-nonprod backup runner

A small Railway **cron service** that takes a daily encrypted logical backup of the parallax-nonprod
PostgreSQL database, uploads it to durable off-service storage, healthchecks it, and prunes local
retention. It holds NO decryption key (encrypts with a public age recipient only).

Not deployed yet. Creating this service and its storage is AUTHORIZATION-GATED (see
`docs/WS9_BACKUP_ACTIVATION_PLAN.md`).

## What it runs
`entrypoint.sh`: `pg_backup.py` (pg_dump 18 `-Fc` | age -r PUBLIC) -> `aws s3 cp` to the bucket ->
`backup_healthcheck.py` -> `pg_backup_prune.py`. Any step failing exits non-zero (the alert signal).

## Image
`deploy/backup-runner/Dockerfile` (build context = repo root). Installs `postgresql-client-18`
(server is 18.6; `pg_dump` must be >= server major), `age`, and `awscli`. A build-time assertion
fails the build if `pg_dump` is not >= 18.

## Railway service config
- Type: service built from this Dockerfile; Root Directory = repo root; Dockerfile Path =
  `deploy/backup-runner/Dockerfile`.
- Cron Schedule: `0 7 * * *` (daily 07:00 UTC; cron services run to completion then stop).
- Region/env: parallax-nonprod only.

## Variables (set on the runner service)
- `DATABASE_URL` - reference the parallax-postgres connection (Railway variable reference), read-only use.
- `RANGER_BACKUP_AGE_RECIPIENT` - age PUBLIC recipient (`age1...`). The private identity is NOT here.
- `RANGER_BACKUP_S3_URL` - e.g. `s3://ranger-nonprod-backups/pg/`.
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` - bucket credentials (scoped to this prefix).
- `AWS_ENDPOINT_URL_S3` - set for a Railway/non-AWS S3-compatible bucket; omit for AWS S3.
- `RANGER_BACKUP_PRUNE_APPLY=1` - enable local retention deletion (default dry-run).
- Retention knobs (optional): `RANGER_BACKUP_KEEP_DAILY=7`, `_WEEKLY=4`, `_MONTHLY=3`.
- Freshness: `RANGER_BACKUP_MAX_AGE_HOURS=26`.

## Secrets kept OUT of source control and logs
The age private identity, the DB password, and the bucket secret live only in the Railway secret
store (and the age identity additionally escrowed offline). `pg_backup.py` redacts the DB URL in
logs; `age`/`aws` read keys from env/files and never print them.

## Failure alerting
A non-zero run (backup, upload, or healthcheck failure) is the alert. Wire a Railway webhook on the
cron service's deploy/exec failure, or run `backup_healthcheck.py` as an independent scheduled monitor
whose non-zero exit pages an on-call channel.
