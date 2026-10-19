> STATUS UPDATE (direction change): the operator chose Railway's NATIVE PostgreSQL volume backup as
> the only mechanism for now - no external S3, no Railway storage bucket, no separate runner service,
> no PITR. The S3/runner path described below (sections A1 Option 1/2, B) is retained as DOCUMENTED,
> NOT-OPERATIONALIZED tooling for future use. The active plan is docs/WS9_NATIVE_BACKUP_ACTIVATION.md.

# WS9 - operational backup activation plan (exact configs + approval request)

Continues from WS8 (commit 13b7390, deployment 4fef1c65). Two actions are AUTHORIZATION-GATED and are
presented here for approval; nothing billable has been provisioned and no live backup has run. This
document gives their exact Railway configuration, the runner config, costs, the once-approved runbook
(steps 1-9), and the restore-drill procedure. Operational backup readiness is NOT claimed: it is only
claimed after a scheduled backup, durable storage, failure detection, and a successful restore are all
demonstrated.

## A. Approval-gated actions (exact Railway configuration)

### A1. Durable billable backup storage  (REQUIRES APPROVAL)
A storage bucket to hold encrypted artifacts outside the database service. Two options:

Option 1 - Railway storage bucket (S3-compatible, same account):
- Create: project qwalora-ranger -> environment parallax-nonprod -> New -> Storage Bucket, name
  `ranger-nonprod-backups`.
- Access: generate bucket credentials (access key id + secret) scoped to this bucket; expose them to
  the runner service as `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and set
  `AWS_ENDPOINT_URL_S3` to the bucket's S3 endpoint.
- Retention: set an object lifecycle/expiry rule (e.g. expire objects older than 95 days) as primary
  retention; the runner's prune pass is secondary.
- Cost: object storage billed per-GB. ~14 retained encrypted dumps x ~0.1-0.3 GB each ~= 1.5-4.2 GB
  -> on the order of $0.25-0.70/month at a ~$0.15/GB rate. Confirm the exact bucket rate at creation.

Option 2 - External S3 (e.g. AWS), outside Railway (strongest blast-radius isolation):
- Create an S3 bucket with Object Lock/versioning + a lifecycle rule; an IAM principal limited to
  `s3:PutObject`/`s3:ListBucket`/`s3:GetObject` on `ranger-nonprod-backups/pg/*`.
- Expose `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (no `AWS_ENDPOINT_URL_S3`).
- Cost: AWS S3 Standard ~$0.023/GB-month -> ~$0.03-0.10/month for this volume, plus negligible PUT
  request cost. External egress from Railway on upload is small (a few GB/month) at ~$0.05/GB.

Recommendation: Option 2 (external S3) for true off-Railway durability; Option 1 if you prefer staying
in one vendor. Either is a few cents to <$1/month.

### A2. Railway scheduled native volume backups on parallax-postgres  (REQUIRES APPROVAL)
- Enable: parallax-postgres service -> Backups tab -> enable scheduled volume backups; set the
  schedule (daily) and keep Railway's default retention.
- Mechanics: incremental copy-on-write snapshots of the Postgres volume; restore is staged in the
  dashboard (new volume mounted at the original path, previous retained, review + Deploy). Restores
  only into the same project+environment; a restore removes backups newer than the chosen one.
- Cost: billed at the volume rate ($0.15/GB-month) on incremental unique data. For a 0.87 GB database
  with low daily change, ~$0.15-0.40/month.

### Not requested here (explicitly out of scope / separately gated)
PITR, deleting qwalora-ranger-control, resizing either 50 GB volume, production changes, main merge.

## B. Backup runner (prepared; deploys only after A1 is approved)
A Railway cron service built from `deploy/backup-runner/Dockerfile` (PostgreSQL 18 client + age +
awscli; a build-time assertion fails if pg_dump < 18). Config and variables: see
`deploy/backup-runner/README.md`. Schedule `0 7 * * *` (daily 07:00 UTC). The runner encrypts with the
PUBLIC age recipient only and holds no decryption key. Compute cost: ~1-2 min/day metered per minute,
effectively <$0.10/month.

## C. Failure detection and alerting (prepared, tested)
`scripts/backup_healthcheck.py` (WS8) is the dead-man's-switch: exit 0 healthy; non-zero for
missing/stale/corrupt/suspect. The runner runs it each cycle; any non-zero run (backup, upload, or
healthcheck) is the alert signal. Delivery: a Railway webhook on cron failure, or run the healthcheck
as an independent scheduled monitor whose failure pages a channel. Validated with disposable fixtures
and an end-to-end cron-chain dry run (fresh backup -> exit 0; missed run -> non-zero).

## D. Retention
- Off-box (authoritative): S3 lifecycle/expiry on the bucket (primary).
- Runner local mirror (secondary, auditable): `scripts/pg_backup_prune.py`, GFS 7 daily / 4 weekly /
  3 monthly, dry-run by default, never deletes the only/newest backup, refuses to delete everything.
  Tested (5 cases).

## E. Once-approved runbook (steps 1-9)
1. Build+verify runner: deploy the cron service from the Dockerfile; the build asserts pg_dump >= 18.
   Set `RANGER_BACKUP_AGE_RECIPIENT` (public); escrow the private identity offline + in the secret
   store (never in the repo). Confirm `age`/`pg_dump 18` present in the built image.
2. Read-only backup of live PG18: run the runner once (manual trigger) so `pg_dump -Fc` reads the
   actual parallax-postgres 18.6 database (read-only) and produces an encrypted artifact.
3. Durable storage: the same run uploads `*.dump.age` + `.sha256` + `.manifest.json` to the approved
   bucket (A1), outside the database service.
4. Schedule/retention/alerting: set the daily cron, the bucket lifecycle rule + prune, and wire the
   non-zero-exit alert (C).
5. Native backups: enable A2 on parallax-postgres.
6. Verify a real backup exists + passes integrity: list the bucket; run `backup_healthcheck.py` (and
   a SHA-256 check) against the uploaded artifact.
7. Restore drill: into a DISPOSABLE PostgreSQL 18 database (never in place), run
   `scripts/pg_restore_verify.py` - row-count parity, candidate + program-membership records, and the
   Ed25519 signed-evidence chain re-verified from the restored rows. Requires the private age identity
   and the signing public keys (verify-only registry); uses a PG18 client.
8. Measure RTO: time the end-to-end restore (download + decrypt + pg_restore + verify) and record it;
   document the observed recovery-point limitation (daily cadence => up to ~24h RPO unless PITR is
   later enabled).
9. Record actual incremental cost (from Railway usage by service) and operating instructions.

## F. Restore target note (PostgreSQL 18)
The restore drill (step 7) needs a disposable PostgreSQL 18 instance and an 18 client. This
environment could not provide PG18 (the PostgreSQL apt repo is blocked by the egress allowlist), so
the drill runs either in a short-lived disposable PG18 (a temporary Railway service, torn down after)
or any PG18 host available at activation time. The WS7 round-trip evidence stands on PG16
(client=server=16); the PG18 path is validated at the drill.

## G. Cost summary
- Current parallax-nonprod baseline (measured, WS8): ~$9.8/month.
- Incremental for activation: durable storage ~$0.03-0.70/month + native volume backups
  ~$0.15-0.40/month + runner compute <$0.10/month => ~$0.3-1.2/month.
- Estimated total after activation: ~$10-11/month. (Deleting the accidental service, separately gated,
  would save ~$1.2/month and roughly offset this.)

## H. Status
Prepared and committed: runner image + entrypoint, retention pruning (+tests), healthcheck (WS8),
backup/restore-verify (WS7), this plan. Awaiting explicit approval of A1 (durable storage, with the
Option 1/2 choice) and A2 (native volume backups) before any live backup, upload, or native-backup
enablement. Operational readiness will be claimed only after steps 2, 3, 5, 6, 7, 8 are demonstrated.
