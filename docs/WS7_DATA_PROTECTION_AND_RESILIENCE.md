# WS7 - parallax-nonprod data protection and operational resilience

Scope: nonproduction data protection for the `parallax-nonprod` PostgreSQL database and the operational
resilience around it. Nothing destructive or billable was performed. The application-level backup
workflow is implemented and tested; its scheduled execution and durable off-box storage target, and any
volume resize or service deletion, are called out as AUTHORIZATION-GATED below.

STRATA/PARALLAX authorization, grading, signed evidence, and production isolation are unchanged by this
work. All commands here target `parallax-nonprod` only; none touch `production` or `main`.

## 1. Existing Railway backup capability (inspected first)

Railway already provides two platform mechanisms on the existing `parallax-postgres` service. Neither
requires a new service from this work; enabling them is a dashboard/CLI action with storage cost, which
is the operator's billable decision.

- **Scheduled volume backups.** Incremental, copy-on-write snapshots of the volume attached to Postgres,
  billed only for data unique to each snapshot at the per-GB volume rate. Restore is staged in the
  dashboard (Backups tab -> Restore): Railway mounts a new volume from the snapshot at the original mount
  path, retains the previous volume, and redeploys on review + Deploy.
- **Point-in-time recovery (PITR).** The Postgres image archives every WAL segment to a Railway storage
  bucket via pgBackRest, with a weekly full + daily differential base-backup schedule; the last 4 full
  backups are retained, giving a restore window of roughly 4 weeks to any timestamp in that window.

Recommendation: enable **scheduled volume backups** on `parallax-postgres` as the primary mechanism, and
enable **PITR** if a sub-snapshot RPO is wanted. Both are operator actions in the dashboard (storage
cost). Confirm current enablement state in the dashboard; it is not exposed through the API tooling used
here.

## 2. Application-level encrypted logical backup (implemented, complementary)

Why add one when Railway has native backups: the native mechanisms are volume/WAL based and live inside
the Railway account and region. A logical `pg_dump` that is independently encrypted and portable gives
(a) restore to a non-Railway target or a different Postgres major version path, (b) archival beyond the
~4-week PITR window, and (c) a recovery path that does not depend on the Railway account itself being
intact. It is a complement, not a replacement.

Implementation: `scripts/pg_backup.py` and `scripts/pg_restore_verify.py`.

- **Format:** `pg_dump -Fc --no-owner --no-privileges` (custom, compressed, selective restore).
- **Encryption:** `age` with an X25519 **public** recipient. The service encrypts with the public key
  only; it never holds the decryption key, so compromise of the portal or inference service does not
  expose historical backups. The private age identity lives in a secret store or offline, used only at
  restore time.
- **Credential handling:** the database password is passed via a 0600 `PGPASSFILE`, never on argv
  (so it is not visible in `ps`/`/proc/<pid>/cmdline`); the temp file is removed in a finally block.
- **Fail-closed:** with no recipient configured the run refuses before `pg_dump` is invoked; only
  ciphertext ever reaches disk (verified by test).
- **Integrity:** a SHA-256 of the ciphertext and a non-secret JSON manifest are written beside each
  artifact. Logs are structured JSON with the DB URL redacted to a user-masked `host:port/db`; no
  secret, token, password, or evidence payload is logged. Nothing is written to GitHub.

Restore-verify (`pg_restore_verify.py`) refuses to run against a production-like or non-disposable
target name, verifies the ciphertext SHA-256 BEFORE decrypting, restores into an isolated throwaway DB,
and then checks:
1. per-table **row-count parity** against the live source (or a supplied counts manifest);
2. **signed-evidence integrity** - the Ed25519 hash-chained audit trail re-verifies from the restored
   rows (`parallax.auditlog.verify_chain` + `audit_integrity.verify_events`), so any corruption of
   signed bytes across dump/restore is caught;
3. **representative records** - candidate rows and program-membership counts by (program, status).

### Measured backup/restore evidence (disposable PostgreSQL 16, 127.0.0.1)
Seeded source: 4 candidates, 4 program memberships (2 strata-active, 2 parallax-active), 5 signed
hash-chained audit events (chain verified pre-backup).
- Backup artifact: `age`-encrypted (header `age-encryption.org/v`), pg_dump custom-format magic absent
  from the ciphertext, ~125 KB, SHA-256 recorded in sidecar + manifest, source URL redacted in logs.
- Restore into an isolated DB: SHA-256 gate passed, row-count parity exact (4 / 4 / 5), audit chain
  re-verified from restored rows (`chain_ok=true`, `events_ok=true`), candidate/membership samples
  correct, throwaway DB dropped afterward.
- Negative cases proven: no recipient -> refuse, 0 files written; 1-byte tamper -> SHA-256 gate fails
  (no decrypt/restore); production-like target name -> refused; a WRONG signing key -> signature check
  FAILS (so verification genuinely checks signatures, not a rubber stamp).
Automated as `siem/tests/test_backup_restore.py` (5 tests, gated by the `_pgtest` authorization guard).

## 3. Credential and signing-material protection

- **Database password:** never on argv, never logged (section 2). Sourced from `DATABASE_URL` /
  `RANGER_BACKUP_SOURCE_URL` in the environment.
- **Backup decryption key:** asymmetric. The running service only needs the age **recipient (public)**
  in `RANGER_BACKUP_AGE_RECIPIENT`. The age **identity (private)** is a restore-time secret, held in a
  secret store or offline, never in the service that produces backups and never in GitHub.
- **Signing material:** `RANGER_SIGNING_KEY` / `RANGER_SIGNING_KEYS` remain in the Railway secret store
  (already the case). Backups contain the signed records and their signatures, not the signing seed, so
  a backup never discloses the Ed25519 private key. Restore-time verification needs only the PUBLIC keys
  (via a verify-only `RANGER_SIGNING_KEYS` registry) to confirm evidence integrity.
- **No secrets in logs or VCS:** structured logs redact the DB URL; `.age`, `.sha256`, and
  `.manifest.json` artifacts carry no secret; `backups/` is not committed.

## 4. RPO, RTO, retention, alerting, restore procedure

- **RPO (recovery point objective):** nonprod target 24h. A daily logical backup plus Railway scheduled
  volume backups meets it; enabling PITR tightens the effective RPO to minutes within the archive window.
- **RTO (recovery time objective):** nonprod target <= 1h. Observed logical restore of this dataset is
  seconds; RTO is dominated by operator action (locating the artifact, provisioning a target, running
  the verify). Railway volume-backup restore is a staged redeploy, typically minutes.
- **Retention:** logical backups - keep 7 daily, 4 weekly, 3 monthly (encrypted). Railway volume
  backups/PITR retain per platform policy (PITR ~4 weeks / last 4 full). Prune logical backups on the
  same schedule; never delete the only verified restore point.
- **Backup-failure alerting:** the backup emits a structured `backup.ok` / `backup.*_failed` JSON line
  and a non-zero exit on failure. Wire the scheduled runner's failure (non-zero exit, or absence of a
  fresh `backup.ok` within RPO) to an alert channel. A Railway webhook on deploy/cron failure, or a
  dead-man's-switch that checks manifest freshness, both work; alerting delivery is an operator wiring
  step (no new billable service required for a webhook).
- **Restore runbook (logical):**
  1. Identify the artifact and confirm `sha256` against its sidecar.
  2. Provide the age identity at restore time (`RANGER_BACKUP_AGE_IDENTITY_FILE`, 0600) - never on the
     backup-producing service.
  3. Set `RANGER_RESTORE_TARGET_URL` to a fresh disposable DB (name containing test/restore/verify).
  4. Run `pg_restore_verify.py <artifact>`; require exit 0 (SHA + counts + signatures all pass).
  5. For an in-place nonprod restore, prefer Railway's dashboard volume-backup restore (staged, review +
     Deploy); use the logical restore to seed a fresh DB or an off-Railway target.
  6. Record the restore in the audit trail; re-run `verify_chain` on the live DB post-restore.

## 5. Oversized-volume reduction plan (reversible, AUTHORIZATION-GATED - not performed)

Both volumes are 50 GB provisioned vs ~1 GB used (confirmed live: `parallax-postgres-volume` and
`parallax-inference-volume`, 50000 MB each). Railway bills provisioned size and volumes cannot shrink in
place, so reduction means create-smaller -> migrate -> verify -> delete-old. Do NOT resize or delete
persistent storage without separate approval.

- **Inference volume (lowest risk):** the model re-pulls from the registry, so the volume holds no
  irreplaceable state. Plan: provision a smaller inference volume (e.g. 5 GB), redeploy inference onto
  it (Ollama re-pulls `qwen2.5:0.5b-instruct`, observed ~9 s first pull + ~6 s cold start), confirm
  `/api/tags` + a live `/api/generate`, then delete the old 50 GB volume. Reversible until the old
  volume is deleted.
- **Postgres volume (gated, careful):** take a fresh verified logical backup (section 2) AND a Railway
  volume backup first. Provision a smaller Postgres volume (size to current + headroom, e.g. 5 GB),
  restore into it, verify row counts + a `verify_chain` signature pass + candidate/membership spot
  checks, cut over, and only then delete the old volume. Keep the old volume until verification passes
  so the step is reversible. Railway's own backup-restore flow (new volume mounted, old retained) is the
  preferred, lowest-custom-tooling path for this cutover.

Either reduction is a billable/destructive storage change and is held for explicit approval.

## 6. Accidental service cleanup (verified, AUTHORIZATION-GATED - not performed)

`qwalora-ranger-control` re-confirmed live (2026-10-19) with **no volume mounts**, **no service or
custom domains**, **no user-defined variables** (only Railway-injected `RAILWAY_*` system vars), and
**no dependents** (`parallax-portal` carries no reference variable to it; nothing else points at it). It
is an idle copy from `main`. Deletion is non-destructive here but is held for approval.

Operator steps (Railway dashboard):
1. Project `qwalora-ranger` -> environment `parallax-nonprod` -> service `qwalora-ranger-control`.
2. Re-confirm Settings (no volumes), Variables (none), Domains (none public/custom), and that no other
   service references it.
3. Confirm no external consumer points at it (a DNS record or another project) - not visible from inside
   the environment.
4. Settings -> remove service. No persistent data, so removal is non-destructive.

## 7. Activation checklist (what turns the implemented workflow on - approval/secret/billable)

1. Add `postgresql-client` (pg_dump/pg_restore) to the runner image, or run the backup from a small
   scheduled job that has it. (Build change; no new billable service if run on the existing service's
   Railway cron.)
2. Generate the age keypair; set `RANGER_BACKUP_AGE_RECIPIENT` (public) as a nonprod service variable;
   store the private identity in the secret store / offline. (Secret handling; operator.)
3. Choose a durable off-box destination for `RANGER_BACKUP_DEST` (object store or a dedicated backup
   volume). (BILLABLE - requires approval; not provisioned here.)
4. Add a daily Railway cron to run `scripts/pg_backup.py`, and wire failure alerting (section 4).
5. Enable Railway scheduled volume backups (and optionally PITR) on `parallax-postgres`. (Storage cost;
   operator dashboard action.)

Items 3 and 5 are billable and item 6/section 5 are destructive; all are held for explicit authorization.
