# WS8 - parallax-nonprod backup activation readiness (decision document)

Prepared from verified WS7 (commit 74aed74, deployment 963d3307). All inspections here are read-only;
nothing billable was provisioned, nothing destructive was performed, production was not touched. This
document ends with the exact approval-gated actions, their monthly cost, and a recommended activation
sequence.

## 0. Headline findings

1. **PostgreSQL server is 18.6; the backup client must be >= 18.** The live `parallax-postgres` runs
   `PostgreSQL 18.6` (image `ghcr.io/railwayapp-templates/postgres-ssl:18`, confirmed in startup logs).
   `pg_dump` refuses a server newer than itself, so the backup runner MUST ship `pg_dump`/`pg_restore`
   18.x. This container only has client 16.15, and the PostgreSQL apt repo is blocked by the egress
   allowlist here, so the PG18-client-against-PG18-server path could not be exercised in this
   environment. It must be validated once in the runner (a read-only `pg_dump` is non-destructive).
2. **Volume cost was overstated in WS6/WS7 - correction below.** Railway bills volumes on ACTUAL usage
   ($0.15/GB-month, metered per minute), not provisioned size. The two 50 GB volumes hold 0.87 GB and
   1.19 GB, so together they cost about **$0.31/month**, not ~$15. Oversized provisioning is therefore
   NOT a material cost and volume reduction is not a cost lever (section 6).
3. **Backup activation is cheap.** Full activation (daily encrypted logical dump + off-box storage +
   native volume backups) adds roughly **$1-2/month**. The dominant Ranger cost is always-on memory.
4. **RPO/RTO are achievable targets, not yet verified** (no scheduled backup has run in production and
   no production-scale/PG18 restore has been timed). Section 5.

## 1. Railway native backup capability (inspected)

- **Scheduled volume backups** (Data & storage > Backups): incremental, copy-on-write snapshots of the
  Postgres volume. Billed only for incremental size at the volume rate ($0.15/GB-month), metered per
  minute. Restore is staged in the dashboard (new volume mounted at the original path, previous volume
  retained, review + Deploy). **Restrictions:** a restore removes any backups newer than the one chosen,
  and backups can only be restored **into the same project and environment** (no cross-env/cross-project
  restore).
- **Point-in-time recovery (PITR)** (Data & storage > Point-in-Time Recovery): the Postgres image
  archives every WAL segment to a Railway storage bucket via `pgBackRest`, with a weekly full + daily
  differential base-backup schedule; `expire` reclaims old base backups, so the bucket stabilizes at
  roughly 4 weeks of write volume. Restores to any timestamp in the window. In-place CLI restore is not
  supported on HA clusters (dashboard only); this service is single-replica, so not a constraint today.
- **Current enablement:** not exposed through the API tooling available here; confirm on/off state in
  the dashboard (Postgres service > Backups / PITR tabs). Treat as NOT yet enabled until confirmed.
- **Railway's own recommendation** matches the WS7 design: for an offsite copy that survives anything
  happening to the project, run `pg_dump` on a schedule from a cron service and upload to a separate
  storage bucket or any S3-compatible store outside Railway.

Native mechanisms live inside the Railway account/region and (for volume backups) only restore into the
same project+environment. The WS7 logical backup is the portable, independently-encrypted complement.

## 2. Tool compatibility, runner, storage, and alert path

- **Server:** PostgreSQL 18.6 (`server_version_num` ~180006). **Client required:** `pg_dump`/
  `pg_restore` >= 18. The backup scripts already auto-select the highest installed
  `/usr/lib/postgresql/*/bin`, so they pick up an 18 client automatically once present.
- **Runner options:** (a) a Railway **cron schedule on a small dedicated cron service** whose image
  includes `postgresql-client-18` and `age`; or (b) a Railway cron on the existing portal service if its
  image is extended with those tools. Either runs ~1-2 minutes/day. Option (a) is cleaner (isolates the
  backup toolchain from the web image) and barely costs more (compute is metered per minute).
- **Artifact storage:** encrypted `*.dump.age` + `.sha256` + `.manifest.json` to a durable off-service
  target: a Railway storage bucket (S3-compatible) or an external S3 bucket. Never to the Postgres
  volume (same failure domain), never to GitHub.
- **Failure alerting:** `scripts/backup_healthcheck.py` is a dead-man's-switch over the destination -
  exit 0 healthy; non-zero for missing / stale (older than the RPO window) / corrupt (ciphertext no
  longer matches its recorded SHA-256) / suspect (too small). Wire a non-zero exit to an alert: a
  Railway cron-failure webhook, or run the healthcheck itself as a scheduled monitor whose failure pages
  a channel. Validated with disposable fixtures (healthy/missing/stale/corrupt/missing-artifact/
  newest-wins) and end-to-end: a fresh `pg_backup` run followed by the healthcheck exits 0, and a missed
  run (freshness window exceeded) exits non-zero.

## 3. Minimal operational architecture and cost

Daily at a fixed UTC time, the cron runner: `pg_backup.py` (pg_dump 18 -Fc | age -r <public>) ->
`*.dump.age` + sha256 + manifest to the off-box store; then `backup_healthcheck.py` -> non-zero exit
fires an alert. Retention pruning keeps 7 daily / 4 weekly / 3 monthly.

Current `parallax-nonprod` usage (measured, 60-min window) and cost at Railway published rates
(memory $10/GB-month, vCPU $20/month, volume $0.15/GB-month, egress $0.05/GB; all usage-based):

| Service | Memory | vCPU (idle avg) | Volume used | ~$/month |
|---|---|---|---|---|
| parallax-portal | 0.127 GB | ~0.00014 | none | ~$1.3 |
| parallax-postgres | 0.057 GB | ~0.0002 | 0.867 GB | ~$0.7 |
| parallax-inference | 0.641 GB | ~0.00006 | 1.191 GB | ~$6.6 |
| qwalora-ranger-control (accidental) | 0.120 GB | ~0.00014 | none | ~$1.2 |
| **Total** | **0.945 GB** | negligible | 2.06 GB | **~$9.8** |

(Compute is dominated by always-on memory; CPU is near-zero at idle, with brief inference bursts during
active cohorts. Plan base fees / included credits are separate - confirm on the billing page.)

**Backup activation increment:**

| Item | ~$/month | Notes |
|---|---|---|
| Cron runner compute | ~$0 - 0.05 | ~1-2 min/day, metered per minute |
| Off-box backup storage | ~$0.10 - 0.70 | ~14 retained copies x ~0.3 GB compressed; Railway bucket ~$0.15/GB or external S3 ~$0.023/GB |
| Railway scheduled volume backups | ~$0.15 - 0.40 | incremental on 0.87 GB, small daily deltas |
| PITR (optional) | ~$0.20 - 0.50 | ~4 weeks of (low) nonprod write volume |
| **Backup increment total** | **~$1 - 2** | |

**Estimated total parallax-nonprod with full backup activation: ~$11 - 12/month.** The production
environment is separate, not in scope, and was not measured or changed.

## 4. Correction to the WS6/WS7 cost assumption (accuracy)

WS6 and WS7 stated Railway bills volumes by PROVISIONED size and called the two 50 GB volumes "the
largest avoidable cost." Railway's current documentation and this account's measured usage show billing
is by ACTUAL usage, metered per minute: a 50 GB volume holding ~1 GB bills for ~1 GB. The two volumes
cost about $0.31/month combined. The earlier framing is withdrawn: oversized provisioning is not a
material cost, and shrinking the volumes is not a cost saving (section 6). The genuine small avoidable
cost is the accidental `qwalora-ranger-control` service (~$1.2/month of always-on memory).

## 5. RPO / RTO: achievable targets, not yet verified

- **RPO 24h - achievable, not verified.** A daily cron meets a 24h recovery point by design; enabling
  PITR tightens it to minutes within the ~4-week window. Not verified because no scheduled backup has
  run in production yet.
- **RTO 1h - achievable target, not verified.** A disposable logical restore (WS7) completed in seconds,
  and a 0.87 GB database extrapolates to well under an hour, but no production-scale restore and no
  PG18-client restore have been timed. Do NOT treat RTO as verified until a restore drill is run in the
  runner environment against a real PG18 dump and timed. This is the single most important
  post-activation verification step.

## 6. Volume reduction plan (reversible; now LOW priority - not a cost lever)

Under usage-based billing, reducing the provisioned size of the two 50 GB volumes saves effectively
nothing (both already bill for ~1 GB used). This plan is retained only for tidiness or to cap accidental
growth, and remains AUTHORIZATION-GATED and prerequisite-guarded; it is not recommended as a cost action.
If done anyway: take a fresh verified logical backup AND a Railway volume backup first; for inference,
provision a smaller volume and let Ollama re-pull the model, verify `/api/tags` + a live generate, then
delete the old volume; for Postgres, provision smaller, restore, verify row counts + a `verify_chain`
signature pass + candidate/membership spot checks, cut over, and only then delete the old volume. Keep
the old volume until verification passes (reversible). Prefer Railway's own volume-backup restore flow
for the Postgres cutover.

## 7. Key custody, key-loss, and signing continuity

- **Backup decryption key (age identity).** The producing runner holds only the age **recipient
  (public)**; the **identity (private)** is a restore-time secret kept off the runner. If the identity is
  LOST, every encrypted backup is permanently unrecoverable - a catastrophic single point of failure.
  Mitigation: escrow the identity in at least two independent secure locations (e.g., the team password
  manager plus a sealed offline copy); if a passphrase protects it, escrow the passphrase separately.
  Never store the identity in the repo, in the backup store, or on the backup-producing service.
- **Key rotation.** `age` encrypts to one or more recipients. To rotate, start encrypting new backups to
  the new recipient while retaining the old identity to read historical backups; never discard an
  identity while any backup encrypted to it is still within retention.
- **Signing-key continuity.** Evidence verification after restore needs the Ed25519 PUBLIC keys that
  signed the records. Keep a verify-only `RANGER_SIGNING_KEYS` registry (public keys, with retired/
  verify_only `kid` states) so restored historical evidence re-verifies across rotations; the signing
  module already enforces per-`kid` trust. The signing PRIVATE seed stays in the secret store, is never
  placed in a backup, and is never exported. Production credentials were not read or exported in this
  work (variable values are redacted by the platform regardless).

## 8. Accidental service

`qwalora-ranger-control` is unchanged (item 8). It remains an idle copy with no volumes, domains,
user-defined variables, or dependents, costing ~$1.2/month in always-on memory. Deletion (the real
small cost saving) stays held for explicit authorization.

## 9. Preservation

STRATA/PARALLAX entitlements, assessment rules, candidate records, and signed research evidence are
unchanged by WS8. The restore-verify path re-verifies the signed audit chain from restored rows, so a
restore that silently corrupted evidence would fail closed. Full PG-backed regression remains green
(section 10).

## 10. Approvals required, costs, and recommended activation sequence

**Actions requiring approval (billable or destructive):**

| # | Action | Type | ~$/month |
|---|---|---|---|
| A | Provision durable off-box backup storage (Railway bucket or external S3) | billable (small) | $0.10 - 0.70 |
| B | Enable Railway scheduled volume backups on parallax-postgres | billable (small) | $0.15 - 0.40 |
| C | Enable PITR on parallax-postgres (optional, tighter RPO) | billable (small) | $0.20 - 0.50 |
| D | Delete accidental qwalora-ranger-control | destructive | saves ~$1.2 |
| E | Reduce 50 GB volumes | destructive | ~$0 saved (not recommended) |

Non-billable preparation that does not need approval (and is done/ready): the backup, restore-verify,
and healthcheck scripts and their tests; the runner/alert design; this document.

**Recommended activation sequence:**
1. Build the runner image with `postgresql-client-18` + `age`; set `RANGER_BACKUP_AGE_RECIPIENT`
   (public) as a nonprod variable; escrow the private identity (section 7). Run one read-only `pg_dump`
   18 against the live PG18 to confirm the client path (non-destructive).
2. Approve + provision the off-box storage target (action A); set `RANGER_BACKUP_DEST`.
3. Schedule the daily cron: `pg_backup.py` then `backup_healthcheck.py`; wire the non-zero exit to an
   alert channel. Add retention pruning (7 daily / 4 weekly / 3 monthly).
4. Run a **timed restore drill** into a disposable DB from a real PG18 dump; record RTO and confirm
   row-count + signature verification. Only then treat RPO/RTO as verified (section 5).
5. Approve + enable Railway scheduled volume backups (action B); optionally PITR (action C).
6. Separately, approve deletion of the accidental service (action D) for the ~$1.2/month saving. Do not
   pursue volume reduction (action E) as a cost measure.

Nothing in steps 1-6 has been executed; all billable/destructive steps await explicit authorization.
