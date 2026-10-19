# WS9 - native PostgreSQL volume backup activation (parallax-nonprod)

Active plan for WS9. The operator chose Railway's built-in volume backup for the parallax-postgres
service as the single backup mechanism, to avoid added infrastructure. No external S3, no Railway
storage bucket, no separate backup runner service, no PITR. The encrypted logical-backup tooling
(WS7 scripts, WS9 runner image/entrypoint/prune) stays in the repo as DOCUMENTED, NOT-OPERATIONALIZED
tooling for future use; nothing of it is deployed or scheduled.

## Decision
- Mechanism: Railway scheduled volume backups on the `parallax-postgres` volume
  (`parallax-postgres-volume`, mounted at `/var/lib/postgresql/data`).
- Out of scope / not enabled: PITR, external S3, Railway storage buckets, the logical backup runner,
  volume resizing, deleting qwalora-ranger-control, production changes, main merge.

## Exact configuration (verified from Railway docs)
Railway volume backups offer three independent schedules; choose one or more, each with its own fixed
retention:
- Daily: every 24 hours, kept 6 days
- Weekly: every 7 days, kept 1 month
- Monthly: every 30 days, kept 3 months

Recommended minimal configuration: enable **Daily** (meets a 24h recovery point, 6-day history).
Optionally also enable **Weekly** + **Monthly** for longer history at negligible extra cost
(snapshots are incremental and de-duplicated). Manual on-demand backups can also be created in the
same tab.

## Cost (actual basis)
Volume backups bill at the volume rate, **$0.15/GB-month**, on the INCREMENTAL (copy-on-write,
de-duplicated) size only, metered per minute. The database is 0.867 GB with low change, so the
retained backup set is on the order of 1-2x the database size over the window:
- Daily-only: roughly **$0.15 - 0.35/month**.
- Daily + Weekly + Monthly: roughly **$0.20 - 0.50/month**.
No base fee. "Modest" as required.

## Restore procedure (document; drill deferred by operator)
1. Railway dashboard -> project `qwalora-ranger` -> environment `parallax-nonprod` -> service
   `parallax-postgres` -> Backups tab.
2. Find the backup by its date stamp -> click Restore. Railway STAGES the change: a new volume named
   after the backup's date stamp is mounted at the original mount path (`/var/lib/postgresql/data`)
   and the previous volume is unmounted but RETAINED (not destroyed).
3. Review the staged change, then click Deploy. The service redeploys on the restored data.
4. Verify after restore: candidate + program-membership counts and a signed-evidence check
   (`parallax.auditlog.verify_chain`) against the restored database, e.g. via the admin Operations
   page or a read-only query.
Restrictions: a restore can only target the SAME project and environment, and restoring a given
backup REMOVES any backups created after it. Because the previous volume is retained until you
replace it, the staged restore is reversible up to the Deploy step.
Recovery point: with the Daily schedule, up to ~24h of data could be lost (last daily snapshot).
Recovery time: a staged volume restore is a dashboard action plus a service redeploy (minutes); not
yet drilled on this service (operator deferred the timed drill).

## Activation action presented for approval
Enable scheduled volume backups on `parallax-postgres` in `parallax-nonprod`:
- Dashboard: service `parallax-postgres` -> Backups tab -> enable the **Daily** schedule (optionally
  Weekly + Monthly) -> save.
This is an account/billing configuration change, so it is held for explicit approval. After approval
and enablement: confirm a backup appears in the Backups tab (an on-demand backup can be taken
immediately to confirm without waiting 24h), and this document's restore procedure stands as the
operating instruction. Operational readiness is limited to: scheduled native backups enabled + a
backup present; a verified restore remains explicitly pending (drill deferred).

## Preserved
Production and all existing Ranger services are untouched. STRATA/PARALLAX entitlements, assessment
rules, candidate records, and signed evidence are unaffected by enabling volume backups (snapshots
are read-side; they do not alter the database).
