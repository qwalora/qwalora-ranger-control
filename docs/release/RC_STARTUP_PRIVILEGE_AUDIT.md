# RC startup privilege audit (rc_rw) — commit acf50ec

Scope: whether `parallax-portal-rc` startup succeeds under the non-superuser `rc_rw` role, given the
restored RC database (migrated from `b0f1588`) and tables owned by `postgres`.

## Finding: rc_rw is sufficient for startup; no owner-run migration is required before deploy
`models.py` is byte-identical between `b0f1588` (the restored schema) and `acf50ec` (the RC code), so
startup requires no new schema. Step-by-step (`create_app()` in `app.py`):

1. `db.create_all()` — checkfirst; all 34 tables already exist, so it emits no DDL. OK under rc_rw.
2. `ensure_schema()`:
   - `ADD COLUMN` is guarded (`if name in have: continue`) and only runs for a MISSING column. The
     schema matches, so no `ALTER TABLE ... ADD COLUMN` is attempted. OK.
   - The `resources.summary` widen to `VARCHAR(900)` is **unconditional** on PostgreSQL. `rc_rw` does
     not own `resources`, so this `ALTER` raises `permission denied` and is **swallowed**
     (`try/except rollback`). Harmless, because the column is already `VARCHAR(900)` from the completed
     migration — but a healthy boot does NOT prove this ALTER ran. The acceptance checks therefore
     verify `resources.summary = 900` independently (see `scripts/rc_acceptance_checks.sh`, step 3).
   - `uq_unit_result_record` is a model-level constraint; `ensure_schema` does not add it. It is
     already present in the restored DB (verified). The acceptance checks confirm it.
   - `startup_pathway_check()` is detection-only (no writes) unless `RANGER_PATHWAY_MIGRATE=1`
     (intentionally unset).
3. `_bootstrap_cohorts()`, `_backfill_cert_ids()`, `_bootstrap_resources()`, `_refresh_publications()`
   — DATA writes (INSERT/UPDATE/DELETE), covered by `rc_rw`'s `pg_write_all_data`. On the restored DB
   these are largely no-ops (rows exist). OK.
4. `_promote_publications()` — gated by `PUBLISH_PUBLICATIONS` (unset ⇒ no publish). No draft research
   is published.

## The only privileged gap, and the correct fix if ever needed
The sole operation requiring table ownership is the unconditional `resources.summary` widen (and, in a
drift scenario, a missing-column `ADD COLUMN`). Under `rc_rw` these fail and are swallowed, so they
succeed only because the objects already exist. If the acceptance checks ever find a required schema
object missing, run a **narrow, auditable migration as the RC database owner (`postgres` on the RC
fork only)** — do **not** grant `rc_rw` superuser, and do **not** transfer ownership of historical
tables to the application account. No such migration is needed for the current restored schema.

## Conclusion
Deploy under `rc_rw` is safe for commit `acf50ec`. "Do not assume a healthy process means schema
initialization succeeded" is honored by independent post-startup schema verification rather than by
granting elevated privileges.
