# Backup role privilege verification and read-only export test (Stage 2, item A)

Scope: validate the PostgreSQL 18 privileges the backup actually needs, flag objects or database
configurations that could require more, and give a read-only procedure that PROVES the proposed role
can export the required data completely. No role is created here. Companion:
`BACKUP_DR_STAGE2_READINESS.md`.

## The exact command the runner issues
From `scripts/pg_backup.py`:

```
pg_dump -h <host> -p <port> -U <user> -d <db> -Fc --no-owner --no-privileges --no-password
```

Full single-database logical dump, custom compressed format, password via `PGPASSFILE`. `--no-owner`
and `--no-privileges` drop ownership/ACL restoration (so no object-ownership is needed to RESTORE).
`--no-large-objects` is NOT passed, so large objects (if any exist) are included and must be readable.

## What `pg_dump` must be able to read
`pg_dump` reads, for the whole database: all table/view/materialized-view/sequence DATA (SELECT),
every schema it visits (USAGE), and object DEFINITIONS from the system catalogs (readable by any
role). It does not need INSERT/UPDATE/DELETE, DDL, EXECUTE on functions, or superuser.

## Proposed minimal role (PostgreSQL 14+; 18 confirmed)
```sql
CREATE ROLE ranger_backup_ro LOGIN PASSWORD '<set-via-railway-secret>';
GRANT CONNECT ON DATABASE railway TO ranger_backup_ro;
GRANT pg_read_all_data TO ranger_backup_ro;
```
`pg_read_all_data` is a built-in predefined role that confers SELECT on all tables, views and
sequences and USAGE on all schemas, for current AND future objects, without per-object GRANTs and
without `ALTER DEFAULT PRIVILEGES`. It does not grant write, DDL, or superuser, and does not set
`BYPASSRLS`.

## Configurations that can require MORE than `pg_read_all_data` (verify at the DB)
1. Row-Level Security (RLS). `pg_read_all_data` does NOT bypass RLS. If any table has
   `relrowsecurity` set, a non-`BYPASSRLS` role can read a FILTERED subset and `pg_dump` will produce
   an INCOMPLETE dump with NO error. This is the single most important check. Remedies if RLS is in
   use on dumped tables: grant `BYPASSRLS` to the role (`ALTER ROLE ranger_backup_ro BYPASSRLS;`), or
   dump as a role that owns the tables, or exclude/handle those tables deliberately.
2. Large objects. Because `--no-large-objects` is not set, `pg_dump` exports large objects. Reading
   large-object data is not covered by `pg_read_all_data`; it needs ownership, superuser, or explicit
   per-object GRANTs. If `pg_largeobject_metadata` is non-empty, either add `--no-large-objects` (only
   if LOs are not needed) or grant read on them. The Ranger schema is expected to store evidence in
   `bytea`/text columns (covered by SELECT), not large objects; confirm with the check below.
3. Password/auth and transport. The role needs `LOGIN` and a password; the connection uses the
   Railway private network with SSL as the server requires. No extra DB privilege.

Not required and intentionally excluded: table ownership, write privileges, `CREATE`, `EXECUTE`,
`SUPERUSER`, `REPLICATION`.

## Read-only test procedure (proves completeness; no role created yet)

### Phase 0 - pre-role DB inspection (read-only; run now by an authorized operator)
Run as an existing admin/read role in `parallax-nonprod`. Detects the two risk configurations and
captures a trusted row-count baseline for the parity proof.

```sql
-- RLS-enabled tables (would under-dump for a non-BYPASSRLS role): expect ZERO rows.
SELECT n.nspname AS schema, c.relname AS table
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relrowsecurity
  AND n.nspname NOT IN ('pg_catalog','information_schema');

-- Large objects present? expect 0.
SELECT count(*) AS large_objects FROM pg_largeobject_metadata;

-- Schemas pg_dump will visit (pg_read_all_data covers USAGE on all of these):
SELECT nspname FROM pg_namespace
WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema'
ORDER BY 1;

-- Trusted per-table row-count baseline (exact; captured as an admin/BYPASSRLS role):
SELECT format('%I.%I', schemaname, relname) AS tbl,
       (xpath('/row/c/text()',
              query_to_xml(format('SELECT count(*) AS c FROM %I.%I', schemaname, relname),
                           false, true, '')))[1]::text::bigint AS exact_count
FROM pg_stat_user_tables
ORDER BY 1;
```
Acceptance for Phase 0: zero RLS-enabled dumped tables and zero large objects means
`CONNECT + pg_read_all_data` is sufficient with no additions. Any RLS table or large object triggers
the corresponding remedy above BEFORE provisioning.

### Phase 1 - post-role completeness proof (after authorized role creation; still read-only to data)
Connect AS `ranger_backup_ro` and prove read coverage without writing data anywhere.

1. Every user table is readable (raises on the first denied table):
```sql
DO $$
DECLARE r record; n bigint;
BEGIN
  FOR r IN SELECT format('%I.%I', schemaname, relname) AS t FROM pg_stat_user_tables LOOP
    EXECUTE format('SELECT count(*) FROM %s', r.t) INTO n;  -- permission error aborts the test
  END LOOP;
  RAISE NOTICE 'ranger_backup_ro: all user tables readable';
END $$;
```

2. Real end-to-end export + parity (catches RLS silent under-dump). Run the project's own tooling as
   the role, against a disposable target, with no plaintext on disk:
```bash
# as ranger_backup_ro, encrypting to a TEST public recipient (throwaway identity for the drill):
RANGER_BACKUP_SOURCE_URL="postgresql://ranger_backup_ro@<private-host>:5432/railway" \
RANGER_BACKUP_AGE_RECIPIENT="age1<test-recipient>" \
python scripts/pg_backup.py            # produces *.dump.age + *.sha256 + *.manifest.json

# restore-verify into a disposable PostgreSQL target and require exit 0:
python scripts/pg_restore_verify.py <dump.age> --identity <test-identity>   # row-count parity vs manifest
```
`pg_backup.py` records per-table `row_counts` in the manifest; `pg_restore_verify.py` compares
restored counts against the manifest. Cross-check those counts against the Phase 0 trusted baseline:
equality across every table proves the role exported the data COMPLETELY (no RLS truncation). Any
table whose role-dumped count is lower than the trusted baseline indicates an RLS or permission gap to
fix before Stage 2 provisioning.

Acceptance for Phase 1: step 1 reports all tables readable; step 2 produces a dump that restore-
verifies at exit 0 with per-table counts equal to the Phase 0 baseline. The drill uses a throwaway
age recipient so no production recovery key is involved.

## Validated privilege requirement (bottom line)
`CONNECT` + `pg_read_all_data` on a `LOGIN` role is the necessary and sufficient minimum for the
runner's `pg_dump`, PROVIDED Phase 0 shows no RLS on dumped tables and no large objects. If RLS is
present on dumped tables, add `BYPASSRLS` to the role (still no write, no DDL, no superuser); if large
objects exist, either add `--no-large-objects` (when LOs are not needed) or grant read on them.

## Remaining operator actions for item A
- Run Phase 0 in `parallax-nonprod` and record the three results (RLS tables, large-object count,
  schema list) plus the trusted row-count baseline.
- If Phase 0 is clean, authorize the role creation SQL above (no additions). If not clean, apply the
  named remedy, then authorize.
- After role creation, run Phase 1 and confirm the completeness acceptance before any scheduled
  backup. Do not create the role until authorized.
