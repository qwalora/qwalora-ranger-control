# Qwalora Ranger — PostgreSQL Recovery Runbook

Operator procedure to recover the Ranger PostgreSQL system of record from an independent encrypted
logical backup, and to verify the recovery. Restores are explicit and operator-authorized. This
runbook never restores in place and never targets the live database; recovery always lands in an
isolated database first and is promoted only by a deliberate, separate decision.

Prerequisites
- The age PRIVATE identity (held offline / in the secret store), as a 0600 file. It is never on the backup runner.
- The signing-key material that signed the records to be verified (`RANGER_SIGNING_KEY` or `RANGER_SIGNING_KEYS`); without it, verification fails closed (by design).
- `pg_restore`/`age` available, with a `pg_dump`/`pg_restore` major version >= the backup's server major (PostgreSQL 18 for nonprod).
- Read access to the offsite bucket (restore-only principal), and an isolated target PostgreSQL whose database name matches a test/restore pattern and is not a production-like name.

## A. Retrieve and verify a backup (no database change)
1. List candidates in the offsite bucket; pick the artifact and its `.sha256` and `.manifest.json` sidecars. Prefer the newest that passes the healthcheck.
2. Confirm freshness/integrity before trusting it: run `backup_healthcheck.py` against a directory holding the manifest set (exit 0 = healthy; 2 missing, 3 stale, 4 corrupt).
3. Download the artifact + both sidecars to a working directory.

## B. Restore into an ISOLATED database and verify
1. Set, in the operator shell (values from the secret store; never commit, never echo):
   - `RANGER_BACKUP_AGE_IDENTITY_FILE` = path to the age private identity (0600).
   - `RANGER_SIGNING_KEY` (or `RANGER_SIGNING_KEYS`) = the signing material that signed the records.
   - `RANGER_RESTORE_TARGET_URL` = an isolated target, e.g. `postgresql+psycopg2://user:pass@host:5432/ranger_restore_drill` (name must contain test/restore/verify/disposable/scratch; production-like names are refused).
   - optional `RANGER_VERIFY_SOURCE_URL` = a reference DB for row-count parity.
   - optional `RANGER_PG_BIN` = the PostgreSQL 18 bin directory.
2. Run: `python scripts/pg_restore_verify.py <artifact>.dump.age`
3. Interpret the exit code: 0 = all checks passed (ciphertext SHA, schema, counts, audit chain, research/adjudication signatures); 2 = misconfiguration or a refused non-disposable target or missing signing key; 3 = tool failure (decrypt/restore); 4 = a verification check failed. Only exit 0 is a successful, verified restore.
4. The tool drops the isolated database afterward by default. To inspect before dropping, call `rv.run(..., drop_after=False)` and drop manually when finished.

## C. Promote to service (deliberate, separately authorized)
Promotion of a verified restore to a live service is a separate, authorized operation and is out of
scope for this runbook's automation. It is performed by the platform owner against a new or
quiesced database, never by overwriting a live database in place, and only after step B returns exit 0.

## D. Signing-key dependency recovery
Restored records verify only under the key(s) that signed them. Keep every historical signing kid
available in a trusted state (active/verify_only/retired). For current nonprod records that is
`legacy:696697820b69d289` (public key published at `/pubkey`). If migrating to a key registry, include
that kid verbatim and pin it with `RANGER_SIGNING_VERIFY_KIDS` (see Sprint 1A
`docs/parallax/SECRET_CONFIG_MIGRATION.md`). Loss of the signing key does not corrupt data but makes
historical signatures unverifiable, so the signing key is itself a recovery dependency and must be
backed up separately from the database, offline.

## E. Failure handling
- Exit 4 at the SHA gate: the artifact is corrupt or truncated in transit; re-download and re-verify; if it persists, use the previous good backup.
- Exit 3 at decrypt: wrong age identity or a truncated ciphertext; confirm the identity matches the recipient and the download is complete.
- Exit 4 at schema check: the backup's schema differs from the restored schema; investigate before trusting the data (migration drift).
- Exit 4 at signatures: the signing key is wrong/absent, or records were altered; do not promote.
- Exit 2 missing signing key: configure the correct signing material; the tool refuses to verify under a derived key.
Never promote a restore that did not return exit 0.

## F. Drill cadence
Run a live isolated restore drill (steps A-B against a real backup) on a defined cadence (for example
monthly and after any schema migration), recording the measured restore + verify time to validate the
RTO target. A drill never touches the live database.
