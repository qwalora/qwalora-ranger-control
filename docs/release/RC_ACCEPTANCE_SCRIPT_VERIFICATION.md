# RC acceptance script - correction + verification evidence

File: `scripts/rc_acceptance_checks.sh`
Branch: `chore/rc-static-hardening`  commit `5e97897` (parent `3376ddb`)
Deploy target unchanged: `acf50ec`. This commit does NOT re-pin the RC source and does NOT
promote `3376ddb`. No RC database or accepted environment was touched.

## The seven findings and how each is now satisfied

1. Read-only sessions enforced correctly. The whole libpq session is forced read-only with
   `PGOPTIONS=-c default_transaction_read_only=on` (applies to every `psql` call and to the
   auditor's own psycopg connection), not a per-statement `SET TRANSACTION READ ONLY` in a
   separate `-c`. A fail-closed GATE runs first and asserts `current_user=rc_ro`,
   `current_database=railway`, `current_setting('transaction_read_only')=on`, and that a write
   attempt (`CREATE TEMP TABLE`) is rejected, then the single-row `rc_fork_marker`.

2. Malformed identity SQL fixed: `SELECT current_user || '@' || current_database();`.

3. Publications compared against the preserved pre-startup full-row fingerprint baseline. Predicate
   is the code's own definition of a publication, `resources.pub_id IS NOT NULL` (matches
   `is_publication = bool(r.pub_id)`), not a 4-field `resources` projection. The fingerprint uses the
   exact expression the existing baseline was produced with: `md5(row_to_json(r)::text)` over the
   complete resource row (corrected from an earlier `md5(resources::text)`, which yields a different
   hash - verified: for one fixture row `row_to_json` gives `a7e1d0e8...` vs `resources::text`
   `babecad9...`). The comparator is identifier-agnostic: it exposes `id`/`pub_id`/`slug` per live row
   and matches whichever record identifier the baseline keyed on, across flat `{key: hex}`,
   `{"fingerprints": {...}}`, or record-list shapes. It requires baseline count == 24, live count ==
   24, identical identifier sets, and identical fingerprints, and prints a precise difference report
   (which identifiers are missing/extra, which fingerprints changed). A missing, empty, unparsable,
   wrong-count, or mismatched baseline is a FAIL, never SKIP/PASS. `BASELINE_SHA256` (optional) is
   enforced byte-for-byte before the file is trusted, so the original evidence is preserved. The file
   is read-only here and is never regenerated or overwritten.

4. Pinned auditor reused and proven. The script fetches `px_review_audit.py` at
   `b04698e...`, verifies its git blob is `57f2ce5...` before running, and runs it with
   `cwd` and `PYTHONPATH` set to the `acf50ec` checkout so `from models import ...` /
   `from parallax... import ...` resolve. `python -I` is intentionally not used (isolated mode
   ignores `PYTHONPATH`); the fetched file sits alone in its own temp subdir so nothing can
   shadow a module. The audit passes only when it exits 0 AND `summary.total == 41` AND
   `summary.failed == []`; abort, crash, non-zero exit, or unparsable JSON all FAIL. Two pre-run
   gates guard the auditor (both fail-closed - on failure the auditor is not run and the check
   FAILs):
   - Signing registry shape. `RANGER_SIGNING_KEYS` (a JSON array of
     `{kid,alg,state,seed_b64?,public_b64?}`) is validated without printing any key material:
     exactly one `active` entry which MUST carry a private `seed_b64` (the disposable signer,
     legitimately private); every `verify_only`/`retired`/`revoked` entry MUST NOT carry a
     `seed_b64`; and `legacy:696697820b69d289` must be present once as `verify_only`, public-only.
     A private seed on the historical verify-only entry is a FAIL.
   - Audit connection identity. The audit uses `RC_AUDIT_URL` as `DATABASE_URL`, which may differ
     from `RC_RO_URL`, so the same identity gate (`current_user=rc_ro`, `current_database=railway`,
     read-only session) is applied to that exact connection before the auditor runs. The auditor's
     own psycopg connection inherits the read-only `PGOPTIONS`.

5. Schema names verified against `models.py` (not assumed): tables `resources`, `candidates`,
   `cohorts`, `qualification_decisions`, `parallax_research_runs`, `program_memberships`,
   `unit_results`; columns `resources.summary|rtype|pub_id`, `candidates.status|current_board`,
   `cohorts.pathway`, `program_memberships.program`; constraint `uq_unit_result_record` on
   `unit_results` (a model constraint `create_all` applies only to fresh DBs, so on the migrated
   RC its absence is a real gap and FAILs); fixture `nonprod-fixture:parallax-review-selftest`.

6. Fail closed everywhere. `set -uo pipefail`; no `SKIP`-that-passes remains; the identity gate is
   fatal (exit 2); every check is an explicit PASS or FAIL (no `&& ok || no` that could run both;
   no `|| true` masking). `RESULT: PASS` is printed only when control reaches the end with zero
   failures, so any uncaught error exits non-zero before that line.

7. Secrets / active signing seeds kept out of stdout, logs, args, and temp files. `RC_RO_URL` is
   parsed once into `PG*` env vars, so the rc_ro password never appears on a `psql` argv; `psql`
   runs with `-w` (never prompts) and no connection string. The auditor receives `DATABASE_URL`
   and `RANGER_SIGNING_KEYS` by environment only, never on argv. `RANGER_SIGNING_KEYS` is the
   verify-only public key plus a disposable active key (no historical private seed). Temp files
   hold only sanitized data (`{pub_id, fp}`, the auditor's sanitized JSON); no connection string
   or key material is written.

## Static analysis

- `bash -n scripts/rc_acceptance_checks.sh` - clean.
- `shellcheck 0.11.0` (default severity) - clean, zero findings.

## Isolated regression (no RC/accepted DB involved)

A disposable PostgreSQL 16 instance on `127.0.0.1:55433` held a schema-compatible fixture in a
database named `railway`, with a genuinely read-only `rc_ro` role (SELECT only, non-owner): the
eight referenced tables, a single-row `rc_fork_marker`, 24 publication rows (`pub_id` set) plus 3
non-publications, 7 research runs including both protected `run_id`s, the review fixture candidate
with a single `parallax` membership and zero qualification decisions, and `uq_unit_result_record`.

Results (all passed):

- Identity gate PASS: `rc_ro@railway`, read-only session enforced, write attempt rejected,
  marker == 1.
- Gate fatals (exit 2): wrong user (connect as `postgres`); wrong database (`otherdb`); marker row
  count != 1. None printed a PASS result.
- Schema/runs/entitlement: all PASS (base-table count, `summary=900`, `uq_unit_result_record`,
  every column, 7 runs + both protected records, fixture entitlement == `parallax`, 0
  qualification decisions).
- Publications: `EMIT_BASELINE` (now `md5(row_to_json(r)::text)`) then compare == all 24 match,
  across record-list, flat `{pub_id: hex}`, and `{"fingerprints": {...}}` baseline shapes (matched on
  the baseline's own identifier). Negatives each FAIL: one-record drift (reported 1 of 24 changed),
  wrong baseline count (23 vs 24), `BASELINE_JSON` unset (FAIL, no SKIP wording), unparsable baseline.
- Baseline integrity: correct `BASELINE_SHA256` matches; a wrong SHA FAILs with
  "baseline SHA-256 ... does not match expected". Expression cross-check in psql confirmed the live
  value equals `md5(row_to_json(r)::text)` and differs from the former `md5(resources::text)`.
- Signing registry: a valid registry (one active-with-seed + historical verify_only public-only)
  PASSes; a registry whose historical verify_only entry carries a `seed_b64` FAILs with
  "carries a private seed_b64 - forbidden", the auditor is skipped (fail-closed), and the forbidden
  seed value never appears in the output.
- Audit connection gate: with `RC_AUDIT_URL` pointed at the wrong database the audit-connection gate
  FAILs (and the auditor is not run) while the primary `psql` gate on `RC_RO_URL` still reports
  `rc_ro@railway`.
- Audit: fetch + blob-verify against GitHub returns the pinned blob `57f2ce5`. With `REPO_ROOT`
  set to the `acf50ec` checkout the auditor's app imports resolve (verified: the old temp-dir
  invocation failed with `No module named 'models'`; the corrected `cwd`+`PYTHONPATH` invocation
  imports successfully). Against the minimal fixture the audit correctly FAILs closed and is
  recorded as a failure (never silently skipped), and the overall result is `RESULT: FAIL`.
- Secret hygiene (structural): no `psql` call carries a connection URL on argv; password only via
  the `PG*` parse; auditor DB URL only via `DATABASE_URL=` in the environment; `-w` set; `set -x`
  never enabled.

## One honest limitation

A GREEN audit (exit 0 / 41 / 0) cannot be produced here because it requires the actual restored RC
database and the real signing material over the tunnel. What is verified in-session is the audit
step's full mechanism - fetch, blob pin, app import path, execution, strict 41/0 parse - and its
fail-closed behavior. The GREEN audit is confirmed by the operator running the script over the
tunnel once Railway builds resume and the RC service is deployed on `acf50ec`.

## Operator run (over the tunnel, read-only)

Open the read-only tunnel, then run with the locally held credentials. Nothing prints secrets: the
rc_ro password is read from `RC_RO_URL`/`RC_AUDIT_URL` into `PG*` env (never on a psql argv), and
`RANGER_SIGNING_KEYS` reaches the auditor by environment only. Read the private signing JSON from the
local file into the variable so it is not typed inline.

    export RC_RO_URL='postgresql://rc_ro:<pw>@127.0.0.1:<tunnel-port>/railway'
    export RC_AUDIT_URL="$RC_RO_URL"
    export RANGER_SIGNING_KEYS="$(cat ~/qwalora-rc-migration/rc-audit-signing.json)"
    export BASELINE_JSON=/home/franck/qwalora-rc-migration/rc-publications-before-startup.json
    export BASELINE_SHA256=cab041be0f896a1c0c49eed7e5eb75f383d12cea6e53b91c38ae6ea35b0d4c95
    export REPO_ROOT=/path/to/acf50ec/checkout
    scripts/rc_acceptance_checks.sh

Exit codes: 0 = PASS (zero failures); 1 = one or more checks failed; 2 = identity/gate fatal. The
baseline is read-only input and is neither regenerated nor overwritten; do not create another
baseline after deployment. The fingerprint expression (`md5(row_to_json(r)::text)` over the full
resource row) matches how `rc-publications-before-startup.json` was produced.
