# Qwalora Ranger - isolated RC deployment plan (nonproduction validation)

Release candidate: `integration/release-candidate` @ `1a9590f` (baseline `b0f1588` + Sprint 1A
fail-closed secrets `31625e8` + Sprint 1B Railway-native backups + dependency remediation).
Validation state: 627 passed / 0 failed / 0 errored / 17 environment-gated skips on disposable
PostgreSQL; `pip-audit` 0 known vulnerabilities. This document is non-deploying design only.

Preserved and never touched by this plan: `parallax-portal` `eb9e925e`, `parallax-postgres`
`3475da91`, Railway PITR, both backup buckets, all signed research evidence, STRATA/PARALLAX
entitlements.

## 1. Read-only database safety finding (correction)
The RC application cannot run end-to-end against a read-only PostgreSQL role. Evidence from the code:
- `create_app()` (app.py:466) at startup calls `db.create_all()` (no-op on a full copy),
  `ensure_schema(db)`, `_bootstrap_cohorts()`, and `_bootstrap_resources()`.
- `ensure_schema()` (models.py) ALTERs only missing columns (`if name in have: continue`) and the RC
  adds no columns over `b0f1588`, so on a schema-matched fork it issues no DDL. Safe read-only.
- `_bootstrap_cohorts()` calls `db.session.commit()` unconditionally and performs INSERT (missing
  cohort row) or UPDATE (activate a cohort when none is active) with NO error handling. On a
  consistent fork these are no-ops, but any triggered write fails closed under a read-only role and
  aborts startup. Not safe to rely on.
- `_bootstrap_resources()` upserts the editorial catalog and removes legacy rows (writes when the
  catalog differs).
- Sessions are cookie-based (`SESSION_COOKIE_*`, signed with `SECRET_KEY`); session persistence needs
  no DB write.
- All authenticated flows write: GitHub OAuth callback (candidate create/update), candidate
  membership updates, draft autosave (`workspace_drafts`), research submission and adjudication
  (`parallax_research_runs`, audit events), admin approve/reject.

Conclusion: a read-only RC web app is NOT fully functional. Only `/healthz`, pure-read pages, and
out-of-band evidence verification work read-only; the core auth/candidate/research flows require
writes. Do not represent a read-only RC application as functional.

## 2. Corrected architecture: two separated tracks
One disposable PITR fork of `parallax-postgres`, two roles, two independent test tracks. The accepted
`parallax-postgres` is never connected in either track.

- Track A - read-only historical-evidence verification. A read-only role (`CONNECT` +
  `pg_read_all_data`) on the fork, used ONLY by the verifier (`scripts/px_review_audit.py` 41-check /
  `store.admin_verify_run`), run out-of-band (not through the web write paths). Guarantees the records
  cannot be modified and proves historical Ed25519 verification under cryptography 50.0.2.
- Track B - application smoke testing. The RC web app runs against a read-write role on the SAME
  disposable fork, so OAuth, drafts, submission, adjudication, and admin approval exercise real write
  paths. All writes land only in the disposable fork; the accepted DB is untouched. Record protection
  here is by ISOLATION (disposable fork, never the accepted DB), not by a read-only role.

This separation resolves the conflict: full app functionality needs writes; hard protection of the
real records needs read-only. They cannot both hold on the same role, so verification (read-only) and
app smoke (writable-disposable) are split.

## 3. Isolation: network, environment, and database-identity boundaries
- Place the RC in a NEW Railway environment (`parallax-rc`) so its variables and private network are
  separate; `*.railway.internal` names resolve only within an environment, so the RC cannot reach
  `parallax-postgres` in `parallax-nonprod` even by name.
- No shared writable database credentials: the RC uses only the fork's roles; the accepted DB's
  `DATABASE_URL`/`PG*` are never set on the RC.
- No shared OAuth secrets: register a dedicated test GitHub OAuth app for the RC callback; never reuse
  production or nonprod `GITHUB_OAUTH_CLIENT_ID/SECRET`.
- No bucket access: the RC sets no `WAL_ARCHIVE_*` and no `ranger-nonprod-backups` credentials unless
  a specific test explicitly requires it (none in this plan).
- Mandatory database-identity assertion BEFORE startup or verification (fail closed). The fork is
  stamped at setup with a unique marker and the RC refuses any target lacking it or matching the
  accepted DB:
  ```sql
  -- at fork setup (on the fork only): create an RC-only marker
  CREATE TABLE IF NOT EXISTS rc_fork_marker (token text primary key);
  INSERT INTO rc_fork_marker VALUES ('rc-<run-id>-disposable') ON CONFLICT DO NOTHING;
  ```
  ```sql
  -- preflight (app entrypoint and verifier): REQUIRE the marker, REFUSE the accepted DB
  SELECT 1 FROM rc_fork_marker WHERE token = current_setting('rc.expected_token', true);
  -- and assert current_database()/inet_server_addr() are the fork's, not parallax-postgres.
  ```
  Operationally: gate the web container on `python scripts/preflight_prod_secrets.py` plus an RC
  DB-identity assertion (require the marker row and an explicit `RANGER_RC_ALLOW=1` opt-in), so the
  app cannot boot against anything but the stamped disposable fork. The verifier (Track A) performs
  the same assertion before reading.

## 4. Signing-key strategy (no private seed on the RC)
- `RANGER_SIGNING_KEYS` = a JSON array with:
  - one `verify_only` entry carrying ONLY `public_b64` for the historical key, kid
    `legacy:696697820b69d289` (the kid is derived from the public key, so it matches historical
    `signing_kid` stamps); and
  - one `active` entry with a freshly generated, DISPOSABLE seed created on the RC (satisfies the
    registry rule "exactly one active with a private seed" for boot/signing).
- `RANGER_SIGNING_VERIFY_KIDS=legacy:696697820b69d289` so startup fails closed if that kid is not
  present and trusted.
- The real `RANGER_SIGNING_KEY` private seed is NEVER copied to the RC.
- Confirmed supported by the implementation: `signing.py` trusts verification for
  `{active, verify_only, retired}`; a record stamped with the legacy kid verifies under the matching
  `verify_only` public key; the canonical format and historical record validity are unchanged (the
  disposable active key signs only new, discarded RC records). The operator derives `public_b64` once,
  offline, from the private key (`priv.public_key().public_bytes(Raw)`), which does not expose the
  seed.

## 5. Final deployment procedure (for later authorization)

### 5.1 Exact Railway resource configuration
- New environment `parallax-rc` in project `qwalora-ranger`.
- PITR restore-to-new-service of `parallax-postgres` at a recent timestamp into `parallax-rc` (source
  untouched); this is the disposable fork `parallax-postgres-rc`.
- New web service `parallax-portal-rc`: RAILPACK V3, source `integration/release-candidate`,
  `gunicorn app:app --workers 2 --timeout 120`, 1 replica, auto-deploy OFF until configured.

### 5.2 Database startup and permission strategy
- On the fork, create two roles: `rc_ro` (`CONNECT` + `pg_read_all_data`) for Track A, and `rc_rw`
  (owner or write-capable, scoped to the fork) for Track B. Both on the fork only.
- Stamp the fork with `rc_fork_marker` (section 3). The web app uses `rc_rw` and asserts the marker +
  `RANGER_RC_ALLOW=1` before serving; the verifier uses `rc_ro` and asserts the marker before reading.
- No role is created on the accepted `parallax-postgres`.

### 5.3 OAuth setup
- Dedicated test GitHub OAuth app; `GITHUB_OAUTH_CLIENT_ID/SECRET` are the test app's; callback =
  `<RC URL>/auth/callback` (match the app's route); `PORTAL_BASE_URL` = the RC service URL. Never the
  production/nonprod OAuth credentials.

### 5.4 Variable names and validation (RC web service)
`SECRET_KEY` (fresh random, >=32 chars), `DATABASE_URL` (fork `rc_rw`, private ref),
`RANGER_SIGNING_KEYS` (verify_only public + disposable active), `RANGER_SIGNING_VERIFY_KIDS`,
`RANGER_PARALLAX_LABA_ENV=nonproduction` (no production marker, so lenient secret mode),
`GITHUB_OAUTH_CLIENT_ID/SECRET` (test app), `PORTAL_BASE_URL`, `REVIEWER_GITHUB_IDS` (test),
`ADMIN_TOKEN` (fresh), `RANGER_RC_ALLOW=1`. Validation: `python scripts/preflight_prod_secrets.py`
proves the fail-closed gate (set `RANGER_REQUIRE_SECURE_SECRETS=1` in that step only to exercise it);
the RC itself runs in lenient mode mirroring nonprod.

### 5.5 Historical evidence verification method (Track A)
Run the pinned `scripts/px_review_audit.py` (git blob `57f2ce5`, from `b04698e`) against the fork over
`rc_ro`, with `RANGER_SIGNING_KEYS` set to the `verify_only` public entry. Require the 41-check matrix
`summary.failed == []` and both protected records (`run-f0d33a285717`, `run-e07852969609`) to verify
(hash + Ed25519 + trusted kid). This proves historical compatibility under cryptography 50.0.2 with no
private seed present and no record modified.

### 5.6 Acceptance test matrix
| Area | Test | Track | Pass criterion |
|---|---|---|---|
| Health | `GET /healthz` | B | `{"status":"ok","db":true}` |
| DB identity | marker assertion at boot | A+B | refuses any non-fork target |
| Auth | GitHub OAuth round-trip (test app) | B | session issued; CSRF enforced on POST |
| Sessions | cookie persists across requests | B | no DB dependency |
| Draft persistence | autosave + restore | B | writes to fork only |
| Research submission + adjudication | submit, reviewer decision | B | signed under disposable active; audit chain intact |
| Historical evidence | 41-check `px_review_audit.py` | A | `failed==[]`; protected records verify |
| Signing pin | `RANGER_SIGNING_VERIFY_KIDS` | A+B | startup fails closed if kid absent |
| Rendering | a `/resources` Markdown page | B | renders under Markdown 3.11.2 |
| Entitlement isolation | no qualification issued; STRATA/PARALLAX separation | A+B | unchanged |

### 5.7 Rollback and teardown
- Rollback: the RC is isolated; nothing to roll back on the live side. The live portal stays on
  `b0f1588` (`eb9e925e`, `canRollback: true`).
- Teardown (after sign-off): delete `parallax-portal-rc`, the fork `parallax-postgres-rc`, and the
  `parallax-rc` environment; delete the test OAuth app; discard the disposable active signing key. No
  change to `parallax-postgres`, PITR, or the buckets (Railway grace windows apply to deletions).

### 5.8 Cost estimate (incremental)
- RC web service: ~$5-15/mo if left on; prorated to a 1-2 day window, under ~$1-2.
- PITR fork PostgreSQL: small dataset (base backup ~33 MB), base compute ~$5-10/mo; prorated to a
  short window, under ~$1.
- Egress/API: negligible. Total for a short validation window: under ~$5 (likely ~$1-2). Continuous:
  ~$15-30/mo for the pair. Tear down after sign-off.

## 6. Actions requiring owner approval (all currently gated)
1. Create the `parallax-rc` environment.
2. PITR restore-to-new-service of `parallax-postgres` into `parallax-rc` (source untouched).
3. Create `rc_ro` and `rc_rw` roles and the `rc_fork_marker` on the fork (no role on the accepted DB).
4. Create the RC web service from `integration/release-candidate`; set its variables (section 5.4).
5. Register a dedicated test GitHub OAuth app.
6. One controlled deploy (auto-deploy off), then teardown authorization.

No provisioning, deployment, key generation, database modification, or restoration is performed by
this document.
