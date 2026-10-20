# PARALLAX RC deploy & rollback runbook — service parallax-portal-rc (env parallax-rc)

Isolated release candidate. Never touches `parallax-nonprod`, `parallax-portal`, `parallax-postgres`,
`main`, or the accepted application branch. Deploy target is pinned commit `acf50ec`.

## Fixed identifiers
- Project `qwalora-ranger` `ee093894-30f7-4c82-ab5d-d7ef4d1a6454`; env `parallax-rc`
  `6abda105-12e3-4310-b764-bd92cd354957`.
- App `parallax-portal-rc` `709cb0d3-6ef8-4670-b772-cf49ae3b873d` (RAILPACK, Procfile:
  `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60`).
- DB `parallax-postgres-rc` `f14887e3-4f6e-433b-9ec7-4fb8c77f7628` (PG 18.6, volume
  `parallax-postgres-rc-data` `0ca416cc`), private-only.

## Pre-deploy state (verified)
- Source pinned: repo `qwalora/qwalora-ranger-control`, branch `integration/release-candidate`,
  commit `acf50ec…`.
- 8 variables present (values never disclosed): `DATABASE_URL` (rc_rw → RC private domain),
  `RANGER_RC_ALLOW=1`, `RANGER_RC_EXPECT_TOKEN`, `RANGER_ENV=staging`, `RANGER_REQUIRE_SECURE_SECRETS=1`,
  `SECRET_KEY` (RC-only), `RANGER_SIGNING_KEYS` (disposable active + historical verify_only public),
  `RANGER_SIGNING_VERIFY_KIDS=legacy:696697820b69d289`.
- No public domain; no TCP proxy. `RANGER_PATHWAY_MIGRATE`, `PUBLISH_PUBLICATIONS` unset (disabled).

## Deploy (when Railway builds are healthy)
1. Confirm staged/live config: source == `acf50ec`, 8 vars present, no public domain.
2. Deploy: Railway dashboard → `parallax-rc` → Deploy (commits any staged changes and builds
   `acf50ec`). The tool `accept-deploy` is equivalent but was being cancelled at the approval gate;
   the dashboard Deploy is the reliable path.
3. Verify the DEPLOYED commit SHA == `acf50ec`. If it differs, STOP and investigate (branch-head drift).

## Health / acceptance verification (authorized internal inspection)
- Deployment status SUCCESS; read deploy logs and confirm, in order: RC identity guard passed (marker
  matched; no `RCGuardError`), `create_app` proceeded, DB connected as `rc_rw`, bootstrap steps ran,
  gunicorn serving. A healthy process does NOT prove schema init — run the schema checks below.
- `/healthz` (no public domain yet): `railway connect`/tunnel to the service or `railway run -- curl`
  internally; expect `{"status":"ok","db":true}`.
- Full internal acceptance: `scripts/rc_acceptance_checks.sh` (READ-ONLY, over `rc_ro`): connectivity,
  RC marker, schema objects (34 tables, summary=900, uq_unit_result_record, migration columns),
  7 research runs + 2 protected records, the pinned 41-check audit (public-key-only), publication diff
  vs `rc-publications-before-startup.json`, and entitlement isolation. Require 0 failures.
- OAuth: deferred; see `RC_OAUTH_SETUP.md`. Keep candidate access closed until a real callback succeeds.

## Rollback / teardown (RC only; no effect on nonprod/production)
- Pre-deploy abort: discard the `parallax-rc` staged changes (if any). Nothing is live for the app.
- Bad app deploy: in `parallax-rc`, roll back to a prior `parallax-portal-rc` deployment, or detach the
  source. The RC database is unaffected.
- Config rollback: variables are per-service in `parallax-rc`; reset/remove them without touching other
  environments.
- Full teardown: delete `parallax-portal-rc` (`709cb0d3`), delete `parallax-postgres-rc` (`f14887e3`),
  delete volume `parallax-postgres-rc-data` (`0ca416cc`), then delete the `parallax-rc` environment.
  Do not delete the `Postgres-PITR` bucket or touch `parallax-postgres`.

## Static-hardening note
Commit `acf50ec` is the reviewed deploy target. A separate branch `chore/rc-static-hardening` clears
bandit High findings (debug-runner off-by-default; non-security MD5 marked `usedforsecurity=False`).
It does NOT change schema or behavior. Re-pin the RC source to that commit only if you choose to adopt
it (no re-migration needed, same schema); otherwise `acf50ec` stands with the findings documented.
