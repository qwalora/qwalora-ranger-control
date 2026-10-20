# PARALLAX RC - operational readiness notes

Concrete operator-executable procedures for the remaining RC readiness items. RC-only. No change
to production, `parallax-nonprod`, historical evidence, signing keys, or the accepted commit
`acf50ec`. The RC app service `parallax-portal-rc` is pinned to the SHA `acf50ec`, so branch
pushes and variable edits do not redeploy it unless a deployment is explicitly triggered.

## 1. RC Postgres superuser password rotation (previously exposed)

Context: `parallax-postgres-rc` is the disposable PITR fork. Its superuser is `POSTGRES_USER`
(password in `POSTGRES_PASSWORD`, mirrored into `PGPASSWORD` and the service `DATABASE_URL`). The
fork has no public TCP proxy, so it is reachable only from inside `parallax-rc` or over an
authorized private Railway connection. Changing the Railway variable alone does NOT change the
live database password (the cluster was initialized with the old one); it must be altered inside
the database and then the variables resynced, or the services desync and fail to connect.

Dependents to check before rotation (the blast radius):
- `parallax-portal-rc` `DATABASE_URL`: confirm whether it connects as the `rc_rw` application
  role or as the superuser. Per the RC plan it uses `rc_rw`, in which case the superuser rotation
  does not touch the portal. Verify with the portal's `DATABASE_URL` role name before proceeding.
- Any verifier/Track-A tooling using `rc_ro`: unaffected by a superuser rotation.

Supported RC-only rotation (operator, over a private connection - `railway connect`/`railway ssh`
to a `parallax-rc` service, or the operator WSL private tunnel):

```sh
# 1. Record current state for before/after verification
railway variables --service parallax-postgres-rc   # note names only; do not paste secrets

# 2. Rotate the live superuser password INSIDE the database (as the current superuser)
psql "$DATABASE_URL" -c "ALTER ROLE <POSTGRES_USER> WITH PASSWORD '<NEW_STRONG_PASSWORD>';"

# 3. Resync the Railway variables on parallax-postgres-rc to the new password
#    POSTGRES_PASSWORD, PGPASSWORD, and the password component of DATABASE_URL must all match.
railway variables --service parallax-postgres-rc \
  --set "POSTGRES_PASSWORD=<NEW_STRONG_PASSWORD>" \
  --set "PGPASSWORD=<NEW_STRONG_PASSWORD>"
#    If DATABASE_URL is a literal (not a Railway reference), update its password component too.

# 4. Update any dependent service that connects AS the superuser (skip if the portal uses rc_rw)

# 5. Restart the dependents and verify
railway redeploy --service parallax-postgres-rc   # only if required for the new env to take
#    then verify the portal reconnects (see section 3 smoke checks) and /healthz db:true
```

Verification: before - capture the failing/old state is not needed, just the variable names and
which role the portal uses; after - the portal `/healthz` returns `db:true`, a trivial
`SELECT 1` as the app role succeeds, and the audit (`rc_ro`) still returns `failed == []`.

Blocker from the automation environment: the cloud sandbox is not on the `parallax-rc` private
network and `parallax-postgres-rc` has no TCP proxy, so the `ALTER ROLE` cannot be issued from
here without creating exposure (ruled out). This step is operator-executed.

## 2. RC GitHub OAuth application (separate, no reused credentials)

Create a DEDICATED GitHub OAuth app for the RC only. Never reuse production or `parallax-nonprod`
`GITHUB_OAUTH_CLIENT_ID`/`GITHUB_OAUTH_CLIENT_SECRET`.

| Setting | Value |
|---|---|
| Application name | `Qwalora Ranger RC (nonproduction)` |
| Homepage URL | the RC access URL (see reachability note) |
| Authorization callback URL | `<RC base URL>/auth/callback` |
| Scopes | minimal: `read:user`, `user:email` (identity + verified email only) |
| Device flow | off |
| Secret handling | store `GITHUB_OAUTH_CLIENT_ID`/`_SECRET` only on `parallax-portal-rc`; set `PORTAL_BASE_URL=<RC base URL>` |
| Restriction | enroll only the test researcher/reviewer GitHub accounts; `REVIEWER_GITHUB_IDS` = test reviewer id(s) |

Reachability dependency (genuine blocker/decision): GitHub OAuth must redirect to a callback URL
GitHub can reach, but the RC has no public domain by instruction. To run live OAuth you must pick
one access-controlled path and confirm it:
- a Railway private/access-controlled domain restricted to the test accounts, or
- a time-boxed authenticated tunnel for the validation window only.
Until that access path is chosen, the live OAuth round-trip cannot be exercised. Everything else
below can be validated with minted sessions (no OAuth) exactly as the design-completion acceptance
harness did.

## 3. Controlled authenticated researcher/reviewer acceptance tests

Run against the RC over the access path from section 2 (or with minted signed sessions for the
non-OAuth cases). Preserve PARALLAX/STRATA entitlement separation throughout; issue no real
qualification.

| # | Area | Actor | Pass criterion |
|---|---|---|---|
| 1 | Health | n/a | `GET /healthz` -> `{"status":"ok","db":true}` |
| 2 | OAuth round-trip | test researcher | session issued; CSRF enforced on POST |
| 3 | Session persistence | researcher | cookie persists across requests, no DB dependency |
| 4 | Command center | researcher (PARALLAX active) | own signed activity only; no fabricated stats |
| 5 | Console run | researcher | real model output only; no fabricated progress; signed record written to the fork |
| 6 | Draft autosave/restore | researcher | writes land only in the fork |
| 7 | Submission + adjudication | researcher submits; reviewer decides | reviewer-only adjudication enforced; researcher cannot adjudicate; audit chain intact |
| 8 | Evidence + export | researcher | owner-scoped records; export 200 + attachment; cross-owner export 404 |
| 9 | Entitlement separation | STRATA-only identity | denied PARALLAX evidence page/export/history (cross-program isolation) |
| 10 | Program authorization | researcher | PARALLAX vs STRATA shown independently; requesting != granting |

Existing automated coverage already green (local, pre-deploy): `tests/test_parallax_ui.py` (14),
`tests/test_research_execution.py` (7), `tests/test_security_acceptance.py` (4) - 25 passed; the
researcher-journey harness - 10/10. These assert the same authorization, entitlement-separation,
reviewer-only, and provenance properties the live matrix above re-checks against the deployed RC.
