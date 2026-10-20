# PARALLAX RC - operational readiness notes

Concrete operator-executable procedures for the remaining RC readiness items. RC-only. No change
to production, `parallax-nonprod`, historical evidence, signing keys, or the accepted commit
`acf50ec`. The RC app service `parallax-portal-rc` is pinned to the SHA `acf50ec`, so branch
pushes and variable edits do not redeploy it unless a deployment is explicitly triggered.

## 0. Private health verification (Railway SSH local port-forward)

`railway ssh` has no `-L` flag; local forwarding uses the system `ssh` client to `ssh.railway.com`,
and for a service with no public domain the SSH username is the SERVICE INSTANCE ID (not the
service id `709cb0d3`, not the deployment id). The Railway read APIs do not expose the instance
id; `railway ssh config` (or the service SSH command in the dashboard) reveals it. The forwarded
local port also serves as the origin for the Phase 2 OAuth tunnel.

Three operator commands (WSL; project linked, or add `-p ee093894-30f7-4c82-ab5d-d7ef4d1a6454`):

```sh
# 1. reveal the service instance id (the `User` in the printed ssh config)
railway ssh config -s parallax-portal-rc -e parallax-rc

# 2. port-forward local 127.0.0.1:8080 -> the RC container's loopback :8080 (separate terminal)
ssh -N -L 127.0.0.1:8080:127.0.0.1:8080 <service-instance-id>@ssh.railway.com

# 3. verify locally, no public domain
curl -s http://127.0.0.1:8080/healthz    # expect {"status":"ok","db":true}
```

Prerequisite: Railway SSH access configured (`railway login`; `railway ssh config` sets the
identity/alias). If step 1 writes a host alias, step 2 may use that alias instead of the raw
instance id.

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

Secret-safe RC-only rotation (operator; no password in shell history, args, logs, or chat):

```sh
# A. Verify the role the portal actually uses (prints the USERNAME only, never the password)
railway ssh -s parallax-portal-rc -e parallax-rc \
  "python -c 'import os,urllib.parse as u; print(u.urlparse(os.environ[\"DATABASE_URL\"]).username)'"
#    rc_rw  -> superuser rotation does NOT touch the portal (blast radius = Postgres service vars)
#    postgres (superuser) -> the portal DATABASE_URL must be updated in the same window

# B. Rotate the live superuser password over an SSH tunnel, interactively (SCRAM; not in argv/logs)
railway connect parallax-postgres-rc -e parallax-rc   # auto --ssh (no public proxy); opens psql
#    at the psql prompt:
\password <POSTGRES_USER>     # type the new secret twice at the prompt; never on a command line
SELECT 1;                     # confirm the session still works
\q

# C. Resync Railway variables in the DASHBOARD (type into the field; never `railway variables --set`,
#    which would place the secret in shell args). On parallax-postgres-rc: POSTGRES_PASSWORD and
#    PGPASSWORD; and the password component of any LITERAL DATABASE_URL that uses the superuser.
#    (If DATABASE_URL is a Railway reference to POSTGRES_PASSWORD, updating that var propagates it.)

# D. Verify fresh connections and integrity (new secret):
#    - a fresh `railway connect parallax-postgres-rc -e parallax-rc` succeeds
#    - /healthz returns db:true (section 0)
#    - rerun the read-only audit over rc_ro: scripts/px_review_audit.py -> summary.failed == []
```

Notes: the live password change via `\password` takes effect immediately with no DB restart;
existing connections persist, new connections use the new secret. Avoid an unnecessary Postgres
restart - only the variable resync (D is dashboard-only) is needed. Rotate credentials for
`parallax-rc` only; never touch another environment's credentials.

Blocker from the automation environment: the cloud sandbox is not on the `parallax-rc` private
network and `parallax-postgres-rc` has no TCP proxy, so neither the role check nor `\password` can
run from here without creating exposure (ruled out). These steps are operator-executed over the
authorized private SSH connection above.

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

Temporary access path (only after Phase 0 health + Phase 1 rotation verified): a Cloudflare
email-protected Quick Tunnel over the Phase 0 local SSH forward. No public Railway domain, no new
service, $0 recurring; stopping `cloudflared` ends access.

```sh
# Phase 0 forward must be up first (127.0.0.1:8080 -> RC portal). Then, time-boxed:
cloudflared tunnel --url http://127.0.0.1:8080 \
  --allowed-mail '<test-researcher-email>,<test-reviewer-email>'
# note the HTTPS hostname cloudflared prints; set the OAuth app callback to <that host>/auth/callback
```

NOT YET verified - confirm all of the following against the real tunnel before relying on it; do
not call it secure or OAuth-compatible until each passes:
1. Hostname stability: the protected tunnel's hostname (the changelog does not confirm it stays a
   random `trycloudflare.com`). The GitHub OAuth callback must match it exactly, so register/update
   the OAuth app AFTER the tunnel is up and keep the tunnel running for the whole session.
2. Redirect interaction: the `--allowed-mail` gate is itself an email-OTP redirect. Pass the OTP in
   the browser FIRST (visit the tunnel root), then start GitHub OAuth, so the GitHub callback to the
   tunnel is not interrupted by the Cloudflare interstitial.
3. Cookie: the app session cookie is set with `Secure` (tunnel is HTTPS) and survives the
   github.com -> tunnel redirect; if the app sets `SameSite=Strict`, verify the cookie is not
   dropped on the cross-site return (Lax is expected to work).
4. CSRF state: the OAuth `state` parameter round-trips and a mismatch is rejected.
5. Access control: only `--allowed-mail` addresses pass; others are blocked.

Until these are verified, the non-OAuth checks below can run against the Phase 0 local forward
(unauthenticated negative cases); the authenticated matrix needs the verified tunnel + test OAuth app.

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
