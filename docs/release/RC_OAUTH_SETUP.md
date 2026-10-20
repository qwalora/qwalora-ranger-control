# RC GitHub OAuth setup (separate app; do not reuse accepted credentials)

Ranger authenticates with GitHub OAuth. The RC must use its OWN OAuth app and callback — never the
accepted portal's `GITHUB_OAUTH_CLIENT_ID`/`SECRET` or its callback URL.

## Code contract (from `githuboauth.py`, commit acf50ec)
- `is_configured()` is true only when both `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET`
  are set. When unset, login is disabled and candidate access stays closed — so the RC can start and
  pass internal `/healthz` acceptance BEFORE OAuth exists.
- Authorize URL: `https://github.com/login/oauth/authorize`; Token URL:
  `https://github.com/login/oauth/access_token`.
- `redirect_uri()` = `PORTAL_BASE_URL` (trailing slash stripped) + `/auth/github/callback`.

## Exact registration (human step — do only after internal acceptance passes)
1. Establish an RC-only hostname first. Options: a Railway-generated domain on `parallax-portal-rc`
   (e.g. `parallax-portal-rc-<hash>.up.railway.app`) created only when you are ready to test login, or
   a custom `rc.` subdomain. Keep it private until login + reviewer authz + entitlement checks pass.
2. GitHub → Settings → Developer settings → OAuth Apps → New OAuth App:
   - Application name: `Qwalora Ranger RC` (clearly non-production).
   - Homepage URL: the RC hostname (e.g. `https://<rc-host>`).
   - Authorization callback URL: `https://<rc-host>/auth/github/callback` (exact; must equal
     `PORTAL_BASE_URL` + `/auth/github/callback`).
   - Register, then generate a client secret.
3. Set on `parallax-portal-rc` (RC env only; `--skip-deploys` until ready), never printing values:
   - `PORTAL_BASE_URL=https://<rc-host>`
   - `GITHUB_OAUTH_CLIENT_ID=<rc app client id>`
   - `GITHUB_OAUTH_CLIENT_SECRET=<rc app client secret>`
4. Redeploy. Verify a REAL callback round-trip succeeds (authorize → `/auth/github/callback` → session)
   before claiming OAuth is tested. Do not represent OAuth as verified until a real callback succeeds.

## Guardrails
- Do not reuse the accepted portal's OAuth app, client id/secret, or callback.
- Keep candidate enrollment/public access disabled until authenticated login, reviewer authorization,
  and program-entitlement checks all pass on the RC.
- `PORTAL_BASE_URL` defaults to `https://portal.qwalora.com` if unset — set the RC value explicitly so
  the callback is never pointed at production.
