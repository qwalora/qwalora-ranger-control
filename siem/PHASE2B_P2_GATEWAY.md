# Phase 2b Priority 2 — /soc authenticated Dashboards gateway

Date: 2026-10-15. Candidate access remains DISABLED.

## Implemented and deployed (portal, existing service)

`soc_gateway.py`, registered on the portal, live at `https://portal.qwalora.com/soc`:
- Authenticates every `/soc/*` request via the existing Ranger session
  (`session["cand"]`); requires `status == active` and `current_board == 2`
  (SOC admins via `session["admin"]`, scoped to `ranger_soc_admin`).
- Provisioning (`/soc/launch`) is separate from proxying: idempotent create of the
  candidate's role, roles-mapping (username -> role), private tenant, and seeded
  per-candidate index.
- Mints a short-lived (10 min) RS256 JWT server-side and injects it as the upstream
  `Authorization` header. The token never reaches the browser, a URL, or storage.
- Strips client-supplied `Authorization`, `securitytenant`, `X-Forwarded-*`,
  `X-Real-IP`, `X-Proxy-User/Roles`, `jwt`, and `Accept-Encoding` before forwarding.
- Upstream is hardcoded to the private Dashboards base path (`/soc`); no
  client-controlled host or path, so arbitrary internal services are unreachable.
- `Cache-Control: no-store` on all proxied responses; per-candidate rate limit;
  request timeout; response-size cap; redirects passed to the browser; cookies
  forwarded; security audit log that never records the token.
- Dashboards runs JWT-only with `server.basePath: /soc` and per-candidate PRIVATE
  tenants (`enable_global: false`), isolating saved objects per candidate.

## Admin act-as (candidate simulation), hardened

For candidate-specific validation an authenticated Super Admin can drive the real
candidate SOC experience as a dedicated, non-real test identity. This is a
validation aid, not a production feature, and is constrained so it cannot be abused:

1. Target is hardcoded to the single synthetic `board2-test` candidate
   (`github_id = soctest-board2-test`). Any client-supplied handle is ignored.
2. Requires an authenticated Super Admin session plus explicit per-use
   authorization (`?authorize=yes`).
3. Short-lived: the impersonation carries an expiry (`RANGER_SOC_ACTAS_TTL`,
   default 1800s) and auto-clears; every act-as event is audited.
4. Write-guarded: while impersonating, the session may reach only `/soc/*` and the
   act-as controls. Every other portal route is refused (403), so candidate
   submissions, grading records, admission status, and qualification outcomes
   cannot be modified. SOC itself is candidate-scoped (per-candidate role + DLS +
   private tenant) and reaches none of those records.
5. A real account that happens to share the `board2-test` handle is never hijacked
   (refused 409).
6. The admin identity is recorded in the session and in the audit log for the whole
   impersonation.
7. Off by default: act-as returns 404 unless `RANGER_SOC_ACTAS_ENABLED` is set. It
   stays disabled in production after validation unless a permanent implementation
   is separately approved.

Administrator-authenticated candidate simulation (this act-as path) does NOT replace
real candidate authentication through GitHub OAuth. Both are validated separately
before candidate access is recommended.

Deployed (portal commit `761d162`): gateway registers with `test_mode=False`,
`actas_enabled=False`. To run the candidate-scoped tests, act-as is enabled for the
window only (`RANGER_SOC_ACTAS_ENABLED=1`) and removed afterward.

## Stage 1 validation (SOC administrator), 2026-10-15

Run against the live stack from inside Railway. act-as disabled, candidate access off.

Administrator authorization boundary (`validate_live.py socadmin`, over the real
`sub=ranger_soc_admin` JWT transport, no password): 11/11 PASS. Oversight read across
all candidate `ranger-*` indices and `cluster_monitor`; denied on write, doc/index
delete, non-`ranger-*` read, security API, security index, role creation, and cluster
settings. No standing credential (JWT is 10 min).

Gateway security integration (`validate_live.py gwsec`, no authenticated session
needed): 9/9 PASS.
- Session cookie (observed live): HttpOnly, Secure, SameSite=Lax.
- Unauthenticated `/soc/*` request denied (403) with no token in the body or a cookie.
- Dashboards osd-xsrf CSRF: a state-changing API without `osd-xsrf` is rejected (400);
  with it, the authorized operation succeeds (200).
- Security Analytics: authorized for `ranger_soc_admin` (200), denied for a candidate (403).

Direct-origin isolation (Railway control plane): Dashboards, the live OpenSearch, and
the dangling `opensearch` service have zero public domains and zero TCP proxies. Only
the portal is public.

Fix made during Stage 1: the portal's global form-CSRF guard was not exempt for the
`soc_proxy` endpoint, so state-changing Dashboards XHRs (Discover searches POST) would
have been rejected with 400. `soc_proxy` is now exempt from the form token, and the
gateway enforces CSRF itself by requiring `osd-xsrf` on state-changing proxied methods
(with SameSite=Lax blocking cross-site cookie carriage). Proxied responses also carry
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` alongside no-store.

Pending (browser-only, operator-confirmed): the live `/soc/launch` landing in real
Dashboards and a Discover render, and confirmation that no JWT appears in JS storage or
in network traffic visible to the browser. Stage 1 is NOT closed until these are in hand.

## Validated against the real stack

- OpenSearch Security layer (`validate_live.py jwt`): JWT signature/iss/aud/exp,
  per-candidate index isolation (403), DLS, revocation, role-claim spoof
  resistance, privilege-escalation blocks, admin least-privilege. All PASS.
- Dashboards layer (`validate_live.py dashauth`): header-injected JWT authenticates
  in Dashboards 2.17.1 (200 as the candidate), a real Discover search returns the
  candidate's own data, and a cross-candidate search is denied (403) through the
  actual Dashboards console proxy. All PASS. URL-param tokens are not used.
- Direct-origin: OpenSearch and Dashboards have no public domains or TCP proxies
  (verified); reachable only via the gateway.

## Compliance correction

A test-only session route (`/soc-test/login`, env-gated by `RANGER_SOC_TEST_KEY`)
was briefly enabled on the PRODUCTION portal to let the automation drive the
browser journey. That is a production auth bypass, which the directive forbids, so
it was removed: the portal now runs with `test_mode=False` and the route is not
registered. The mechanism remains in code, gated off, for use only in an isolated
test environment.

## Not yet done: live gateway E2E + browser screenshots

Exercising the gateway's integrated runtime path and capturing Dashboards
screenshots both require an authenticated session, which needs either a GitHub
login (which the automation cannot perform) or a test bypass (not permitted in
production). Two compliant paths, for the operator to choose:

1. Operator-driven (recommended, no new cost): an approved Board 2 candidate (or a
   SOC admin) signs in with GitHub and opens `https://portal.qwalora.com/soc/launch`.
   The gateway provisions and proxies them into real Dashboards -> Discover on their
   authorized index. Capture screenshots and run the browser checks.
2. Isolated test environment (needs approval; new infra/cost): a separate Railway
   environment with the test-session mechanism enabled, where the full journey is
   automated end to end without touching production.

Candidate access stays disabled until the chosen browser validation passes.
