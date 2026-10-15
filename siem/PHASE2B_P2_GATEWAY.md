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
