# WS1 - STRATA Board-1 SOC access: what was delivered, and the OpenSearch upgrade proposal

## A. What ships now (VERIFIED, existing resources, no new infra)

Audit result: `/soc` (OpenSearch Dashboards) is a **Board-2** surface and hard-requires a live
OpenSearch+Dashboards upstream that **does not exist in parallax-nonprod** (no `OPENSEARCH_ADMIN_PASSWORD`,
no `RANGER_JWT_PRIVATE_B64`, no OpenSearch/Dashboards service - confirmed by service inventory). **Board 1
is dataset-based and already OpenSearch-free**: a per-candidate, seeded, answer-free alert queue
(`scenarios.public_board1`) graded server-side (`scenarios.score_board1`). The only gap was that no browser
page rendered it.

Delivered: a portal-served **Board-1 SOC alert-triage workspace** (`/me/workspace`, template
`board1_workspace.html`) - a genuine, authorized, candidate-scoped, browser-accessible investigation
surface. No OpenSearch, no fabricated URL, no direct cluster exposure. Controls at every boundary:
- `require_program('strata')` + active status; the triage surface is Board 1.
- Ownership is **structural**: the dataset derives from the *session* candidate's own seed; no handle/seed
  is accepted from the client. Two candidates get different datasets.
- The **answer key never leaves the server**: `/me/workspace/data` returns only `{id,timestamp,host,signal,raw}`;
  grading re-derives the key from the seed and returns correctness flags only.
- `/me/workspace/submit` is session + CSRF authed; it records the objective and evaluates the promotion
  gate exactly like the token API (STRATA 95% policy unchanged).

Verified: `test_soc_workspace.py` (4 tests - launch entitlement, answer-free + ownership, server-side
grading with flags-only feedback + discrimination, CSRF) and a real-browser check (Chromium against a live
gunicorn server with an authenticated session: 14 alerts fetched and rendered in the DOM, no key leak,
submission graded live). This is "actual lab launch and reachability", not button rendering.

## B. OpenSearch Dashboards SIEM - upgrade proposal (needs approval; NOT provisioned)

This is the richer environment (full Dashboards SOC console, and the Board-2 `/soc` experience). It needs
billable infra, so per the Phase-3 constraints it is proposed here, not provisioned.

### Design (reuses the existing, already-built gateway)
- Stand up **single-node OpenSearch + OpenSearch Dashboards** in `parallax-nonprod` (Railway), private
  network only (`opensearch.railway.internal:9200`, `dashboards.railway.internal:5601`).
- The portal already has `soc_gateway.py`: a reverse proxy that mints a short-lived server-side JWT
  (`RANGER_JWT_PRIVATE_B64`), injects `Authorization: Bearer` + `securitytenant`, strips client auth/forward
  headers, and provisions per-candidate role + roles-mapping + seeded index + private tenant via
  `siem/live.py LiveCluster` against the admin credential (`OPENSEARCH_ADMIN_PASSWORD`). The STRATA program
  gate is already wired into `_authorize()`.
- Isolation: index-per-candidate-board + a per-candidate role scoped to that index pattern + document-level
  security on `candidate_id` (see `siem/authz.py`). The admin credential never leaves the gateway; the
  candidate never sees OpenSearch directly.
- Env to set on the portal only (no code change needed to register): `OPENSEARCH_ADMIN_PASSWORD`,
  `RANGER_JWT_PRIVATE_B64`, `OPENSEARCH_URL`, `DASHBOARDS_URL`. `RealOpenSearch`/`LiveCluster` would need the
  currently-stubbed `put_role`/`put_user` methods completed and tested against the live cluster.

### Threat model (summary)
- **Cross-candidate data access**: mitigated by index-per-candidate + per-candidate role + DLS; the gateway
  authorizes (program entitlement + ownership + board) before minting any credential. Residual risk: a
  role/rolesmapping misconfiguration. Mitigation: automated provisioning + an isolation test that one
  candidate's credential cannot read another's index.
- **Direct OpenSearch exposure**: avoided - OpenSearch/Dashboards bind to the private network only; the only
  ingress is the authenticated portal reverse proxy.
- **JWT key compromise**: short-lived tokens, minted server-side only; key stored as a Railway secret, never
  in code/logs. Rotation plan required.
- **Admin credential**: held only by the gateway; never sent to the browser.
- **CSRF / XSRF**: Dashboards `osd-xsrf` enforced upstream; portal session is SameSite=Lax.
- **Resource exhaustion**: OpenSearch JVM is memory-heavy; a single node caps concurrency. Mitigation: a
  small fixed heap + per-candidate index lifecycle (close/delete after attempt).

### Cost estimate (to confirm at provisioning)
- OpenSearch single node (JVM, ~2 GB min, 4 GB recommended) + Dashboards (~1 GB) + a small index volume,
  always-on on Railway: **~$15-35/month** added to the current ~3 always-on services. Still inside the
  $300/month budget, but it raises the always-on floor and the volume footprint (see WS6).
- A scale-to-zero SOC is not realistic (stateful JVM, slow cold start, ingestion); treat as always-on while
  a cohort is active, or snapshot+destroy between cohorts (adds multi-minute wake latency).

### Explicit approval request
To proceed with the OpenSearch Dashboards SIEM in `parallax-nonprod`, I need explicit approval to:
1. Provision a single-node OpenSearch + Dashboards (billable, ~$15-35/mo) on the private network.
2. Set the four portal env vars above and complete + test the `LiveCluster` role/user provisioning.
3. Enable `soc_gateway` (Board-2 `/soc`); Board 1 stays on the portal workspace already delivered.
I will not provision, set those vars, or enable `/soc` without that approval. Board-1 candidates have a
genuine, accessible environment today regardless of this upgrade.
