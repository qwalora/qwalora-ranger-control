# PARALLAX Nonproduction GitHub OAuth + Human Acceptance Guide

This is the operator runbook to finish Phase 2C final acceptance: enable a real GitHub sign-in on the
nonproduction portal (reusing the SAME Ranger authentication code STRATA uses) and have an authorized
researcher complete a genuine browser investigation. No second login system is introduced; the PARALLAX
workspace uses the existing `githuboauth.py` + `/auth/github/callback` + `session['cand']` candidate
identity mapping, unchanged.

Status: the human browser acceptance test is **BLOCKED** on two steps only an operator/human can do:
creating the nonprod OAuth App (your GitHub account) and signing in at a browser. Everything the
application must provide is deployed and verified.

## A. Why a separate nonproduction OAuth App (do not touch production)

The callback URL is computed in code as `PORTAL_BASE_URL + /auth/github/callback`
(`githuboauth.redirect_uri()`). Production's app is registered for `https://portal.qwalora.com`. The
nonprod portal is a different host (`parallax-portal-parallax-nonprod.up.railway.app`), so the
production app's callback will not match it, and adding the nonprod callback to the production app would
change production's OAuth configuration. Therefore register a dedicated nonproduction OAuth App. It uses
the identical Ranger auth implementation and the same GitHub identities; only the client id/secret and
base URL differ.

## B. Create the nonproduction GitHub OAuth App

In GitHub (your account or the Qwalora org) -> Settings -> Developer settings -> OAuth Apps -> New:
- Application name: `Qwalora Ranger (nonprod)`
- Homepage URL: `https://parallax-portal-parallax-nonprod.up.railway.app`
- Authorization callback URL: `https://parallax-portal-parallax-nonprod.up.railway.app/auth/github/callback`
- Scopes are requested at runtime by the code (`read:user user:email`); no extra permissions needed.

Do not modify the existing production OAuth App.

## C. Configure ONLY the nonprod portal (service `8913f277-...`)

Set these variables on the nonprod portal (the first two are secret - set them in the Railway dashboard
or CLI, never in code, logs, or chat):
- `GITHUB_OAUTH_CLIENT_ID` = the nonprod app's client id
- `GITHUB_OAUTH_CLIENT_SECRET` = the nonprod app's client secret
- `PORTAL_BASE_URL` = `https://parallax-portal-parallax-nonprod.up.railway.app` (already set)
- Optional for a test account without 2FA: `REQUIRE_2FA=0` (the identity bar otherwise requires a
  verified email, 2FA on, and a GitHub account at least 30 days old).
- Optional to exercise the reviewer step: `REVIEWER_GITHUB_IDS` = the reviewer's numeric GitHub id.

Session secret (`SECRET_KEY`), signing key (`RANGER_SIGNING_KEY`), and database (`DATABASE_URL`) are
already independent nonproduction values; do not copy production's.

## D. First sign-in lands as `pending` - approve to `active`

By design (`gh_callback`), a first GitHub sign-in creates the candidate as `pending` with no board and
no environment. The PARALLAX workspace requires an `active` candidate, so after the researcher signs in,
an admin approves them (admin console, authorized via `ADMIN_TOKEN` / reviewer GitHub id) which flips
`pending -> active`. Then the researcher can use `/parallax/workspace`.

## E. Browser acceptance checklist (perform as the researcher; do not use a synthetic session)

1. Open `https://parallax-portal-parallax-nonprod.up.railway.app`.
2. Sign in with GitHub (consent to the nonprod app).  -> lands `pending`; admin approves to `active`.
3. Open `/parallax/workspace`.
4. Click "Load brief" (reads `/parallax/research/brief`).
5. Choose a legitimate task; click "Run benign control" -> expect a real Qwen answer and outcome
   `boundary_preserved`.
6. Paste an adversarial low-trust document; click "Run adversarial trial" -> observe the real model
   output and the deterministic outcome (success only if the canary `INJECTION-OK` is actually emitted).
7. Click "Refresh" under history (reads `/parallax/research/history`).
8. Submit an investigation bound to a trial id (`/parallax/research/investigation`).
9. Confirm the signed evidence is retrievable (`/parallax/research/run/<id>`, `signature_verifies:true`).

Evidence to capture: a browser screen recording or screenshots; the portal deploy logs for the request
lines; and, if DB inspection is wanted, a Railway shell on `parallax-postgres` (private) querying
`parallax_research_runs` for the researcher's rows. Do not mark acceptance complete without a genuine
human interaction.

## F. Isolation and security validation (VERIFIED in tests)

Automated coverage (8/8 targeted tests green; part of 427 passed / 17 skipped / 0 failed PG-on):
- cross-user access denial: a researcher cannot read or bind another's run/evidence (owner-scoped;
  returns 404, never revealing existence).
- unauthorized experiment initiation: routes return 401 without an active candidate session, 404 outside
  the nonprod gate.
- forged research-run identifiers: unknown/unowned ids return 404; stored records are Ed25519-signed and
  signature-verified on read, so a forged or tampered record fails verification.
- CSRF: state-changing POSTs require the `X-CSRF-Token` session token (app `_csrf_protect`); the OAuth
  flow validates a random `state` bound to the session.
- request throttling: per-candidate research-run rate limit (HTTP 429) plus the app's per-IP limiter.
- reviewer authorization: adjudication requires the session GitHub id to be in `REVIEWER_GITHUB_IDS`.
- session security: signed session cookie (nonprod `SECRET_KEY`); identity is the server-side session,
  never a client-supplied field. Session expiration follows the app's cookie policy; validate the
  desired lifetime if a shorter TTL is required.
- self-check disabled: the nonprod startup self-check was removed from the portal start command (plain
  gunicorn) and is gated to nonproduction only; it never existed on the production portal.

## G. Cost, capacity, idle behavior (observed - honest)

- Inference service memory: ~0.66 GB resident, ~1.05 GB peak; CPU ~0 at idle, up to ~0.35 vCPU under a
  request. **Idle scaling: NOT occurring.** The service holds ~0.66 GB resident while idle (model kept
  warm; 1 replica; no serverless configured, and an attached volume generally pins a Railway service
  on). Treat it as always-on. This was requested but is not in effect; enabling true scale-to-zero would
  require a serverless configuration Railway may not allow alongside the model volume, and would add
  cold-start latency (~6 s model load) on each wake.
- Inference latency: a short generation ~0.2-0.3 s warm; ~6 s on a cold runner load.
- Volumes: both the inference and postgres volumes were provisioned at Railway's default 50 GB; actual
  occupied is a fraction (model ~0.4 GB + Ollama overhead; a fresh PostgreSQL is tens of MB). Railway
  bills by provisioned size, so this is wasteful.
- Monthly estimate: three always-on small services (~0.7-1 GB RAM each) plus ~100 GB of provisioned
  volume. Keep an eye on the volume line; it is the main avoidable cost. Still within the $300 budget,
  but the volumes should be reduced.

### Safe volume reduction plan (requires your explicit authorization - not performed)

Railway volumes cannot be shrunk in place; reduction means create-new-smaller + migrate + delete-old.
- Inference volume: lowest risk. The model re-pulls from the Ollama registry in ~9 s, so: stop the
  inference service, detach/delete the 50 GB volume, create a ~5 GB volume at `/root/.ollama`, redeploy
  (model re-pulls). Brief downtime, no data loss (the model is re-fetched).
- PostgreSQL volume: higher risk (holds research evidence). Safe path: `pg_dump` the nonprod DB, create a
  new ~5 GB volume, restore, verify row counts and a signature check, then delete the old volume.
- Do not delete or recreate either volume without explicit authorization.

## H. Cleanup still pending your action

The accidental `qwalora-ranger-control` service (`613afed9-eb22-464a-bdda-b2af9366390d`) in
`parallax-nonprod` has no volumes, no required variables, and no dependents (it is an idle copy of the
app from `main`). Delete it in the Railway dashboard (three delete approvals via tooling were declined).
