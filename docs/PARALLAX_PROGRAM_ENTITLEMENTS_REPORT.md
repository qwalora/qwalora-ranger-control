# Ranger program entitlements - acceptance report

One Ranger identity (GitHub). Two independently authorized programs (STRATA, PARALLAX),
enforced server-side, with a unified program-aware experience on the existing Ranger design
system. Nonproduction feature branch only; STRATA's 95% policy untouched; no main/prod.

## 1. Existing architecture findings (audit)

- Identity (`session['cand']` -> Candidate), admission (`pending -> active` via `_approve_candidate`),
  and admin authz (`admin_required`: reviewer OAuth / `ADMIN_TOKEN`) were all SHARED and program-blind.
- The `Candidate` model had NO program/pathway column; a pathway existed only at the COHORT level
  (`Cohort.pathway`, `pathways.py` ids `strata`/`parallax`, default `strata`) and was read in exactly one
  place (the Board-2 qualification record).
- Every approved candidate was unconditionally put on the STRATA six-board ladder
  (`current_board=1` hardcoded at enroll/OAuth/approve) and the whole `/me*` dashboard assumed STRATA.
- The core exposure: `parallax_routes.py` gated only on `status=='active'` (+ nonprod flag + signed
  governance) and NEVER checked program membership, so a STRATA-approved active candidate satisfied the
  PARALLAX identity gate.

## 2. Authorization model and schema changes

New tables (created by `create_all` on boot; `ensure_schema` unchanged for existing tables):
- `program_memberships`: `candidate_id` FK, `program` ('strata'|'parallax'), `status`
  (requested|pending|active|suspended|rejected|revoked), `granted_by`, `cohort`, timestamps; unique
  `(candidate_id, program)`. Only `status=='active'` grants access.
- `program_membership_events`: append-only authorization audit (action, from/to status, actor, reason, at).

`_program_active(cid, program)` is the single server-side check, read fresh each request (so
suspend/revoke take effect with no re-login). STRATA-only legacy fallback: a zero-membership active
candidate is treated as a historical STRATA participant; PARALLAX always requires an explicit active
grant; any candidate with a row is strict/deny-by-default.

## 3. Routes and policies changed

- STRATA session routes gated with `require_program('strata')`: `/me/mission`, `/me/start`,
  `/me/report`, `/me/wireguard`.
- STRATA token/CI API checks STRATA entitlement after candidate resolution: `/labs/start`,
  `/labs/status`, `/labs/dataset`, `/reports`, `/grade`, `/grade/submit`.
- PARALLAX surface requires an explicit active PARALLAX membership (strict, no fallback):
  `/parallax/research/*` (brief, trial, run, run/<id>, model/health), `/parallax/workspace`,
  durable `/parallax/laba/assessment*`, and the laba brief/evaluate preview when the session resolves to
  a real candidate. Workspace redirects a non-member to `/me`; APIs return 403.
- `/me` is program-aware (not gated to one program): STRATA-only, PARALLAX-only, dual (switcher),
  no-access. Forged `?program=` selection is ignored (authorization never trusts it).
- Admission: enroll + GitHub sign-in record a pending membership (cohort pathway); `_approve_candidate`
  activates it and provisions STRATA board 1 only for STRATA; `_reject_candidate` rejects it.
- New admin area `/admin/program-access` (+ `POST /admin/program-access/<cid>/<program>/<action>`):
  grant/approve/reject/suspend/revoke/reinstate each program independently, audited; `@admin_required`.
- New candidate self-service `POST /me/request-program`: creates a `requested` row for admin review
  (never self-grants).

## 4. Migration and rollback

`migrate_program_memberships.py` - one-shot, idempotent, reversible, gated behind
`RANGER_PROGRAM_MIGRATE=1`. Evidence-based per candidate with no membership yet:
- strong STRATA record OR strong PARALLAX record -> that program;
- both -> both; neither -> the single cohort-pathway program.
Never blanket-grants both; never locks out an active candidate. Each row writes a `migrate` audit event
(`granted_by='system:migration'`). `--rollback` removes only untouched system-migration rows.
Verified locally on synthetic data: strong-strata -> strata, strong-parallax -> parallax, no-evidence ->
cohort pathway; rollback removed all system rows.

## 5. Tests and results

- `siem/tests/test_program_entitlements.py`: the A-I identity matrix (12 tests) - unauth, no-membership,
  STRATA-only, PARALLAX-only, dual, suspended-each, reviewer, unauthorized-admin - plus revocation
  freshness (no re-login), forged client-side selection, and cross-program research-API denial. All pass.
- `siem/tests/test_entitlement_flagged_surfaces.py` (3 tests): /case and /workbench deny a PARALLAX-only
  candidate (403) with the flag enabled in-test; /case 404s when off.
- Full PG-on regression: 459 collected (444 prior baseline + 12 identity-matrix + 3 flagged-surface),
  17 skipped, 0 failed (exit 0). The prior 427-pass baseline is preserved. STRATA route tests stay green
  via the legacy fallback; PARALLAX route fixtures seed memberships (PARALLAX is now an explicit grant).

## 6. Screenshots

Rendered through the real templates and real server-side authz (seeded memberships), desktop width:
STRATA-only (board ladder + "Request PARALLAX", no research console), PARALLAX-only (research workspace
+ "Request STRATA", no board content), dual (STRATA|PARALLAX switcher), admin Program Access
(candidate x program matrix with independent grant/suspend/revoke). Delivered in the conversation.

## 7. Railway deployment

- Environment: `parallax-nonprod` (id a7126c4e-a022-4968-8686-a9ea9a3708d7); service `parallax-portal`
  (id 8913f277), PostgreSQL `parallax-postgres`, inference `parallax-inference`.
- Branch tracked: `feature/parallax-p1-architecture-foundations`. Deployed commit: 145b3e1
  (deployment id recorded at verification). New tables created by `create_all` on boot.
- Production, `main`, the deployment hold, and the staged nonprod patch `9853e4b4` were not touched.

## 8. Flag-gated STRATA surfaces (/case, /soc, /workbench) - now gated + tested

The three flag-gated STRATA surfaces now carry server-side STRATA entitlement enforcement via a shared
`_strata_ok(c)` gate (uses the app's `_program_active` when provided, else a legacy-aware membership query
identical in effect), added at each module's candidate-resolution point:
- `case_routes._candidate()` -> 403 for a non-STRATA candidate (before the board check).
- `workbench_routes._cand()` -> the locked page (403) for a non-STRATA candidate.
- `soc_gateway._authorize()` -> 403 for a non-STRATA candidate.
`app.py` passes `program_active` into all three `register()` calls. The flags stay OFF in parallax-nonprod;
this is enforcement-in-place, not activation. Tested (`test_entitlement_flagged_surfaces.py`): with the
flags enabled IN-TEST, a PARALLAX-only candidate is denied `/case` and `/workbench` (403) while STRATA and
legacy candidates pass; `/case` still 404s when the flag is off. `/soc` requires JWT+OpenSearch to register,
so it is covered by the shared gate + code review rather than a route test.

## 9. Real-browser verification (automated) vs human-required checks

Automated real-browser verification (Chromium/Playwright against a live local gunicorn server with
authenticated Flask session cookies, server-served CSS - not the test client): 15/15 authorization checks
pass across direct routes AND APIs for STRATA-only, PARALLAX-only, dual, and unauthenticated identities
(e.g. STRATA-only `/parallax/research/brief` -> 401, `/labs/start` -> 200; PARALLAX-only `/labs/start` ->
403, `/parallax/workspace` -> 200; unauth everything denied). Screenshots were captured from this real
server.

Still requires a human (cannot be done headlessly because GitHub OAuth + 2FA is interactive): the live
nonprod authenticated walkthrough - sign in with GitHub, confirm the dashboard, run a benign control and an
adversarial trial against the real Qwen model, retrieve signed evidence, submit an investigation, and
(as admin) grant/suspend a program in `/admin/program-access` and confirm the effect without re-login.

## 10. Outstanding limitations

- The per-candidate research-run rate limiter is in-process (per worker); a shared store is the documented
  multi-worker follow-up.
- Running the one-shot membership migration against the nonprod database requires executing
  `RANGER_PROGRAM_MIGRATE=1 python migrate_program_memberships.py` inside the portal service (it needs the
  private DATABASE_URL). Until then, existing candidates retain STRATA access via the legacy zero-row
  fallback and are never locked out; PARALLAX access is granted per candidate via `/admin/program-access`.
- `/soc` has the STRATA gate in code but no automated route test (registration needs JWT+OpenSearch).

## 11. Required action for the PARALLAX browser acceptance

Under the new model, PARALLAX access is an explicit grant. The existing nonprod candidate (GitHub sign-in)
retains STRATA via the legacy fallback but must be granted PARALLAX to use the research workspace:
sign in to `/admin` (ADMIN_TOKEN or reviewer OAuth), open Program access, and click `grant` on that
candidate's PARALLAX cell. This both completes the PARALLAX acceptance and demonstrates independent
per-program authorization.
