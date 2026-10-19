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
- Full PG-on regression: 456 collected (444 prior baseline + 12 new), 17 skipped, 0 failed (exit 0).
  The prior 427-pass baseline is preserved. STRATA route tests stay green via the legacy fallback;
  PARALLAX route fixtures seed memberships (PARALLAX is now an explicit grant).

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

## 8. Outstanding limitations

- Three STRATA surfaces behind feature flags that are OFF in parallax-nonprod were not modified:
  `/case` (RANGER_CASE_UI), `/soc` (OpenSearch/JWT), `/workbench` (RANGER_WORKBENCH). They resolve the
  shared candidate session but do not yet carry `require_program('strata')`; add it before enabling those
  flags. These are same-program STRATA features; the cross-program exposure (the core finding) is fully
  closed on the active surfaces.
- The per-candidate research-run rate limiter is in-process (per worker); a shared store is the
  documented multi-worker follow-up.
- Running the one-shot membership migration against the nonprod database requires executing
  `RANGER_PROGRAM_MIGRATE=1 python migrate_program_memberships.py` inside the portal service (it needs the
  private DATABASE_URL). Until then, existing candidates retain STRATA access via the legacy zero-row
  fallback and are never locked out; PARALLAX access is granted per candidate via `/admin/program-access`.

## 9. Required action for the PARALLAX browser acceptance

Under the new model, PARALLAX access is an explicit grant. The existing nonprod candidate (GitHub sign-in)
retains STRATA via the legacy fallback but must be granted PARALLAX to use the research workspace:
sign in to `/admin` (ADMIN_TOKEN or reviewer OAuth), open Program access, and click `grant` on that
candidate's PARALLAX cell. This both completes the PARALLAX acceptance and demonstrates independent
per-program authorization.
