# Ranger Program Entitlements - design, authorization model, and migration

One Ranger identity (GitHub). Two independently authorized programs: STRATA and PARALLAX.
Least privilege, server-side enforcement, unified UI. Nonproduction feature branch only;
no main, no production. STRATA's 95% qualification policy is untouched.

## 1. Problem (from the audit)

- Identity, admission (`pending -> active` via `_approve_candidate`), and admin authz are all
  SHARED and program-blind. The `Candidate` model has NO program/pathway column.
- Every approved candidate is unconditionally put on the STRATA six-board ladder
  (`current_board=1` hardcoded at enroll/OAuth/approve) and the whole `/me*` dashboard assumes STRATA.
- `parallax_routes.py` gates only on `status=="active"` (+ nonprod flag + governance), and NEVER
  checks program membership -> a STRATA-approved active candidate currently satisfies the PARALLAX
  identity gate. This is the cross-program exposure to close.
- A pathway concept already exists but only at the COHORT level (`Cohort.pathway`, `pathways.py`
  ids `strata`/`parallax`, `DEFAULT_PATHWAY="strata"`); it is never attached to a candidate.

## 2. Authorization model

New table `program_memberships` (one row per candidate per program):

| column        | type         | notes                                                             |
|---------------|--------------|-------------------------------------------------------------------|
| id            | Integer PK   |                                                                   |
| candidate_id  | FK candidates.id, not null, index |                                              |
| program       | String(20), not null, index | canonical pathway id: `strata` | `parallax` (pathways.py) |
| status        | String(20), not null, index | `requested|pending|active|suspended|rejected|revoked` |
| granted_by    | String(120), nullable | admin github id / handle that last changed it            |
| cohort        | String(40), nullable | cohort at grant time (where applicable)                   |
| requested_at  | DateTime     | default now                                                       |
| decided_at    | DateTime, nullable | approve/reject time                                         |
| revoked_at    | DateTime, nullable | suspend/revoke time                                         |
| created_at    | DateTime     | default now                                                       |
| updated_at    | DateTime     | default now, onupdate now                                         |

`__table_args__`: `UniqueConstraint(candidate_id, program)` -> at most one membership per program.
Only `status == 'active'` grants access. Any other value denies.

New append-only audit table `program_membership_events` (verifiable authorization history):
`id, candidate_id, program, action (request|approve|reject|suspend|revoke|reinstate|migrate),
from_status, to_status, actor, reason, at`. Never updated or deleted.

Status semantics:
- `requested` - candidate asked for a program they are not yet granted (self-service REQUEST only).
- `pending` - applicant awaiting the platform/program approval decision.
- `active` - authorized; the ONLY status that grants access.
- `suspended` - temporarily revoked by an admin; reinstatable.
- `rejected` - application declined (from pending/requested).
- `revoked` - access removed by an admin (from active/suspended).

## 3. Enforcement (server-side, every boundary)

A single source of truth: `_program_active(candidate_id, program) -> bool` (DB read, never session-cached,
so suspension/revocation takes effect on the very next request with no re-login).

Backward-compatibility fallback (STRATA only, asymmetric by design): a candidate with NO membership rows
at all who is platform-active is treated as a pre-entitlement STRATA participant - STRATA was the universal
historical default, so legacy/un-migrated rows (and existing tests that seed bare active candidates) are
not locked out. The fallback NEVER applies to PARALLAX (PARALLAX was never a default; access is always an
explicit active grant) and NEVER applies once the candidate has any membership row (then strict,
deny-by-default). After the migration runs, no zero-row candidates remain, so the fallback is a transition
aid, not a standing grant. Identity B in the matrix is modeled as a candidate with a non-active (pending)
row, which is governed strictly and denied.

- `require_program(program)` decorator for session (cookie) routes: resolves the session candidate;
  401 if unauthenticated; 403 (no cross-program leak) if authenticated but lacks an ACTIVE membership
  for `program`; else proceeds.
- STRATA surface gated with `require_program('strata')`: `/me/mission`, `/me/start`, `/me/report`,
  `/me/wireguard`, and the token/CI API `/labs/start`, `/labs/status`, `/labs/dataset`, `/reports`,
  `/grade`, `/grade/submit` (after candidate resolution, require the resolved candidate's STRATA
  membership). `/case/*`, `/soc/*`, `/workbench/*` are STRATA surfaces and get the same gate where they
  resolve a candidate.
- `/me` (dashboard) is program-aware (section 4), not gated to one program.
- PARALLAX surface: `parallax_routes.py` `_resolve_candidate_key()` / `_resolve_candidate()` additionally
  require an ACTIVE `parallax` membership; every research/workspace/laba route already funnels through
  these, so one change gates the whole surface. The workspace page redirects an authenticated
  non-member to `/me` (their real dashboard); APIs return 403.
- `siem/authz.decide_access` keeps its active+SIEM-board check; the STRATA route gate runs before any
  SIEM credential is minted, so SIEM access inherits the STRATA entitlement.
- Admin membership changes require `@admin_required` (existing reviewer/token authz).
- Forged client-side program selection is never trusted: the program SWITCHER only sets a cosmetic
  `session['program_sel']`; authorization always checks DB membership for the program the ROUTE belongs
  to, independent of the selected program or any request field.

Denied-access behavior: 401 unauthenticated, 403 authenticated-but-not-entitled, 404 when the whole
surface is flag-gated off (nonprod flag). No response reveals another program's data.

## 4. Program-aware unified dashboard (`/me`, Ranger design system)

`_me_vm(c)` computes `programs` (active memberships) and a validated `selected` program
(`?program=` or `session['program_sel']`, intersected with active memberships; never trusts an
unentitled value). Rendering:
- No active program -> neutral admission-status view (pending/rejected/no-entitlement). Renders neither
  program's protected nav or data. Offers a "request access" affordance (creates a `requested` row;
  never self-grants).
- STRATA selected -> the existing STRATA dashboard (board ladder, lab, report, record).
- PARALLAX selected -> a PARALLAX summary card + CTA into `/parallax/workspace` (assessment-only).
- Both active -> a program switcher in the `.anav` header; last choice remembered only while still
  entitled. Shared account controls (sign out, handbook) stay outside both scopes.
Nav shows only programs the candidate holds; hiding is UX only, never the control.

## 5. Admission (platform vs program)

- Platform admission (`pending -> active`) stays: it means "has a Ranger candidate record".
- At candidate creation (enroll + OAuth), also create a `program_memberships` row for the candidate's
  cohort pathway in status `pending` (the program they are applying to). No access yet.
- `_approve_candidate(c)` -> platform active AND activates that pending program membership; STRATA board 1
  is provisioned ONLY when the activated program is `strata` (a PARALLAX approval provisions no STRATA
  range). `_reject_candidate` -> rejects the pending membership too.
- New admin "Program Access" area (`/admin/program-access`): list candidates + memberships; grant a
  program (creates/activates a membership; provisions STRATA board 1 if strata), approve a `requested`
  one, suspend, revoke, reinstate - each program independently, each audited. Granting a second program
  never resets the first's progress and never duplicates the candidate.
- Candidate self-service REQUEST (`POST /me/request-program`) creates a `requested` row for admin review;
  it never grants.

## 6. Migration and rollback (reliable-evidence based; nonprod synthetic data only)

One-shot, idempotent, reversible. Driven by `migrate_program_memberships.py` and gated behind
`RANGER_PROGRAM_MIGRATE=1` (never runs implicitly on boot). For each candidate with no membership yet:

Evidence (strongest first):
- strong STRATA  = any STRATA-owned record (BoardResult, Report, ScenarioBinding, RangeRequest, Badge,
  Case, CaseSubmission, QualificationDecision) OR `current_board > 1` OR status `graduated`.
- strong PARALLAX = any PARALLAX-owned record (ParallaxResearchRun by researcher_id==github_id/handle,
  UnitResult pathway==parallax, ParallaxReviewerAssignment by candidate_key) OR cohort pathway parallax.
- cohort pathway  = `normalize_pathway(cohort.pathway)` (declared, weak-but-reliable signal).

Rule (never blanket-grants both; never locks out a currently-active candidate):
1. If exactly one program has strong evidence -> grant that program; status mirrors the candidate
   (`active->active`, `pending->pending`, terminal->that terminal). No membership for the other program.
2. If BOTH have strong evidence -> grant both (genuine dual use; reflects reality). Mirror status.
3. If NEITHER has strong evidence -> grant the single program named by `cohort.pathway` (exactly
   preserves today's implicit entitlement; one program only, never both). Mirror status.
Every migration row writes a `migrate` audit event recording the evidence basis. Ambiguity that cannot
be resolved to a single program is left to explicit admin review (a `requested` row), never auto-active.

This satisfies: existing active STRATA participants keep access (rules 1/3); no PARALLAX participant gets
STRATA via legacy active alone (strong PARALLAX -> parallax only, rule 1); no candidate is auto-granted
both without real dual evidence (rule 2 only).

Rollback: `migrate_program_memberships.py --rollback` deletes only system-migration rows (audit
`action='migrate'`, `granted_by='system:migration'`) and their memberships, leaving admin-made grants
intact; or drop `program_memberships` + `program_membership_events` entirely (the app falls back to
flag-gated behavior). ensure_schema adds the tables on fresh DBs via create_all; a new UNIQUE constraint
on an already-deployed table needs a manual `ALTER TABLE ... ADD CONSTRAINT` (documented; nonprod DB is
recreated so create_all covers it).

## 7. Security test matrix (identities A-I)

Automated integration tests seed memberships and assert, per identity: dashboard/sidebar visibility,
direct-URL access, API access, cross-program data retrieval, experiment/range initiation, evidence
retrieval, program-specific approvals, and revocation freshness (effect without re-login), plus forged
client-side program selection and manipulated identifiers.

A unauth; B authed no membership; C STRATA-only; D PARALLAX-only; E both; F suspended-STRATA/active-PARALLAX;
G suspended-PARALLAX/active-STRATA; H reviewer; I unauthorized candidate attempting admin actions.

## 8. Invariants preserved

GitHub-only identity; CSRF, rate limits, Ed25519 signed evidence, reviewer controls, owner-scoping;
STRATA 95% bar (`program.py:PASS_BAR`); PARALLAX assessment-only (no pathway qualification, no credential);
live Qwen inference untouched; nonprod + feature branch only; no second login system.
