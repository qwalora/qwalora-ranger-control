# PARALLAX / STRATA - Final Program Separation Integration Gate

Work branch `feature/parallax-research-program-separation` @ `4190c9c` (PR #12), stacked on
`feature/parallax-agent-trace` @ `035a010` (PR #11). Staging artifact on
`staging-min/parallax-research` @ `271162a`. No deploy, no merge, no production change. STRATA Board-1
untouched.

## 1. Navigation displays the two programs independently (verified, authenticated UI)

The candidate sidebar (`_candnav.html`, rendered on `/me`, `/parallax/workspace`, etc.) shows a
program's links only when it is the `selected_program` and active, with a program switcher shown only
for dual-entitled users. Added an "Investigations" link (line-style search icon) to the PARALLAX group
pointing at `/parallax/research/investigations`, so the corrected route is discoverable; the edit is
strictly inside the `selected_program == 'parallax'` branch, so STRATA nav is unchanged.

`tests/test_program_nav.py` (4, authenticated `/me` renders):
- PARALLAX-only: sees "Research console" + "Investigations", not "SOC workspace"/"Mission brief".
- STRATA-only: sees SOC/Mission, not the PARALLAX links; `/parallax/research/investigations` absent.
- Dual: program switcher present; `?program=parallax` shows PARALLAX links, `?program=strata` shows
  STRATA links.
- Genuinely unentitled (inactive membership, so no legacy STRATA zero-row fallback): no program links.

## 2. All PARALLAX investigation/trace links use the corrected routes (verified)

A full grep of templates and code shows the only remaining `/parallax/strata` strings are in the alias
handlers' docstrings. Every live link - back-links, the investigation<->trace cross-links, campaign
navigation, the filter form action, and the nav - uses `/parallax/research/*`. Browser evidence: the
trace explorer rendered through `/parallax/research/traces` shows the title "PARALLAX Research - Trace
Explorer", px-trust-v1.1, grounded authorization status, and corrected campaign navigation.

## 3. Legacy URLs cannot disclose another user's records or bypass membership

The deprecated `/parallax/strata/*` aliases run the PARALLAX gate FIRST (`_parallax_page_gate`), then
redirect only an authorized PARALLAX user to the new route; an unauthenticated or non-PARALLAX user
gets the gate's safe denial (login / own dashboard) and is never redirected into PARALLAX. The alias
preserves the requested `run_id`, but the destination research route enforces owner-scoping, so a
foreign `run_id` returns 404 (no disclosure). Tests: `test_legacy_strata_urls_gate_and_redirect_correctly`,
`test_unauthenticated_legacy_url_goes_to_login_not_research`, `test_legacy_alias_cannot_disclose_another_users_records`.

Recommendation on the aliases: KEEP them for ONE release as 302 redirects (preserves any bookmarks /
in-flight links without weakening the boundary), then RETIRE them in the following release once traffic
confirms no external dependence. They add no access surface (same gate) and no data surface (ownership
enforced at the destination).

## 4. No unexpected STRATA Board-1 / grading / dataset / training modifications (PR #11 + #12)

`git diff --name-only ffb0d4b..deb3a40` (both PRs combined) touches only PARALLAX research files, the
two renamed PARALLAX templates, `parallax_routes.py` (PARALLAX route registration), reports, and tests.
`app.py` has ZERO changes, so every STRATA route, `@require_program("strata")` gate, `scenarios.grade`
/ `strata_assignment.grade`, Board-1 SOC workspace, datasets, and training progress are untouched. The
`_candnav.html` change (PR #12 follow-up commit) adds a link only inside the PARALLAX nav branch.

## 5. Integration candidate rebuilt and tested

Integration candidate = the work branch tip `4190c9c` (includes all of PR #11 + PR #12). Full suite on
the exact commit: **236 passed, 0 failed** (includes the new-trace components, existing STRATA,
PARALLAX research, access-control/adversarial, program-separation, program-nav, and end-to-end
authenticated UI suites). Authenticated UI tests run against the real routes with a genuine session
cookie and real stored runs. Browser evidence captured via headless Chromium.

## 6. Revised minimal PARALLAX staging artifact

Branch `staging-min/parallax-research` @ `271162a`, parent `bf9266c` (which is parented on `b0f1588`,
the deployed nonproduction revision = `eb9e925e`). It is bf9266c's additive investigation-workspace
backport with ONLY the program-naming correction applied:
- the research investigation page is served at `/parallax/research/investigations[/<run_id>]` with
  PARALLAX terminology; `/parallax/strata/investigation` kept as a gated deprecated alias;
- template renamed to `parallax_research_investigation.html`.

Deliberately EXCLUDED (not fabricated into a smaller release): the trace explorer and the px-trust-v1.1
authorization correction. They depend on `store.overview_for` and `agent_trace`/`trust_analysis`, which
are NOT on `b0f1588`; including them would require pulling the later development increment, which would
be unrelated integration commits. They are a documented SECOND staging increment to be sourced from the
development integration branch once it lands.

Verification of the artifact: 44 tests pass; the app boots; `/parallax/research/investigations` and the
legacy alias are registered; the nonprod gate holds (404 in prod, 302 unauthenticated). No change to
stored records, hashes, signatures, evidence, measurement, or STRATA Board-1. NOT deployed.

## 7. bf9266c unchanged and marked superseded

`bf9266c` (`staging-min/parallax-strata`) is unchanged - the revised artifact is a NEW branch, not an
amendment. For deployment planning, bf9266c is SUPERSEDED by `staging-min/parallax-research` @
`271162a`: both are additive investigation-workspace backports on `b0f1588`, but bf9266c uses the
incorrect `/parallax/strata` program naming, which the permanent program-separation requirement
forbids. Deploy planning should target `271162a` (or a later increment), not bf9266c.

## 8. Deliverables summary

- **Exact code changes:** PR #11 (trace/trust/bundle), PR #12 (program separation + nav), staging
  artifact `271162a` (naming-corrected minimal investigation workspace).
- **Tested commit hashes:** work branch `4190c9c` (236 passed); staging artifact `271162a` (44 passed);
  both PRs combined vs base `ffb0d4b..deb3a40` (app.py zero changes).
- **Browser evidence:** `/parallax/research/traces` authenticated render (corrected title + grounded
  authorization); program-nav independence proven by `test_program_nav.py`.
- **Remaining defects:** none blocking. Known deferrals: (a) internal legacy module filenames
  `strata_view.py` / `strata_investigation.py` (PARALLAX-owned; rename in a follow-up to avoid cross-PR
  churn); (b) the trace explorer + px-trust-v1.1 as a second staging increment.
- **Final staging approval recommendation:** APPROVE `staging-min/parallax-research` @ `271162a` for a
  nonproduction staging deployment decision by the operator - it is additive on the deployed baseline,
  nonprod-gated, reversible (redeploy `eb9e925e`/`b0f1588`), and carries the corrected program naming.
  I did not deploy it. bf9266c is superseded. Do not deploy the trace-explorer increment until its
  dependencies are present in the chosen baseline.
