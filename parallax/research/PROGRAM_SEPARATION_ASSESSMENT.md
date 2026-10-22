# PARALLAX / STRATA Program Separation - Compatibility and Dependency Assessment

Branch: `feature/parallax-research-program-separation` (off `feature/parallax-agent-trace` @ `035a010`).
Read-only audit first, per the migration-safeguards requirement. No deploy, no merge, STRATA Board-1
untouched.

## 1. Program ownership matrix

| Component | Owner | Evidence / gate | Action |
|---|---|---|---|
| `/me`, `/me/mission`, `/me/workspace`, `/me/workspace/*`, `/grade`, `/grade/submit` | **STRATA** | `@require_program("strata")`; `scenarios.grade` / `strata_assignment.grade`; Board-1 SOC | KEEP UNCHANGED |
| `strata_missions.py`, `strata_assignment.py`, `strata_qualification.py`, `strata_range_attestation.py`, `board1_workspace.html`, `scenarios` | **STRATA** | cyber-training mission/alert/grading code | KEEP UNCHANGED |
| `/parallax/workspace`, `/parallax/research/*` (run, brief, trial, history, investigation [POST submit], adjudicate, evidence, model/health) | **PARALLAX** | `_parallax_member_cid`; research store | Correctly named - keep |
| `/parallax/strata/investigation` (GET page) | **PARALLAX** (misnamed) | gates on `_parallax_member_cid` | RE-HOME to `/parallax/research/investigations[/<id>]` + redirect |
| `/parallax/strata/trace` (GET page) | **PARALLAX** (misnamed) | gates on `_parallax_member_cid` | RE-HOME to `/parallax/research/traces[/<id>]` + redirect |
| `parallax/strata_trace_view.py` (this session) | **PARALLAX** (misnamed) | research view-model | RENAME -> `parallax/research/research_trace_view.py` |
| `parallax/strata_investigation.py` | **PARALLAX** (legacy filename) | research store bridge | KEEP FILENAME (deferred; documented) |
| `parallax/research/strata_view.py` | **PARALLAX** (legacy filename) | research view-model | KEEP FILENAME (deferred; documented) |
| `templates/parallax_strata_investigation.html`, `templates/parallax_strata_trace.html` | **PARALLAX** (misnamed, "STRATA" in titles) | research pages | RENAME + PARALLAX terminology |
| `store.py`, `measurement.py`, `evidence_verifier.py`, `signing.py`, `agent_trace.py`, `trust_analysis.py`, `investigation_bundle.py` | **PARALLAX** | under `parallax/research/` | Correctly placed - keep |
| `ProgramMembership` (`program` in {strata, parallax}), `_parallax_member_cid`, `require_program`, app shell, auth | **SHARED infrastructure** | per-program entitlement; clear ownership contract | KEEP (reuse) |
| `ParallaxResearchRun` + research store | **PARALLAX** data | research runs/investigations | KEEP |
| `Report` / scenario grading / seeds | **STRATA** data | training submissions/grades | KEEP |

## 2. Identified architectural confusion

The confusion is **naming/presentation only, not authorization or data**:

1. Two PARALLAX research pages were routed under `/parallax/strata/...` and titled "STRATA
   Investigation" / "STRATA Trace Explorer", implying STRATA owns the PARALLAX research investigation
   UX. It does not: STRATA is the cyber-training/SOC program.
2. Internal module and template filenames use the `strata_` prefix for PARALLAX research code.

What is already correct (verified, not assumed):

- **Access control is already separated.** Both misnamed routes gate on `_parallax_member_cid`
  (active PARALLAX membership); a STRATA-only user is already redirected away. STRATA routes gate on
  `@require_program("strata")`. There is no path by which STRATA enrollment grants PARALLAX access or
  vice versa.
- **Data stores are already separate.** PARALLAX research lives in `ParallaxResearchRun` + the research
  store; STRATA training lives in scenario datasets / `Report` / grades. No shared records, no shared
  measurement. `measurement.summarize` consumes research records only; `scenarios.grade` consumes a
  STRATA scenario + submission only.
- No duplicate databases or measurement systems are needed or introduced.

## 3. Dependency assessment for the rename (compatibility)

- Importers of `strata_trace_view` (this session's module): 3, all in-repo (`parallax_routes.py`,
  two test files). Safe to rename -> `parallax/research/research_trace_view.py`.
- Importers of `strata_view` / `strata_investigation` (pre-existing): all in-repo (routes + tests +
  each other). Renaming is mechanically possible but touches pre-existing files that other open PRs
  (e.g. the investigation PR) may also carry; to avoid cross-PR churn and per "do not blindly rename
  modules", the **filenames are kept this pass** and documented as PARALLAX-owned legacy names, to be
  renamed in a dedicated follow-up once the investigation PR lands. Their user-facing surface (routes,
  titles, terminology) is corrected now.
- Templates are referenced only via `render_template(...)` in `parallax_routes.py`; safe to rename and
  re-point.

## 4. Migration approach (safe, versioned)

- Add PARALLAX research routes: `/parallax/research/traces` and `/parallax/research/traces/<run_id>`;
  `/parallax/research/investigations` and `/parallax/research/investigations/<run_id>`. These do not
  collide with the existing `/parallax/research/investigation` (singular, POST submit).
- Keep `/parallax/strata/trace` and `/parallax/strata/investigation` as DEPRECATED aliases that run the
  SAME PARALLAX gate first, then 302-redirect an authorized PARALLAX user to the new URL. An
  unauthenticated or non-PARALLAX user hits the gate first (404 in prod / login / own dashboard) and is
  NEVER redirected into the PARALLAX program. So old URLs cannot bypass the boundary, and no
  unauthorized user is redirected into another program.
- No change to stored records, hashes, signatures, evidence, measurement, or historical investigations:
  the migration is routing + presentation. `trace_hash`, evidence signatures and `confirmed_asr`
  semantics are untouched.

## 5. Signed-evidence / reproducibility preservation

Routing changes do not touch persistence or verification. A run persisted before the change is read by
the new route through the same owner-scoped `store.get_run` and verifies identically (signature +
`evidence_hash`). A regression test persists a signed run and verifies it through the new route.

## 6. Tests added (the eight required separation properties)

1. STRATA-only user cannot access the PARALLAX research routes (redirected).
2. PARALLAX-only user cannot access STRATA (`/me/workspace`, `@require_program("strata")`).
3. Dual-entitled user reaches both programs.
4. No research findings in STRATA training scores (grading path independent of the research store).
5. No training grades in PARALLAX scientific metrics (measurement consumes research records only).
6. Campaign/investigation ownership enforced (cross-owner 404 on the new routes).
7. Signed evidence survives the migration (verifies through the new route).
8. Old `/parallax/strata/*` URLs cannot bypass the corrected boundary (still PARALLAX-gated).
