# QWALORA PARALLAX - Researcher Experience: Design Completion & UX Acceptance Report

Mandate: QWALORA RANGER PARALLAX - Final Product Design, UX Engineering & Acceptance.
Scope: complete (not redesign) the existing PARALLAX researcher interface to design-complete
quality and perform real acceptance testing with reproducible evidence.

- Branch: `feature/parallax-design-completion`
- Base: `integration/parallax-research-platform` @ `2dd429e42fb949737bed075e81e493983e122c6f`
- Protected branches (`acf50ec`, `parallax-nonprod`, production), historical evidence, and
  signing keys were not modified. No merge to a protected branch and no deployment were performed.
- Infrastructure spend: $0. No GPUs, no new Railway services/volumes/endpoints/databases, no
  paid subscriptions. All verification ran on local resources (a local Flask process, a local
  Chromium, SQLite, and npm/pip packages).

## Determination

**QWALORA PARALLAX - RESEARCHER EXPERIENCE: DESIGN COMPLETE / UX ACCEPTANCE PASSED**

This designation is used because the evidence below supports it: the automated accessibility
audit actually ran against the rendered application and reports 0 violations (0 critical, 0
serious, 0 moderate) across 4 surfaces x 2 viewports; the 10-step researcher journey executed
end to end with every step passing against the real backend; the full relevant regression suite
executed with 25/25 passing; and 16 full-page screenshots were captured across all four required
viewports with 0 capture errors. Remaining dependencies (Section I) are operational
prerequisites for a production research *finding* and for live sign-in/deployment; they are not
design-acceptance gaps, and each is labeled as blocked or not-tested rather than passed.

---

## A. Design inventory

The researcher experience is a Flask + Jinja server-rendered application sharing one app-shell
(`.shell` / `.app.app-2col` / `.nav` / `.ranges-main`) with the admin and STRATA surfaces. The
design system lives in `static/app.css` and the shared chrome macros in `templates/_candnav.html`,
`templates/_icons.html`, `templates/_brand.html`.

Identity preserved: restrained violet/indigo (`--vio`, `--indigo`) with a single orange accent
(`--orange`), Geist Sans / Geist Mono typography, token-driven spacing and radii. No new gradient
system, no decorative shadow stack, no animation framework was introduced; the completion work
was corrective (contrast, landmarks, headings) rather than cosmetic.

Design-system surface in use by the researcher experience:

- Typography: `--f` (Geist Sans), `--m` (Geist Mono); weight/line-height set per component.
- Color tokens: `--ink`, `--navy`, `--med`, `--mut`, `--dim` (text ramp); `--vio`, `--indigo`,
  `--orange` (brand); `--ok`/`--amber` + `-bg`/`-dot` (status).
- Components exercised: `.card` / `.card-head` / `.card-body`, `.eyebrow`, `.pill` family
  (`pill-ok`, `pill-amber`, `pill-orange`), `.dot` indicators, `.record` / `.rec-row` / `.rec-id`,
  `.btn` family (`btn-outline`, `btn-sm`), form controls (`select`, `textarea`, `input`),
  verification banners (`.vb-ok`, `.vb-warn`), evidence items (`.pxe-item`, `.pxe-kind-*`).
- States: empty (console "Run a trial to see the genuine model output…"), loading/liveness
  (synchronous "Check liveness"), error (not-found 404, model-backend failure surfaced), and
  the honest-provenance caveats.

Changes made in this mandate are confined to 6 existing files and are all additive-or-corrective
(12 insertions, 12 deletions total):

| File | Change | Purpose |
|---|---|---|
| `static/app.css` | darkened `--mut`, `--dim`, `--amber`, `.eyebrow`, `.vb-ok`, `.vb-warn` colors | WCAG AA contrast |
| `templates/_candnav.html` | `<aside class="nav">` -> `<nav class="nav" aria-label="Primary">` | named navigation landmark |
| `templates/parallax_evidence.html` | `role="main"` on `.ranges-main`; `.pxe-kind-investigation` color | main landmark + contrast |
| `templates/parallax_workspace.html` | `role="main"` on `.ranges-main` | main landmark |
| `templates/candidate_me.html` | `role="main"` + `<h1 class="sr-only">` | main landmark + page heading |
| `templates/candidate_account.html` | `role="main"` + `<h1 class="sr-only">` | main landmark + page heading |

---

## B. Implemented screens

All four required researcher surfaces are complete and server-rendered from authorized data only.

1. **Command Center** (`/me?program=parallax`) - assignment brief, lab-access cards, and a
   Research Activity panel whose stats (signed records, trials, investigations, awaiting review)
   are computed from the researcher's own signed records. No fabricated telemetry or findings;
   the "real model / measured / inconclusive / simulated" counts are derived from the stored
   provenance classification, and an explicit note states that real-model runs here use a model
   not approved as validated, so they are infrastructure-backed measurements, not validated
   findings.
2. **Research Console** (`/parallax/workspace`) - the existing experiment workflow (legitimate
   task, attacker-controlled document, benign-control vs adversarial-trial, submit investigation)
   is preserved. The model-response panel shows an honest empty state ("Output appears only after
   a real model call; nothing is fabricated"); the model-version badge is synchronous
   (`stub/rule-v1 · in-process · simulated`, "Check liveness"); "Save progress stores your setup
   only - it never runs a trial." No fake job progress, no asynchronous progress fiction.
3. **Evidence & Publications** (`/parallax/research/evidence`) - owner-scoped signed records with
   the corrected 4-level taxonomy (Execution / Infrastructure-backed / Measurement / Finding
   status). Inconclusive runs are labeled "proof-of-concept - NOT a validated AI-security
   finding" and never presented as validated. A verified signature is shown as integrity/custody,
   never as proof of scientific validity. Drafts remain unpublished unless authorized. Per-record
   export is owner-scoped JSON.
4. **Program Access** (`/account`) - one GitHub identity; authentication (GitHub OAuth; verified
   email, 2FA, account age at sign-in) is separated from program authorization. PARALLAX and
   STRATA are shown as independently authorized (PARALLAX active, STRATA not enrolled in the
   fixture). Fixtures are labeled as fixtures (GitHub id `nonprod-fixture:parallax-review-selftest`,
   account name "NONPROD ACCEPTANCE / SIMULATED"). Requesting a program does not grant it.

---

## C. Visual verification screenshots

16 full-page screenshots, 4 surfaces x 4 viewports (390 / 768 / 1280 / 1440 px), captured by the
acceptance harness against the rendered app. Committed under
`docs/research/acceptance_screenshots/`:

```
accept-command-center-{mobile390,tablet768,desktop1280,large1440}.png
accept-console-{mobile390,tablet768,desktop1280,large1440}.png
accept-evidence-{mobile390,tablet768,desktop1280,large1440}.png
accept-account-{mobile390,tablet768,desktop1280,large1440}.png
```

Capture errors: 0. Responsive behavior verified at each breakpoint: at 390/768 the sidebar
collapses to a wrapped top navigation row; stat tiles reflow (4-up -> 2-up); evidence records,
badges, and record ids wrap without overflow; identity and program-access cards remain readable.
No important information is hidden without an accessible alternative; the navigation is a named
`<nav aria-label="Primary">` landmark at every width.

---

## D. Accessibility results (genuine automated audit)

Tool: **axe-core 4.10.2**, loaded via `page.add_script_tag` and executed with
`axe.run(document, {runOnly:{type:'tag', values:['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa','best-practice']}})`
against the **rendered** application in a real Chromium, at desktop (1280) and mobile (390), on
all four surfaces. This audit actually ran; results are machine-recorded in
`scripts/research/acceptance/acceptance_results.json`.

Result: **0 violations total** - 0 critical, 0 serious, 0 moderate - across all 8 surface/viewport
audits.

```
command-center@desktop1280: []    command-center@mobile390: []
console@desktop1280:        []    console@mobile390:        []
evidence@desktop1280:       []    account@mobile390:        []
account@desktop1280:        []    evidence@mobile390:       []
axe_total_violations: 0 ; axe_critical_serious: 0
```

Fixes applied to reach zero (all critical/serious found by the tool were resolved):

- **color-contrast (serious):** darkened muted/dim text and status colors to clear WCAG AA 4.5:1
  on their actual backgrounds - `--mut` #565b68 (6.79:1 on white), `--dim` #666c7a (5.26:1),
  `.eyebrow`/`.pxe-kind-investigation` #b4500a (5.13:1 on white; 4.52:1 on orange-50),
  `--amber` pill text #8a4b00 (6.02:1 on amber-bg), `.vb-ok` #0f7a48 (4.96:1), `.vb-warn` #8a5a00
  (5.26:1).
- **landmark/region + aria-allowed-role (serious):** replaced a non-semantic `<aside>` nav
  wrapper with a native `<nav aria-label="Primary">`, and marked each page's primary content
  region `role="main"`, giving every surface exactly one named navigation and one main landmark.
- **page-has-heading-one (moderate/best-practice):** added a page-level `<h1>` (visually hidden
  where the visual design already carries the title) on the dashboard and account surfaces.

Remaining moderate issues: none. The audit reports zero at every level, so there are no
documented moderate exceptions to carry forward.

---

## E. Functional acceptance (10-step researcher journey)

Playwright-driven Chromium against the real backend, local fixtures, owner-scoped session cookie
minted via Flask's own `SecureCookieSessionInterface` (no fake OAuth claim; the session is a
genuine signed Flask session for the fixture researcher). All 10 steps passed; recorded in
`acceptance_results.json`:

| # | Step | Result |
|---|---|---|
| 1 | Open Command Center | PASS |
| 2 | Open Research Console | PASS |
| 3 | Inspect trial list (Evidence) | PASS |
| 4 | Open signed evidence detail | PASS |
| 5 | Verify provenance + metadata (Execution / Evidence / Measurement / Finding status) | PASS |
| 6 | Export authorized JSON | PASS - `status=200`, `Content-Disposition: attachment` |
| 7 | Return to workspace | PASS |
| 8 | Account + program authorization | PASS |
| 9 | Not-found / unavailable state | PASS - `status=404` |
| 10 | Keyboard focus reaches a named control | PASS - `{tag:A, text:"Dashboard", outline:auto}` |

---

## F. Security / regression negative tests

New suite `tests/test_security_acceptance.py` (4 tests), complementing the existing authorization
and provenance coverage in `tests/test_parallax_ui.py` and `tests/test_research_execution.py`:

- `test_csrf_required_on_trial_post` - POST `/parallax/research/trial` without `X-CSRF-Token` is
  rejected (400); with a valid token it is not a CSRF rejection (proving the guard is real, not
  blanket-blocking).
- `test_malformed_record_id_export_is_404` - malformed/traversal/SQLi-like record ids
  (`run-%2e%2e%2f`, `run-'; DROP TABLE x;--`) return 404, never an error or existence leak.
- `test_invalid_signature_is_not_infrastructure_backed` - a real-model record whose stored
  signature is tampered reports `signature_verifies=False`, `infrastructure_backed=False`,
  `is_empirical_finding=False` (a broken signature can never be presented as validated evidence).
- `test_model_backend_failure_is_surfaced_not_faked` - a dead model endpoint yields
  `observed_behavior=None`, `infra_error` containing `model_backend_error`, and an
  `infrastructure_failure`/`evaluation_error` outcome; no fabricated model output.

Existing coverage already exercised and re-run here: unauthenticated access, unauthorized PARALLAX
access, cross-program (STRATA-only denied evidence page/export/history), cross-owner export 404,
reviewer-only adjudication (researcher cannot adjudicate), owner-can-export-own, and the
provenance/host-authorization/isolation checks in `test_research_execution.py`.

---

## G. Regression (exact commands and actual results)

Command (from repository root, local UI venv active):

```sh
python -m pytest tests/test_parallax_ui.py tests/test_research_execution.py \
    tests/test_security_acceptance.py -q
```

Actual result:

```
25 passed, 14 warnings in 0.33s
```

Per-file: `test_parallax_ui.py` 14, `test_research_execution.py` 7, `test_security_acceptance.py` 4
(= 25). The 14 warnings are SQLAlchemy `LegacyAPIWarning` deprecations (`Query.get()`), not test
failures.

Acceptance harness command (axe + screenshots + journey, one reproducible run):

```sh
AXE_CORE_JS=node_modules/axe-core/axe.min.js \
PLAYWRIGHT_CHROMIUM=/opt/pw-browsers/chromium-1194/chrome-linux/chrome \
python scripts/research/acceptance/acceptance.py "$PWD/scratchpad-accept"
```

Actual result: `screenshots: 16 | errors: 0`, `axe total violations: 0 | critical/serious: 0`,
journey 10/10 PASS, process exit code 0. The harness exits non-zero on any axe critical/serious
violation, failed journey step, or capture error, so a green exit is a real gate.

---

## H. Release artifact

- Branch: `feature/parallax-design-completion`
- Base: `2dd429e42fb949737bed075e81e493983e122c6f` (`integration/parallax-research-platform`)
- Changed existing files (6): `static/app.css`, `templates/_candnav.html`,
  `templates/parallax_evidence.html`, `templates/parallax_workspace.html`,
  `templates/candidate_me.html`, `templates/candidate_account.html` (12 insertions, 12 deletions).
- New files: `tests/test_security_acceptance.py`; `scripts/research/acceptance/`
  (`acceptance.py`, `README.md`, `acceptance_results.json`);
  `docs/research/acceptance_screenshots/` (16 PNGs); this report.
- Integration instructions: open a PR from `feature/parallax-design-completion` into
  `integration/parallax-research-platform`. The change is corrective CSS/templates plus
  test/evidence artifacts; it introduces no schema change, no new route, and no runtime
  dependency. CI gate: the pytest command in Section G plus the acceptance harness (both must
  exit 0). Do not merge to a protected branch or deploy without separate authorization (none is
  claimed here).

---

## I. Remaining dependencies (explicitly not claimed as passed)

These are operational prerequisites, documented honestly, and are out of scope for design
acceptance:

1. **Capable validated model - BLOCKED (environment egress).** HuggingFace/model hosts are
   policy-blocked (HTTP 403) from this environment, so a capable model (e.g. Qwen2.5-0.5B-Instruct)
   could not be fetched. Real-model runs therefore use a non-validated local model and are
   correctly presented as infrastructure-backed proof-of-concept, never as validated empirical
   findings. Promoting a run to a finding requires a validated model enabled via
   `RANGER_RESEARCH_VALIDATED_MODELS`; that is a deployment/data prerequisite, not a UI gap.
2. **Live GitHub OAuth - NOT TESTED (by design).** Acceptance used a genuine signed Flask session
   for a labeled fixture researcher rather than a live OAuth round-trip. No false OAuth success is
   claimed anywhere. End-to-end live sign-in requires real GitHub OAuth credentials and a
   reachable callback host.
3. **Deployment - NOT PERFORMED.** No Railway service, domain, or deploy was created or modified;
   $0 infrastructure. Production rollout (and any paid SIEM/GOAD work in the separate platform
   plan) remains gated on explicit authorization.

---

Evidence files: `scripts/research/acceptance/acceptance_results.json`,
`scripts/research/acceptance/acceptance.py`, `scripts/research/acceptance/README.md`,
`docs/research/acceptance_screenshots/` (16 PNGs), `tests/test_security_acceptance.py`.
