# PARALLAX researcher-experience acceptance harness

This directory holds the reproducible acceptance harness used for the PARALLAX design-completion
mandate. It runs the real Flask app and a real Chromium against the rendered researcher surfaces.
Nothing in it is mocked: the axe-core audit runs against the live DOM, the screenshots are
full-page captures of the served pages, and every journey assertion reads back a rendered DOM
fragment or a real HTTP response.

## What it does

1. Seeds a throwaway SQLite DB with the `px-review-selftest` fixture researcher plus three
   additional signed real-model trial records (owner-scoped, Ed25519-signed, via the real
   `parallax.research.store.persist_run`).
2. Serves the real app in a daemon thread (same process, so the server cannot die between steps).
3. Captures 16 full-page screenshots: 4 surfaces (Command Center, Research Console, Evidence &
   Publications, Program Access) x 4 viewports (390 / 768 / 1280 / 1440 px).
4. Runs an axe-core WCAG 2.2 AA audit (`wcag2a, wcag2aa, wcag21a, wcag21aa, wcag22aa,
   best-practice`) on every surface at desktop (1280) and mobile (390).
5. Executes the 10-step researcher journey (command center -> console -> evidence detail ->
   provenance + metadata verification -> authorized JSON export (200 + attachment) -> back to
   workspace -> account/program authorization -> not-found (404) -> keyboard focus reaches a
   named control).

The process exits non-zero if any axe critical/serious violation, any failed journey step, or
any capture error is recorded, so it can gate CI.

## Prerequisites

- The local UI venv with Flask, Playwright, and the app's runtime deps.
- axe-core: `npm i axe-core` (or point `AXE_CORE_JS` at an existing `axe.min.js`).
- A Chromium for Playwright: `playwright install chromium`, or set `PLAYWRIGHT_CHROMIUM` to an
  existing Chromium binary.

## Run

From the repository root:

```sh
AXE_CORE_JS=node_modules/axe-core/axe.min.js \
PLAYWRIGHT_CHROMIUM=/opt/pw-browsers/chromium-1194/chrome-linux/chrome \
python scripts/research/acceptance/acceptance.py "$PWD/scratchpad-accept"
```

`AXE_CORE_JS` defaults to `./node_modules/axe-core/axe.min.js` and `PLAYWRIGHT_CHROMIUM`
defaults to Playwright's bundled Chromium, so both env vars can be omitted once those are
installed in the standard locations.

Outputs land in the output directory: `accept-<surface>-<viewport>.png` (16 files) and
`acceptance_results.json`.

## Last recorded run

`acceptance_results.json` in this directory is the committed result of the accepted run:

- `axe_total_violations: 0` (0 critical, 0 serious, 0 moderate across all 8 surface/viewport audits)
- 10 / 10 journey steps `ok: true` (export `status=200`, not-found `status=404`, keyboard focus
  reaches a named control with a visible focus outline)
- 16 / 16 screenshots captured, `errors: []`

The 16 screenshots from that run are committed under `docs/research/acceptance_screenshots/`.

## Security / regression tests (run separately with pytest)

```sh
python -m pytest tests/test_parallax_ui.py tests/test_research_execution.py \
    tests/test_security_acceptance.py -q
```
