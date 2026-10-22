# PARALLAX Research UI - Ranger Shell Integration Map

## Root cause of the visual disconnect

The investigation and trace templates extended `base.html` but did NOT adopt the candidate
application shell. `base.html` only emits `<head>` (loads `static/app.css`) and `{% block body %}`;
it does not provide the sidebar or layout. The live candidate pages compose the shell themselves:

```
{% extends "base.html" %}
{% from "_candnav.html" import candnav %}
{% block body %}
<div class="shell">                         <- purple radial-gradient backdrop, 26px pad
  <div class="app app-2col">                <- grid: 238px sidebar + 1fr main
    {{ candnav('<active>', vm) }}           <- persistent dark sidebar (Qwalora Ranger brand, program nav)
    <section class="ranges-main">           <- white, scrollable main canvas
      ... page content using shared classes ...
    </section>
  </div>
</div>
{% endblock %}
```

My pages instead rendered a centered `.si-wrap` / `.tx-wrap` with a private inline `<style>` system
(si-/tx- classes), so they had no sidebar, no purple shell, and a conflicting visual language. That is
the disconnect - not colors/headings, but the missing shell and non-reuse of components.

## Existing Ranger components reused (from static/app.css + _candnav.html)

- Shell/layout: `.shell`, `.app.app-2col`, `.ranges-main`, responsive collapse (<=900px -> 1 col).
- Sidebar: `candnav(active, vm)` macro (brand, program group, program switcher for dual, active states).
- Header: `.rg-head`, `.eyebrow` (orange uppercase label), `.ttl`, `.rg-sub`, `.muted`, `.mono`.
- Cards/surfaces: `.rcard` (icon-tile card), `.progcard`, `.msg`, `.note`/`.rg-note`, `.meta`, `.crumb`.
- Controls: `.btn`, `.btn-ghost`, `.btn-sm`, `.input`, `.seg`/`.seg-i` (tabs/segmented).
- Pills/badges: `.pill`, `.pill-orange`, `.pill-violet`.
- Color tokens: `--ink #160d42` (text), `--orange #f96702` (research accent), `--line/--line2`
  (borders), `--sub/--light` (surfaces), `--med/--mut/--dim` (muted text).
- Master-detail precedent: `board1_incident.html` uses `.list` + detail panels; the trace explorer
  mirrors that pattern inside `.ranges-main`.

## Nav view model

The sidebar needs the candidate's program fields. Factor the workspace route's inline builder into
`_parallax_nav_fields(c)` (name, handle, ini, status, board, programs, selected_program='parallax',
program_brands, is_dual) and pass it to the investigation and trace templates so `candnav(...)` renders
identically to the Research Console, with "Investigations" active.

## Changes

- `parallax_routes.py`: add `_parallax_nav_fields(c)`; use it in the workspace, investigation and trace
  routes; add `?event=<seq>` selection + `?return=` context to the trace route.
- `_candnav.html`: add a "Trace explorer" entry is NOT added (Trace is reached from an investigation/
  campaign, keeping the sidebar lean); "Investigations" stays the research-analysis entry and both the
  investigation and trace pages highlight it.
- `templates/parallax_research_investigation.html`: rebuild on the shell; campaign selector, timeline,
  verification and measurement rendered with Ranger cards/pills; link to the trace explorer and back to
  the console/history, preserving selected campaign.
- `templates/parallax_research_trace.html`: rebuild on the shell as a master-detail investigation
  interface (event list + selected-event detail), campaign selector, trace overview, trust-zone
  classification, evidence excerpt + provenance, candidate findings, authorization status, review
  status, evidence verification, investigation summary; server-side event selection (no-JS baseline),
  safe escaping, bounded content.
- Research workflow links: Research Console -> investigation -> trace -> back to campaign/history.

## Boundaries preserved

STRATA (app.py routes, `@require_program("strata")`, Board-1, grading, datasets) untouched. PARALLAX
entitlement, campaign ownership, signed evidence, measurement semantics, frozen evaluator, and
legacy-route protections unchanged. No deploy, no merge; staging artifact untouched.
