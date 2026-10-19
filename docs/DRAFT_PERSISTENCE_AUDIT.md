# Draft-persistence audit (work-loss risk)

Date: 2026-10-19. Scope: the confirmed STRATA Board-1 SOC triage defect is fixed (see below);
this audit records the equivalent work-loss risk on the other candidate input surfaces, per
task section C. It does not redesign those surfaces; it documents findings and the ready-to-reuse
shared infrastructure.

## Shared infrastructure now in place

`drafts.py` + the `workspace_drafts` table are a program-agnostic, secure autosave service:
scope = (candidate, program, board, kind, case_key, dataset_version); optimistic concurrency via a
version-guarded conditional UPDATE; per-kind payload validators; CSRF + rate-limit + ownership
enforced at the route. It couples no program data (payload is opaque per kind) and never grades.
Extending it to another surface is a localized addition (a `kind`, a validator, a load/save route,
and UI wiring), not a redesign.

## Findings

| # | Surface | Current behavior | Work-loss risk | Final-submission model |
|---|---|---|---|---|
| 1 | **STRATA Board-1 SOC triage** (`board1_workspace.html`) | **FIXED** — server-side autosave via `drafts.py` (kind `board1_triage`); restores verdict/severity/technique/IOC across navigation, refresh, new session | Resolved | `/me/workspace/submit` (graded, explicit) — unchanged |
| 2 | **STRATA incident investigation** (`board1_incident.html`) | **FIXED** — server-side autosave via `drafts.py` (kind `board1_incident`); restores incidents, alert assignments, entry/technique-chain/hosts/accounts/evidence across navigation, refresh, new session. Submit now requires ≥1 incident with ≥1 assigned alert (server + client). | Resolved | `/me/workspace/incident/submit` (signed, **non-gating** `IncidentAssessment`) — unchanged |
| 3 | **STRATA written report** (`candidate_me.html` textarea → `/me/report`) | **FIXED** — server-side autosave via `drafts.py` (kind `strata_report`); restores the report text across navigation, refresh, new session. Save progress separate from Submit; draft cleared on successful submit; empty submit still rejected (existing policy). | Resolved | `/me/report` (human review channel) — unchanged |
| 4 | **PARALLAX experiment workspace** (`parallax_workspace.html` `#task`+`#attack`) | **FIXED** — server-side autosave via `drafts.py` (kind `parallax_experiment`); restores selected task + attacker document across navigation, refresh, logout/login, new session | Resolved | `/parallax/research/trial` (explicit model-backed run; nonprod) — unchanged |
| 5 | **PARALLAX investigation analysis** (`parallax_workspace.html` `#ev-id`+`#analysis`) | **FIXED** — server-side autosave via `drafts.py` (kind `parallax_investigation`); restores evidence-run reference + written analysis across navigation, refresh, logout/login, new session; restore never reruns a trial | Resolved | `/parallax/research/investigation` (explicit signed submission; nonprod) — unchanged |

All five share the same root cause: candidate inputs live only in browser memory and are discarded
on any full-page navigation, refresh, or session change.

## Recommendation (no broad redesign)

Roll the existing shared infra out in risk order, each as an independent, reviewable change that
preserves final-submission semantics and program isolation:

1. **Incident investigation** (HIGH, same board): **DONE** — kind `board1_incident`, validated
   incidents/assignments/detail payload, draft folded into `/me/workspace/incident/data`, and
   `POST /me/workspace/incident/draft`, STRATA-scoped like the triage draft. Submit completeness
   enforced server-side and client-side.
2. **Written report** (HIGH): **DONE** — kind `strata_report`, autosave of the textarea, draft
   superseded on submit; the explicit `/me/report` POST stays the submit and enforces the existing
   non-empty policy.
3. **PARALLAX experiment + analysis** (MEDIUM): **DONE** — kinds `parallax_experiment` and
   `parallax_investigation` scoped to `program="parallax"`. Because `drafts.py` keys on program,
   STRATA and PARALLAX drafts can never collide or leak across programs. Routes:
   `POST /parallax/research/experiment/draft`, `POST /parallax/research/investigation/draft`, and
   `GET /parallax/research/draft` (restore). Authorization is PARALLAX-only: nonprod gate + active
   authenticated session + active PARALLAX membership (`_parallax_member_cid`, no STRATA fallback).
   The draft scope folds the research PROTOCOL identity (protocol + harness + prompt-template +
   corpus version/hash) into the `case_key`, so a draft composed under one protocol can never
   silently reattach to an incompatible one. The handlers call only `drafts.save`/`drafts.load` —
   never `model_backend.from_config`, `harness.run_trial`, `store.persist_run`, the trial
   rate-limiter, or any signing path — so a draft save can never run a model, consume trial quota,
   submit, sign evidence, or change qualification. The immutable Ed25519-signed `ParallaxResearchRun`
   records are untouched.

Each addition is bounded (one kind + one validator + one route + UI wiring + tests), uses the same
security envelope (CSRF, rate limit, ownership, optimistic concurrency, no grading), and does not
touch grading, the 95% standard, signatures, entitlements, or final-submission behavior.

Status: all five surfaces — Board-1 triage (1), incident investigation (2), written report (3),
and the PARALLAX experiment (4) and investigation-analysis (5) workspaces — are fixed on the shared
infrastructure. (1)–(3) have passed human-authenticated nonproduction acceptance; (4)–(5) have
local PostgreSQL-backed tests and deployed-route verification pending the operator's live
acceptance run.
