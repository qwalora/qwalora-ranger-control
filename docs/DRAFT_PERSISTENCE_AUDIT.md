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
| 2 | **STRATA incident investigation** (`board1_incident.html`) | State is client-only JS: `alerts[], assign{}, incidents[], selKey`, plus per-incident entry/technique-chain/hosts/accounts/evidence fields. No persistence of any kind. | **HIGH** — same board, same navigation pattern; building an incident and navigating away loses it | `/me/workspace/incident/submit` (signed, **non-gating** `IncidentAssessment`) |
| 3 | **STRATA written report** (`candidate_me.html` textarea → `/me/report`) | Plain `<textarea>` submitted by form POST; no autosave | **HIGH** — a long written analysis typed and then navigated away is lost | `/me/report` (human review channel) |
| 4 | **PARALLAX experiment workspace** (`parallax_workspace.html` `#attack`) | Attacker-document `<textarea>`; no autosave | **MEDIUM** — a composed adversarial document is lost on navigation | `/parallax/research/run` (model-backed run; nonprod) |
| 5 | **PARALLAX investigation analysis** (`parallax_workspace.html` `#analysis`) | Analysis `<textarea>` + evidence-id input; no autosave | **MEDIUM** — a written trust-boundary analysis is lost on navigation | `/parallax/laba/assessment` (dry-run; no credit) |

All five share the same root cause: candidate inputs live only in browser memory and are discarded
on any full-page navigation, refresh, or session change.

## Recommendation (no broad redesign)

Roll the existing shared infra out in risk order, each as an independent, reviewable change that
preserves final-submission semantics and program isolation:

1. **Incident investigation** (HIGH, same board): add kind `board1_incident`, validate the
   incidents/assignments/detail payload, fold the draft into `/me/workspace/incident/data` and add
   `POST /me/workspace/incident/draft`. STRATA-scoped exactly like the triage draft.
2. **Written report** (HIGH): add kind `strata_report` scoped to (candidate, board); autosave the
   textarea; the draft is never the submission (the explicit `/me/report` POST stays the submit).
3. **PARALLAX experiment + analysis** (MEDIUM): add kinds `parallax_experiment` /
   `parallax_analysis` scoped to `program="parallax"`. Because `drafts.py` keys on program, STRATA
   and PARALLAX drafts can never collide or leak across programs.

Each addition is bounded (one kind + one validator + one route + UI wiring + tests), uses the same
security envelope (CSRF, rate limit, ownership, optimistic concurrency, no grading), and does not
touch grading, the 95% standard, signatures, entitlements, or final-submission behavior.

Status: findings documented; the confirmed Board-1 triage defect is fixed and verified. Surfaces
2–5 are tracked here as the prioritized follow-up, not implemented in this change, to keep the
confirmed-defect fix focused and reviewable.
