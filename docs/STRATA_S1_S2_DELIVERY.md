# STRATA S1 + S2 delivery

Branch `feature/strata-readiness-s1-s2`, based on `ef3b345`. Not committed to the F5 PR. No merge, no deploy, no candidate activation, no paid infrastructure, no production migration. STRATA's 95 percent standard is unchanged (`program.PASS_BAR = 95.0`, quoted read-only everywhere). PARALLAX not started. F5 preserved.

Infrastructure note accepted: Ranger already runs live OpenSearch 2.17.1 + Dashboards on Railway (private, per `siem/AS_BUILT.md`), and the Board 2 live SOC chain was validated end to end (`siem/BOARD2_M4_2_VALIDATION.md`). No additional OpenSearch cluster is proposed. The Board 2 mission package references this existing SOC environment; boards 5 and 6 show their GOAD range as unavailable until a real Ludus deployment is approved and validated.

## Changed files

New:
- `siem/tests/test_strata_boards.py` — S1 generator/grader regression tests for boards 1, 3, 4, 5, 6.
- `strata_missions.py` — S2 approved, versioned, candidate-safe mission packages for boards 1-6 + availability API.
- `templates/mission_brief.html` — candidate-facing mission-brief view (reuses the existing design system).
- `siem/tests/test_strata_missions.py` — S2 mission-integrity + integration tests.
- `docs/STRATA_S1_S2_DELIVERY.md` — this report.

Modified:
- `app.py` — `import strata_missions`; `_mission_summary()`; `mission` added to `_me_vm` and `_demo_vm`; new route `GET /me/mission`.
- `templates/candidate_me.html` — a discoverable "Mission brief" link in the active-candidate dashboard.

No existing generator, grader, grading interface, or F5 workbench screen was modified. The Board 2 signed-citation workflow is untouched.

## S1 — assessment verification

New module `test_strata_boards.py`: **17 tests, all passing** (boards 1/3/4 = 4 each, board 5 = 3, board 6 = 1, plus 1 shared dispatch/95-bar regression). Each board verifies deterministic seed reproduction, candidate-visible content excludes hidden truth, a correct solution grades at or above the 95 bar, empty cannot pass, incorrect/unsupported claims are penalized, trivial guessing/padding cannot pass, repeated-attempt assignment rules hold, candidate isolation, and the board-specific competency.

Per-board results:

| Board | Tests | Representative assertions (all passing) |
|---|---|---|
| 1 Sentinel (SOC triage) | 4 | correct triage >= 95; empty < 95; inverted verdicts < 95; blanket-true_positive guessing < 95; wrong technique/severity/IOC strictly lowers score (components measured); another seed's answers do not grade this world |
| 3 Warden (detection eng) | 4 | invariant-tradecraft ruleset >= 95 on the held-out corpus (precision >= 0.9, macro-recall >= 0.9); no rules < 95; match-everything rule < 95 with FPs counted; single-technique rule < 95 (macro-recall floor); holdout/seed never in the public view |
| 4 Reclaimer (IR/forensics) | 4 | correct IR report >= 95; empty < 95; reversed timeline strictly lower (order penalized); wrong patient-zero/scope strictly lower; missing persistence strictly lower; truth never in the public view; another incident's answers do not grade this one |
| 5 Raider (red-team GOAD) | 3 | correct seed-derived flags = 100; empty/guessed = 0; flags per-candidate and non-transferable (A's flags score 0 in B's world); padding with extras cannot reach the bar; fail-closed: broker is mock without `LUDUS_API_URL` |
| 6 Vanguard (capstone) | 1 | distinct capstone objective set; correct flags = 100; board-6 flags carry the `QR6{...}` tag; a board-5 capture never satisfies a board-6 objective (cross-board non-transfer) |

Anti-gaming / negative results (the key ones): blanket-guessing, match-everything detection rules, reversed timelines, wrong scope, guessed flags, and cross-candidate/cross-board flag reuse all score below the 95 bar (flags score exactly 0). Hidden truth (`_key`, `truth`, `_flags`, `_seed`, holdout) is absent from every candidate-visible projection.

Note, as the audit stated: the heavily-tested "F4 forensic" suite is the PARALLAX media engine, not STRATA Board 4. This milestone adds the missing STRATA Board 4 IR coverage directly.

## S2 — candidate documentation

New module `strata_missions.py`: one approved, versioned, candidate-safe mission package per board (v1, `approved: True`), each with the ten required sections, built on one reusable structure with genuinely board-specific content. `test_strata_missions.py`: **8 tests, all passing** (completeness, candidate-safety, explicit versioning/approval, real-signal availability, availability independent of documentation existence, cohort/scenario-reference-readiness, index coverage, and the candidate route).

Documentation index (`strata_missions.mission_index()`):

| Board | Title | Role | Environment | Availability (real signal) |
|---|---|---|---|---|
| 1 | SOC alert triage | SOC Analyst | seeded dataset workspace | available |
| 2 | Enterprise SOC investigation | Threat Hunter | live OpenSearch SOC (private) | available on assignment |
| 3 | Detection engineering | Detection Engineer | seeded dataset workspace | available |
| 4 | Incident response and forensic reconstruction | Incident Responder | seeded dataset workspace | available |
| 5 | Authorized AD red-team assessment | Red Team Operator | isolated GOAD range (WireGuard) | unavailable until Ludus deployed + validated |
| 6 | Capstone: multi-forest AD compromise | Capstone (Vanguard) | isolated multi-forest GOAD range | unavailable until Ludus deployed + validated |

The ten sections per package: business context, assigned role, authorized scope, environment and access, technical objectives, expected deliverables, evidence and integrity, submission and acceptance, evaluation expectations, and troubleshooting/recovery/support. Each includes candidate-safe professional references (MITRE ATT&CK, NIST, Sigma, GOAD, etc.) explicitly marked as background, not solutions.

Candidate-safety: no exploitation commands, no step-by-step solutions, no suggested attack paths, no query strings that locate a hidden incident, no expected answers, no private grading rules, no evaluator truth, no coaching. Verified by `test_packages_are_candidate_safe`. Submission vocabulary the candidate must use (for example the verdict values or the disposition names) is present because it is legitimately candidate-facing; it reveals nothing about which items are malicious.

Integration (no new CMS or LMS): the mission is surfaced on the existing candidate dashboard (`/me`) as a discoverable "Mission brief" card, and rendered in full at `GET /me/mission` for the candidate's own current board only. The F5 workbench screens are unchanged; the Board 2 case workflow is unchanged. Protected keys and evaluator configuration remain server-side.

### Representative mission briefs

Full text is in `strata_missions.py` and renders at `/me/mission`. In brief, per board:

- Board 1 Sentinel: as a Tier 1 SOC analyst at Valyria Financial Group, adjudicate an overnight alert queue (true/false positive, severity, ATT&CK technique on true positives, indicators), from a per-candidate seeded dataset; graded answer-free; environment ready.
- Board 2 Tracker: as a SOC investigator, determine and scope incidents in a live per-candidate OpenSearch index over a defined window; deliver dispositioned incidents with cited, reproducible events; the established signed-citation workflow verifies and preserves evidence; environment provisioned, access on assignment.
- Board 3 Warden: as a detection engineer, author detection rules that generalize to a held-out corpus and stay quiet on legitimate near-misses; graded on macro-recall and precision; environment ready.
- Board 4 Reclaimer: as an incident responder, reconstruct a completed breach from a per-candidate forensic evidence set (patient zero, scope, ordered timeline, persistence); graded against ground truth; environment ready.
- Board 5 Raider: as a red-team operator, run an authorized assessment of your own isolated GOAD range over WireGuard and prove each objective by capturing its cryptographically derived flag; range unavailable until a real deployment is validated.
- Board 6 Vanguard: as the capstone operator, compromise a multi-forest estate across a trust and prove each escalation with its board-specific flag; range unavailable until a real deployment is validated.

Screenshots of the actual candidate documentation view are provided for Board 1 (environment ready) and Board 5 (environment pending) since a template was added.

## Cohort-diversity compatibility (no S3/S4 implemented)

Mission packages are cohort- and scenario-reference-ready and do not block S3/S4:
- Each package carries `scenario_ref` / `scenario_version` (nullable at the board-level base) and `required_evidence_types`, so a future cohort can bind a different approved scenario without changing the template.
- The board-level mission text states the enterprise, role, scope, objectives, and deliverables, and deliberately does not hard-code a single specific incident or vulnerability; the specific incident is supplied by the bound, approved scenario. Verified by `test_cohort_and_scenario_reference_ready` (for example, no literal alert id appears in Board 1's business context).
- The deterministic ScenarioSpec compiler, calibration pipeline, material-diversity controls, and human-approval requirement are untouched. A future Cohort B can receive a different mission binding without altering templates or Cohort A's historical assignments.

## End-to-end demonstration (the ten requested points)

1. Every board's generator and grader has meaningful passing regression tests — S1, 17 tests.
2. Each candidate-facing board has a detailed mission package — S2, six packages, 8 tests.
3. Documentation and scenario versions are bound correctly — packages are versioned and carry scenario-reference fields; `is_approved`/`get(board, version)` enforce approval.
4. Candidates cannot access hidden evaluator content — public views and mission packages carry no truth/keys; `test_packages_are_candidate_safe` and the board truth-safety tests pass.
5. An authorized candidate can locate and understand their board's mission — `/me` shows the brief link; `/me/mission` renders the full package for the candidate's own board only.
6. Board 2's citation-verification path remains intact — unchanged; `test_strata_board2_compat` and `test_case_routes` still pass.
7. Boards 5-6 cannot imply a live range exists when the broker is mock — `environment_availability` returns unavailable; the brief shows a "not yet available" banner; `test_availability_independent_of_documentation_existence` proves it flips only on a real live signal.
8. The 95 percent standard is unchanged — `program.PASS_BAR == 95.0`, asserted in both new test modules.
9. No PARALLAX qualification activated — untouched.
10. No candidate-access flags changed in production — no flag defaults changed; no deployment.

## Test results

- Full offline suite: **75 passed, 5 skipped** (was 50 passed before this milestone; +25 are the new S1/S2 tests). The 5 skips are the PostgreSQL fail-closed tests with no authorized server. pyflakes clean on all changed files.
- The live OpenSearch and Ludus/GOAD paths are not exercised here (S2 is documentation and offline assessment coverage); Board 2's live path remains validated per the existing M4.2 report, and the GOAD range remains undeployed by design.

## Unresolved gaps / honest limitations

- Boards 5 and 6 remain non-operational: the mission packages are complete, but no live GOAD range exists (the broker is mock by default). Declaring them operational requires a real, isolated, validated Ludus deployment (a later, cost-gated milestone).
- The mission packages are board-level v1. Per-cohort materially distinct scenario bindings are S3/S4; the reference fields are in place but no second cohort spec is authored yet.
- Board 1's mission reuses the existing `strata-soc-triage` workbench scenario reference; boards 2-6 have no workbench scenario binding yet (the mission packages stand alone until S3/S4 bind approved scenarios).
- Public evaluation criteria in the missions state the 95 bar and the review boundary without a published rubric, by design (a candidate-safety choice).

## S3 / S4 dependency notes

- S3 (Board 2 cohort catalog) can proceed now: bind two approved, materially distinct family portfolios to Board 2 mission packages via `scenario_ref`/`scenario_version`, using the existing `enterprise.generate(families=...)` + pipeline + human approval. The mission template already supports the binding.
- S4 (material variation for boards 1, 3, 4) requires giving those generators a cohort/spec dimension (currently seed-only); the mission packages will bind the resulting approved scenarios without template changes.
- Boards 5/6 cohort variation and operational status depend on the live GOAD milestone.

Stop for S1/S2 acceptance.
