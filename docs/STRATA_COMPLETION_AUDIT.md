# QWALORA RANGER - STRATA Completion Audit and Cohort Readiness

Status: gap audit for review. No code changed, nothing merged, deployed, activated, or provisioned. F5 preserved at `ab579ca`. PARALLAX not started.

This audit is deliberately conservative. Existing generator functions, passing unit tests, mock provisioning, and written architecture are NOT treated as a candidate-ready lab. Each claim below is grounded in a source reference or an actual test run.

---

## 1. Headline verdict

STRATA is a strong, well-architected platform with one board that is close to candidate-ready and five that are not. The qualification scaffolding (95 percent bar, admission gate, isolation design, evidence and assessment contracts, the scenario-approval pipeline) is sound and should be preserved. The gaps are real assessment content, real environments for boards 5 and 6, cohort-level scenario variation, test coverage, and per-board candidate documentation.

Two-line summary:
- Board 2 (SOC case) is substantially complete: real generator, calibrated grader, evidence contract, and a working material-diversity engine, all exercised offline.
- Boards 1, 3, 4, 5, 6 are code-present but unverified: their generators and graders have zero tests, they have no cohort dimension, and boards 5 and 6 have no live environment (the Ludus broker is mock by default).

---

## 2. Method and evidence basis

- Code read directly: `scenarios.py`, `program.py`, `siem/scenario_spec.py`, `siem/scenario_pipeline.py`, `siem/enterprise.py`, `siem/calibration.py`, `siem/case_contract.py`, `broker.py`, plus targeted reads of `app.py`, `soc_gateway.py`, `siem/live.py`, `workbench_scenarios.py`, `workbench_core.py`.
- Offline test suite actually run: `50 passed, 5 skipped` (the 5 skips are the PostgreSQL fail-closed tests with no authorized server). Exit 0, no failures.
- Cohort-variation claims demonstrated with generated evidence (section 6), not asserted.
- Three structured sweeps of the codebase (candidate environment and live infra; test evidence per board; candidate documentation) corroborated the reads above.

What this audit does NOT claim: no live OpenSearch run, no live GOAD range deploy, no PostgreSQL concurrency run in this pass. Those are called out as untested where relevant.

---

## 3. STRATA completion matrix

Classification per cell: `impl` = implemented in code; `off` = tested offline; `live` = tested against live infra; `prod` = production-ready (verified candidate-usable); `none` = not implemented.

| Dimension | B1 SOC triage | B2 SOC case / hunt | B3 detection eng | B4 IR / forensics | B5 red-team GOAD | B6 capstone GOAD |
|---|---|---|---|---|---|---|
| Scenario generator | impl | impl + off | impl | impl | impl | impl |
| Grader | impl | impl + off (calibrated) | impl | impl | impl | impl |
| Candidate environment | live (static dataset) | static live; real SIEM dark | live (static dataset) | live (static dataset) | mock only | mock only |
| Realism of environment | medium | high when live; medium static | medium-high | medium | high blueprint, none running | high blueprint, none running |
| Live infra dependency | none | OpenSearch + JWT (unset) | none | none | Ludus/Proxmox (unset) | Ludus/Proxmox (unset) |
| Authorization and isolation | seed only | DLS per-candidate index when live | seed only | seed only | per-range WireGuard when live | per-range WireGuard when live |
| Evidence and verification | in-proc key scoring | signed citation contract (off) | in-proc holdout scoring | in-proc truth scoring | seed-derived flags | seed-derived flags |
| Cohort-specific variation | none | engine exists (families), not populated | none | none | none | none |
| Candidate-specific variation | seed (surface) | seed + per-candidate entities | seed (surface) | seed (surface) | seed (flags only) | seed (flags only) |
| Generator/grader test evidence | none | off (extensive) | none | none | none | none |
| Candidate documentation | thin | substantial | reference only | reference only | reference only | none |
| Production blocker | tests, variation, docs | live cluster + live test + cohort catalog | tests, variation, docs | tests, variation, docs | live range + tests + variation + docs | live range + tests + variation + docs (nothing yet) |

Accept vs implement, in one line per board:
- B1: accept the generator/grader design; implement tests, cohort variation, and operational docs.
- B2: accept broadly; implement live-cluster validation, a live-path test, and an approved per-cohort spec catalog.
- B3: accept the holdout-graded design; implement tests, cohort variation, and docs.
- B4: accept the IR truth-scoring design; implement tests, cohort variation, and docs.
- B5: accept the flag model and blueprints; implement a live validated range, tests, variation, and a mission brief. Not candidate-ready.
- B6: same as B5, plus all documentation from zero. Least ready.

---

## 4. Per-board detail

### Board 1 - SOC triage (Sentinel)
- Generator/grader: `scenarios.generate_board1` / `score_board1` (scenarios.py:57-155). Pure function of seed; 12-16 alerts, TP/FP mix drawn from a fixed pool of six techniques (`_TP_TECHNIQUES`). Grades verdict, severity, technique, IOC overlap against a stripped key.
- Environment: live static lab. `_provision_for_board` marks boards 1-4 `tier="shared"` and `status="deployed"` instantly with no VM (app.py around 787-811). Served via `/labs/dataset` -> `scenarios.dataset(1, seed)`, graded via `/grade/submit`.
- Variation: seed only. No cohort input. The technique pool and theme are fixed.
- Docs: `strata-soc-triage` v1 exists in `workbench_scenarios.py`, but it is generic (one "Authorized investigation surface" interface), and the richer case template is Board-2-specific.
- Test evidence: none. No test calls `generate_board1`/`score_board1`.
- Remaining work: unit tests for the generator/grader; a cohort-variation mechanism; operational per-board documentation; a non-generic environment/access section.

### Board 2 - SOC case / threat hunting (Tracker)
- Three implementations, to be distinguished:
  1. Static hunt dataset: `generate_board2`/`score_board2` (scenarios.py:226-323). F1 over the malicious set; a fixed 10-step kill chain, each seed taking a prefix `_B2_CHAIN[:tp_count]`.
  2. Enterprise SOC world: `siem/enterprise.generate` (enterprise.py) produces ECS-normalized telemetry across many data sources with a hidden truth model; the candidate logs into a real per-candidate OpenSearch index via the `/soc` gateway (soc_gateway.py) and works the case through `/case` (case_routes.py), which verifies every cited event against the candidate's own index (`case_contract.verify_evidence`).
  3. Shadow grader: `enterprise_grader.score_board2_enterprise`, calibrated against archetypes and anti-gaming probes (calibration.py), shadow-only, not wired to qualification.
- Environment: the static path is live. The real SIEM is fully implemented but dark by default. `/soc` is registered only when `RANGER_JWT_PRIVATE_B64` and `OPENSEARCH_ADMIN_PASSWORD` are set; `_default_reader_factory` hard-requires `OPENSEARCH_ADMIN_PASSWORD` (case_routes.py around 88). Defaults point at `opensearch.railway.internal` / `dashboards.railway.internal`, which resolve only if those services run.
- Isolation when live: per-candidate internal user and per-candidate role with document-level security on `ranger.candidate_id`; a private per-subject Dashboards tenant forced at the proxy; `/soc` requires status active and `current_board == 2`.
- Variation: this is the one board with a real material-diversity engine (section 6). Not yet populated with an approved per-cohort catalog.
- Docs: substantial. `case_contract.candidate_brief` gives a deterministic, truth-free brief; `case_overview.html` / `case_workspace.html` cover objectives, deliverables, and evidence structure.
- Test evidence: extensive, all offline on a fake OpenSearch reader. `test_enterprise.py`, `test_enterprise_grader.py`, `test_case_contract.py`, `test_case_routes.py`, `test_calibration.py`, `test_shadow_regression.py`, `test_strata_board2_compat.py`. The live OpenSearch path is NOT tested.
- Remaining work: stand up and validate a real OpenSearch cluster (paid infra, out of scope here, requires approval); add an automated live-path test (even against a local single node); build and approve a cohort spec catalog of distinct family portfolios.

### Board 3 - detection engineering (Warden)
- Generator/grader: `generate_board3`/`score_board3` (scenarios.py:448-532) with the `detect.py` rule engine. Candidate authors detection rules; grading compiles the ruleset and runs it against a seeded holdout corpus computed in-process, scoring macro-recall times precision. The holdout never leaves the server. This is a genuinely good answer-free design.
- Environment: live static lab; rule execution is pure Python.
- Variation: seed only. The eight techniques (`_B3_TECHNIQUES`) are fixed for every seed; only surface tokens vary.
- Docs: reference material only; no operational case doc. A candidate reaching this board in the workbench gets "instructions not available."
- Test evidence: none.
- Remaining work: tests for the generator, the holdout, and `detect.compile_ruleset`; cohort variation (different technique sets and decoy strategies per cohort); operational documentation.

### Board 4 - IR and forensics (Reclaimer)
- Generator/grader: `generate_board4`/`score_board4` (scenarios.py:563-715). Seed-derived ordered kill chain plus benign noise; grades patient zero, initial-access vector, affected hosts and accounts (set F1), timeline membership and order, and persistence.
- Do not conflate: the heavily-tested "F4" forensic modules (`siem/forensic_ops.py`, `forensic_jobs*.py`, `forensic_sandbox.py`, and their tests) are the PARALLAX media-forensics engine, a different pathway. STRATA Board 4's IR generator/grader has zero tests.
- Environment: live static lab. The forensic sandbox/workbench is a separate subsystem, flag-gated off, and fails closed (synthetic fixtures only, no container runtime on the host).
- Variation: seed only. Three initial-access vectors (`_B4_VECTORS`); the rest of the chain is a fixed template.
- Docs: reference material only; no operational case doc.
- Test evidence: none for the STRATA IR board.
- Remaining work: tests for `generate_board4`/`score_board4`; cohort variation (materially different incident progressions); operational documentation.

### Board 5 - red team on GOAD (Raider)
- Generator/grader: `generate_board5`/`score_board5` with the flag model (`flags_for_board`, scenarios.py:762-839). Objectives are a fixed nine-step GOAD attack path; the flag value is a seed-derived SHA-256 token, unique per ranger and useless to share. `/labs/start` reserves a slot and calls the Ludus broker; `/grade/submit` compares captured flags to the seed-derived expected set.
- Blueprints and control plane are real: `ludus/goad-range.yml` (sevenkingdoms.local plus north child), the `qwalora_flags` Ansible role that plants per-seed flags, slot reservation with `MAX_CONCURRENT`, queueing, and reclamation.
- Environment: mock by default. `broker.is_live()` is true only when `LUDUS_API_URL` is set (broker.py around 45-64). In mock mode `deploy_range`, `range_status`, and `wireguard_config` return deterministic simulated results, including a WireGuard profile literally stamped "MOCK ... no live range yet." No live range exists without a Ludus/Proxmox host and credentials.
- Variation: none. The objective set is byte-identical across seeds (demonstrated in section 6); only flag values and a few target names vary.
- Docs: reference/study material is tagged to this board, but there is no operational mission brief.
- Test evidence: none. There is zero automated test of GOAD/Ludus provisioning, flag planting, or the board 5 generator/grader.
- Remaining work: a real, isolated, technically validated range on standing infra (paid, out of scope, requires approval); an end-to-end provisioning and flag-capture test; cohort variation (different attack paths or objective sets per cohort); a candidate mission brief. Not candidate-ready.

### Board 6 - Vanguard capstone (full-forest GOAD)
- Generator/grader: `generate_board6`/`score_board6` with ten escalating objectives (recon, child DA, trust abuse, parent EA, forest persistence, cross-forest, crown jewels). Same flag model as board 5. Blueprint `ludus/capstone-range.yml` adds the essos.local forest and a trust.
- Environment: mock by default, same broker. No live range.
- Variation: none.
- Docs: none at all. No operational scenario and zero reference resources tagged to board 6; it appears only in narrative prose.
- Test evidence: none.
- Remaining work: everything board 5 needs, plus documentation from zero. Least ready of the six.

---

## 5. Integrity preservation (confirmed intact)

- Six-board progression preserved: `program.BOARD_PLAN` defines boards 1-6 with roles, badges, and tiers.
- 95 percent objective bar preserved and unchanged: `program.PASS_BAR = 95.0` (program.py:15), enforced at app.py:1140, 1344, 1397 (`score >= P.PASS_BAR`). `assessment_contract` and `enterprise_grader` only reference it read-only.
- Subjective review preserved: reviewer feedback and shadow grading exist without overwriting signed records (case_routes.py admin routes).
- GitHub OAuth and selective admission preserved: enrollment and OAuth create candidates subject to an admin approval gate; nothing is provisioned before approval.
- Cohort and candidate isolation preserved: per-candidate seeds never reused across (github_id, board, cohort); Board 2 live isolation via document-level security.
- Established Board 2 signed-citation workflow preserved and now protected: F5.1 added a guard so a generic workbench receipt cannot finalize a STRATA Board 2 case (`test_strata_board2_compat.py`).
- F1-F5 assessment and evidence contracts preserved: evidence persistence, custody, blob lifecycle, and receipts all pass offline.
- No candidate self-grading and no protected truth in the browser: graders re-derive the key server-side; `candidate_verification` runs in a candidate-safe mode that never consults truth; the ScenarioSpec separates `evaluator_only` from candidate-visible layers.
- No scenario self-approval or self-grading: `scenario_pipeline.promote` requires a named human approver and a passing simulation; an LLM cannot approve its own scenario or set its own difficulty.

Boards 5 and 6 remain non-operational until real, isolated, technically validated environments exist. This audit does not declare them operational.

---

## 6. Cohort variation assessment (demonstrated)

Requirement: cohorts must differ in actual technical content (attacker objectives, incident progressions, authorization conditions, detection gaps, evidence, decisions, remediation), not only in seeds, usernames, timestamps, IPs, hashes, tokens, flags, or document names.

Current reality, demonstrated by generated evidence:

Board 2 has a real material-diversity engine, and it works:
- `enterprise.generate(candidate_id, board, seed, profile, families=...)` accepts an explicit, ordered list of incident families from five distinct families, each with a different objective, technique chain, and (for `detection-failure`) a genuine detector gap.
- Two cohorts given different approved family portfolios receive materially different worlds. Verified: cohort A `[privileged-identity-compromise, data-exfiltration, detection-failure]` versus cohort B `[compromised-service-identity, endpoint-lateral-movement, data-exfiltration]` produce different family sets and largely different technique sets (small expected overlap on common techniques like T1078).
- Two candidates in one cohort (same families, different seed) receive the same family structure but different entities (different victims, actor IPs, hosts, timestamps), so cases are unique and non-shareable within a cohort.
- The ScenarioSpec pipeline enforces that this is material, not superficial: `scenario_pipeline.is_materially_diverse` compares objective, families, systems, detection gaps, and decoys, and deliberately excludes identifiers and timestamps; `promote` blocks a spec whose axes duplicate an existing one (`NOT_MATERIALLY_DIVERSE`), blocks promotion without a human approver (`NO_APPROVER`), and blocks a self-declared difficulty that the simulation does not support (`DIFFICULTY_MISMATCH`). These are tested in `test_scenario_catalog.py` and pass.

Boards 1, 3, 4, 5, 6 have no cohort dimension at all:
- All `generate_boardN` signatures take only `(seed)`. There is no cohort parameter and no spec-driven composition.
- Technique and objective pools are fixed: Board 3 uses all eight `_B3_TECHNIQUES` every seed; Board 5's objective ids are byte-identical across seeds (verified: identical ordered id list for different seeds). Board 2's static path takes a fixed prefix of one kill chain.
- These boards are not connected to `enterprise.generate`, the ScenarioSpec, or the approval pipeline, so material cohort variation cannot be produced for them today.

Conclusion: the variation ENGINE and the human-approval, no-self-approve, no-superficial-variation controls are built and tested, but they cover Board 2's world only, and no approved per-cohort catalog has been authored yet. Realizing cohort variation across all six boards requires either extending the family-composition approach to the other board types or driving each board's generator from the ScenarioSpec.

Preserved as required: the deterministic ScenarioSpec compiler and the human approval pipeline are intact and should remain the single path to catalog eligibility. Secure random assignment, version pinning, no-repeat, and family cooldowns are partially present (seed no-repeat per candidate exists; version pinning exists in `workbench_scenarios`; family cooldown and a cohort-level no-repeat policy are not yet implemented) and are itemized in the closure plan.

---

## 7. Documentation assessment

- Framework: production-ready. Operational instructions are sourced only from approved, versioned, candidate-safe metadata (`workbench_scenarios.py`, `case_contract.candidate_brief`), with fail-closed "instructions not available" fallbacks and no leakage of truth, answer keys, exploit sequences, or coaching. The reference library (`catalog.py`, `catalog_kb.py`) is review-gated, with original and KB content inserted as draft and only reviewer-published content shown.
- Content: roughly two of six boards populated. Board 1 thin, Board 2 substantial, Boards 3/4/5 reference material only (no operational case docs), Board 6 nothing (no scenario, zero tagged resources).
- Systemic gaps across boards: operational support and recovery guidance is absent everywhere; public evaluation criteria are intentionally limited to boundaries rather than a published rubric (a safety choice to preserve, but worth stating explicitly to candidates).
- `workbench_scenarios.py` currently defines three approved scenarios (two PARALLAX, one STRATA Board 1). There is no approved workbench scenario for STRATA boards 2-6, so the candidate-safe metadata contract is not yet populated for most of STRATA.

---

## 8. Prioritized closure plan (milestone-based)

The ordering favors finishing real assessments and candidate documentation over expanding generic platform architecture. No milestone below provisions paid infrastructure, activates candidates, modifies the 95 percent bar, or begins PARALLAX; the two that touch live infra are explicitly gated on separate cost approval.

S1. Test the five untested boards (no infra, highest value per effort).
- Add generator and grader tests for boards 1, 3, 4, 5, 6 mirroring the Board 2 offline pattern: determinism/reproducibility, key-never-in-public-view, score monotonicity (empty submission -> 0, ground-truth submission -> 100), and board-specific properties (B3 holdout generalization vs overfit; B4 timeline order; B5/B6 flag derivation and non-transfer across boards/seeds).
- Exit: every board's generator and grader is exercised offline and passes.

S2. Author and approve candidate documentation for boards 1-4 (no infra).
- Populate `workbench_scenarios.py` with approved, versioned STRATA scenarios for boards 1-4 covering the ten required sections (section 9), each through the human approval path.
- Make the operational case template board-parametric rather than Board-2-hardcoded.
- Exit: a candidate on boards 1-4 sees complete, candidate-safe operational documentation; nothing leaks truth.

S3. Build the cohort-variation catalog for Board 2 (no infra).
- Author at least two approved cohort specs with materially distinct family portfolios; expand the family library beyond five so many cohorts are feasible; add a cohort-level no-repeat and family-cooldown policy and version pinning on assignment.
- Exit: the two-cohort acceptance test (section 10) passes for Board 2.

S4. Extend material cohort variation to boards 1, 3, 4 (no infra).
- Give each board a cohort dimension driven by the ScenarioSpec (different technique sets, decoy strategies, incident progressions, and detection gaps per cohort), reusing the pipeline's material-diversity and approval gates. Keep the generators deterministic.
- Exit: the acceptance test generalizes to boards 1, 3, 4.

S5. Board 2 live-cluster validation (gated on cost approval).
- Stand up a real OpenSearch plus Dashboards (a local single node is enough for validation), wire `/soc` and `/case` to it, and add an automated live-path test (ingest a per-candidate index, verify DLS isolation, verify citation reproduction end to end).
- Exit: the Board 2 live SIEM is validated, not just implemented.

S6. Boards 5 and 6 real range validation (gated on cost approval and a standing Ludus host).
- Deploy one real GOAD range and one capstone range, validate flag planting end to end, add a provisioning and flag-capture test, and author the board 5 and 6 mission briefs and the (currently empty) board 6 documentation. Add cohort variation (different attack paths or objective sets per cohort).
- Exit: boards 5 and 6 have real, isolated, technically validated environments and can be declared operational.

Dependency note: S1-S4 are free and unblock most of the readiness story. S5 and S6 are the only paid items and are where "declared operational" for the live boards is earned.

---

## 9. Proposed candidate-facing mission brief and documentation structure (per board)

Every section below is generated or selected from approved, versioned, candidate-safe metadata. None contains step-by-step commands, solutions, attack paths, answer keys, hidden truth, or coaching.

Common structure (all boards), the ten required sections:
1. Mission and business context: the fictional organization, the situation, why it matters.
2. Authorized scope: systems, data, and actions the candidate is authorized to touch, and the boundary.
3. Environment and access instructions: how to reach the investigation surface (dataset download, SIEM login, or range WireGuard) and how to re-establish access.
4. System and interface references: the tools and interfaces available and what each is for.
5. Investigation objectives: what to establish, as outcomes, not steps.
6. Expected technical deliverables: the exact artifacts to submit and their format.
7. Evidence and chain-of-custody requirements: what counts as acceptable evidence, how it is preserved, and that submission is immutable and signed.
8. Submission and report structure: the fields and sections of the submission.
9. Public evaluation criteria: the stated objective bar (95 percent) and the review boundary, framed as criteria, without a leaking rubric.
10. Operational support and recovery guidance: what to do if the environment is unavailable, how to resume, and support contacts.

Board-specific shape:
- B1 SOC triage: brief frames a shift of alerts to adjudicate; deliverable is per-alert verdict, severity, technique, IOCs; environment is the seeded alert dataset.
- B2 SOC case: brief frames a suspected incident in the enterprise; deliverable is dispositioned incidents with cited, reproducible evidence; environment is the per-candidate SIEM index.
- B3 detection engineering: brief frames a detection-gap closure task; deliverable is a detection ruleset; environment is the labeled sample set plus benign baseline; criteria emphasize generalization and precision.
- B4 IR and forensics: brief frames a post-breach investigation; deliverable is an IR report (patient zero, scope, timeline, persistence); environment is the forensic evidence set.
- B5 red-team GOAD: brief frames an authorized engagement with objectives and rules of engagement; deliverable is captured flags proving each objective; environment is the candidate's isolated range over WireGuard.
- B6 capstone: brief frames a full-forest engagement across a trust; deliverable is captured flags across the escalation chain; environment is the multi-forest range.

---

## 10. Two-cohort acceptance test

Purpose: prove that two cohorts receive materially different worlds while covering comparable competencies, that two candidates in one cohort receive unique non-shareable cases, and that everything is reproducible and isolated. Runnable today for Board 2; blocked for the other boards until S4 and S6.

Board 2 acceptance test (executable now):
1. Author two approved cohort specs, A and B, with disjoint-enough family portfolios chosen for comparable difficulty (calibrated to the same band). Both must pass `scenario_pipeline.promote` with a named human approver.
2. Material difference: `is_materially_diverse(specB, [specA])` returns material; the generated truths for A and B differ in families and techniques (not only identifiers). Assert the family sets differ and the technique sets differ beyond common-technique overlap.
3. Comparable competency: both specs calibrate to the same difficulty band, and both cover the core competencies (detection, correlation, evidence citation). Assert equal band and a minimum technique-count floor on each.
4. Within-cohort uniqueness: for two candidates in cohort A (same families, different seed), assert different primary identities, actor IPs, and event content, so neither candidate's answers transfer.
5. Isolation: assert each candidate's events carry only their own `candidate_id`, and (when live, S5) that document-level security blocks cross-candidate reads.
6. Reproducibility: regenerating either candidate's world from the same seed yields identical event ids and identical truth.
7. Integrity: the grader puts a ground-truth submission at or above 95 for each cohort and keeps guessing and padding below the bar (reuse the calibration probes).

Steps 1-4, 6, 7 run offline today against `enterprise.generate` and the pipeline; step 5's live half is gated on S5. The same test structure applies to boards 1, 3, 4 after S4 and to boards 5, 6 after S6, substituting each board's material axes (technique sets and decoys for B3, incident progressions for B4, attack paths or objective sets for B5/B6).

---

## 11. Constraints honored

No merge to `main`, no deployment, no candidate activation, no paid infrastructure provisioned, no external security services purchased, no paid inference enabled. The 95 percent qualification standard is unchanged. PARALLAX Lab A has not begun. F5 is preserved at `ab579ca`. This document is an audit for review and changed no platform code.

Recommended next step: approve S1 and S2 (free: tests for the five untested boards, and candidate documentation for boards 1-4), which move the most boards toward readiness without any infrastructure spend, and decide separately on S5/S6 cost approval for the live boards.
