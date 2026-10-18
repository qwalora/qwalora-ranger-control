# STRATA S3 + S4 delivery - cohort-aware scenario diversity, randomized assignment, verified grading

Branch `feature/strata-s3-s4-cohort-diversity`, based on accepted commit `b66ae35`. No merge, deploy, candidate activation, production flag change, live migration, or paid infrastructure. The 95 percent objective standard is unchanged (`program.PASS_BAR = 95.0`, quoted read-only). PARALLAX not started. The portfolio integration ships behind a default-off flag (`RANGER_STRATA_PORTFOLIOS`).

## A. Branch and commit
Branch `feature/strata-s3-s4-cohort-diversity`; commit SHA in the final line of this delivery (see the handoff message). Based on `b66ae35`.

## B. Changed files and implementation summary

New:
- `siem/board_variants.py` - the structural variant library: multiple genuinely different variants per board (1-4), each selecting the actual technical content (technique pools, incident families, kill chains, benign look-alikes), with competencies, difficulty intent, diversity axes and candidate-safe business context.
- `strata_catalog.py` - governance: build a ScenarioSpec per variant, schema-validate, board-aware executable simulation (generate + grade a reference-correct submission + reproduce + no-leak), analytic calibration, material-diversity, and REAL authenticated admin approval into `ScenarioCatalogEntry`.
- `strata_assignment.py` - runtime: CSPRNG cohort-portfolio -> candidate binding, durable + version-pinned (`ScenarioBinding`), idempotent + concurrency-safe, no-repeat + family cooldown + explicit exhaustion, and generation/grading against the pinned variant.
- `siem/tests/test_strata_s3_s4.py` - the two-cohort acceptance suite (10 tests).
- `docs/STRATA_S3_S4_DELIVERY.md` - this report.

Modified (backward-compatible; default behavior unchanged):
- `scenarios.py` - `generate_board1/3/4` accept an optional `variant`; expanded the Board 3 technique catalog (14 techniques) with matching benign near-misses; Board 4 kill chain made declarative. `variant=None` reproduces the original scenarios exactly.
- `siem/scenario_spec.py` - added typed payload validators `soc-triage`, `detection-engineering`, `ir-forensics` (S4) alongside `soc-investigation` (S3).
- `siem/scenario_pipeline.py` - strengthened material-diversity: a scenario must differ from every prior on at least `MIN_DIVERGENT_AXES` (2) material axes; added a generic `axis_divergence` / `axes_materially_diverse`.
- `siem/capability_inventory.py` - added the `soc-dataset` environment inventory for boards 1/3/4.
- `models.py` - added `ScenarioBinding` (durable, version-pinned assignment). Additive table (release gate for production, below).
- `strata_missions.py` - `for_binding()` makes the S2 mission scenario-aware (cohort, scenario version, variant context) without revealing the hidden family.
- `app.py` - behind `RANGER_STRATA_PORTFOLIOS` (default off): `/labs/dataset` and `/grade/submit` serve and grade boards 1/3/4 against the candidate's bound approved variant; `/me/mission` renders the scenario-aware mission. Board 2 qualification is untouched (its signed-citation `/case` workflow).

## C. Scenario portfolio inventory (boards 1-4)

Three validated structural variants per board (12 total), each approved into the catalog in the acceptance run:

| Board | Variant | Difficulty | Competencies |
|---|---|---|---|
| 1 Sentinel | b1-credential-access | standard | verdict, severity, technique attribution, IOC extraction |
| 1 | b1-execution-persistence | standard | (same competency set) |
| 1 | b1-lateral-exfil | standard | (same competency set) |
| 2 Tracker | b2-identity-takeover | advanced | incident scoping, evidence citation, timeline, detection gap |
| 2 | b2-insider-exfil | advanced | (same) |
| 2 | b2-stealth-lateral | advanced | (same) |
| 3 Warden | b3-execution-c2 | standard | coverage, precision, generalization |
| 3 | b3-credential-identity | standard | (same) |
| 3 | b3-evasion-impact | standard | (same) |
| 4 Reclaimer | b4-phish-rdp-schtask | advanced | patient zero, initial access, scope, timeline, persistence |
| 4 | b4-webshell-service | advanced | (same) |
| 4 | b4-vpn-registry | advanced | (same) |

Meaningful diversity dimensions: Board 1 - attack theme, technique pool, false-positive look-alike pattern. Board 2 - adversary objective, incident families, detection gaps, security boundary. Board 3 - detection domain, technique set to detect. Board 4 - initial access, kill-chain structure, lateral pattern, persistence mechanism. Difficulty is calibrated from the generated world (Board 2 analytically from the family portfolio), not from a self-declared label. Within each board the variants share one competency set (parity). Family compatibility / exclusions: Board 2 families are composed per the enterprise profile incident count (3 at profile B); `detection-failure` is the only genuine-gap family. Reuse cooldown: a person will not receive the same family within their most recent binding (`FAMILY_COOLDOWN`). Authoring a new variant: add it to `board_variants.VARIANTS`, `strata_catalog.register`, then an authenticated admin `approve`s it. Exhaustion: when no eligible non-repeat variant remains, assignment raises `AssignmentExhausted` (never a silent generic scenario). This is a finite pool (3/board now); it is not claimed to serve unlimited cohorts.

## D. Two-cohort diversity matrix (real generated technical content)

Two cohorts with different approved portfolios (overlapping on one variant, differing on another). The distinguishing variants differ on 2-3 material axes, with genuinely different generated content:

| Board | Cohort A distinguishing variant | Cohort B distinguishing variant | Axes differ | Real content difference |
|---|---|---|---|---|
| 1 | b1-credential-access | b1-lateral-exfil | 3 | A techniques T1078/T1110.001/T1110.003/T1558.003 vs B T1021.001/T1021.002/T1048/T1074.001 |
| 2 | b2-identity-takeover | b2-stealth-lateral | 3 | A families privileged-identity / endpoint-lateral / data-exfiltration vs B compromised-service / endpoint-lateral / privileged-identity |
| 3 | b3-execution-c2 | b3-evasion-impact | 2 | A detect T1059.001/T1105/T1047/T1053.005/T1071.001/T1048.003 vs B T1562.001/T1490/T1105/T1003.002/T1053.005/T1047 |
| 4 | b4-phish-rdp-schtask | b4-webshell-service / b4-vpn-registry | 3 | A initial access T1566.001, scheduled-task persistence vs B T1190 webshell/service persistence or T1078 VPN/registry persistence; different kill chains |

These are not renamed hosts or rotated seeds: the generators emit different techniques, families, kill chains and benign look-alikes. Demonstrated in `test_cohort_portfolios_are_structurally_different_and_parity`.

## E. Generated sample + protected-truth comparison
Protected truth (the hidden answer key / incident family / ground-truth event ids) is never emitted to a candidate surface and is not reproduced in this document. The acceptance suite verifies the candidate-facing projection carries none of `_key`, `truth`, `_flags`, `_seed`, `_techniques`, `_variant` (test_assignment_generation_and_grading_dataset_boards, point 9), while the server-side scenario (used only for grading) carries the key. Cross-variant content differences are shown structurally in section D from the diversity axes, which are derived from the generated world, not from labels.

## F. Candidate assignment and replay behavior
- Assignment: CSPRNG selection among approved eligible variants restricted to the cohort portfolio; durable binding storing spec_id, spec_version, content_hash, variant, family, and a CSPRNG seed.
- Idempotent + concurrency-safe: 6 concurrent `assign` calls for one (candidate, board, attempt) produce exactly one binding (test_concurrent_assignment_is_idempotent).
- No-repeat + rotation: a returning candidate gets a different variant each attempt; grading stays correct after rotation and the prior attempt's answers do not clear the rotated case (test_grading_correct_after_rotation).
- Replay reproducibility: regenerating from the pinned (variant, seed) reproduces the identical world and truth (point 7).
- Exhaustion is explicit (test_catalog_exhaustion_is_explicit_no_silent_generic); a failed/empty selection creates no binding (test_rollback_on_empty_pool_creates_no_binding).

## G. Tests (grading, isolation, randomness, immutability, anti-gaming)
`siem/tests/test_strata_s3_s4.py` - 10 tests, all passing, covering the 15 required demonstrations:
1-2 different + structural cohort portfolios; 3 equivalent competencies; 4 difficulty parity; 5 independent per-candidate binding; 6+14 cross-variant/cohort non-transfer and isolation; 7 exact replay reproduces truth; 8 unauthorized/revoked rejected; 9 no evaluator truth in candidate views; 10 correct authorized submission grades at/above 95; 11 empty/guessed cannot reach 95; 12 grading correct after rotation; 13 historical binding pins version + content hash; 15 Board 2 signed-citation cannot be bypassed (the generic grader refuses board 2; foreign-index citations are not reference-valid). Plus concurrency, exhaustion, rollback, and unauthorized-catalog-change tests. Full offline suite: 90 passed, 5 skipped (was 80; +10). pyflakes clean.

## H. Screenshots
None required: the S2 mission UI is unchanged; `strata_missions.for_binding` overlays scenario-aware fields through the same accepted interface. No S2 design work was reopened.

## I. Known limitations and deployment blockers
- Finite pool: 3 variants/board. Rotation and selection are demonstrated; unlimited cross-cohort diversity is not claimed. New variants require authoring + real admin approval.
- `ScenarioBinding` is an additive table created by `create_all` offline; a production deployment needs a one-off migration to add it. Not applied here (release gate).
- Board 2 live integration: the portfolio engine binds and generates the enterprise world and grading goes through the established signed-citation `/case` workflow, but wiring the bound variant into the live per-candidate OpenSearch index ingestion via `/soc` is NOT done in this milestone; it is a release gate (requires ingesting the bound variant's telemetry into the candidate's operational index). The flag-gated `/labs` integration covers boards 1/3/4 only.
- Board 4 variant RNG differs from the pre-S4 default namespace, so a variant-driven board-4 scenario is a new world (intended); the `variant=None` default is unchanged and all S1 board-4 tests still pass.

## J. Executable offline vs verified against real infrastructure
- Executable + verified offline (this milestone): variant generation and grading for boards 1-4; catalog governance (validate/simulate/calibrate/material-diversity/real-admin-approval); CSPRNG assignment (idempotency, no-repeat, cooldown, exhaustion, version-pin, reproducibility); the `/labs/dataset` + `/grade/submit` candidate route for boards 1/3/4 behind the flag; Board 2 citation-verification non-bypass via the in-memory reader.
- NOT verified against live infrastructure here: live OpenSearch per-candidate ingestion of a bound Board 2 variant; the live `/soc` gateway serving a bound variant; any Ludus/GOAD path (boards 5/6, out of scope). A successful offline simulation is not live candidate validation.

## K. Next readiness requirements for boards 5-6
Boards 5/6 are unchanged and remain non-operational (no live GOAD range; the broker is mock by default). Before they can be cohort-diversified and operated: a real, isolated, validated Ludus/GOAD deployment; per-cohort objective/attack-path variants for the flag model; an end-to-end provisioning + flag-capture test; and the same approval governance applied to range variants. These are separate, cost-gated milestones.

Stop for engineering acceptance.
