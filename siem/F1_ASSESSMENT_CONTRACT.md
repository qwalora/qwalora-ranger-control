# F1 — Pathway-Aware Assessment Contract (implemented; for review)

Scope: **F1 only.** F2–F5 and Lab A/Lab B are not started. One Ranger qualification platform
with pathway-specific policies — not a second grading engine. STRATA grading unchanged
(`program.PASS_BAR = 95.0`, `scenarios.score_board2`, `BoardResult`, Ed25519 signing). Gates held:
no candidate access, paid inference, unattended ingestion, new GPU, Ludus/GOAD, or production
grading change.

## Interfaces & models delivered

- `pathways.py` — stable ids `strata`/`parallax`, legacy normalization, display-only branding
  (unchanged this step; the contract and migration build on it).
- `siem/assessment_contract.py` — the common contract:
  - `validate_blueprint`, `blueprint_hash` (immutable, content-hashed, versioned).
  - `decide(blueprint, *, authorization, objective_results, critical_findings, rubric_scores,
    reviewer_decision, scenario_version)` → one auditable, deterministic, **no-AI** decision.
  - `sign_decision` / `verify_decision` (immutable signed record) and `append_adjudication`
    (append-only reviewer adjudication that references the prior record by hash, never mutating it).
  - `SUPPORTED_BLUEPRINT_VERSIONS`, policies `strata_objective_bar` and `parallax_portfolio`.
- `siem/evaluator.py` — least-privilege evaluator contract:
  - `EvaluatorScope` (one index + one `ProtectedTruthHandle`), `reject_candidate_truth`,
    `signed_check` / `verify_result_integrity`.
  - `EventReferenceEvaluator` (implemented, wraps `case_contract.verify_evidence`); `EVALUATORS`
    registry with declared-but-gated future checks (`agent_authorization`,
    `tool_execution_boundary`, `rag_data_isolation`, `model_artifact_integrity`,
    `media_provenance`) that raise until their lab milestones build them.
- `models.py` — additive tables (created by `create_all`; no existing table changed):
  `AssessmentBlueprint` (versioned, hashed, pathway-aware) and `UnitResult` (signed,
  pathway-scoped qualification record; append-only adjudication chain via `parent_record_hash`).
  STRATA keeps writing `BoardResult` unchanged.

## The ten separated concerns → where each lives

| # | Concern | Mechanism |
|---|---|---|
| 1 | Program pathway | `blueprint.pathway` (stable id) |
| 2 | Versioned assessment blueprint | `blueprint_version` + `blueprint_hash`; `SUPPORTED_BLUEPRINT_VERSIONS` |
| 3 | Candidate authorization | `decide(authorization=...)`; must match the blueprint's pathway |
| 4 | Scenario/environment version | `environment_version` + `scenario_version` binding (mismatch fails) |
| 5 | Evidence requirements | `evidence_requirements[]`, each satisfied by a trustworthy passing check |
| 6 | Objective technical checks | `objective_checks[]` verified by evaluators (verified + integrity-checked) |
| 7 | Critical failure conditions | `critical_failures[]` → **VETO** (cannot be outvoted) |
| 8 | Human-review criteria | `reviewer_decision` (authorized reviewer, decision=pass) |
| 9 | Qualification decision policy | `decision_policy` (STRATA bar unchanged; PARALLAX threshold gated) |
| 10 | Signed evidence + decision records | `sign_decision`/`verify_decision`; append-only `append_adjudication` |

## Mandatory outcome gate (critical-failure veto)

An unremediated required critical failure forces `qualified=False` (`reason=CRITICAL_FAILURE_VETO`)
**regardless** of a perfect rubric or a reviewer pass. Example (worked, in the test): a candidate
with a strong agent/RAG investigation report but an unremediated critical authorization
vulnerability does **not** qualify; once remediated, the same case qualifies and is signed.
The PARALLAX pass threshold is **not activated** (`decision_policy.activated=false`,
`rubric_threshold=None`) — PARALLAX never returns `qualified=True` until a threshold is separately
approved.

## Production migration — detection-only boot + authorized versioned migration

Assessment of the prior boot-time write: writing on every startup is a repeatable, uncontrolled
mutation of production records. Replaced with:

- **Boot = detection-only** (`detect_legacy_pathways`, `startup_pathway_check`): counts legacy
  values, logs a warning, performs **no writes**.
- **Authorized versioned migration** (`normalize_persisted_pathways`): runs only under explicit
  authorization (`RANGER_PATHWAY_MIGRATE=1`, or `python migrate_pathways.py --apply`). One
  transaction per table with rollback on error (all-or-none, no partial writes), idempotent,
  value-only (non-destructive), genuine rows untouched.

**Validated on real PostgreSQL 16** (not just SQLite): `siem/tests/test_pathway_migration_pg.py`
(9/9) covers read-only detection, detection-only startup (no writes), transaction atomicity +
rollback on injected mid-migration failure, idempotency, authorized startup migration, and
startup-failure handling (never crash-loops). Run it with a Postgres `DATABASE_URL`:

```
initdb/pg_ctl a local cluster (as the postgres user), createdb ranger_test, then:
DATABASE_URL="postgresql+psycopg2://postgres@/ranger_test?host=<socketdir>" \
  python siem/tests/test_pathway_migration_pg.py
```
It SKIPs automatically when `DATABASE_URL` is not Postgres, so the offline suite is unaffected.

## Authorization & signing invariants

- A decision requires a candidate authorization whose pathway equals the blueprint's; a STRATA
  token cannot qualify a PARALLAX unit (and vice versa).
- Only evaluator-signed, integrity-verified objective results count; a tampered result (even a
  flipped `passed`) fails `verify_result_integrity` and is ignored.
- Candidates never supply authoritative truth or self-certify (`reject_candidate_truth`); truth is
  resolved server-side through `ProtectedTruthHandle`. Evaluators see only their scoped index/truth.
- Signed decision records are immutable (any mutation breaks `verify_decision`); reviewer
  adjudications are appended as new signed records referencing the parent hash.
- Decision records disclose no hidden truth; decisions are deterministic (identical inputs →
  identical signed record hash + signature) and carry `ai_involved=False`.
- STRATA objective bar (`PASS_BAR=95.0`) and `score_board2` are untouched; the contract represents
  STRATA's policy, it does not recompute or change it.

## Test evidence

- `siem/tests/test_assessment_contract.py` — 27 checks: STRATA unchanged; cross-pathway authz;
  unsupported blueprint version; critical-failure veto + remediation; alternate valid solutions;
  missing/contradictory evidence; tampered results; immutable/append-only records + unauthorized
  reviewer refusal; protected-truth non-disclosure + least-privilege evaluator + gated future
  evaluators; deterministic no-AI; persistence of new models with `BoardResult` intact; plus the
  worked PARALLAX C1 example.
- `siem/tests/test_pathway_migration_pg.py` — 9 checks on real Postgres (above).
- `siem/tests/test_pathway_migration.py` — 13 checks (SQLite gap→fix). Full siem suite green.

## Not in F1 (require their own authorized milestones)

F2 typed evidence/media interfaces; F3 secure media/artifact persistence + provenance; F4 bounded
forensic processing; F5 candidate workbench; Lab A (C1) and Lab B (C4). The future evaluators are
declared and gated (raise) until then. Stop here for review; do not continue to F2.
