# PARALLAX Phase 1E — Engineering Report

**End-to-end integration, operational readiness, and controlled research validation**

Starting branch: `feature/parallax-p1-architecture-foundations` · Phase 1D handoff: `9526bb4`
`main`: unchanged at `431a183` · Railway hold: intact · Both PARALLAX qualification flags: OFF

Verdict vocabulary (used precisely): **PASS** (implemented + executed tests), **PARTIAL** (some
verification, critical conditions untested), **OPEN** (cannot currently be established / known
limitation), **FAIL** (demonstrably fails). Skipped is never PASS.

---

## 1. Executive summary

Phase 1E connects the previously test-only PARALLAX durable architecture into Ranger's real application
and demonstrates one complete assessment lifecycle through actual HTTP request + persistence
boundaries: an authenticated candidate submits a Lab A assessment (governance approval read from the
persisted registry, never minted in a route), the signed decision is persisted, an authorized admin
assigns a reviewer, the assigned reviewer submits an identity-bound signed adjudication, and the
candidate retrieves an assessment-only status that is never a pathway qualification. A machine-readable
evidence-to-decision traceability verifier reconstructs the full chain with a four-state verdict.
Adversarial tests exercise the same boundaries. STRATA is unchanged; both qualification flags remain
OFF; the Railway hold is intact; `main` is untouched. OpenSearch and independent audit anchoring remain
explicitly OPEN.

## 2. Starting repository state

Branch `feature/parallax-p1-architecture-foundations`, HEAD `9526bb4`; Phase 1D commits present;
`main` at `431a183` (local + remote); worktree clean. Disposable PostgreSQL 16.15 re-stood-up on
127.0.0.1:55433 with the `ranger_test_sentinel` authorizing database. STRATA 95% bar confirmed
(`program.PASS_BAR = 95.0`). Both flags OFF.

## 3. Existing architecture integration map

Before 1E: the durable modules (`registry`, `reviewer_store`, `assessment_store`, `pathway_persistent`,
`auditlog`, `audit_integrity`, `signing` registry) were reachable **only via tests/programmatic calls**.
The only PARALLAX routes (`parallax_routes.py`) were a **dry-run preview** (`/parallax/laba/brief`,
`/parallax/laba/evaluate`) that persists nothing and does not touch the durable modules. STRATA's
`/workbench` routes use a separate evidence/receipt system, not the PARALLAX governance registry. So the
integration gap was: no application path drove the durable lifecycle.

After 1E: `parallax_routes.py` gains durable, nonproduction-gated endpoints that drive the durable
modules through real request + persistence boundaries. No new blueprint or parallel portal; the existing
gating (`_nonprod`, authenticated session, signed approval) is reused.

## 4. Implemented application integration

New endpoints in `parallax_routes.py` (all behind the existing `RANGER_PARALLAX_LABA` + non-production
gate; 404 otherwise; session identity only):

- `POST /parallax/laba/assessment` — candidate submit; loads the **persisted registry** approval
  (`registry.active_spec_approval`), runs the assessment (reviewer applied separately), persists the
  signed decision (`assessment_store.record_assessment`), returns the assessment-only disposition with
  explicit simulation labeling.
- `GET /parallax/laba/assessment/status` — candidate's own status via `traceability.verify_assessment`;
  never qualified.
- `POST /parallax/laba/admin/assign-reviewer` — authorized-admin-only (`_is_authorized_admin`, session-
  bound) reviewer assignment (`reviewer_store.assign_reviewer`). Governance/assignment is never created
  in a candidate route.
- `GET /parallax/laba/review/assignments` — the authenticated reviewer's own active assignments.
- `POST /parallax/laba/review/adjudicate` — the assigned reviewer submits a signed, bound adjudication
  (`review.make_adjudication`, which enforces authorized + assigned), persisted via
  `assessment_store.record_assessment`.

Candidate identity is resolved from `session['cand']` (the OAuth-set Candidate id) to a stable
github-id key, active status enforced; identity never comes from a query parameter or body.

## 5. Candidate identity and access validation — PASS

`test_parallax_lifecycle_e2e.py`: unauthenticated candidate denied (401 on GET; POST denied by CSRF/
auth); a candidate sees only their own status (`test_candidate_sees_only_own_status`); a
`candidate_key` query param does not redirect identity (`test_identity_from_session_not_query_param`);
active-status enforced in `_resolve_candidate_key`. Session-authed POSTs are CSRF-protected.

## 6. Reviewer authorization validation — PASS

Only the assigned reviewer can adjudicate: an authorized admin without an assignment is denied (403,
`test_admin_without_assignment_cannot_adjudicate`); an authorized reviewer identity without an
assignment is denied; a revoked assignment is denied
(`test_unassigned_reviewer_denied_and_revoked_assignment_denied`). Administrative access does not imply
reviewer eligibility. Reviewer identity comes from the session, not the request body.

## 7. End-to-end assessment execution evidence — PASS

`test_parallax_lifecycle_e2e.py::test_full_assessment_lifecycle_through_http` drives all 14 lifecycle
steps over HTTP: submit → persist signed decision (201, awaiting review) → status (VALID, not met) →
admin assign reviewer (201) → reviewer sees assignment → reviewer adjudicate pass (201) → candidate
status (VALID, requirements_met=true, reviewer_pass=true, rubric_ok=true, **qualified=false**,
simulation=true). Also validated on genuine PostgreSQL in `test_parallax_lifecycle_pg.py` (full
lifecycle + client-retry idempotency + process-restart persistence).

## 8. Evidence-to-decision traceability — PASS

`parallax/traceability.py::verify_assessment` reconstructs, from the existing persisted + cryptographic
architecture (no competing ledger): assessment id+version, candidate+cohort binding, attempt, contract
MAC, blueprint hash, governance approval (+verifies), evidence provenance (submission_sha,
objective_result_sig), evaluator id+version, scoring result (objective/evidence/critical gates),
reviewer id+assignment, adjudication, signature kids, audit-chain refs + integrity, persistence state,
and the assessment-only disposition. Four-state verdict, tested in `test_parallax_traceability.py`:
VALID (awaiting-review and met), INVALID (tampered decision → signature invalid; broken audit chain),
INCOMPLETE (no record; revoked/absent governance approval), UNAVAILABLE (records table missing). It
never converts missing evidence into success and never reports a single assessment as qualified.

## 9. Adversarial test results — PASS

`test_parallax_lifecycle_e2e.py` (9) + `test_parallax_traceability.py` (8) cover: unauthenticated
candidate; cross-candidate access; identity-from-session-not-param; admin-without-assignment;
unassigned/revoked reviewer; routes 404 when flag/env off; adjudicate requires an existing record;
tampered decision → INVALID; broken audit chain → INVALID; unretrievable records → UNAVAILABLE; and the
single-assessment-never-qualified guard under **all four** qualification-flag combinations. Assessment-
integrity and app/db cases (retry idempotency, restart) are additionally covered on real PostgreSQL.

## 10. PostgreSQL integration and concurrency results — PASS

`test_parallax_lifecycle_pg.py` runs the HTTP lifecycle against disposable PostgreSQL 16.15 and asserts
the real `postgresql` dialect, client-retry idempotency (one decision row), and restart persistence.
Lower-level concurrency (idempotent writes, one-active-assignment, deadlock-free lock ordering, audit
concurrency, recovery/backup) remains covered by the 1B/1C/1D PG suites, which continue to pass.

## 11. OpenSearch validation status — OPEN

Reconfirmed unchanged from Phase 1D (no Docker daemon, image registry blocked by the egress allowlist,
no cached image/local install, no authorized node); no repeat pull attempts. All 12 tests in
`test_strata_s5_real_opensearch.py` are preserved with original assertions and skip fail-closed; no
mocks substituted. The integrated nonproduction lifecycle does not require OpenSearch (Lab A is a
simulation). Executable procedure: `docs/PARALLAX_OPENSEARCH_VALIDATION_PROCEDURE.md`.

## 12. Independent audit-anchor readiness — OPEN (design delivered)

`parallax/audit_integrity` provides the export/verify interface and the dual-compromise detection path
(`export_anchor`, `verify_against_external_anchor`, tested in `test_parallax_audit_trust_model.py`). A
truly independent destination is not provisioned/authorized in this environment, so the capability is
OPEN. `docs/PARALLAX_AUDIT_ANCHOR_DESIGN.md` answers the nine integration questions and names the
founder decision required.

## 13. STRATA regression results — PASS

STRATA is unchanged. No STRATA runtime module, scoring rule, gate, or the 95% bar / Board 2 behavior was
modified. The new PARALLAX routes are isolated behind their flag and do not affect STRATA paths. Full
forward and reverse PG-on suite results in §14.

## 14. Full test counts and skips

Regression runs on PostgreSQL 16.15 (disposable, 127.0.0.1:55433):

- Full forward order, PostgreSQL enabled: **396 passed, 16 skipped, 0 failed** (492.5s).
- Full reverse order, PostgreSQL enabled: **396 passed, 16 skipped, 0 failed** (533.1s).
- New 1E in-process tests within that total: `test_parallax_lifecycle_e2e.py` (9 PASS),
  `test_parallax_traceability.py` (8 PASS); new PG test `test_parallax_lifecycle_pg.py` (1 PASS when
  PostgreSQL is authorized, skips otherwise). This is +18 over the Phase 1D baseline of 378.
- The 16 skips are the 12 OPEN OpenSearch tests + the 4 STRATA S6-capacity tests on their separate gate.
  Both orders pass with zero failures; the Phase 1D baseline is preserved.

## 15. Operational readiness checklist

See `docs/PARALLAX_OPERATIONAL_READINESS.md` for the full package (configuration, schema/migration
preflight, key-registry, governance, reviewer setup, evidence persistence, audit verification, backup/
recovery, observability, OpenSearch + audit-anchor limitations, rollback), the three-mode distinction
(local simulation / integrated nonproduction / infrastructure-backed), and the pilot checklist
separating technical prerequisites (all checked) from founder authorization decisions (all unchecked).

## 16. Outstanding security and infrastructure limitations

1. **OpenSearch integration** — OPEN (§11).
2. **Independent audit anchor** (dual DB+key compromise) — OPEN (§12).
3. **Signing-key rotation** is mechanism-only (1C); live rotation is an operational step — not done.
4. **`UnitResult` uniqueness migration** on production — scheduled operator action (1C CLI) — not run.
5. **Canonical-JSON profile** portability (1D) — PARTIAL; document before any third-party verifier.

## 17. Founder authorization decisions

Provision an authorized OpenSearch node; provision an independent audit-anchor destination; approve a
production signing-key rotation window; schedule the production `UnitResult` migration; and — separately
and deliberately — define/approve a PARALLAX portfolio and authorize activation. None is taken here.

## 18. Git commit, branch, and push verification

_Filled at commit time:_ commit SHA(s), author `cloudcwfranck <yakengne@gmail.com>` (no trailers), files
changed, push target, `main` unchanged at `431a183`.

## 19. Railway production-hold and qualification-flag verification

Read-only this phase: portal `watchPatterns = ["/.railway-autodeploy-hold/**"]` (hold intact),
`staged: null`, production variables contain **neither** qualification flag (both OFF). No deploy, no
merge, no production migration, no key rotation.

## 20. Final engineering readiness classification

The integrated PARALLAX assessment lifecycle executes end-to-end through real application request +
persistence boundaries with governance, identity, reviewer authorization, durable signed evidence,
identity-bound adjudication, independently-verifiable traceability, explicit simulation labeling, and an
assessment-only disposition that is never a pathway qualification — demonstrated on SQLite and genuine
PostgreSQL, with adversarial coverage. **Classification: PASS at the engineering level for the
integrated nonproduction lifecycle.** OpenSearch validation and independent audit anchoring are OPEN;
production remains blocked on the founder decisions in §17. Qualification remains impossible without a
genuinely approved portfolio and authorized activation.
