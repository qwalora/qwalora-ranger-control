# STRATA S5 - end-to-end Board 2 enterprise SOC qualification (development delivery)

Branch `feature/strata-s5-board2-qualification`, based on the accepted S3/S4 commit `04f4662`. F1-F5 and S1-S4 preserved. Not merged to `main`. Production qualification remains securely disabled.

## A. What S5 delivers

One authoritative, independently verifiable Board 2 assessment path. A candidate's `/soc` environment, their `/case` investigation, and server-side grading all refer to the SAME pinned S3/S4 `ScenarioBinding`; the legacy static seed is no longer the source of truth for qualification. A governed, release-gated decision service can award Board 2 objective credit and drive Board 3 promotion in an authorized isolated test, while the production activation gate stays closed.

## B. Changed / new files

New:
- `strata_board2.py` - the single authoritative Board 2 assignment: `resolve_assignment()` (binds an approved cohort scenario, validates the pinned generation contract, fails closed), `dataset_fingerprint()` (keyed MAC over the whole identity), `provision()` (binding-driven OpenSearch ingestion, idempotent + fingerprint-verified + retry-safe), `generate_world()`/`grading_truth()`, and `board2_reference_submission()` (truth-derived reference-correct investigation, non-candidate-facing).
- `strata_qualification.py` - the governed decision service: shadow vs proposed vs **authorized** decision; signed `ActivationAuthorization` gate (a bare env flag cannot open it); principal authorization; signed-submission + binding checks; independent citation + truth verification; the real grader at the unchanged 95% bar; critical-failure rules; an Ed25519-signed, idempotent decision record; the only authorized writer of Board 2 objective credit.
- `siem/fake_cluster.py` - an in-process DOUBLE of `siem.live.LiveCluster` (same method surface incl. `_req`, same role/DLS model) for OpenSearch-layer tests where no disposable node exists. Clearly labelled; not a live-validation substitute.
- `siem/tests/test_strata_s5_board2.py` - the S5 acceptance suite (16 tests).
- `docs/STRATA_S5_BOARD2_QUALIFICATION.md` - this document.

Modified (all additive / default-off):
- `siem/authz.py` - `qualification_index_name()` (graded index, separate from operational, still inside the candidate `-b*` role pattern).
- `soc_gateway.py` - candidate Board 2 provisioning uses the pinned binding via `strata_board2.provision()` when `RANGER_B2_BINDING` is on; legacy seed path unchanged when off.
- `case_routes.py` - `_ensure_case()` pins the qualification case to the authoritative binding (index/seed/version/rubric/variant/content-hash) when `RANGER_B2_BINDING` is on; resumes an assigned case; never re-pins a submitted (locked) case; fails closed; legacy path unchanged when off.
- `models.py` - `QualificationDecision` table; `Case.binding_id/content_hash/variant_id`; `ensure_schema` ALTERs. Additive; migration is a release gate.
- `app.py` - the flag-gated reviewer route `POST /admin/cases/submission/<sid>/qualify` (404 unless `RANGER_B2_QUAL_UI`), which runs the decision service and, only on an authorized award, evaluates the promotion gate (which still also requires report approval).

## C. One authoritative assignment -> index -> case

`resolve_assignment(db, candidate)` is the single resolver. It reuses the S3/S4 cohort-portfolio governance (approved portfolio + CSPRNG; no candidate-controlled selection), validates the binding's pinned generation contract (`strata_assignment.resolve`, which fails closed on tamper/drift), confirms the bound variant is still approved+eligible (revocation check), and returns a `Board2Assignment` carrying: candidate identity + cohort + pathway, board, attempt, spec id + version, content hash, variant, family, seed, generation-contract MAC, rubric version, the qualification index name, and the dataset fingerprint. `/soc` provisioning, `/case`, and grading all derive the index and world from this one object, so they cannot diverge. Missing / revoked / incompatible / corrupt -> `Board2AssignmentError` (never a legacy fallback).

## D. Approved scenario -> real OpenSearch telemetry

`provision(cluster, assignment)`:
- generates the approved telemetry from the pinned binding (`enterprise.generate` with the variant's families + pinned seed + profile), tags every document `data.plane=qualification`, and ingests into the candidate-authorized qualification index (`ranger-<cohort>-<slug>-b2-q<attempt>`), distinct from the operational `…-b2` index;
- keeps hidden truth, answer labels and the protected seed OUT of the index (verified by test); the normalized events carry the keyed `scenario_ref`, never `scenario_seed`;
- is idempotent and positively fingerprint-verified: an existing index is reused only when its stored meta fingerprint equals this assignment's; an index whose contents belong to another seed/variant/attempt/candidate is REFUSED;
- is retry-safe: events bulk-upsert by `_id` and the completion meta is written LAST, so an interrupted ingest converges on the next call instead of leaving a mixed/partial world;
- preserves per-candidate role + DLS on `ranger.candidate_id` (cross-candidate read -> 403, proven by test);
- never deletes or re-indexes an index that is not its own incomplete qualification index.

## E. Qualification decision contract (release-gated)

`strata_qualification.decide(...)` distinguishes three things and never conflates them:
- **shadow** (`enterprise_grader`, `shadow=True`): advisory only, never awards.
- **proposed** (`mode="proposed"`): computes and signs a decision record for calibration/comparison, never awards objective credit.
- **authorized** (`mode="authorized"`): may award, and ONLY when the activation gate is open.

An authorized decision requires, together: an authenticated authorized principal (or trusted internal service identity); a valid signed `ActivationAuthorization` naming the approved rubric (a bare env flag is insufficient; a production activation additionally needs `RANGER_B2_QUAL_ACTIVE`, and a test activation is refused in a process that declares `RANGER_ENV=production`); a finalized, signed, unmodified submission whose preserved record binds to this exact candidate/case/cohort/board/attempt/scenario; citations re-verified `reference_valid` against the authorized index, independently of candidate-side verification; protected truth recomputed from the pinned scenario (never stored, never candidate-facing); a composite score from that pinned scenario at the unchanged `PASS_BAR = 95.0`; the critical-failure rules (`FOREIGN_OR_OUT_OF_SCOPE_CITATION`, `CONFIRMED_INCIDENT_WITHOUT_VALID_EVIDENCE`, `FALSE_INCIDENT_CLAIMED`, scenario-identity mismatch - any one fails the attempt regardless of score); an Ed25519-signed decision record persisted idempotently (`uq_qual_decision`, so repeat evaluation never duplicates or re-awards). The separate human report-approval gate is unchanged and is applied by `_evaluate_gate`, not here.

## F. Positive + negative progression (isolated, demonstrated)

`test_board2_full_legitimate_progression` walks all 12 steps: eligible candidate -> approved cohort binding -> provisioned qualification index -> complete signed investigation -> server-side evidence verification -> authorized decision (score 100, 95% satisfied) -> objective recorded -> report approved separately -> Board 2 cleared -> promoted to Board 3 exactly once (a repeat qualify does not re-award or double-promote). The reverse set is proven by dedicated tests: objective-without-report and report-without-objective do not promote; score < 95 does not award; unsigned/modified evidence cannot qualify; foreign/forged citations cannot qualify (critical failure); wrong scenario version cannot qualify; shadow and `proposed` cannot promote; the generic `/grade/submit` still 409s Board 2; the authorized gate is closed without a signed activation and refuses a test activation in a production process; repeated evaluation is idempotent.

## G. Cohort A vs Cohort B (real telemetry)

`test_two_cohorts_materially_different_and_isolated`: two cohorts bound to different approved variants (`b2-identity-takeover` vs `b2-stealth-lateral`) produce investigations whose incident FAMILIES differ in the generated truth, not just labels; candidate A's role cannot read candidate B's index (DLS 403); and cohort A's correct answers do not auto-pass cohort B's scenario. Uses the accepted S3/S4 material-diversity + cohort-portfolio governance.

## H. Key protection + scenario integrity

- The scenario reference is a keyed HMAC (S3/S4 correction, carried forward), so a 64-bit legacy seed cannot be recovered from a published reference.
- The dataset fingerprint and the generation-contract MAC are keyed HMACs binding the WHOLE identity (candidate, cohort, board, attempt, seed, spec id+version, content hash, variant, contract MAC, rubric) - not just the serialized parameter object (`test_fingerprint_binds_full_identity_not_just_params`).
- Provisioned indices and their meta carry no seed, no `_malicious`, no truth (`test_no_seed_in_provisioned_index_or_meta`).
- Production-safe configuration required before activation: `SECRET_KEY`, `RANGER_REF_KEY`, `RANGER_SIGNING_KEY` must be set to real values (the dev-derived MAC/signing key must not be used in production). Key versioning + rotation for stored contract MACs, and old-key verification for historical signed records, are enumerated in the "future authorizations" list below.

## I. Test results (this environment)

- A. Unit / logic + B. PostgreSQL-transactional: the S3/S4 suite and the rest of the offline suite (run counts in the handoff message). The S5 acceptance suite is 16 tests, all passing offline.
- C. OpenSearch: exercised against `FakeCluster`, the in-process LiveCluster double (same role/DLS model and `_req` surface). This demonstrates the Ranger-side ingestion, search, per-candidate isolation and evidence-reproduction logic and the authorization contract. It is explicitly NOT live OpenSearch validation.
- D. End-to-end candidate progression: demonstrated in isolation (sqlite + FakeCluster), positive and negative.
- B (concurrency). `test_concurrent_authorized_decision_is_idempotent_postgres` runs against a disposable authorized PostgreSQL instance (the existing `_pgtest` boundary): 6 concurrent authorized evaluations produce exactly one signed decision and one award (the `uq_qual_decision` constraint). Skips with an explicit reason when no authorized PG server is configured.
- E. Remaining live validation: see below.

### Pre-existing full-suite test-order failures (investigated, section 12)

A full suite run WITH the PostgreSQL env shows two failures, `test_f4_review_boundaries` and `test_forensic_f4` ("working outside of application context"). These predate S5 (verified earlier by running against clean `04f4662`/`bc395b8`): both pass standalone and skip offline. Root cause: the forensic F4 PG-backed phases (`forensic_jobs_db` via the global `db`) do not create and push their own Flask application context - they depend on an ambient context left by whichever test ran before them. In a full PG-env run an earlier test binds the global `db` to its own app and then tears it down (context popped / engine disposed), so the forensic phases find no active app context. This is a shared-global-state / missing-fixture-isolation issue in the test harness, not a product defect. The right fix is a `conftest` fixture that gives each test its own pushed application context (and resets the global `db` binding), which spans several suites and is intentionally NOT bundled into S5 (the review asked not to expand into a forensic rewrite). The new S5 PostgreSQL test is self-isolating (its own `isolated_pg_database`, app context, `db.session.remove()` and `db.engine.dispose()`), so it does not contribute to the issue.

## J. Production migration + rollback

Migration (release-gated, NOT run here): add the `scenario_bindings`, `qualification_decisions` tables and the `cases.binding_id/content_hash/variant_id` columns. `ensure_schema()` carries idempotent ALTERs for the columns; the new tables are created by `create_all` / a one-off migration. A migration script lands with the activation change.

Rollback: all S5 behavior is behind default-off flags. With `RANGER_B2_BINDING`, `RANGER_B2_QUAL_UI` and `RANGER_B2_QUAL_ACTIVE` unset and no `RANGER_B2_QUAL_ACTIVATION`, Board 2 behaves exactly as before S5 (legacy seed path; no authorized grading; generic routes still refuse Board 2). The additive tables/columns are inert when unused. The qualification feature can be disabled by clearing those flags without a schema change.

## K. Remaining production + live validation requirements (future authorizations)

1. Written authorization to activate (per the SHADOW_GRADER §8 blockers); a real-cohort shadow run with reviewer adjudication of every near-bar/flagged case before any flip.
2. Live OpenSearch validation on an authorized disposable instance: binding-driven ingestion, search, DLS isolation and evidence reproduction against a real 2.17.1 node (not the double, not the production Railway cluster).
3. Operational plane stood up and kept separate from qualification (continuous ingestion / detector scheduling) - a separate approved milestone.
4. Production-safe `RANGER_SIGNING_KEY` / `RANGER_REF_KEY` / `SECRET_KEY`; a key-version + rotation scheme for stored contract MACs and decision signatures, with old-key verification retained for historical records.
5. A signed production `ActivationAuthorization` for the approved rubric, plus `RANGER_B2_QUAL_ACTIVE`, issued only after 1-4; historical indexed telemetry carrying `ranger.scenario_seed` re-indexed or dropped under separate authorization.
6. Candidate access remains disabled; only the synthetic test identity exercises the path until activation.

## L. Stop conditions honored

No merge to `main`; no deploy; no Railway/production-DB change; the production qualification grader is not enabled; no candidate access; no paid infrastructure; the 95% standard is unchanged; the S1/S2 design is unchanged; Boards 5-6 and PARALLAX untouched.

Stop for engineering review.
