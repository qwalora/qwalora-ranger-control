# PARALLAX Phase 1D — Engineering Report

**Deterministic validation, STRATA isolation, and security assurance**

Starting branch: `feature/parallax-p1-architecture-foundations` · Phase 1C handoff: `f53ef9c`, `426c8ae`
`main`: unchanged at `431a183` · Production hold: intact · Both PARALLAX qualification flags: OFF

Verification-status vocabulary (used precisely, never inflated): **Demonstrated** (implementation +
executed tests), **Partially verified** (some tests, critical conditions untested), **OPEN** (cannot
currently be established / known limitation), **Failed** (a control demonstrably fails). Skipped is
never reported as PASS.

---

## 1. Executive summary

Phase 1D is a focused engineering-assurance phase. It (a) fully root-causes and fixes the STRATA F4
cross-test contamination left OPEN in 1C, with before/after evidence and a regression lock; (b)
establishes test-order independence across the four required configurations plus recorded randomized
orders; (c) bounds the audit-checkpoint guarantees with an explicit threat model, adds an external-
anchor interface, and marks true independent anchoring OPEN with a concrete architecture; (d) reviews
cryptographic context separation and adds an explicit domain-separation primitive without touching any
historical signature or STRATA signing; (e) re-validates persistence invariants and deadlock-free
advisory-lock ordering on genuine PostgreSQL; and (f) reconfirms the OpenSearch restriction and ships
an executable validation procedure, keeping those 12 tests OPEN.

No STRATA scoring, no qualification activation, no portfolio, no deploy, no key rotation. Both flags
remain OFF, the Railway hold is intact, and `main` is untouched.

## 2. Starting repository state

Branch `feature/parallax-p1-architecture-foundations`, HEAD `426c8ae`; Phase 1C commits `f53ef9c` and
`426c8ae` present; `main` at `431a183` (local and remote); worktree clean. Disposable PostgreSQL 16.15
re-stood-up locally on 127.0.0.1:55433 with the `ranger_test_sentinel` authorizing database. STRATA
95% bar confirmed in code (`program.PASS_BAR = 95.0`, represented by `siem/assessment_contract`). No
repository divergence from the handoff.

## 3. STRATA F4 root-cause investigation

**Demonstrated root cause.** `test_f41_persistence_pg.py` installs a DB-backed trusted-fixture registry
into the process-global `evidence_validation._REGISTRY` (via `set_fixture_registry` /
`install_db_backends`). Before Phase 1C it was never restored. Later STRATA F4 tests
(`test_f4_review_boundaries.py`, `test_forensic_f4.py`) call `register_trusted_fixture` relying on the
process default — an in-memory registry usable with no Flask application context. With the DB-backed
registry leaked in, that call runs `self.M.query` outside an app context and raises "Working outside of
application context". The second condition for the full-suite failure is that the consuming F4 test has
no ambient app context at that moment (F4 tests do not push their own); that condition is itself
order/state-sensitive, which is why the 1C full forward+PG run failed while the 3-file triplet did not.

**Evidence that reproduces the original failure and confirms the fix.**
`siem/tests/test_f4_registry_isolation.py` encodes it deterministically: `test_unrestored_db_registry_
would_leak_outside_context` reproduces the exact `RuntimeError` (DB-backed registry active + no
context), and `test_restored_default_registry_works_without_context` confirms the fix. A hash-seed sweep
(`PYTHONHASHSEED` 0,1,2,7,13,42,99,123,777,2026) of the f41→review_boundaries→forensic_f4 triplet is
uniformly green, and the full forward+PG suite passes (363/0) with the fix.

**Other causes ruled out** (spec: do not assume the earlier diagnosis is complete): `install_db_backends`
mutates only the fixture registry globally and returns a non-global coordinator; `keyed_mac`/signing
read configuration fresh (no order-dependent cache that affects F4); there is no other process-global
mutable registry in the F4 dependency set (`artifact_store`, `evidence_persistence`, `blob_lifecycle`,
`forensic_ops`, `forensic_jobs`). The one laba observation (seeds depend on the process `SECRET_KEY`
pinned by first import) is recorded as a separate note, not an F4 cause.

## 4. Test-isolation corrections (explicit state ownership)

Two complementary, defense-in-depth fixes, both pure test hygiene (no assertion or STRATA behavior
change):

1. **Source side (1C, retained):** `test_f41_persistence_pg.py` autouse fixture snapshots and restores
   `evidence_validation.fixture_registry()` around each test, so the DB-backed registry cannot escape.
2. **Consumer side (1D):** `test_forensic_f4.py` and `test_f4_review_boundaries.py` each gain an autouse
   fixture that gives the test its OWN fresh `InMemoryFixtureRegistry` and restores the prior one after
   — so an F4 test can never inherit a leaked DB-backed registry regardless of execution order.

Verified: with the source-side fixture deliberately disabled, the triplet (and the full forward+PG run)
still pass, because the consumer-side ownership fixture alone prevents the leak. The regression test
(`test_f4_registry_isolation.py`, 3 tests) locks the invariant.

## 5. Full four-configuration test matrix

Genuine disposable PostgreSQL 16.15 for the enabled configurations; one process per run; PG-enabled
runs never concurrent. Commands and exact counts:

| Execution order | PostgreSQL | Command | Result |
|---|---|---|---|
| Forward | Disabled | `python -m pytest` (gate env unset) | **PASS** — 355 passed, 39 skipped, 0 failed (445.6s) |
| Reverse | Disabled | `python -m pytest --reverse` (gate env unset) | **PASS** — 355 passed, 39 skipped, 0 failed (472.5s) |
| Forward | Enabled | `RANGER_TEST_ALLOW_DB_MUTATION=1 … python -m pytest` | **PASS** — 378 passed, 16 skipped, 0 failed (495.7s) |
| Reverse | Enabled | `… python -m pytest --reverse` | **PASS** — 378 passed, 16 skipped, 0 failed (522.7s) |

All four required configurations PASS with zero failures. PG-enabled runs execute 23 additional tests
(the disposable-PostgreSQL suites) that skip when disabled; the 16 PG-on skips are the 12 OPEN
OpenSearch tests plus the 4 STRATA S6-capacity tests on their separate gate. The previously-failing
forward + PostgreSQL-enabled configuration now passes without any special workaround.

## 6. Randomized-order results and seeds

A narrowly-scoped, dependency-free collection shuffler was added to `siem/tests/conftest.py`
(`pytest_collection_modifyitems`), a no-op unless `RANGER_TEST_SHUFFLE_SEED` is set, which shuffles
collected items deterministically by that seed so any failure is reproducible. Recorded seeds (PG
enabled):

| Seed | Command | Result |
|---|---|---|
| 101 | `RANGER_TEST_SHUFFLE_SEED=101 … python -m pytest` | **PASS** — 378 passed, 16 skipped, 0 failed (507.0s) |
| 202 | `RANGER_TEST_SHUFFLE_SEED=202 … python -m pytest` | **PASS** — 378 passed, 16 skipped, 0 failed (498.1s) |
| 303 | `RANGER_TEST_SHUFFLE_SEED=303 … python -m pytest` | **PASS** — 378 passed, 16 skipped, 0 failed (499.2s) |

All three randomized orders pass; any failure would be reproducible by re-running with the same
`RANGER_TEST_SHUFFLE_SEED`. Together with the four-configuration matrix this demonstrates test-order
independence (no hidden shared-state dependency across STRATA Board 2, STRATA F4, STRATA S6 capacity,
PARALLAX Lab A, governance persistence, key rotation, audit integrity, and database recovery).

## 7. Cryptographic security findings (Workstream D)

**Determination.** The existing signed artifact types (governance approval, audit event, assessment
decision/adjudication, audit checkpoint, STRATA clearance/badge) are **mutually non-verifiable**: their
canonical payloads have disjoint required fields, so a signature over one cannot verify another. This is
demonstrated in `test_parallax_domain_separation.py::test_existing_signed_types_do_not_cross_verify`
(each signature verifies only its own payload). Cross-context reuse among current types is therefore
**not possible** — context separation holds structurally today.

**Explicit domain separation added (for new types).** `signing.sign_domain(domain, payload)` /
`verify_domain(...)` bind an artifact TYPE + SCHEMA VERSION + SECURITY CONTEXT label into the signed
bytes with a length-delimited header. A domain signature never verifies under a different domain, nor as
a plain signature, and vice versa; it is kid-aware and fails closed on rotation/revocation. This is
**additive**: plain `sign()`/`verify()` and every existing signature are byte-for-byte unchanged
(`test_plain_signing_unchanged_by_domain_additions`), so no historical record is invalidated and shared
STRATA signing behavior is unchanged (compatibility test included).

**Disposition.** Cross-context reuse: Demonstrated-closed for existing types (structural) with an
explicit primitive now available for new types. Retrofitting explicit type tags onto existing records is
**OPEN** (would require re-signing historical content and is unnecessary given structural separation;
keys are not rotated this phase). Canonical-JSON profile portability (a non-Python verifier must match
`json.dumps(sort_keys, compact, ensure_ascii)`) remains a documented Partially-verified item.

## 8. Audit-checkpoint trust model (Workstream C)

`audit_integrity.THREAT_MODEL` states precisely what the in-DB, same-key checkpoint mitigates:

| Adversary capability | Mitigated | How |
|---|---|---|
| Accidental corruption | Demonstrated | chain hash + per-event signature + seq ordering |
| Unauthorized DB modification **without** the signing key | Demonstrated | any edit/insert/reorder breaks a signature or the chain |
| Tail truncation **without** the signing key | Demonstrated | signed checkpoint anchors event count + head |
| Truncation **plus** checkpoint deletion, without key | Demonstrated **iff** an external anchor was emitted | `export_anchor` / `verify_against_external_anchor` |
| Compromised signing key **without** DB write | Demonstrated | key alone cannot insert/alter rows; chain + unique(seq) constrain |
| Simultaneous DB **and** signing-key compromise | **OPEN (not mitigated)** | attacker forges events AND a matching checkpoint; needs an independent external anchor |

Tests: `test_parallax_audit_trust_model.py` (6) demonstrates each mitigated row, proves the external
anchor catches truncation even when every in-DB checkpoint is deleted, and demonstrates the honest
unmitigated case (with key+DB an attacker fools the in-DB view, and only a pre-existing external anchor
exposes it). The in-DB anchor is always labeled `not_independent_same_store_same_key`.

**Independent anchoring — OPEN, with architecture.** Ranger has no currently-authorized component that
provides an independent, immutability-controlled store reachable from this environment (the SIEM/
OpenSearch telemetry environment is itself OPEN; Railway object storage would require provisioning and
authorization). The `export_anchor(sink)` interface is the integration point. Proposed architecture
(founder decision, no paid infra activated here): emit each signed checkpoint's `anchor_record`
(stream, count, head hash, checkpoint hash, ts, kid — no secrets) to a sink OUTSIDE the signing
authority's control — e.g. append-only object storage with object-lock/immutability, a separately-
managed verification service, or a transparency log. Validation plan: periodically call
`verify_against_external_anchor` with the externally-held latest anchor; a `truncated`/`rewritten`
result with a verifying in-DB checkpoint is positive evidence of a dual compromise. Until a sink outside
the signing authority is provisioned and authorized, protection against simultaneous DB+key compromise
is **OPEN** and is not claimed.

## 9. Persistence and concurrency findings (Workstream E)

Re-validated on genuine PostgreSQL 16.15 (`test_parallax_persistence_review_pg.py`, plus the retained
1B/1C PG suites):

- Governance approvals authoritative, reviewer assignments server-side, assessment records candidate-
  bound, adjudications assessment/attempt-bound, idempotent duplicates, deterministic revocation,
  fail-closed on missing authoritative evidence — Demonstrated (1B/1C suites + security-review tests).
- **Advisory-lock ordering is deadlock-free under cross-operation concurrency** — Demonstrated: a mixed
  concurrent run (two spec-approval retries, two assessment records for different candidates, two
  racing reviewer assignments) all complete with no deadlock and all invariants hold (one approval row,
  one decision per candidate, one active assignment, audit chain verifies). The lock order is always
  subject→stream.
- **Concurrent revoke + verify never returns a torn artifact** — Demonstrated: every non-None read of
  the approval during a concurrent revocation is signature-valid, and the end state is revoked.
- Transaction isolation: the idempotency/one-active invariants rely on per-subject advisory locks under
  READ COMMITTED (not on a stricter isolation level); validated on real PG, not inferred from SQLite.

## 10. OpenSearch validation status (Workstream F) — OPEN

Reconfirmed (no repeat pull attempts): no Docker daemon, no cached OpenSearch image, no local install,
no authorized `RANGER_TEST_OPENSEARCH_URL`; the registry remains unreachable through the egress
allowlist. All 12 tests in `test_strata_s5_real_opensearch.py` are preserved with original assertions
and SKIP fail-closed; no mocks are substituted. `docs/PARALLAX_OPENSEARCH_VALIDATION_PROCEDURE.md` gives
the exact executable procedure (provision disposable 2.17.1 + Security plugin, create the sentinel
index, set the `_ostest` env, run the 12 tests, tear down). Status: **OPEN**, 12 cases enumerated.

## 11. STRATA regression evidence

STRATA is unchanged. The 95% bar, Board 2 signed-citation workflow, F4 evidence/forensic validation, and
S6 capacity behavior all pass in every matrix configuration (§5–6). The only STRATA-file edits are the
F4 test-isolation fixtures (§4) and the conftest shuffle hook (§6) — no runtime module, scoring rule,
gate, or assertion changed.

## 12. PARALLAX qualification-boundary evidence

Unchanged and re-verified: individual assessments are `qualified=False`; no approved portfolio exists;
`decide_pathway_persistent` fails closed; the two-flag matrix leaves qualification impossible;
substitution-proof writes; reviewer authorization enforced; signed evidence identity/provenance intact.
No test run authorizes an assessment or portfolio for actual qualification. Both flags OFF.

## 12a. Traceability (claim → implementation → test)

| Security claim | Implementation | Test(s) |
|---|---|---|
| F4 registry leak root cause + fix | `test_f41_persistence_pg.py` autouse restore; `test_forensic_f4.py` / `test_f4_review_boundaries.py` ownership fixtures | `test_f4_registry_isolation.py` (neg+pos); full forward+PG matrix |
| Test-order independence | `conftest.py` shuffle hook; `--reverse` | matrix §5, seeds §6 |
| Signing rotation / kid / states / fail-closed | `signing.py` registry, `verify`, `_resolve_and_verify` | `test_parallax_signing_lifecycle.py` |
| No cross-context signature reuse (existing types) | canonical disjoint schemas | `test_parallax_domain_separation.py::test_existing_signed_types_do_not_cross_verify` |
| Explicit domain separation (new types), legacy untouched | `signing.sign_domain`/`verify_domain` | `test_parallax_domain_separation.py` |
| Audit tamper/reorder/dup/truncation detection | `auditlog.verify_chain`, `audit_integrity` checkpoint | `test_parallax_audit_integrity.py`, `test_parallax_audit_pg.py` |
| Audit threat model + external-anchor interface | `audit_integrity.THREAT_MODEL`, `export_anchor`, `verify_against_external_anchor` | `test_parallax_audit_trust_model.py` |
| Deadlock-free lock ordering; no torn revoke/verify | per-subject→stream advisory locks in `registry`/`reviewer_store`/`assessment_store`/`auditlog` | `test_parallax_persistence_review_pg.py` |
| Persistence invariants, idempotency, fail-closed | `parallax/*` persistence modules | `test_parallax_persistence.py`, `test_parallax_persistence_pg.py`, `test_parallax_recovery_pg.py`, `test_parallax_migration_pg.py` |
| Qualification boundary (no single-assessment qual) | `assessment_contract`, `pathway_persistent` | `test_parallax_persistence.py` (flag matrix), `test_parallax_pathway_qualification.py` |
| OpenSearch validation | `test_strata_s5_real_opensearch.py`, `_ostest.py` | OPEN — `docs/PARALLAX_OPENSEARCH_VALIDATION_PROCEDURE.md` |

## 13. Outstanding security and operational risks

1. **Simultaneous DB + signing-key compromise** — OPEN; needs an independent external anchor (§8).
2. **Explicit type tags on existing signed records** — OPEN; unnecessary given structural separation,
   available via the new primitive for new types (§7).
3. **Canonical-JSON profile portability** — Partially verified; document a canonical profile before any
   third-party verifier (§7).
4. **Signing-key rotation is mechanism, not live rotation** (from 1C) — operational procedure, not done.
5. **OpenSearch integration** — OPEN (§10).
6. **`UnitResult` uniqueness migration on production** (from 1C) — scheduled operator action, not run.

## 14. Production-hold and qualification-flag verification

- Railway portal service (`qwalora-ranger-control`, env `production`) read-only check this phase:
  `watchPatterns = ["/.railway-autodeploy-hold/**"]` (auto-deploy hold intact), `staged: null`, and the
  production variable set contains **neither** `RANGER_PARALLAX_QUALIFICATION_ACTIVE` **nor**
  `RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE` (both gates OFF). This work targets the feature branch,
  not `main`.
- No deploy, no merge, no production migration, no live key rotation, no portfolio, no awards.

## 15. Git commit and push evidence

- Branch: `feature/parallax-p1-architecture-foundations` (never `main`).
- Phase 1D commit: `f060d08` — "feat(parallax): Phase 1D deterministic validation, STRATA isolation,
  security assurance", author `cloudcwfranck <yakengne@gmail.com>`, no attribution trailers. 11 files
  changed (+1005 / -2): `signing.py`, `parallax/audit_integrity.py`, `siem/tests/conftest.py`,
  `siem/tests/test_forensic_f4.py`, `siem/tests/test_f4_review_boundaries.py` modified;
  `siem/tests/test_f4_registry_isolation.py`, `test_parallax_audit_trust_model.py`,
  `test_parallax_domain_separation.py`, `test_parallax_persistence_review_pg.py`, and two docs added.
  (The `test_f41_persistence_pg.py` source-side fixture was committed in Phase 1C, `f53ef9c`.)
- Matrix evidence: 4 configurations + 3 randomized seeds, all PASS, 0 failed (§5–6), on PostgreSQL
  16.15.
- Pushed to `origin/feature/parallax-p1-architecture-foundations`. `main` unchanged at `431a183`
  (local and remote). No merge, no deploy.

## 16. Readiness recommendation

Engineering-level: Phase 1D criteria are met where infrastructure permits — F4 contamination resolved
with regression lock; four-config matrix + three randomized seeds green (§5–6); STRATA unchanged;
PARALLAX boundaries intact; signing/persistence regressions zero; audit guarantees accurately bounded by
the threat model. OpenSearch validation and independent audit anchoring are explicitly OPEN. No critical
security or migration defect is unresolved. Recommendation: accept Phase 1D at the engineering level;
production remains blocked on the OPEN founder decisions below.

## 17. Founder decisions

1. Provision an authorized disposable OpenSearch 2.17.1 node to execute the 12 OPEN tests (procedure
   shipped).
2. Select and provision an independent, immutability-controlled anchor sink for audit checkpoints to
   close the dual-compromise gap (or accept the documented bound).
3. Approve a production signing-key rotation window + secret-store procedure (1C mechanism ready).
4. Schedule the `UnitResult` uniqueness migration against production (1C CLI ready).
5. Any move toward qualification (defining/signing a portfolio, enabling either flag) remains a separate,
   explicitly-authorized decision.
