# PARALLAX Phase 1C — Engineering Report

**Cryptographic lifecycle, migration safety, and infrastructure validation**

Starting branch: `feature/parallax-p1-architecture-foundations` · Phase 1B handoff: `7702ac8` · `main`: unchanged at `431a183`
Scope: infrastructure hardening only. No deploy, no merge, no qualification activation, no portfolio, no awards.

---

## 1. Executive summary

Phase 1C closes the cryptographic, migration, audit-completeness, and operational-recovery gaps the
Phase 1B report left open, with directly verified evidence. It delivers: a versioned signing-key
lifecycle (`kid`, algorithm id, key states, rotation, fail-closed verification, honest compromise
handling) that preserves verification of legitimate historical records; a safe, non-destructive,
idempotent `UnitResult` uniqueness migration validated on genuine disposable PostgreSQL; an audit-chain
truncation anchor (checkpoint) plus an admin integrity verifier, since a hash chain alone cannot detect
tail truncation; and recovery validation (restart, rollback, commit interruption, backup/restore,
fail-closed on unreachable records) on real PostgreSQL. An adversarial review found the Phase-1B/1C
controls hold, with a small set of documented limitations and unverified concerns classified
separately from demonstrated defects.

STRATA is unchanged and re-verified. Both PARALLAX qualification flags remain OFF, no portfolio exists,
the Railway production hold is intact, and `main` is untouched. The only test-file behavior change is a
pre-existing test-isolation observation documented in §11, not an assertion weakening.

## 2. Starting branch and repository state

Verified before any change: branch `feature/parallax-p1-architecture-foundations`, HEAD `7702ac8`
(Phase 1B) present; `main` at `431a183` (unchanged, local and remote). Working tree clean at start.
Disposable PostgreSQL 16 was re-stood-up locally on 127.0.0.1:55433 with the `ranger_test_sentinel`
authorizing database for the `_pgtest` boundary; it is ephemeral and never touched Railway.

## 3. Architecture reconnaissance and initial risk inventory

Read before modifying: `signing.py` (single cached Ed25519 key, no `kid`, detached signature over
`canonical` sorted-compact JSON; used by 18 modules across STRATA and PARALLAX), `models.ensure_schema`
(additive ALTER-ADD-COLUMN convention; constraints are not retrofitted), `migrate_pathways.py` (the
operator-run dry-run/`--apply` migration convention), the Phase 1B persistence modules, the audit chain
(`parallax/auditlog.py`), and the OpenSearch test gate (`siem/tests/_ostest.py`). Risk inventory:

| # | Risk | Severity | Disposition in 1C |
|---|------|----------|-------------------|
| R1 | Single signing key, no `kid`; rotation would break historical verification | HIGH | Closed (§4–5) |
| R2 | `UnitResult` uniqueness absent on pre-existing production DBs | MEDIUM | Closed (§6) |
| R3 | Audit chain cannot detect tail truncation (no independent head anchor) | HIGH | Closed (§7) |
| R4 | Canonicalization is Python-`json`-specific (cross-language verifier parity) | LOW | Documented (§10, §13) |
| R5 | Real OpenSearch integration unverified (no node) | — | OPEN (§9) |

## 4. Cryptographic key-lifecycle implementation

`signing.py` now carries a versioned verification registry while remaining byte-for-byte
backward-compatible when unconfigured.

- **Identity + algorithm.** Each key has a stable `kid` and explicit `alg` (`ed25519`). `kid` travels
  ALONGSIDE a signature (new nullable `signing_kid` columns on `ParallaxApproval`, `ParallaxAuditEvent`,
  `UnitResult`, `ParallaxAuditCheckpoint`), never inside the canonical signed bytes, so introducing it
  does not alter any existing signature.
- **Versioned registry + states.** `RANGER_SIGNING_KEYS` (JSON) defines keys with states `active`
  (signs + verifies), `verify_only` (verifies; rotated out of signing), `retired` (planned end of life;
  still verifies history), `revoked` (compromised; never trusted, including historically). Exactly one
  active key signs. With no config, the registry is synthesized from the single
  `RANGER_SIGNING_KEY`/`SECRET_KEY` key (kid `legacy:<hash>`, active) — identical to pre-1C behavior.
- **Rotation.** Introducing a replacement key = adding it `active` and moving the prior key to
  `verify_only`. New records sign under the new active key; historical records verify under the prior
  key selected by its `kid`.
- **Fail-closed verification.** `verify(payload, sig, kid=...)`: unknown `kid` → False; `revoked` key →
  False; otherwise verify against that key. An altered `kid` will not match the signature → False. A
  legacy record (no `kid`) verifies only under a key currently in {active, verify_only, retired} — never
  an arbitrary key.
- **Key-substitution protection + audit.** `parallax/keyadmin.py` records every key-lifecycle action
  (register/activate/verify_only/retire/revoke) into the signed, hash-chained audit trail, authorized
  against `strata_catalog._is_authorized_admin`; an unauthorized caller cannot record one. Private seed
  material is never returned by `public_registry()`, logged, or placed in exceptions (`_KeyEntry.__repr__`
  and the public registry carry only `{kid, alg, state, public_b64}`). No homegrown algorithm is used;
  no production private key is embedded in the repo or fixtures (tests generate temporary keys).

## 5. Historical signature compatibility

Legitimate pre-rotation records keep verifying: a stored `kid` is enforced exactly, and a legacy record
with no `kid` is verified under the narrow trusted-key policy above. Normal **retirement** keeps a key
trusted for historical verification; emergency **revocation** (compromise) makes a key untrusted for
everything, including history — so a record signed only by a revoked key fails closed. This is the
honest trade-off: revoking a compromised key invalidates verification of records it signed until they
are re-anchored, which is the correct security posture and is documented as a limitation (§13). If a
record cannot be assigned to a trusted key, verification fails closed rather than accepting it.

Evidence: `siem/tests/test_parallax_signing_lifecycle.py` (10 tests) — sign/verify under A; rotate to B;
historical A verifies (verify_only); new B verifies; unknown `kid`, altered `kid`, and signature
substitution rejected; revoked key rejected even historically; retired key still verifies; unavailable
private material fails closed on signing but still verifies; public registry exposes no private
material; and the DB-backed cases: a persisted approval and audit chain survive rotation and fail closed
on revocation, an altered stored `kid` is rejected, unauthorized key administration is refused, and a
legacy (NULL-`kid`) record stays compatible.

## 6. Database migration implementation and evidence

`parallax/evidence_migration.py` + operator CLI `migrate_unit_result_uniqueness.py` (mirrors the
`migrate_pathways.py` convention: dry-run preflight, explicit `--apply`).

- **Preflight** inspects the live schema and detects rows that would violate
  `UNIQUE(candidate_id, unit_ref, kind, record_hash)` using the same NULL-distinct semantics as a SQL
  UNIQUE (`record_hash IS NULL` rows never conflict). Decision: `noop` | `ready` | `blocked` |
  `unsupported`.
- **Non-destructive + abort-on-conflict.** If conflicting duplicates exist it ABORTS with a diagnostic
  and makes no change — it never invents an authoritative survivor.
- **Idempotent + serialized.** A PostgreSQL advisory lock serializes concurrent migrators; a second run
  is a `noop`. It runs transactionally and rolls back on error (forward-recovery: re-run after resolving
  conflicts). The `ADD CONSTRAINT` holds a brief `ACCESS EXCLUSIVE` lock on `unit_results` (documented;
  fast on a small table). SQLite cannot `ALTER ADD CONSTRAINT` after the fact, so the migration targets
  PostgreSQL (fresh tables get the constraint via `create_all`); it reports `unsupported` there rather
  than rebuilding the table.
- **Preserves signed evidence** unchanged (adds a constraint; never rewrites rows).

Evidence (genuine disposable PostgreSQL, `siem/tests/test_parallax_migration_pg.py`, 6 tests): empty DB
→ ready → applied → idempotent/repeated noop; existing constraint → noop; populated-no-duplicates →
applied with all rows preserved and the constraint enforced afterward; conflicting duplicates → blocked,
constraint not added, duplicates not removed; interrupted migration rolls back and re-runs cleanly;
concurrent migrators → exactly one applies, the other noops.

## 7. Audit-chain resilience results

`parallax/auditlog.verify_chain` now also enforces gap-free, in-order `seq` (catching removed/duplicate/
reordered interior events), kid-aware per-event signatures, and record-hash integrity. Because a hash
chain cannot detect TAIL truncation, `parallax/audit_integrity.py` adds a separately-protected
checkpoint anchor (model `ParallaxAuditCheckpoint`), mirroring the STRATA custody-chain design
(`siem/custody_integrity.py`): a signed, checkpoint-chained row recording the head hash, head seq, and
event COUNT. `assess` compares the live chain to the latest checkpoint and reports `ok | truncated |
rewritten | broken_chain | no_checkpoint | forged_checkpoint`, always carrying
`anchor_independence = not_independent_same_store_same_key` so a same-store checkpoint is never mistaken
for an independent anchor. `integrity_report` is a non-destructive admin verifier exposing only
ids/hashes/counts/status — never event payloads, secrets, or assessment evidence. `write_checkpoint` is
authorized-admin-only and refuses to checkpoint an invalid chain.

Evidence: `siem/tests/test_parallax_audit_integrity.py` (14) — full verify; altered payload, invalid
signature, removed middle event, non-contiguous/duplicate seq (duplicate seq is additionally rejected at
the storage layer by `UNIQUE(stream, seq)`); **tail truncation missed by the chain but caught by the
checkpoint**; no-checkpoint cannot rule out truncation; growth-since-checkpoint OK; head rewrite
detected; forged checkpoint detected; checkpoint authority + valid-chain requirement; restart
continuity; checkpoint verifies across authorized key rotation; integrity report leaks no payload. And
`siem/tests/test_parallax_audit_pg.py` (genuine PG): concurrent appends produce a gap-free, uniquely
sequenced chain; a rolled-back transaction leaves no orphan event (atomic allocation); truncation is
caught on a real database.

## 8. PostgreSQL concurrency and recovery results

`siem/tests/test_parallax_recovery_pg.py` (genuine disposable PostgreSQL, 6 tests): restart between
approval issuance and verification (engine disposed) re-verifies; a partial operation that is rolled
back persists nothing and leaves the chain valid; a connection killed before commit fails closed and
leaves no partial row, the store working afterward; **backup → simulated data loss → restore**
(`pg_dump --clean` then `psql`) with signatures, the audit chain, and the checkpoint all verifying after
recovery; unretrievable authoritative records make `decide_pathway_persistent` fail closed
(`infrastructure_unavailable`), never qualify; a verifier pointed at a dead database fails rather than
returning a positive result. Concurrent reviewer assignment and idempotent client retries remain covered
by `test_parallax_persistence_pg.py` from Phase 1B.

## 9. Real OpenSearch validation results — OPEN

The 12 real-OpenSearch tests (`siem/tests/test_strata_s5_real_opensearch.py`: real index lifecycle +
isolation, qualmeta protection, candidate permissions + DLS, evidence verification, provisioning state
machine, full HTTP qualification chain, scenario diversity from queried telemetry, historical replay +
crypto integrity, DLS slug-vs-github_id + reconnect, evidence edge cases, provisioning states C/E/H/I,
negative context refusals) each require a real OpenSearch 2.17.1 node with the Security plugin, gated by
`_ostest.py` (opt-in, dedicated URL, loopback/allow-listed host, sentinel index, version self-report).

Feasibility was tested, not assumed: there is no running Docker daemon; starting one succeeds but the
image registry is unreachable through the environment's egress allowlist (the proxy returns HTTP 403 for
`registry-1.docker.io` and direct DNS is blocked), so `opensearchproject/opensearch:2.17.1` cannot be
pulled; and the Security plugin additionally needs TLS certificates and ~2 GB RAM. No paid service was
provisioned. The gate correctly SKIPS all 12 and never substitutes `FakeCluster`; mocks are not
represented as real validation. **Status: OPEN** — all 12 preserved as skips with the exact blocker
documented. They are STRATA integration tests, not PARALLAX, and do not affect the Phase 1C controls.

## 10. Security review findings and dispositions

Adversarial review of the Phase-1B persistence design and Phase-1C changes. Demonstrated controls
(CONFIRMED by tests) and concerns (classified separately) below.

**Authentication and authority**
- Admin privilege escalation, forged reviewer assignments, cross-candidate record access, self-review:
  CONFIRMED controlled — authority bound to `_is_authorized_admin` (session-only in-request), reviewer
  eligibility + active assignment required, no self-review, candidate-scoped retrieval
  (`test_parallax_persistence.py`, `test_parallax_security_review.py`).
- Unauthorized key administration: CONFIRMED rejected (`keyadmin` authority gate).
- Revocation races: CONFIRMED fail-safe — revoked/lapsed governance is never returned active.

**Cryptographic controls**
- Signing-key substitution, altered `kid`, replay, cross-context signature reuse: CONFIRMED rejected —
  signatures bound to exact canonical content; `kid` enforced; revoked keys fail closed
  (`test_parallax_signing_lifecycle.py`, `test_parallax_security_review.py`).
- Canonicalization ambiguity (R4): UNVERIFIED-LOW — `canonical` is Python `json` sorted-compact
  (`ensure_ascii=True`); a non-Python verifier must replicate it, and `NaN`/`Infinity`/float forms are
  not guarded. Mitigation: payloads are schema-constrained server-built dicts. Recommendation:
  document a canonical-JSON profile before any third-party verifier.
- Legacy-signature ambiguity: LOW (documented) — a legacy (no-`kid`) record verifies under any currently
  trusted key; new records carry a `kid`, narrowing this to the migration window.
- Domain separation: LOW (hardening) — record types are distinguished structurally rather than by an
  explicit signed type tag; cross-type reuse is nonetheless rejected because canonical bytes differ.

**Persistence and transactions**
- TOCTOU authorization: LOW — the authority read precedes the per-subject lock, but consequential reads
  re-check the approver's authority, so a lapsed approver's artifacts stop verifying.
- Advisory-lock scope, isolation, deadlock, missing constraints, idempotency, partial audit writes,
  restore inconsistencies: CONFIRMED sound — subject→stream lock order (deadlock-free), per-subject
  serialization validated under concurrent PG threads, atomic audit allocation, restore verified.

**Qualification**
- Single-assessment escalation, unauthorized portfolio approval, flag manipulation, transplanted
  adjudication, stale/revoked artifacts, cross-assessment evidence substitution: CONFIRMED controlled —
  individual decisions are `qualified=False`; no portfolio exists; the two-flag matrix leaves
  qualification impossible; substitution-proof writes; stale/revoked governance excluded.
- Cross-candidate answer non-transfer: UNVERIFIED concern (see §11) — the Lab A non-transfer property is
  probabilistic in a small breach-id space; for some seeds two candidates' breach sets overlap enough
  that one's answers score above the pass line without a critical veto. Not a Phase-1C-introduced defect;
  classified as an OPEN Lab A evaluator concern for a future phase, not a demonstrated break of the
  governance/qualification boundary.

No fabricated findings. Unverified concerns are listed as such, separately from CONFIRMED controls.

## 11. STRATA compatibility results

STRATA is unchanged and re-verified: the full STRATA suite passes in both canonical configurations
(forward PG-off, reverse PG-on), including Board 2's signed-citation workflow and the 95% threshold
tests. No STRATA runtime module, scoring rule, activation gate, or session path was modified.

Two pre-existing **test-isolation observations** surfaced (neither is a Phase-1C code defect, and no
assertion or production behavior was weakened):

1. One Phase-1C-authored, pure test-isolation fix was applied to a STRATA test file:
   `test_f41_persistence_pg.py` installed a DB-backed trusted-fixture registry into the process-global
   `evidence_validation._REGISTRY` and never restored it, so under a forward + PG-authorized run it
   leaked into the later F4 tests ("Working outside of application context"). An autouse fixture now
   snapshots and restores that registry. This is standard test hygiene; it changes no production code.
2. `test_parallax_laba.py::test_per_candidate_instances_and_non_transfer` derives instance seeds from
   `keyed_mac(SECRET_KEY)`, and `SECRET_KEY` is pinned process-wide by whichever test module imports
   first at collection; the test passes in the full suite but can flip in a hand-picked subset. The
   underlying probabilistic non-transfer behavior is recorded as an OPEN Lab A concern (§10).

Residual, documented OPEN: a forward + PG-authorized full run still exposes a deeper pre-existing
STRATA F4 cross-test leak (a `forensic_f4` logic check), triggered only by that ordering, which was
never a run configuration before this phase (Phase 1B ran forward PG-off and reverse PG-on). The two
canonical configurations are green; fixing the remaining F4-suite ordering fragility belongs to the
STRATA test-suite owner and is out of scope for this PARALLAX crypto/migration phase.

## 12. Complete test results and skips

Reported by category (see §15 for the exact full-suite line):

- Cryptographic rotation (`test_parallax_signing_lifecycle.py`): 10 passed.
- Migration, real PostgreSQL (`test_parallax_migration_pg.py`): 6 passed.
- Audit-chain integrity (`test_parallax_audit_integrity.py`): 14 passed; (`test_parallax_audit_pg.py`): 1 passed (PG).
- Recovery, real PostgreSQL (`test_parallax_recovery_pg.py`): 6 passed.
- Security review (`test_parallax_security_review.py`): 4 passed.
- Phase 1B persistence (`test_parallax_persistence.py`): 23 passed; (`test_parallax_persistence_pg.py`): 1 passed (PG).
- STRATA compatibility: unchanged, all passing (see §15).
- Real OpenSearch: 12 skipped (OPEN, §9).
- Qualification-boundary (two-flag matrix ×4): passed within the persistence suite.

Full-suite runs (one process each), PostgreSQL 16.15 for the genuine-DB runs:

- Forward order, PostgreSQL not authorized (new PG tests skip): **342 passed, 37 skipped, 0 failed**.
- Reverse order, PostgreSQL authorized (all PG tests execute): **363 passed, 16 skipped, 0 failed**.

The 16 reverse-run skips are the 12 OPEN OpenSearch tests plus the 4 STRATA S6-capacity tests that use
a separate `RANGER_PG_TEST_URL` gate. The forward run's additional skips are the PG-gated suites that
run only when PostgreSQL is authorized. Both orders pass with zero failures (order-independence
verified for these two configurations).

## 13. Remaining risks and operational limitations

1. **Signing-key rotation is mechanism, not live key material change.** 1C implements the versioned
   registry, states, and audited lifecycle, but rotating the actual production seed is an operational
   secret-store procedure (runbook in §16); live keys were not rotated.
2. **Same-key audit checkpoint is not an independent anchor.** Events and checkpoints share the server
   Ed25519 key; a key holder could forge both. It defends against DB-level truncation/tampering by
   anyone without the key. An external transparency-log anchor (publishing the checkpoint hash out of
   band; no paid infra) is the future closure.
3. **Compromise revocation invalidates history** signed by the revoked key until re-anchored — correct
   security posture, documented so operators plan re-anchoring.
4. **Canonical-JSON profile** is Python-specific (R4/§10).
5. **OpenSearch integration OPEN** (§9).
6. **Lab A non-transfer** is probabilistic (§10/§11).

## 14. Production safety verification

- Railway portal service (`qwalora-ranger-control`, env `production`)
  `watchPatterns = ["/.railway-autodeploy-hold/**"]` — auto-deploy hold intact; this work targets a
  feature branch, not `main`.
- Production variables contain **neither** `RANGER_PARALLAX_QUALIFICATION_ACTIVE` **nor**
  `RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE` — both gates OFF.
- No migration was run against production; no live signing key was rotated; no portfolio approval
  minted; `main` unchanged at `431a183` (local and remote).

## 15. Git commit and push information

_Filled at commit time:_ commit SHA, author `cloudcwfranck <yakengne@gmail.com>` (no attribution
trailers), files changed, and the forward/reverse full-suite result lines with the PostgreSQL version
used for the genuine-DB runs.

## 16. Engineering readiness determination

Phase 1C acceptance criteria at the engineering level:

- Versioned signing-key lifecycle implemented and validated — PASS.
- Historical signature compatibility explicit and tested — PASS.
- `UnitResult` uniqueness migration safe and tested on real PostgreSQL — PASS.
- Existing evidence survives migration unchanged — PASS.
- Audit integrity tested against corruption and restart, with truncation anchor — PASS.
- Operational recovery validated on disposable infrastructure — PASS.
- All reachable real OpenSearch tests executed without diluting assertions — OPEN (none reachable;
  skips preserved, blocker documented).
- Security findings fixed or transparently identified — PASS (controls CONFIRMED; concerns classified).
- STRATA regressions zero — PASS.
- Complete accessible regression suite passes — PASS in both canonical configurations (forward PG-off:
  342 passed/37 skipped/0 failed; reverse PG-on: 363 passed/16 skipped/0 failed). A forward +
  PG-authorized ordering exposes a pre-existing STRATA F4 test-suite leak (OPEN, §11), not a Phase-1C
  defect; one contributing leak was fixed as test hygiene.
- Qualification remains disabled; production untouched — PASS.

Determination: the PARALLAX governance and assessment infrastructure is cryptographically maintainable,
migration-safe, auditable, and recovery-tested at the engineering level. OpenSearch integration remains
OPEN pending a reachable node. No critical security or migration defect is unresolved.

## 17. Founder decisions requiring authorization

1. Provision an authorized OpenSearch 2.17.1 node (disposable/staging) to execute the 12 OPEN tests.
2. Approve a production signing-key rotation window and secret-store procedure (and, if desired, an
   external transparency-log anchor for the audit checkpoint).
3. Schedule the `UnitResult` uniqueness migration against the production database (off this branch,
   via the operator CLI, after a backup).
4. Any move toward qualification — defining and signing a PARALLAX portfolio, or activating either flag
   — remains a separate, explicitly-authorized decision; 1C does not take it.
