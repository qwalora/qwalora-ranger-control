# PARALLAX Phase 1B — Engineering Report

**Persistent governance, reviewer authority, and evidence integrity**

Branch: `feature/parallax-p1-architecture-foundations` · Baseline handoff: `f70299f` · `main`: unchanged at `431a183`
Scope: infrastructure hardening only. No qualification activation, no portfolio approval, no awards.

---

## 1. Executive summary

Phase 1B makes PARALLAX governance approvals, reviewer assignments, and assessment records **durable,
independently verifiable, securely stored, and enforceable across application restarts and concurrent
operations** — all server-side. It converts the Phase‑1 in‑memory/ephemeral governance surfaces into
persisted, signed, authority‑bound tables with an append‑only audit trail, and feeds the pathway
decision entirely from those persisted, re‑verified records.

The work is additive. STRATA is unchanged and re‑verified (95% bar, Board 2 signed‑citation workflow,
activation, auth/session). No PARALLAX qualification flag was enabled, no portfolio approval was minted,
and no real reviewer, award, lab, GPU, paid service, or live adversarial target was introduced. The
Railway production deployment hold is intact and `main` is untouched.

A genuine concurrency bug was found and fixed during real‑PostgreSQL validation (Section 8): the
per‑subject advisory lock was acquired *after* the idempotency check, so a concurrent writer could trip
a unique violation during autoflush instead of returning idempotently. The lock is now taken before the
check, validated under concurrent PostgreSQL threads.

## 2. Mandate, prohibitions, and stop conditions

**Delivered (A–F):** persistent governance registry; authoritative reviewer identity + assignment;
durable signed assessment records; portfolio decision integrity over persisted records; STRATA
preservation; adversarial/regression testing including restart, revocation, concurrency, and the
two‑flag matrix, with genuine disposable‑PostgreSQL validation.

**Not done, by mandate (all honored):** no merge to `main`; no Railway production deploy; the Railway
deployment hold was not modified; neither `RANGER_PARALLAX_QUALIFICATION_ACTIVE` nor
`RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE` was enabled; no production portfolio approval minted; no
real qualification awards/credentials; no new PARALLAX lab; no GPU; no live adversarial targets; no new
paid infrastructure. Simulated evidence is labeled simulated and is never presented as genuine
infrastructure evidence. No Phase‑1 signed‑governance control was weakened or bypassed. The disposable
PostgreSQL used for validation is local and ephemeral and did not touch Railway production.

## 3. Workstream A — Persistent governance registry

`parallax/registry.py` + `models.ParallaxApproval` (`parallax_approvals`). Scoring‑spec and portfolio
approvals are persisted as **signed, versioned** records. Properties enforced:

- **Signed & versioned.** Each row stores the exact canonical `approval_record`, its Ed25519
  `signature`, `assessment_version`/`policy_version`, and the `content_hash` that fingerprints the
  complete approved content (for a scoring spec: rubric, critical‑failure conditions, evaluator
  identity, and blueprint hash — Phase‑1 finding 5).
- **Authorized‑admin bound.** Every mutation runs through `registry._authorize` →
  `strata_catalog._is_authorized_admin`; inside an HTTP request only the session identity is trusted,
  never a caller‑supplied principal. The eligible set is `REVIEWER_GITHUB_IDS` ∪ `AdminUser` approver
  rows, read server‑side.
- **Immutable content, revocable status.** Content columns never change; lifecycle is expressed only
  through `status` (`active`/`revoked`/`superseded`) and `revoked_*`/`superseded_by`. Re‑approving the
  exact content that was revoked is refused (no silent re‑approval).
- **Idempotent on content.** `UNIQUE(kind, content_hash)` + advisory lock + get‑or‑create + commit‑time
  recovery: approving the same content twice returns the same row, never a duplicate.
- **Read‑time re‑verification.** `active_spec_approval`/`active_portfolio_approval` re‑verify the stored
  signature and return `None` if it does not verify **or** if the approver’s governing authorization has
  since lapsed (approval valid only while its authority is effective).
- **Audited.** Every issuance, revocation, and supersession writes a signed audit event atomically with
  the change.

## 4. Workstream B — Reviewer identity and assignment authority

`parallax/reviewer_store.py` + `models.ParallaxReviewerAssignment` (`parallax_reviewer_assignments`).
Reviewer authority is server‑side and bound to Ranger’s administrative identity:

- Eligibility to adjudicate requires **both** an eligible reviewer identity (allowlist ∪ `AdminUser`
  reviewer role) **and** an active, unexpired assignment to the exact `(candidate, cohort, assessment,
  attempt)`. Being an administrator does not by itself make one an assigned reviewer.
- Assignments are created/revoked only by an authorized administrator; no self‑review; one active
  reviewer per attempt; idempotent re‑assignment of the same reviewer.
- `directory_for*` builds the existing `review.ReviewerDirectory` from live DB rows, so the unchanged
  `review.verify_adjudication` enforces the same binding against authoritative data.
- Every lifecycle action is audited.

## 5. Workstream C — Durable signed assessment records

`parallax/assessment_store.py`, persisting into `models.UnitResult` (`kind` =
`qualification_decision` | `reviewer_adjudication`). Preserves every Phase‑1 signed‑identity property
(candidate, cohort, assessment id+version, attempt, competency, provenance, `unit_ref`,
blueprint/scoring‑spec identity, reviewer binding):

- **Verification never weakened.** The exact canonical signed decision is stored and re‑verified with
  `assessment_contract.verify_decision` on read. A record whose signature does not verify is refused on
  write (fail closed).
- **Substitution‑proof.** A record is stored under a candidate only if the record’s **own** signed
  binding names that candidate; cross‑candidate/assessment/cohort/attempt substitution is rejected.
- **Idempotent & append‑only.** `UNIQUE(candidate_id, unit_ref, kind, record_hash)` + advisory lock +
  get‑or‑create + commit‑time recovery. Adjudications are append‑only rows linked to the decision’s
  provenance hash, never mutations.
- **Candidate‑scoped retrieval.** A candidate may read only their own records.
- Consistent with Phase‑1 finding 1, a persisted decision carries `qualified=False`: an individual
  assessment is evidence, never a qualification.

## 6. Workstream D — Portfolio decision integrity over persisted records

`parallax/pathway_persistent.py` feeds `pathway_qualification.decide_pathway` entirely from persisted,
verified inputs: the approved portfolio policy (reconstructed from its signed approval and re‑verified),
the candidate’s signature‑valid assessment records, and live reviewer assignments.

- **Fail closed.** Any missing record, verification failure, or infrastructure error yields
  `qualified=False` with reason `infrastructure_unavailable` (or the specific closed‑path reason).
- **No approved portfolio exists.** `active_portfolio` returns a policy only when exactly one active,
  signature‑valid portfolio approval exists; zero (the Phase‑1B reality) or ambiguous fails closed.
  Therefore **a final pathway qualification is impossible by construction**, regardless of how a
  candidate performed in any single assessment and regardless of either activation flag. A single
  assessment can never independently establish pathway qualification.

## 7. Append‑only signed audit trail

`parallax/auditlog.py` + `models.ParallaxAuditEvent` (`parallax_audit_events`). Modeled on Ranger’s
custody chain: each event carries its own `record_hash`, links to the prior event’s hash
(`parent_hash`), and is Ed25519‑signed. `UNIQUE(stream, seq)`. Events are added to the caller’s
transaction, so an audit entry commits atomically with the action it records — or not at all. Only
ids/hashes are logged (no secrets, tokens, evidence payloads, or unnecessary PII). `verify_chain`
re‑checks every signature and the unbroken parent‑hash chain; tampering with any event is detected.

## 8. Concurrency and transaction model (bug found + fixed)

Every mutating operation takes a **per‑subject PostgreSQL advisory lock** (`pg_advisory_xact_lock`,
auto‑released at commit/rollback; a no‑op on SQLite) **before** its idempotency/conflict read, then the
shared audit‑stream lock inside `auditlog.append`. Lock order is always *subject → stream*, a consistent
order that cannot deadlock. The subject keys are: `scoring_spec`/`portfolio` content hash; the
`(candidate, cohort, assessment, attempt)` assignment key; and the `(candidate, unit_ref)` assessment
key.

**Bug found via genuine PostgreSQL validation.** Originally the advisory lock was acquired only inside
`auditlog.append`, i.e. *after* the get‑or‑create check and after the new row was already pending in the
session. Under real concurrent connections, two writers both passed the "does it exist yet?" check, both
staged an INSERT, and the second writer tripped the `UNIQUE` constraint during an **autoflush inside
`auditlog.append`** — before reaching the commit‑time recovery path — so the idempotent write raised
instead of returning the winner. Fix: acquire the per‑subject lock at the top of each mutation
(`registry.store_spec_approval`/`store_portfolio_approval`, `reviewer_store.assign_reviewer`,
`assessment_store.record_assessment`). A concurrent writer now blocks there and, once the first commits,
observes the committed row and returns idempotently (or, for reviewer assignment, is correctly refused).

The "one active reviewer per attempt" rule has **no unique‑constraint backstop** (two different
reviewers are two distinct rows), so the advisory lock on the attempt key is load‑bearing for that
invariant and is explicitly validated under concurrent threads.

## 9. Data model and schema/migration changes

New tables (created whole by `create_all`; they are new `db.Model`s so they need no `ensure_schema`
entry): `parallax_approvals`, `parallax_reviewer_assignments`, `parallax_audit_events`. One constraint
added to the existing `unit_results`: `UNIQUE(candidate_id, unit_ref, kind, record_hash)`.

**Migration limitation (documented).** `create_all` applies the new `unit_results` constraint to fresh
databases. The additive `ensure_schema` convention adds columns, not constraints, so a **pre‑existing**
production `unit_results` table needs a one‑time manual `ALTER TABLE … ADD CONSTRAINT
uq_unit_result_record UNIQUE(candidate_id, unit_ref, kind, record_hash)`. Application‑level idempotency
does not depend solely on the DB constraint (advisory lock + get‑or‑create + commit‑time recovery), but
the constraint should be added on existing databases for defense in depth.

## 10. Workstream E — STRATA preservation

STRATA is unchanged and re‑verified. The full STRATA suite passes in both collection orders, including
Board 2’s signed‑citation workflow and the 95% threshold tests (`test_strata_s5_board2.py`:
`test_score_below_95_does_not_award`, idempotent re‑evaluation, cached‑decision rejection on source
alteration, authorized‑gate‑closed‑without‑activation, full candidate→reviewer HTTP chain). No STRATA
runtime module, scoring rule, activation gate, or session/auth path was modified. The one test change in
this phase is a **test‑isolation fix** (Section 11), not a behavior change.

## 11. Workstream F — Test and validation methodology

**In‑process DB‑backed suite** (`siem/tests/test_parallax_persistence.py`, SQLite in‑memory): governance
auth/idempotency/restart/drift/revoke/authority‑lapse/audit‑tamper; reviewer
auth/ineligible/self‑review/one‑per‑attempt/revoked/scope‑isolation; evidence
persist‑restart/idempotent/substitution/access‑control/tamper‑verify; pathway
no‑portfolio‑impossible‑with‑flags‑on; the **two‑flag matrix** over
`RANGER_PARALLAX_QUALIFICATION_ACTIVE` and `RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE` independently
and together; infrastructure‑unavailable‑fails‑closed. The module snapshots and restores the flags it
touches so it neither depends on nor leaks process state.

**Genuine PostgreSQL validation** (`siem/tests/test_parallax_persistence_pg.py`): runs only against a
**positively‑authorized, local, disposable** PostgreSQL via `siem/tests/_pgtest.py` (opt‑in
`RANGER_TEST_ALLOW_DB_MUTATION`, dedicated `RANGER_TEST_DATABASE_URL`, loopback/allow‑listed host,
production‑DB‑absent probe, sentinel database, throwaway per‑test database). It asserts the real
`postgresql` dialect (not a mock), then validates under concurrent threads: concurrent spec approval →
exactly one row; concurrent assessment record → exactly one decision row; a two‑reviewer assignment race
→ exactly one active assignment; and re‑verification of persisted signatures and the audit chain after
reconnect. When the authorized instance is absent, it **fails closed (skips)** and never touches a real
database. A mocked DB test is never described as real PostgreSQL validation.

**Order‑independence.** The full suite was run in forward and reverse collection order. Reverse order
surfaced one pre‑existing latent order‑dependence (unrelated to Phase‑1B code): `test_strata_board2_compat.py`
set `RANGER_WORKBENCH_ASSESSMENT_VISIBILITY` only at import time while a sibling test mutates that
process env at run time without restoring it, so in reverse order the flag arrived cleared and
`assessment_status_view` returned the "hidden" shape (`KeyError: 'qualification_active'`). Fixed with an
autouse per‑test fixture in that module that re‑applies its required env before each test and restores
prior values after (snapshot/restore, not pop). After the fix the reverse run is clean.

**Disposable PostgreSQL also used for STRATA.** The 4 STRATA S6 transactional‑capacity concurrency tests
(their own separate `RANGER_PG_TEST_URL` gate) were run against a dedicated disposable database and pass
(8/8 in that file), so STRATA capacity concurrency is genuinely validated on real PostgreSQL as well.

## 12. Verification results

| # | Criterion | Result |
|---|-----------|--------|
| 1 | Full suite, forward order, PG off | **PASS** — 314 passed, 24 skipped, 0 failed |
| 2 | Full suite, reverse order, PG authorized | **PASS** — 322 passed, 16 skipped, 0 failed |
| 3 | Genuine PostgreSQL PARALLAX concurrency (real dialect asserted) | **PASS** |
| 4 | STRATA S6 capacity concurrency on disposable PG | **PASS** — 8/8 |
| 5 | STRATA 95% bar + Board 2 signed‑citation workflow | **PASS** |
| 6 | Governance: signed, versioned, authority‑bound, immutable, revocable, idempotent, restart‑verified, audited | **PASS** |
| 7 | Reviewer: authority‑bound, no self‑review, one active/attempt (lock‑enforced), idempotent, audited | **PASS** |
| 8 | Assessment records: signed, substitution‑proof, idempotent, append‑only, candidate‑scoped, restart‑verified | **PASS** |
| 9 | Pathway integrity: fails closed; no approved portfolio ⇒ qualification impossible with either/both flags on | **PASS** |
| 10 | Audit chain tamper‑evident (signatures + parent‑hash chain) | **PASS** |
| 11 | Collection‑order independence | **PASS** (after test‑isolation fix) |
| 12 | Railway hold intact, both flags OFF in prod, `main` untouched | **PASS** (read‑only verification) |
| 13 | Real‑OpenSearch integration tests | **OPEN** — 12 skipped; require a real OpenSearch 2.17.1 node (no node provisioned; no paid infra / live targets by mandate) |
| 14 | Behavior of the retrofit `UNIQUE` on a pre‑existing production `unit_results` | **OPEN** — needs the one‑time `ALTER TABLE` migration (Section 9); code‑level idempotency holds regardless |
| 15 | Production/at‑scale behavior under Railway load | **OPEN** — not activated; no production deploy performed by mandate |

## 13. Known limitations and risks

1. **Signing‑key rotation.** `signing` uses a single Ed25519 key (`RANGER_SIGNING_KEY` else
   `SECRET_KEY`), cached at import, with no key id and no rotation. Persisted signatures verify only
   while that key is unchanged; rotating or losing it invalidates verification of all previously
   persisted approvals, assessment records, and audit events. A production rotation strategy (keyed
   `kid`, multi‑key verification window, re‑signing/re‑anchoring) is required before any real award and
   is out of scope for 1B.
2. **UnitResult constraint retrofit** on pre‑existing databases (Section 9).
3. **Single global audit stream.** `seq` is allocated under one stream lock; correct and simple, but it
   serializes audit writes across all governance operations. Acceptable for low‑frequency,
   human‑driven governance; revisit if write volume grows.
4. **OPEN items** in Section 12 (rows 13–15) are unverifiable in this offline, no‑paid‑infra, no‑activation
   environment and are reported as OPEN, not PASS.

## 14. Deployment safety posture

- Portal service (`qwalora-ranger-control`, env `production`) `watchPatterns=["/.railway-autodeploy-hold/**"]`
  — the auto‑deploy hold is intact; a push to `main` would not trigger a deploy, and this work targets a
  **feature branch**, not `main`. `staged: null` (no staged changes).
- Production variables contain **neither** `RANGER_PARALLAX_QUALIFICATION_ACTIVE` **nor**
  `RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE` — both activation gates are OFF in production.
- Latest production deployment (2026‑10‑15, SUCCESS) is unrelated STRATA/SIEM work on `main`; no PARALLAX
  deployment occurred. `main` is unchanged at `431a183`.

## 15. Handoff

**New production modules:** `parallax/registry.py`, `parallax/reviewer_store.py`,
`parallax/assessment_store.py`, `parallax/pathway_persistent.py`, `parallax/auditlog.py` (≈619 LOC).
**Model additions:** `ParallaxApproval`, `ParallaxReviewerAssignment`, `ParallaxAuditEvent`, and the
`UnitResult` unique constraint in `models.py`. **Docs:** this report and the Phase 1B section of
`docs/PARALLAX_ARCHITECTURE.md`. **Tests:** `siem/tests/test_parallax_persistence.py` (in‑process) and
`siem/tests/test_parallax_persistence_pg.py` (genuine PG).

**Run the in‑process suite:** `cd siem && python -m pytest tests/test_parallax_persistence.py`.

**Run genuine PostgreSQL validation** against an authorized local disposable server:

```
RANGER_TEST_ALLOW_DB_MUTATION=1 \
RANGER_TEST_DATABASE_URL="postgresql+psycopg2://<user>@127.0.0.1:<port>/postgres" \
RANGER_TEST_SENTINEL_DB=ranger_test_sentinel \
python -m pytest siem/tests/test_parallax_persistence_pg.py
```

(Create the sentinel database once on the dedicated test server to authorize destructive tests.)

**Next steps (future phases, not this one):** a signing‑key rotation strategy before any real award; the
`unit_results` constraint migration on existing databases; and, only under separate approval, the
definition and signed approval of a PARALLAX portfolio and the controlled activation of the pathway
qualification gate.
