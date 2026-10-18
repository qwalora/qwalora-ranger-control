# PARALLAX — AI Security, Adversarial Systems & Digital Trust (Phase 1 foundations)

PARALLAX is Qwalora Ranger's advanced qualification pathway for **AI-security, adversarial-systems,
and digital-trust engineering**. It shares the Ranger platform with STRATA (cybersecurity) but is
architecturally distinct. PARALLAX is **not** a general machine-learning engineering qualification and
**not** a curriculum in statistics or reproducible ML experimentation. It measures an engineer's
ability to find, prove, and reason about security and trust failures in AI systems through bounded,
executable investigations with server-protected grading truth and independently verifiable evidence.

This document is the Phase 1 foundation and the mission of record. It is design plus one working,
executable first assessment (Lab A). Board count, duration, overall passing threshold, and
qualification authority are **not** assigned here and must not be set without separate approval.

## Mission and competency domains

PARALLAX's established competency domains (these are domains, not necessarily boards):

1. **Agent and tool authorization security** — a tool-using AI agent stays within its authorized tool
   and resource scope; unauthorized or out-of-scope tool use and cross-tenant access are detected.
2. **LLM and RAG trust boundaries, prompt injection, and data isolation** — untrusted retrieved or
   user content cannot subvert authorization or exfiltrate tenant-isolated data.
3. **AI red teaming and adversarial evaluation** — systematic adversarial probing and the honest
   evaluation of model/system robustness and failure modes.
4. **Model and AI supply-chain security** — integrity and provenance of models, weights, datasets, and
   pipeline artifacts; detection of tampering and poisoning.
5. **Synthetic media, multimodal fraud, and digital provenance** — detection and provenance
   verification for manipulated or synthetic media.
6. **AI incident response and forensic investigation** — investigating an AI-involved incident,
   reconstructing what happened, and producing defensible, evidence-backed findings.

For any domain to become a graded board, it must first define all ten of: (1) what the engineer must
demonstrate; (2) authorized tools + execution environment; (3) prerequisites; (4) the task/investigation;
(5) the artifact produced; (6) independent evaluation; (7) critical-failure conditions; (8) repeatability
and integrity; (9) safely revealed feedback; (10) why it measures competence, not memorization.

## One platform, two tracks (compatibility architecture)

Reused unchanged (pathway-neutral): `pathways` (PARALLAX identity); `siem.assessment_contract.decide`
(the shared ten-concern decision engine, STRATA and PARALLAX policy branches); the `siem.evaluator`
Evaluator / signed ObjectiveCheckResult / ProtectedTruthHandle / EvaluatorScope contract; top-level
`signing` (Ed25519); `siem.schema.keyed_mac`; and the pathway-scoped, signed `models.UnitResult`
record. STRATA grading is untouched: its objective bar stays `program.PASS_BAR = 95.0`.

Kept STRATA-isolated (PARALLAX builds parallels, never extends): the six-board STRATA ladder
(`program.py`), `siem/board_variants.py`, STRATA scenario generators/graders, Board 2 qualification.

Hard isolation invariant (enforced by `assessment_contract.decide` and by the pathway-qualification
engine): a PARALLAX decision requires a PARALLAX-scoped authorization and a PARALLAX blueprint, so a
PARALLAX submission can never award STRATA credit and vice versa.

## Qualification boundary (assessment completion is NOT pathway qualification)

Two distinct levels, deliberately separated:

- **Assessment completion** — the outcome of one lab: a signed assessment record stating whether that
  lab's objective checks passed, its critical-failure vetoes are clear, and its human review passed. A
  single-assessment decision is **assessment-only**: `assessment_contract.decide` returns
  `qualified=False` for every PARALLAX assessment **regardless of any activation flag** (the prior
  coupling to `RANGER_PARALLAX_QUALIFICATION_ACTIVE` at the assessment level is removed; that flag is
  now only an informational surface flag). No score, remediation, reviewer pass, signature, or flag can
  make a lab read as a final award.
- **Pathway qualification** — a separate decision (`parallax.pathway_qualification.decide_pathway`)
  that requires ALL of: a **signed, authorized portfolio approval** (`governance.approve_portfolio`)
  binding the exact required-competency inventory — there is no caller-controlled `approved` boolean; a
  verified, signed, passing assessment record for every required competency whose OWN signed identity
  (candidate, cohort, assessment id, attempt, provenance) matches the slot, so a valid signature
  transplanted from another candidate or assessment is rejected; an independent **authorized, assigned
  reviewer adjudication** bound to that same identity and provenance for each; and a separately-
  authorized platform activation (`RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE`, OFF). It fails closed
  on any missing piece. No approved portfolio exists yet, so pathway qualification is currently
  impossible by construction.

The pathway gate (`RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE`) is the only qualification activation,
and it is OFF and kept off in Phase 1.

### Governance, reviewer authority, and binding

- **Versioned approval governance** replaces any hardcoded `approved=True`. An assessment spec binds a
  candidate instance only when an authorized admin has issued a signed approval record binding the
  **complete consequential scoring specification** — the spec identity, metric and threshold, and the
  full blueprint hash (rubric dimensions, critical-failure conditions, objective evaluator/checks,
  decision policy, evidence requirements, environment version) (`parallax.governance`). Any material
  change to the spec or blueprint moves the scoring-spec hash and invalidates the approval until it is
  reissued. An unapproved or drifted assessment cannot produce an instance.
- **Authenticated, assigned reviewer authority** (`parallax.review`): a reviewer adjudication is
  accepted only when the reviewer is an authorized reviewer AND was assigned to this
  (candidate, cohort, assessment, attempt), and the adjudication is a signed record bound to that
  identity and to the assessment record's hash. A mere non-empty reviewer id is rejected. Reviewer
  decisions and rubric scores are never accepted from the candidate-accessible boundary.
- **Cryptographic + logical binding**: the signed final assessment record binds the submission content
  hash, the evidence/citation references, the evaluator's signed result, the verified reviewer
  adjudication, the spec/blueprint hash, the instance-contract MAC, and the
  candidate/cohort/assessment/attempt identity. Tampering with any part invalidates the record.

## PX-1 (leakage-safe model evaluation): experimental component only

PX-1 remains in the tree as a **clearly-labeled, reusable experimental assessment component** for
data-integrity / leakage reasoning. It is **not** a mandatory PARALLAX qualification, **not** the first
PARALLAX assessment, and does **not** drive the approved progression. The previously-proposed general-ML
"P2" progression is **cancelled**. PX-1 is retained only because its leakage-ablation evaluation pattern
is a useful, well-tested building block that an AI-security lab may reuse.

## Lab A — Agent & Tool Authorization Security (the actual first assessment)

Competency 1 (agent/tool authorization security) with material overlap into competency 2 (RAG trust
boundaries / data isolation). Implemented in this phase as a working vertical slice.

**Environment (bounded, offline, deterministic).** An enterprise simulator with: an AI agent serving
multiple tenants; a fixed tool catalog (read/search/share/export/delete/escalate class tools); an
authorization policy (per-principal, per-tenant tool and resource scope); tenant-scoped documents; a
realistic sequence of observable agent events (tool calls with principal, tenant, resource, and an
OBSERVED outcome); approved/benign operations that must keep working; and adversarial events driven by
untrusted retrieved content (RAG) carrying injected instructions that attempt cross-tenant access,
out-of-scope tools, or privilege escalation. No live model, no network, no GPU, no external inference,
no execution of candidate-supplied code.

**Task.** The candidate investigates the observable event log and the authorization policy and submits
**evidence-backed findings**: for each event they flag, a classification (actual unauthorized access /
blocked attempt / legitimate) with a cited event id as evidence, plus a short written root-cause /
policy-gap analysis. The grading truth (the true per-event classification and the injected-instruction
provenance) is sealed server-side and never shown to the candidate.

**Objective evaluation (deterministic, replay-based).** The evaluator independently replays the policy
over the sealed event log to recompute truth, then scores the candidate's findings: it distinguishes
actual unauthorized access (a breach that occurred), successfully blocked attempts, unsupported claims
(a flagged event with no valid supporting citation), and legitimate activity. Precision and recall over
breaches are both scored, so flagging everything as a breach fails (false positives on benign ops tank
precision; "deny everything" cannot pass). Critical-failure vetoes: missing an actual cross-tenant
breach that occurred, or asserting a breach with no valid evidence citation. The narrative analysis is
human-reviewed. Per-candidate instances differ (principals, tenants, which events are breaches vs
blocked), so solutions do not transfer. Simulated incidents are always labeled as simulated; they are
never presented as externally observed.

## What Phase 1 delivers (this branch)

Governance (`governance`), reviewer authority (`review`), pathway-qualification separation
(`pathway_qualification`); the Lab A simulator (`laba_sim`), the implemented `agent_authorization`
evaluator (`laba_evaluator`), the Lab A spec/blueprint (`laba_blueprint`), the candidate-safe brief
(`laba_brief`), and the end-to-end orchestration (`laba_assessment`); an optional workbench route behind
a default-off flag; and tests (positive, negative, tampering, authorization, cross-candidate,
cross-tenant, replay, concurrency, STRATA regression). PX-1 is retained as an experimental component.

Phase 1 enables no public enrollment and no real awards. No board count, duration, overall threshold,
or qualification authority is declared. No paid services, GPUs, or external model APIs are used.

## Phase 1B — persistent governance, reviewer authority, and evidence integrity

Phase 1B makes the Phase-1 governance, reviewer-authority, and assessment-evidence layers **durable,
independently verifiable, securely stored, and enforceable across application restarts and concurrent
operations**. It is infrastructure; it does **not** activate qualification, mint a portfolio approval,
or issue any award.

**Persistence model (all server-side, in the single `models.py`).**

- `ParallaxApproval` (`parallax_approvals`) — signed, versioned scoring-spec and portfolio approvals.
  Content columns (`content_hash`, `approval_record`, `signature`, `approver_id`) are immutable;
  lifecycle is expressed only through `status` (`active`/`revoked`/`superseded`) and the
  `revoked_*`/`superseded_by` columns. `UNIQUE(kind, content_hash)` makes an approval idempotent on its
  exact content. Managed by `registry`.
- `ParallaxReviewerAssignment` (`parallax_reviewer_assignments`) — authoritative reviewer→attempt
  bindings. `UNIQUE(candidate_key, cohort, assessment_id, attempt, reviewer_id)`. Managed by
  `reviewer_store`.
- `ParallaxAuditEvent` (`parallax_audit_events`) — append-only, Ed25519-signed, hash-chained audit
  trail; `UNIQUE(stream, seq)`. Managed by `auditlog`.
- `UnitResult` — the durable signed assessment records (`kind` = `qualification_decision` |
  `reviewer_adjudication`), `UNIQUE(candidate_id, unit_ref, kind, record_hash)`. Managed by
  `assessment_store`.

**Guarantees and how they are enforced.**

- **Authority is server-side.** Every governance/reviewer mutation calls
  `registry._authorize` → `strata_catalog._is_authorized_admin`; in an HTTP request only the session
  identity is trusted, never a caller-supplied principal. The eligible set is the reviewer allowlist
  (`REVIEWER_GITHUB_IDS`) ∪ `AdminUser` rows with an approver role. Being an administrator does not by
  itself make one an assigned reviewer.
- **Restart survival.** The exact canonical signed record is stored and re-verified on read
  (`assessment_contract.verify_decision`, `governance.verify_*`), so a process restart changes nothing
  about verifiability. An approval is additionally honored only while its approver's governing
  authorization is still effective.
- **Idempotency + concurrency.** Each mutation takes a per-subject PostgreSQL advisory lock
  (`pg_advisory_xact_lock`, a no-op on SQLite) **before** its get-or-create/conflict read, so a
  concurrent writer blocks and then observes the committed row — rather than racing to a duplicate
  INSERT. This is backed by the UNIQUE constraints and a commit-time recovery path. The
  "one active reviewer per attempt" rule has no unique-constraint backstop (two different reviewers are
  two distinct rows), so the advisory lock on the attempt key is load-bearing and is validated under
  genuine concurrent PostgreSQL threads.
- **Substitution-proof writes.** An assessment record is persisted under a candidate only if the
  record's **own** signed binding names that candidate; cross-candidate/assessment/cohort/attempt
  substitution is rejected on write. Adjudications are append-only rows linked to the decision's
  provenance hash, never mutations.
- **Portfolio decision integrity (fail closed).** `pathway_persistent.decide_pathway_persistent` feeds
  `pathway_qualification.decide_pathway` entirely from persisted, verified records. `active_portfolio`
  returns a policy only when exactly one active, signature-valid portfolio approval exists; zero (the
  Phase-1B reality) or ambiguous fails closed. **No approved PARALLAX portfolio exists, so a final
  pathway qualification is impossible by construction, regardless of how a candidate performed in any
  single assessment and regardless of either activation flag.**

**Known limitations (documented, not resolved in 1B).**

1. **Signing-key rotation.** `signing` uses a single Ed25519 key derived from `RANGER_SIGNING_KEY`
   (else `SECRET_KEY`), cached at import, with no key id (`kid`) and no rotation. Every persisted
   signature therefore verifies only while that key is unchanged; rotating or losing the signing key
   invalidates verification of all previously persisted approvals, assessment records, and audit
   events. A production rotation strategy (keyed `kid`, multi-key verification window, re-signing or
   re-anchoring of historical records) is required before any real award and is out of scope for 1B.
2. **UnitResult unique-constraint retrofit.** `UNIQUE(candidate_id, unit_ref, kind, record_hash)` is
   created for fresh databases via `create_all`. The additive `ensure_schema` migration adds columns
   but not constraints, so an **existing** production `unit_results` table needs a manual
   `ALTER TABLE … ADD CONSTRAINT` to gain the DB-level guarantee. Application-level idempotency does
   not depend solely on the constraint — the per-subject advisory lock plus get-or-create plus
   commit-time recovery enforce single-record semantics even without it — but the DB constraint should
   be added as a migration step on pre-existing databases for defense in depth.

**Validation.** Workstream F runs adversarial/regression tests over both activation flags
(`RANGER_PARALLAX_QUALIFICATION_ACTIVE`, `RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE`) independently
and together, including restart, revocation, authority-lapse, audit-tamper, substitution, and
flag-matrix cases. Genuine database transaction and concurrency behavior is validated against a local,
disposable PostgreSQL instance through the positively-authorized `_pgtest` boundary (opt-in, dedicated
test URL, loopback/allow-listed host, sentinel database, throwaway per-test database); when that
authorized instance is absent the PostgreSQL tests fail closed (skip) and never touch a real database.
