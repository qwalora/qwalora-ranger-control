# PARALLAX Operational Readiness Package (Phase 1E Workstream G)

Implementation-grounded readiness for a future **controlled pilot** of the integrated PARALLAX
assessment lifecycle. This describes prerequisites and procedures only; it executes no production
integration. Every control referenced here is implemented and tested on the feature branch.

## Three assessment modes (precise differences)

| Mode | Routes / entry | Governance | Persistence | Reviewer | Infrastructure | Qualification |
|---|---|---|---|---|---|---|
| **Local simulation** (dev preview) | `/parallax/laba/brief`, `/parallax/laba/evaluate` (dry-run) | env-supplied signed approval | none | none (dry-run) | Lab A in-process simulation | never |
| **Integrated nonproduction assessment** (Phase 1E) | `/parallax/laba/assessment`, `/status`, `/review/*`, `/admin/assign-reviewer` | **persisted registry** approval, signature-verified | durable (`UnitResult`, audit chain) | server-side assignment + signed adjudication | Lab A simulation (explicitly labeled) | never (assessment-only) |
| **Genuine infrastructure-backed research assessment** | same routes, future labs | same | same | same | real OpenSearch/live targets (OPEN) | only via approved portfolio + authorized activation (not in scope) |

Lab A is a bounded **simulation** in every mode; the integrated mode persists and reviews real signed
records but the evidence provenance is labeled `simulation` throughout (records, status, reviewer
views, traceability).

## Required configuration

- `RANGER_PARALLAX_LABA=1` and `RANGER_PARALLAX_LABA_ENV` ∈ {development, nonproduction, test, staging};
  no production marker (`RANGER_ENV`/`APP_ENV`/`ENVIRONMENT`/`FLASK_ENV` = prod*) — otherwise all
  `/parallax/laba/*` routes 404 (fail-closed, production stays dark).
- `RANGER_SIGNING_KEY` (base64 Ed25519 seed) set and its public key published; optional
  `RANGER_SIGNING_KEYS` for the versioned registry.
- `DATABASE_URL` → PostgreSQL. `SECRET_KEY`, `DEFAULT_COHORT` set.
- Both qualification flags (`RANGER_PARALLAX_QUALIFICATION_ACTIVE`,
  `RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE`) remain OFF.

## Database schema prerequisites

- Tables: `parallax_approvals`, `parallax_reviewer_assignments`, `parallax_audit_events`,
  `parallax_audit_checkpoints`, `unit_results` (with the `signing_kid` columns and the
  `uq_unit_result_record` unique constraint).
- `create_all` creates them on a fresh DB; a pre-existing DB needs `ensure_schema` (columns) plus the
  one-time `migrate_unit_result_uniqueness.py --apply` for the `unit_results` constraint.

## Migration preflight procedure

1. `python migrate_unit_result_uniqueness.py` (dry-run) → review decision (noop/ready/blocked).
2. If `blocked` (conflicting duplicates), resolve manually — the migration never auto-removes rows.
3. `python migrate_unit_result_uniqueness.py --apply` against staging/disposable first; never production
   in this phase. Idempotent and advisory-lock serialized.

## Cryptographic key-registry prerequisites

- Active signing key present with a stable `kid`; publish `signing.public_registry()`.
- Rotation (if any) performed out-of-band against the secret store; verify_only/retired keys retained
  for historical verification; revocation is emergency-only (invalidates records signed by that key
  until re-anchored).

## Governance authorization prerequisites

- An authorized administrator (reviewer role / `REVIEWER_GITHUB_IDS`) stores the scoring-spec approval
  via `registry.store_spec_approval` (or an explicitly scoped authorized test fixture in nonproduction).
  Candidate routes NEVER mint governance.

## Reviewer assignment setup

- An authorized admin assigns a reviewer per attempt (`/parallax/laba/admin/assign-reviewer` →
  `reviewer_store.assign_reviewer`). One active reviewer per attempt; admin ≠ reviewer unless assigned.

## Evidence persistence requirements

- Signed decision + appended signed adjudication persist to `UnitResult`; idempotent and
  substitution-proof; audit events commit atomically with each consequential write.

## Application integration dependencies

- Candidate identity from `session['cand']` (GitHub-OAuth), resolved to github_id, active status
  enforced. Reviewer/admin identity from `session['admin']`/`admin_gid`. CSRF token required on
  session-authed POSTs.

## Audit verification operations

- `audit_integrity.integrity_report(db)` — non-destructive admin verifier (ids/hashes/counts only).
- `parallax.traceability.verify_assessment(db, candidate_key=, assessment_id=)` — machine-readable
  VALID/INVALID/INCOMPLETE/UNAVAILABLE per assessment.
- `audit_integrity.write_checkpoint` periodically; `export_anchor` once an independent sink exists.

## Database backup and recovery

- `pg_dump`/`psql` backup+restore preserves signatures and the audit chain (tested). Fail-closed on
  unretrievable records (`decide_pathway_persistent` → infrastructure_unavailable; traceability →
  UNAVAILABLE).

## Observability and error diagnostics

- Route errors return explicit status codes (401/403/404/409/503) with reasons; traceability `reason`
  fields name the exact failure; audit `integrity_report` surfaces chain status without secrets.

## External OpenSearch prerequisites

- OPEN. See `docs/PARALLAX_OPENSEARCH_VALIDATION_PROCEDURE.md` for the exact provisioning + execution
  procedure for the 12 gated tests. Not required for the integrated nonproduction lifecycle (Lab A is a
  simulation).

## Independent audit-anchor limitations

- OPEN. The in-DB checkpoint does not mitigate simultaneous DB + signing-key compromise. See
  `docs/PARALLAX_AUDIT_ANCHOR_DESIGN.md` for the integration design and founder decision.

## Rollback and failure-containment procedure

- All work on the feature branch; Railway auto-deploy hold intact. Roll back by reverting the branch;
  no production migration or key rotation performed. Flags OFF ⇒ no qualification can be conferred.

## Readiness checklist for a controlled pilot

**Technical prerequisites (implemented + tested):**
- [x] Integrated lifecycle over HTTP (candidate submit/status, admin assign, reviewer adjudicate).
- [x] Governance read from persisted registry, signature-verified; never minted in candidate routes.
- [x] Candidate identity authenticated + active; reviewer eligibility + assignment enforced.
- [x] Signed decision + adjudication durably persisted; idempotent; substitution-proof.
- [x] Evidence-to-decision traceability (machine-readable, four-state).
- [x] Simulation provenance labeled throughout.
- [x] Adversarial HTTP tests pass; real-PostgreSQL lifecycle + retry + restart pass.
- [x] STRATA unchanged; qualification impossible without approved portfolio + activation.

**Founder authorization decisions (NOT engineering):**
- [ ] Provision an authorized OpenSearch 2.17.1 node for the 12 OPEN tests.
- [ ] Provision an independent audit-anchor destination (closes dual-compromise gap).
- [ ] Approve production signing-key rotation window + secret-store procedure.
- [ ] Schedule the `UnitResult` uniqueness migration against production.
- [ ] Approve/define a PARALLAX portfolio and authorize activation (separate, deliberate decision).
- [ ] Approve production deployment (remove auto-deploy hold) — out of scope here.
