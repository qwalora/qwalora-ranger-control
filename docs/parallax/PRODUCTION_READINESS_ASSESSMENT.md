# Qwalora Ranger PARALLAX — Production Readiness Assessment

Scope: readiness of the unified Ranger portal (PARALLAX research-review surface in particular) for
controlled production promotion. Baseline commit `b0f1588`, environment `parallax-nonprod`.

This is an assessment. It does not authorize production promotion and makes no external
certification claim. A successful nonproduction acceptance test (see `ACCEPTANCE_REPORT.md`) is not a
security certification.

## Status vocabulary and evidence types
- Status: VERIFIED, IMPLEMENTED/NOT VERIFIED, PARTIAL, NOT IMPLEMENTED, NOT APPLICABLE.
- Evidence type, cited per row: [code] tested application code (source + an automated test in `siem/tests`), [code-only] source present without a dedicated test, [railway] observed Railway configuration, [live] observed live behavior this session, [doc] documented procedure, [assumption] not evidenced.
- VERIFIED is used only where [code]+test, [live], or [railway] evidence supports it. Operational items that are only implemented in code but not proven enabled/exercised in the live environment are IMPLEMENTED/NOT VERIFIED or NOT IMPLEMENTED.
- "Release blocker" is judged on security and operational impact, not convenience.

Risk ids (R1..R14) map to `RISK_REMEDIATION_REGISTER.md`. Gate ids (G*) map to `RELEASE_GATE_CHECKLIST.md`.

---

## A. Security and identity

| Control | Existing implementation | Verified evidence | Gap | Severity | Required action | Release blocker |
|---|---|---|---|---|---|---|
| GitHub OAuth is the only interactive candidate auth | `gh_callback` sets `session['cand']` only after `identity_ok` (verified email, 2FA, min account age) | `githuboauth.py:107-118`, `app.py:3718-3790` [code] | None for browser path | - | None | No |
| Candidate API token (STRATA) | `X-Candidate-Token` vs `c.token` plaintext equality, gated by `_program_active(strata)` | `app.py:1982-1995` [code] | Plaintext token, no hashing at rest, no rotation (R7) | MEDIUM | Hash tokens at rest; rotation; constant-time compare | No |
| Admin auth | `session['admin']` or `Bearer ADMIN_TOKEN` via `hmac.compare_digest`; `DISABLE_ADMIN_TOKEN` supported | `app.py:641-648, 2307-2318` [code] | Shared bearer token still enabled in nonprod (R10) | MEDIUM | Set `DISABLE_ADMIN_TOKEN=1` in prod once OAuth reviewer sign-in confirmed | No |
| Reviewer allow-list governance | env `REVIEWER_GITHUB_IDS` UNION `AdminUser.role='reviewer'`; adjudicate re-checks `admin_gid in _reviewer_ids()` | `app.py:668-676, 3307-3313`; `githuboauth.py:121-122` [code] | None functional; governance of the list is manual | LOW | Document reviewer onboarding/offboarding | No |
| Self-review prevention | `researcher_id == reviewer_id` -> 403 before signing | `parallax/research/store.py:369-370` [code]+`test_parallax_research_review_pg.py` | None | - | None | No |
| Independent STRATA/PARALLAX entitlements | per-request `_program_active`; PARALLAX requires explicit active membership, no legacy fallback | `app.py:717-736, 839-859`; `parallax_routes.py:76-86` [code]+tests | None | - | None | No |
| Privilege separation (no candidate->admin/reviewer path) | mutually exclusive session branches; admin rows only via `@admin_required` routes | `app.py:3741-3761, 2607-2620` [code] | None found | - | None | No |
| CSRF | global before_request on POST/PUT/PATCH/DELETE, `hmac.compare_digest`; documented exemptions for header-token endpoints | `app.py:563-578, 553-561` [code]+tests | Exemptions rely on header-token auth being non-cookie (R-review only) | LOW | Confirm each exempt route is never cookie-authed | No |
| Session cookies | `HttpOnly`, `SameSite=Lax`, `Secure` on by default | `app.py:479-481` [code] | No idle timeout / lifetime (R6) | MEDIUM | Set `PERMANENT_SESSION_LIFETIME` + `session.permanent` | No |
| Security headers | nosniff, X-Frame-Options DENY, Referrer-Policy, HSTS, CSP | `app.py:622-638` [code] | CSP allows `'unsafe-inline'` script/style (R9) | MEDIUM | Tighten CSP (nonces/hashes) | No |
| Rate limiting | per-endpoint sliding window, 429 on exceed | `app.py:585-620`; `parallax_routes.py:55-65` [code] | In-memory per-worker (2 workers), resets on restart, keyed on spoofable XFF (R5) | MEDIUM | Shared store or trusted-proxy client IP; per-identity keys where possible | No (prod-hardening) |
| Secret handling | env-read secrets; `hmac.compare_digest` for tokens | agent-enumerated [code] | `SECRET_KEY` and `RANGER_SIGNING_KEY` have insecure non-failing fallbacks (R1, R2) | CRITICAL | Fail closed in prod; see A-note | YES |
| Secret rotation | signing-key rotation via keyed registry + governance surface | `signing.py:118-146`; `parallax/keyadmin.py` [code] | No rotation for SECRET_KEY/ADMIN_TOKEN/OAuth secret/candidate token; signing-seed swap is manual (R8) | MEDIUM | Document + schedule rotation procedures | No |

A-note (CRITICAL, release-blocking): `signing.py:67-75` derives the Ed25519 signing seed from `SECRET_KEY` or, if that is also unset, a hardcoded literal `"qwalora-ranger-dev"`; `app.py:470-476` falls back to an ephemeral random `SECRET_KEY` with only a warning. In production neither fails closed. A predictable signing seed would allow forging signed research evidence, adjudications, badges, and the audit chain; an ephemeral `SECRET_KEY` also invalidates sessions across the 2 gunicorn workers. Production must require `RANGER_SIGNING_KEYS`/`RANGER_SIGNING_KEY` and `SECRET_KEY` and refuse to boot otherwise.

---

## B. Research integrity

| Control | Existing implementation | Verified evidence | Gap | Severity | Required action | Release blocker |
|---|---|---|---|---|---|---|
| Ed25519 signing + deterministic canonical JSON | `sign`/`verify`/`canonical` (sort_keys, compact separators) | `signing.py:188-275` [code]+signing tests | None | - | None | No |
| Trusted key registry with states | active/verify_only/retired/revoked; exactly one active with private seed | `signing.py:55-61, 118-146` [code]+tests | None | - | None | No |
| Fail-closed verification for unknown/revoked kid | unknown->False, untrusted state->False, legacy kid only if verifies under a trusted key | `signing.py:278-292` [code]+tests | None | - | None | No |
| Key rotation/revocation | config-driven (env registry); governance surface authorizes + audits decisions | `signing.py`, `parallax/keyadmin.py` [code]+`test_parallax_signing_lifecycle.py` | No runtime hot-swap; seed swap is a manual secret-store procedure (R8) | MEDIUM | Document the out-of-band rotation runbook; schedule | No |
| Evidence immutability (append-only) | `persist_run` inserts only; no UPDATE/DELETE of `ParallaxResearchRun` anywhere | `parallax/research/store.py:27-55` [code]; repo-wide grep | None | - | None | No |
| Canonical record binding | signed record binds run_id, researcher_id, manifest, metrics, backend_provenance; record_hash = sha256(canonical) | `store.py:36-48`; `admin_verify_run` `store.py:75-151` [code]+tests | None | - | None | No |
| Audit chain | hash-chained, seq-ordered, signed; `verify_chain` | `parallax/auditlog.py:39-89` [code]+`test_parallax_audit_pg.py` | None in-band | - | None | No |
| Tail-truncation checkpoint | separate anchored checkpoint; statuses ok/truncated/rewritten/broken/forged | `parallax/audit_integrity.py:56-163` [code]+`test_parallax_audit_integrity.py` | Same-key limitation; external anchor interface is a stub, not provisioned (R4) | HIGH | Provision an external/independent anchor before enterprise-integrity claims | YES (for enterprise-grade integrity) |
| Empirical vs simulated provenance | `is_real` -> provenance; `is_empirical` requires infrastructure_backed AND sig valid | `model_backend.py:49-51, 149-174`; `harness.py:85` [code]+tests | None | - | None | No |
| Duplicate submission policy | content dedup (researcher+parent+identical analysis), idempotent 200; different analysis -> new 201 | `store.py:334-346`; `parallax_routes.py:595-614` [code]+tests | Dedup key (identical analysis) is a deliberate policy choice | LOW | Confirm policy with program owner | No |
| Unauthorized qualification prevention | research review writes only `ParallaxResearchRun`; Badge/BoardResult/QualificationDecision are STRATA-only; LABA assessment ledger writes `UnitResult` with `qualified=False` | `parallax_routes.py:749-777`; writers enumerated [code]+`test_parallax_pathway_qualification.py` | Confirm LABA/PX1 `UnitResult` path is intentionally distinct from "review" scope (R14) | LOW/INFO | Program-owner confirmation | No |
| Reproducible research metadata | per-trial manifest: protocol/corpus/prompt-template versions + hashes, backend identity, condition | `harness.py:76-105`; `protocol.py`; `corpus.py` [code]+tests | `reproduce.py` not deeply reviewed | LOW | Review reproduction tooling if in scope | No |

---

## C. Infrastructure and reliability

| Control | Existing implementation | Verified evidence | Gap | Severity | Required action | Release blocker |
|---|---|---|---|---|---|---|
| Service health | `parallax-portal` latest deployment SUCCESS; `/healthz` live ok, db true | `eb9e925e` [railway]; `/healthz` [live] | None | - | None | No |
| Health/readiness endpoint | `/healthz` runs `SELECT 1`, 200 ok / 503 degraded, reports db + broker | `app.py:1909-1918` [code]+[live] | No separate `/readyz`; healthz doubles as readiness | LOW | Acceptable; document | No |
| Private PostgreSQL | `postgres-ssl:18`, single replica, 50 GB volume, private network only (no public proxy) | `get-service-config` [railway] | Single instance, no replica/HA; single point of failure | MEDIUM | Define HA/failover posture or accept documented risk | No (document) |
| Backups (code) | `pg_backup.py` (age-encrypted, public-key, fail-closed), `pg_backup_prune.py` (GFS), `pg_restore_verify.py`, `backup_healthcheck.py` | scripts + `test_backup_*` [code] | No evidence backups are scheduled/enabled, no destination/offsite store provisioned, no evidence of a run (R3) | HIGH | Enable scheduled encrypted backups to an offsite store; wire healthcheck alerting | YES |
| Backup restorability | `pg_restore_verify.py` + `test_backup_restore.py` prove restore + row-count parity + audit re-verify on disposable PG | `test_backup_restore.py` (_pg) [code] | No restore drill executed against a real backup of the live environment (R3) | HIGH | Execute and record a restore drill from a live backup | YES |
| RPO/RTO | not defined | NOT FOUND [assumption] | No formal objectives (R3) | HIGH | Define and document RPO/RTO | YES |
| Post-restore integrity | `test_parallax_recovery_pg.py` verifies signed evidence + audit chain after restore | `test_parallax_recovery_pg.py` (_pg) [code] | Proven in test, not drilled live | MEDIUM | Include in the live restore drill | No (covered by R3) |
| Private inference availability | `parallax-inference` single-replica Ollama, 50 GB volume, `PARALLAX_MODEL_TAG`; portal uses deterministic stub for review path | `get-service-config` [railway]; `model_backend.py` [code] | Single instance, no HA; capacity/limits undefined | MEDIUM | Define capacity + availability posture for empirical runs | No (review path is simulated) |
| Resource/capacity limits | 2 gunicorn workers, 1 replica; no documented capacity model | `Procfile`/`railway.json` [railway/code] | No capacity/load testing evidence | LOW | Load test; set worker/replica policy | No |
| Restart / failure recovery | `restartPolicyType ON_FAILURE`, max 3; db.create_all wrapped for worker race | `railway.json`; `app.py:497-511` [railway/code] | None critical | LOW | None | No |
| Observability / logging / alerting | `/healthz`, `backup_healthcheck.py` exit codes | [code] | No structured logging/metrics/alerting integration evidenced (R11) | MEDIUM | Wire logs/metrics + alerting (incl. backup freshness) | No (prod-hardening) |
| Deployment rollback | Railway `canRollback=true` on `eb9e925e` | [railway] | No documented rollback runbook (R13) | LOW | Write rollback runbook | No |
| Startup side effects | idempotent create_all + ensure_schema + cohort/resource/publication bootstrap; NO seeder, NO audit replay, NO migration hook | `app.py:497-511`; `Procfile`/`railway.json` [code] | Bootstrap writes run at boot (idempotent) | LOW | Confirm acceptable for prod; consider gating bootstrap | No |

---

## D. Application readiness

| Control | Existing implementation | Verified evidence | Gap | Severity | Required action | Release blocker |
|---|---|---|---|---|---|---|
| Draft persistence | `WorkspaceDraft` optimistic concurrency, 5 kinds, 256KiB cap; PARALLAX draft routes nonprod-gated | `models.py:425-449`; `drafts.py`; `parallax_routes.py:630-744` [code]+`test_parallax_research_drafts*.py` | PARALLAX draft routes nonprod-gated only (by design) | INFO | Confirm gating intent for prod | No |
| Submission idempotency | identical resubmission -> existing (200); different -> new (201); server-side draft supersede | `parallax_routes.py:595-614` [code]+tests | None | - | None | No |
| Candidate result visibility | owner-scoped status; cross-owner raises -> 404 | `parallax_routes.py:779-797`; `store.py:309-331` [code]+tests | Verified at store layer; not a human researcher browser session (limitation 2) | LOW | Exercise via a real researcher session when a second identity exists | No |
| Responsive layouts | `.rr-*`, `.ev-*`, `.cand-body` with media queries | `static/app.css:449-530`; templates [code]+`test_admin_layout.py` | None | - | None | No |
| Error/empty/completed states | review + evidence consoles render empty/failure/verified states | `admin_research_review.html`, `admin_evidence.html` [code] | None critical | LOW | None | No |
| Accessibility | `role=status`, `aria-label`, `sr-only` in evidence console | `admin_evidence.html`; `app.css:484` [code] | research-review template lacks `role=status` | LOW | Add status roles to research-review template | No |
| Security-focused acceptance tests | `test_parallax_security_review.py`, `test_f4_review_boundaries.py` | [code] | None | - | None | No |
| Regression reliability | broad `_pg` suites; earlier full PG regression 32 passed | [code] | sqlite-thread concurrency test is the known-weaker path; PG is authoritative | LOW | Keep PG as the gate; mark/skip sqlite-thread flake | No |
| Doc release check | `scripts/doc_release_check.py` fail-closed; validates routes/board facts/links | `test_doc_release_check.py` [code] | Does not assert live PDF currency | LOW | None | No |

---

## E. Governance

| Control | Existing implementation | Verified evidence | Gap | Severity | Required action | Release blocker |
|---|---|---|---|---|---|---|
| Research data classification | provenance labeling (simulated/empirical); sanitized admin views | `model_backend.py`; `store.admin_verify_run` [code] | No formal data-classification policy doc (R12) | LOW | Write classification + handling policy | No |
| Evidence access + retention | owner-scoped reads; admin read-only verifier; append-only | `store.py`; `parallax_routes.py` [code] | No retention/TTL policy for research runs (R12) | LOW | Define retention/retention-hold policy | No |
| Admin/reviewer accountability | signed, hash-chained audit events with actor id | `parallax/auditlog.py` [code]+tests | Audit log tail anchoring not externally provisioned (R4) | HIGH | External anchor (see B) | YES (enterprise) |
| Test-data isolation | collision-proof fixture id; `NONPROD_ACCEPTANCE_SIMULATED`; nonprod-only seeder | `scripts/px_review_fixture.py` [code]+tests+[live] | None | - | None | No |
| Incident response | not evidenced | NOT FOUND [assumption] | No IR procedure doc | MEDIUM | Write IR runbook | No (pre-GA) |
| Change management | git branch discipline; doc release check | [code]+[live] | No formal change-management/release-authorization doc | LOW | Document | No |
| Release authorization | human-gated (this task) | [doc] | Not formalized as a gate | LOW | Adopt `RELEASE_GATE_CHECKLIST.md` | No |
| Legal/contractual | not in scope of code | NOT APPLICABLE here | Out of code scope | - | Owner review | No |

---

## Readiness summary

Strong, test-backed foundations in the areas that matter most for a research-integrity platform:
cryptographic signing and verification, append-only evidence, a hash-chained audit trail with a
tail-truncation checkpoint, strict researcher/reviewer separation, independent program entitlements,
and verified qualification isolation (PARALLAX is assessment-only).

The blockers to controlled production promotion are concentrated in two places: (1) secret and
signing-key fallbacks that do not fail closed in production (R1, R2), and (2) operational recovery
that exists in code but is unproven in the live environment, with no RPO/RTO and no evidence that
backups are scheduled or that a restore drill has been run (R3). For an enterprise-grade integrity
claim, the audit tail anchor should also be externally provisioned (R4). Remaining items (rate-limit
hardening, session timeout, token hashing/rotation, CSP, observability/alerting) are production
hardening that can be scheduled with risk acceptance but should not be waived silently.

Determination: NOT READY FOR PRODUCTION PROMOTION. See `RELEASE_GATE_CHECKLIST.md` for the objective
gate and `IMPLEMENTATION_PLAN.md` for the ordered path to readiness.
