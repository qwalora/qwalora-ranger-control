# Qwalora Ranger PARALLAX — Evidence Traceability Matrix

Every major conclusion traces to actual implementation evidence, test output, deployed Railway
configuration, a live observation, or an explicitly identified limitation. Evidence types: [code]
source + automated test, [code-only] source without a dedicated test, [railway] observed Railway
config, [live] observed live behavior this session, [doc] documented procedure, [assumption] not
evidenced. No conclusion below is marked verified without one of [code], [live], or [railway].

## Baseline and acceptance

| Conclusion | Evidence | Type |
|---|---|---|
| Deployed `parallax-portal` commit is `b0f1588`, deployment `eb9e925e` SUCCESS, unchanged | Railway `list-deployments` (latest = `eb9e925e`, commit `b0f1588`) | [railway] |
| App live and DB reachable | `/healthz` = `{"status":"ok","db":true}` | [live] |
| Research Review page authorization-gated | unauthenticated `GET /admin/research-review` -> 302 `/admin/login` | [live] |
| Reviewer authorization applied to nonprod only | `REVIEWER_GITHUB_IDS=67871275` present; variable list otherwise unchanged | [railway] |
| Live DB-level audit reported 41/41 pass, 0 fail | operator-executed `scripts/px_review_audit.py` (blob `57f2ce5b…`); verifier logic validated 41/41 on disposable PG | [doc] operator run + [code] disposable validation |
| Qualification isolation for the fixture (no credential/clearance/progression) | `/badges/px-review-selftest.json` = `{"badges":[],"certificate":null,"clearances":[],"current_board":1,"status":"active"}` | [live] |
| Audit tooling preserved | branch `chore/px-review-audit`, commit `b04698e`, file blob `57f2ce5bfc25a02c03ecddcaaebc847fc15eccfb` (14038 bytes) | [railway/git] |

## Security and identity

| Conclusion | Evidence | Type |
|---|---|---|
| GitHub OAuth is the only interactive candidate login; identity bar (verified email, 2FA, account age) | `githuboauth.py:107-118`; `app.py:3718-3790` | [code] |
| Candidate API token path is plaintext, STRATA-gated | `app.py:1982-1995` | [code] |
| Admin auth via session or hmac-compared bearer token; `DISABLE_ADMIN_TOKEN` supported | `app.py:641-648, 513-516, 2307-2318` | [code] |
| Reviewer allow-list = env UNION DB reviewer rows; adjudicate re-checks `admin_gid` | `app.py:668-676, 3307-3313` | [code] |
| Self-review blocked before signing | `parallax/research/store.py:369-370` + `test_parallax_research_review_pg.py` | [code] |
| Per-request program entitlement; no PARALLAX legacy fallback | `app.py:717-736`; `parallax_routes.py:76-86` | [code] |
| No candidate->admin/reviewer escalation path | `app.py:3741-3761, 2607-2620` | [code] |
| CSRF global before_request with documented exemptions | `app.py:563-578, 553-561` | [code] |
| Session cookies HttpOnly/SameSite=Lax/Secure; no idle timeout | `app.py:479-481`; timeout NOT FOUND | [code] / limitation |
| Security headers incl. HSTS and CSP (`'unsafe-inline'`) | `app.py:622-638` | [code] |
| Rate limiting in-memory per-worker, keyed on XFF | `app.py:585-620` | [code] |
| Signing-seed + SECRET_KEY insecure non-failing fallbacks | `signing.py:67-75`; `app.py:470-476` | [code] (CRITICAL limitation) |
| Secret rotation only for signing keys (config-driven), none for other secrets | `signing.py:118-146`; `parallax/keyadmin.py`; others NOT FOUND | [code] / limitation |

## Research integrity

| Conclusion | Evidence | Type |
|---|---|---|
| Deterministic canonical Ed25519 signing | `signing.py:188-275` + signing tests | [code] |
| Keyed registry with states; fail-closed for unknown/revoked kid | `signing.py:55-61, 278-292` | [code] |
| Rotation/revocation verification-side complete; seed swap manual | `signing.py`; `parallax/keyadmin.py`; `test_parallax_signing_lifecycle.py` | [code] / limitation |
| Evidence append-only (no UPDATE/DELETE of `ParallaxResearchRun`) | `store.py:27-55`; repo-wide grep | [code] |
| Signed record binds run_id/researcher_id/manifest/metrics/provenance; record_hash = sha256(canonical) | `store.py:36-48, 75-151` | [code] |
| Hash-chained audit with `verify_chain` | `parallax/auditlog.py:39-89` + `test_parallax_audit_pg.py` | [code] |
| Tail-truncation checkpoint; external anchor stubbed | `parallax/audit_integrity.py:56-163, 190-249` + `test_parallax_audit_integrity.py` | [code] / limitation |
| Empirical vs simulated provenance | `model_backend.py:49-51, 149-174`; `harness.py:85` | [code] |
| Duplicate submission content-dedup; append-only adjudications | `store.py:334-346`; `parallax_routes.py:595-614` | [code] |
| Research review writes only `ParallaxResearchRun`; Badge/BoardResult/QualificationDecision STRATA-only; LABA `UnitResult` always `qualified=False` | `parallax_routes.py:749-777`; `strata_qualification.py:404,421`; `app.py:1528,1551`; `parallax/assessment_store.py:77-105` | [code] |
| Reproducible research metadata captured | `harness.py:76-105`; `protocol.py`; `corpus.py` | [code] |

## Infrastructure and recovery

| Conclusion | Evidence | Type |
|---|---|---|
| `parallax-postgres` = postgres-ssl:18, single replica, 50 GB volume, private only | `get-service-config`; no TCP proxy | [railway] |
| `parallax-inference` = single-replica Ollama, 50 GB, `PARALLAX_MODEL_TAG` | `get-service-config` | [railway] |
| `/healthz` liveness+db, 200/503 | `app.py:1909-1918` | [code]+[live] |
| Deploy = gunicorn 2 workers; healthcheck `/healthz`; restart ON_FAILURE max 3; no release hook | `Procfile`; `railway.json` | [railway/code] |
| Startup runs idempotent create_all + bootstrap; no seeder/audit/migration at boot | `app.py:497-511` | [code] |
| Backup/prune/restore-verify/healthcheck tooling exists and is tested | `scripts/pg_backup.py`, `pg_backup_prune.py`, `pg_restore_verify.py`, `backup_healthcheck.py` + `test_backup_*` | [code] |
| Post-restore signature + audit re-verify covered | `test_parallax_recovery_pg.py` | [code] |
| Backups scheduled/enabled, offsite destination, live restore drill, RPO/RTO | none found | [assumption] (gap R3) |
| Rollback available | `canRollback=true` on `eb9e925e` | [railway] |
| Observability/alerting integration | none found beyond healthz + backup exit codes | [assumption] (gap R11) |

## Application readiness

| Conclusion | Evidence | Type |
|---|---|---|
| Draft persistence with optimistic concurrency, 256KiB cap | `models.py:425-449`; `drafts.py`; `parallax_routes.py:630-744` + draft tests | [code] |
| Submission idempotency + server-side supersede | `parallax_routes.py:595-614`; `store.py:334-346` | [code] |
| Owner-scoped result visibility; cross-owner 404 | `parallax_routes.py:779-797`; `store.py:309-331` | [code] |
| Responsive layouts | `static/app.css:449-530`; templates + `test_admin_layout.py` | [code] |
| Error/empty/completed states | `admin_research_review.html`; `admin_evidence.html` | [code] |
| Accessibility (evidence console); research-review lacks role=status | `admin_evidence.html`; `app.css:484` | [code] / minor gap |
| Security-focused acceptance tests | `test_parallax_security_review.py`; `test_f4_review_boundaries.py` | [code] |
| Known sqlite-thread concurrency flake; PG authoritative | `test_strata_s3_s4.py:510-541` | [code] / limitation |
| Doc release check fail-closed | `scripts/doc_release_check.py`; `test_doc_release_check.py` | [code] |

## Limitations carried into every conclusion
1. Historical byte-for-byte immutability of the protected records is not proven (current validity only); no trusted pre-adjudication baseline.
2. Researcher decision visibility verified at the store layer, not via a human-authenticated researcher browser session.
3. Negative authorization controls covered by automated tests, not repeated as live write attempts.
4. The live 41/41 audit figures are as reported by the operator-executed run; this environment cannot reach the private nonprod DB directly. The verifier logic was validated 41/41 on disposable PostgreSQL and the result is corroborated by the independent live `/badges` record and the human-browser acceptance.
