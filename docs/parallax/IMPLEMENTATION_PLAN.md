# Qwalora Ranger PARALLAX — Prioritized Implementation Plan

Ordered path from the current nonproduction-accepted baseline (`b0f1588`) to controlled production
promotion. Priorities: P0 = release blocker, must close before promotion; P1 = pre-GA hardening,
schedule with written risk acceptance; P2 = post-GA improvement. Each item maps to the risk register
and the release gate. This plan proposes engineering work; it does not itself change production and
no promotion is authorized here.

Architecture constraint honored throughout: one unified Ranger platform; STRATA and PARALLAX as
independently authorized programs; portal-hosted STRATA Board 1; advanced lab infrastructure only via
explicit approval; PARALLAX assessment-only with no automatic qualification issuance. No separate
Scholars platform and no product-architecture redesign are proposed.

## P0 — release blockers (must close before any production promotion)

1. Fail-closed secrets in production (R1, R2 / G2, G3).
   - Add a production-mode guard (e.g. when `RANGER_ENV=production`) that refuses to boot unless `SECRET_KEY` and an explicit Ed25519 signing key (`RANGER_SIGNING_KEYS` or `RANGER_SIGNING_KEY`) are set. Remove the `"qwalora-ranger-dev"` literal and `SECRET_KEY`-derived signing fallback in production.
   - Files: `signing.py:67-75`, `app.py:470-476`.
   - Tests: boot fails closed in prod mode without each secret; existing signing/verify tests still pass with explicit keys.
   - Decision needed from you: confirm the production environment marker and that `parallax-nonprod` keeps its current dev-friendly behavior.

2. PostgreSQL recovery proven (R3 / G6).
   - Enable scheduled encrypted backups (`pg_backup.py`) to a provisioned offsite destination; schedule pruning (`pg_backup_prune.py`); wire `backup_healthcheck.py` to alerting.
   - Execute and record a restore drill from a real live backup into an isolated target using `pg_restore_verify.py`, confirming row-count parity and that signed evidence + the audit chain re-verify post-restore (the logic `test_parallax_recovery_pg.py` already covers).
   - Define and document RPO and RTO.
   - Decision needed: backup destination/offsite store (no Railway bucket exists today), and the backup schedule + retention targets.

3. Audit tail external anchor, if an enterprise-grade integrity guarantee is claimed (R4 / G8).
   - Provision an independent append-only anchor and wire `export_anchor` / `verify_against_external_anchor` in `parallax/audit_integrity.py`.
   - If the program accepts the documented same-key residual risk for initial production, record that acceptance in writing and move this to P1.
   - Decision needed: is an enterprise-grade, compromise-resistant audit guarantee in scope for first promotion?

## P1 — pre-GA hardening (schedule with written risk acceptance)

4. Rate-limit hardening (R5 / G1): shared store or Railway edge limits; trusted-proxy client-IP policy so `X-Forwarded-For` cannot be spoofed; per-identity keys where a session exists.
5. Session lifetime/idle policy (R6 / G1): set `PERMANENT_SESSION_LIFETIME` + `session.permanent`; consider re-auth for sensitive reviewer actions.
6. Disable shared admin token in production (R10 / G4): set `DISABLE_ADMIN_TOKEN=1` once OAuth reviewer sign-in is confirmed in prod; scope/rotate if retained for automation.
7. Candidate API token hygiene (R7): hash tokens at rest, constant-time compare, add rotation/revocation.
8. CSP tightening (R9 / G1): replace `'unsafe-inline'` with nonces/hashes.
9. Observability + alerting (R11 / G11): structured logs, metrics, and alerts for health, error rate, backup freshness, and audit-verify failures.
10. Secret rotation procedures (R8 / G3): document and schedule rotation for every long-lived secret; prefer a managed secret store; keep the signing-key registry rotation runbook.
11. Rollback runbook (R13 / G12): trigger criteria, steps, and post-rollback verification.
12. Operational ownership + incident response (R11, G14): named owners for secrets, backups, IR, and release authorization; an IR runbook.

## P2 — post-GA improvements

13. Inference-service availability/capacity posture and load testing (G7); define replica/worker policy and capacity model.
14. PostgreSQL HA/failover posture or a documented single-instance risk acceptance.
15. Data classification + retention/hold policy for research evidence (R12 / G15).
16. Accessibility parity: add `role=status` to the research-review template to match the evidence console.
17. Confirm and document the LABA/PX1 `UnitResult` boundary versus the research-review scope (R14).
18. Review `parallax/research/reproduce.py` reproduction tooling if independent reproduction is in scope.

## Suggested sequencing
- Sprint 1 (P0): items 1 and 2 (and a decision on 3). These unblock G2, G3, G6.
- Sprint 2 (P1): items 4 to 9 (security + observability).
- Sprint 3 (P1 to P2): items 10 to 14.
- Backlog: items 15 to 18.

## Decisions requiring your authorization
- D1: Production environment marker and the fail-closed boot policy for secrets (item 1).
- D2: Backup destination/offsite store, schedule, and retention; authorization to run a live restore drill (item 2). A restore drill reads a live backup into an isolated target and must not touch the live DB.
- D3: Whether an enterprise-grade external audit anchor is required for first promotion or deferred with documented risk acceptance (item 3).
- D4: Target RPO/RTO values (item 2).
- D5: Whether to disable the shared admin token in production now (item 6).
