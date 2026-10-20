# Qwalora Ranger PARALLAX — Release Gate Checklist

Objective minimum criteria for controlled production promotion. Each gate is PASS, FAIL, or PENDING
with the current evidence. Critical blockers must be PASS before promotion; scheduled-after-release
items are called out as such. This checklist does not itself authorize promotion, and passing a
nonproduction test is not an external security certification.

Legend: [BLOCKER] must pass before promotion. [POST] may be scheduled after release with explicit
risk acceptance.

| # | Gate | Criterion | Status | Blocker | Evidence / risk ref |
|---|---|---|---|---|---|
| G1 | Security controls | Session cookies HttpOnly/SameSite/Secure; CSRF enforced; security headers present | PASS | [POST] for CSP tightening + session timeout | `app.py:479-481, 563-578, 622-638`; R6, R9 |
| G2 | Signing + evidence integrity | Signing key is explicit and secret in production (no derived/literal fallback); verification fail-closed; evidence append-only | FAIL | [BLOCKER] | R1 (signing fallback); signing fail-closed + append-only already PASS |
| G3 | Secret management | `SECRET_KEY` and signing key required in prod (fail closed); rotation documented | FAIL | [BLOCKER] for fail-closed; [POST] for rotation docs | R1, R2, R8 |
| G4 | Authentication | GitHub OAuth is the only interactive login; shared admin token disabled in prod | PARTIAL | [POST] | OAuth PASS (`app.py:3718-3790`); `DISABLE_ADMIN_TOKEN=1` pending (R10) |
| G5 | Authorization | Per-request program entitlement; reviewer allow-list; self-review prohibited; no privilege-escalation path | PASS | - | `app.py:717-736, 3307-3313`; `store.py:369-370`; tests |
| G6 | PostgreSQL recovery | Scheduled offsite encrypted backups enabled; restore drill executed; post-restore signature + audit re-verify; RPO/RTO defined | FAIL | [BLOCKER] | R3 (tooling exists + tested on disposable PG, live recovery unproven) |
| G7 | Model execution reliability | Availability/capacity posture for the inference service defined; review path provenance correct | PARTIAL | [POST] | Review path is simulated/correct (PASS); `parallax-inference` single-replica, capacity undefined |
| G8 | Audit logging | Signed hash-chained audit with verify + tail checkpoint; external anchor for enterprise-grade guarantee | PARTIAL | [BLOCKER] only if enterprise-grade integrity is claimed | `auditlog.py`, `audit_integrity.py`; R4 |
| G9 | Candidate isolation | Owner-scoped visibility; cross-owner 404; test-fixture isolation; qualification isolation | PASS | - | `store.py:309-331`; `/badges` [live]; tests |
| G10 | Reviewer workflow | Pending->Reviewed lifecycle; signed decision; self-review barred; human-authenticated acceptance recorded | PASS | - | `ACCEPTANCE_REPORT.md`; live audit 41/41 |
| G11 | Monitoring + alerting | Health, error-rate, backup-freshness, and audit-verify-failure alerting wired | FAIL | [POST] | R11 (only healthz + backup healthcheck exit codes today) |
| G12 | Rollback readiness | Rollback available and a runbook documented with trigger criteria | PARTIAL | [POST] | Railway `canRollback=true` [railway]; runbook missing (R13) |
| G13 | Documentation accuracy | Doc release check passes; candidate-facing docs match live routes/board facts | PASS | - | `scripts/doc_release_check.py`; `test_doc_release_check.py` |
| G14 | Operational ownership | Named owner for secrets, backups, incident response, and release authorization | FAIL | [POST] | R11, IR runbook NOT FOUND; ownership not documented |
| G15 | Data governance | Data classification + retention policy for research evidence | PARTIAL | [POST] | R12 (append-only today; no formal policy) |

## Gate decision
Critical blockers currently FAIL: G2 and G3 (R1/R2 signing + secret fail-closed), and G6 (R3
PostgreSQL recovery unproven). G8 is a blocker only if an enterprise-grade, compromise-resistant
audit guarantee is claimed (R4). Until G2, G3, and G6 are PASS, the gate is NOT MET and production
promotion is not authorized.

The POST items (G1 CSP/timeout, G4 admin-token disable, G7 inference capacity, G11 monitoring, G12
rollback runbook, G14 ownership, G15 governance) should be scheduled with explicit, written risk
acceptance rather than waived silently.
