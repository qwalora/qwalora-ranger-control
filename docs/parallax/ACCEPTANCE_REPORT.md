# PARALLAX Research Review — Nonproduction Acceptance Report

Status: FINAL (nonproduction acceptance only)
Program: Qwalora Ranger / PARALLAX (AI-security research pathway)
Scope of this record: the PARALLAX Research Review reviewer workflow in the `parallax-nonprod` environment.

This report documents a nonproduction acceptance milestone. It does not authorize production
promotion, and it does not constitute an external security certification or a claim of scientific
reproducibility.

---

## 1. Authoritative baseline

| Item | Value |
|---|---|
| Railway project | `qwalora-ranger` (`ee093894-30f7-4c82-ab5d-d7ef4d1a6454`) |
| Environment | `parallax-nonprod` (`a7126c4e-a022-4968-8686-a9ea9a3708d7`) |
| Service | `parallax-portal` (`8913f277-af3f-48f0-a26a-7f9f71efada4`) |
| Accepted application commit | `b0f1588f66754a8748fcfee240b9479968e8ec73` |
| Successful deployment | `eb9e925e-563b-424e-84cc-9cd9f89c8684` (status SUCCESS) |
| Service domain | `parallax-portal-parallax-nonprod.up.railway.app` |
| Preserved audit tooling branch | `chore/px-review-audit` |
| Audit tooling commit | `b04698e1291eaa775162505737641426b496b17b` |
| Audit script | `scripts/px_review_audit.py` (git blob `57f2ce5bfc25a02c03ecddcaaebc847fc15eccfb`, 14038 bytes) |

Baseline integrity confirmed at report time (read-only): the deployed `parallax-portal` commit is
unchanged at `b0f1588`; the latest deployment is `eb9e925e` (SUCCESS) with no subsequent deployment;
`/healthz` returns `{"status":"ok","db":true}`. The reviewer authorization change
(`REVIEWER_GITHUB_IDS=67871275`) was applied to `parallax-nonprod` only and triggered the `eb9e925e`
restart of the same commit `b0f1588` (no code change).

### Acceptance subjects

| Role | Identifier |
|---|---|
| Acceptance investigation | `run-192b88497835` |
| Linked simulated evidence | `run-8332b70211aa` |
| Simulated researcher identity | `nonprod-fixture:parallax-review-selftest` |
| Authorized reviewer (GitHub numeric id) | `67871275` (`cloudcwfranck`) |
| Recorded decision | `inconclusive` |
| Protected empirical trials (must remain unchanged) | `run-f0d33a285717`, `run-e07852969609` |

The acceptance seeder was not rerun and no additional reviewer decision was created in the course of
producing this report.

---

## 2. Test objectives and scope

Objective: exercise the PARALLAX Research Review reviewer workflow end to end against the live
nonproduction PostgreSQL system of record, with a human-authenticated reviewer recording a decision
through the actual administrative interface, and then independently verify the persisted state.

In scope:
- Reviewer workflow lifecycle: investigation submission -> pending review -> human reviewer decision -> reviewed.
- Cryptographic integrity of the signed investigation, linked evidence, and adjudication records.
- Researcher/reviewer separation (self-review prohibition).
- Authorization and object-ownership enforcement.
- Signed, hash-chained governance audit trail.
- Qualification isolation (PARALLAX is assessment-only; no credential or progression issued).

Out of scope (explicitly not claimed here):
- Production security posture, scale, or availability.
- Scientific reproducibility of research findings.
- Any empirical model result (the acceptance evidence is deterministic and simulated by design).

---

## 3. Software and environment versions

- Application commit under test: `b0f1588` (deployment `eb9e925e`, builder RAILPACK, runtime V2).
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120` (no release or migration hook; no seeder or audit invoked at startup).
- System of record: `parallax-postgres` (private network only; no public TCP proxy), 50 GB volume at `/var/lib/postgresql/data`, region us-west2.
- Reviewer authorization: `REVIEWER_GITHUB_IDS=67871275`, set in `parallax-nonprod` only.
- Verification tooling: `scripts/px_review_audit.py` at commit `b04698e` (blob `57f2ce5b…`), executed by the operator inside the `parallax-portal` service shell via `/opt/venv/bin/python`, pinned by the exact commit SHA and verified by Git blob SHA-1 before execution.

---

## 4. Human-authenticated acceptance observations

Recorded by the operator through the live administrative Research Review interface, signed in via the
GitHub reviewer path (`/auth/github/login?role=reviewer`) as `cloudcwfranck` (numeric id `67871275`):

- Decision recorded successfully.
- Investigation status changed from Pending to Reviewed.
- Investigation removed from the Pending queue.
- Investigation signature VERIFIED; evidence signature VERIFIED; evidence ownership VERIFIED.
- Reviewer feedback preserved.
- Decision history marked signed.

These are human-browser observations. They are corroborated, not replaced, by the database-level
audit in section 5.

---

## 5. Database-level integrity audit results

Mechanism: the operator executed the reviewed read-only verifier (`scripts/px_review_audit.py`,
blob `57f2ce5b…`) inside the `parallax-portal` service shell against the live private PostgreSQL.
The verifier opens a PostgreSQL READ ONLY session (`SET SESSION CHARACTERISTICS AS TRANSACTION READ
ONLY` and `SET TRANSACTION READ ONLY`), never commits (rolls back), binds a minimal Flask app with
`db.init_app` only (no `create_app`, `create_all`, `ensure_schema`, seed, or migration), runs no
model, and prints a sanitized JSON matrix (booleans, ids, SHA-256 hashes, short key fingerprints; no
signatures, keys, or payloads).

Reported outcome of the operator-executed live run:

- 41 integrity checks passed; 0 failed.
- Investigation `run-192b88497835` and linked evidence `run-8332b70211aa` exist and are owned by the simulated researcher `nonprod-fixture:parallax-review-selftest`; the investigation references the expected evidence id.
- Ed25519 signatures verify against the trusted signing-key registry for the investigation, the linked evidence, and the adjudication; canonical SHA-256 record hashes match; a tampering negative control fails as required.
- The recorded decision is `inconclusive` by reviewer `67871275`; the reviewer differs from the researcher (self-review prohibited); reviewer feedback is preserved.
- The signed, hash-chained governance audit trail verifies (`auditlog.verify_chain`) and includes an attributable `research_investigation_adjudicated` event.
- Queue lifecycle: the investigation is absent from Pending and present in Reviewed; the owner-scoped status mechanism returns the reviewed status, decision, and feedback to the owning researcher identity.
- Evidence provenance is `simulated` and non-empirical.
- Qualification isolation: no `QualificationDecision`, no `UnitResult` of kind `qualification_decision`, no `Badge`/certificate, no `BoardResult` clearance for the fixture candidate; it remains on board 1 with PARALLAX-only program membership. Independently corroborated live by the public credential record `/badges/px-review-selftest.json` = `{"badges":[],"certificate":null,"clearances":[],"current_board":1,"status":"active"}`.
- Both protected empirical records (`run-f0d33a285717`, `run-e07852969609`) remain cryptographically valid (current signature and hash validity).

Note on provenance of these results: the detailed JSON was produced by the operator-executed live
run. This environment cannot reach the private nonproduction PostgreSQL directly, so the figures
above are recorded as reported by that operator run, corroborated by the independent live public
credential record and by the human-browser observations in section 4. The verifier logic itself was
validated end to end against a disposable PostgreSQL database (41/41 checks) prior to the live run.

---

## 6. Signature verification, separation, authorization, audit, isolation — summary

| Property | Result | Basis |
|---|---|---|
| Investigation Ed25519 signature valid (trusted key) | VERIFIED | live audit `checks.investigation_signature_valid` |
| Evidence Ed25519 signature valid (trusted key) | VERIFIED | live audit `checks.evidence_signature_valid` |
| Adjudication signed, hash + signature valid | VERIFIED | live audit `facts.adjudication.verify` |
| Canonical record hashes match | VERIFIED | live audit `hash_match` (investigation/evidence/adjudication) |
| Researcher/reviewer separation (self-review barred) | VERIFIED | live audit `checks.reviewer_differs_from_researcher`; enforced `parallax/research/store.py` self-review 403 |
| Authorization + object ownership | VERIFIED | live audit `checks.evidence_ownership_matches_investigation`; owner-scoped status; admin+reviewer-gated route |
| Signed audit-chain integrity + attributable event | VERIFIED | live audit `checks.audit_chain_intact` + `checks.adjudication_has_audit_event` |
| Pending -> Reviewed transition | VERIFIED | live audit queue checks |
| Simulated / non-empirical provenance | VERIFIED | live audit provenance checks + `/badges` record |
| Qualification isolation | VERIFIED | live audit `facts.qualification_isolation` + `/badges` public record |
| Protected records currently valid | VERIFIED (current validity only) | live audit `facts.protected_records` |

---

## 7. Known limitations (preserved verbatim in intent)

1. Historical byte-for-byte immutability of the protected records was not independently proven. The audit proves current Ed25519 signature and SHA-256 hash validity, but without a trustworthy pre-adjudication baseline snapshot, historical immutability is not established. Do not infer it.
2. Researcher decision visibility was verified at the store layer (`review_status_for`), not through a separate human-authenticated researcher browser session. The simulated fixture has no GitHub OAuth session.
3. Negative authorization controls (an unauthorized reviewer cannot record a decision; the self-review 403) are covered by automated tests and by code review; they were not repeated as live write attempts, because doing so would require a write against the live system of record (outside the read-only scope).

Additional scoping note: the acceptance evidence is deterministic and simulated by design and must not
be represented as an empirical model finding, as broader production security proof, or as scientific
reproducibility.

---

## 8. Final nonproduction acceptance determination

ACCEPTED (nonproduction).

All essential live security, integrity, authorization, and lifecycle checks for the PARALLAX Research
Review reviewer workflow passed against the live nonproduction system of record (41/41 database-level
checks, corroborated by human-authenticated browser acceptance and by the independent live public
credential record), subject to the three limitations in section 7. This determination is scoped to
`parallax-nonprod` and does not authorize production promotion. Production readiness is assessed
separately in `PRODUCTION_READINESS_ASSESSMENT.md`.
