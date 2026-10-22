# Qwalora Ranger - Release Readiness Decision (2026-10-22)

## Outcome: READY FOR STAGING APPROVAL

Local engineering, functional, visual and security gates pass on the release candidate. Deployment of
the broader PR #12 integration is NOT yet authorized, and the PARALLAX live-model trial can only be
validated on the deployed service (it is not simulated locally). Those two items are the outstanding
approvals before CONTROLLED PILOT.

---

## 1. Exact candidate commit and branch

- Release candidate: **`fda512e`** on `feature/parallax-research-program-separation` (Draft PR #12).
- Ancestry verified: `b0f1588` (deployed nonprod baseline) -> ... -> `035a010` (PR #11) -> ... ->
  `14cf52f` -> `fda512e`. The chain is LINEAR; PR #12 is a strict superset of the deployed baseline.
- Working tree clean.

## 2. Included features

Research Console (existing), program separation (PARALLAX research routes `/parallax/research/*` +
gated legacy aliases), Investigation page and Trace Explorer rebuilt on the real Ranger shell with the
candnav sidebar and shared design system, px-trace-v1 ingestion, px-trust-v1.1 trust-boundary analysis
(grounded-authorization classification), deny-by-default investigation bundles, measurement-integrity
(candidate-vs-confirmed, confirmed_asr=not_established), nav "Investigations" entry, and the STRATA SOC
training program unchanged.

## 3. Excluded features (deferred, not in candidate)

- PR #6 (`fix/parallax-evaluator-canary`, `classify_canary` + its 8 canary tests): NOT in the chain, so
  no evaluator canary tests exist in the candidate and none were silently removed.
- Trace-explorer increment on the minimal staging artifact `271162a` (that artifact is investigation-
  only; it does not include the Trace Explorer or UI integration).
- Internal module file renames (`strata_view.py` / `strata_investigation.py` stay legacy names).

## 4. Dependency review (the 46-commit delta b0f1588..fda512e)

The candidate unavoidably carries its linear ancestors. Beyond the PARALLAX research platform commits
(research execution, provenance, evidence verifier, measurement, investigation, trace, UI), the delta
includes infrastructure/security/ops commits that are NOT PARALLAX/STRATA features but are security and
operational hardening already on the development line:

- Fail-closed production secret + signing-key configuration and the deployment-time secret gate
  (`0064b78`, `06626fb`, `2c29443`).
- Dependency advisory remediation, pip-audit clean (`3e9e8b0`).
- Backup/DR (Sprint 1B restore-verify, offsite upload verification, GFS retention) (`563d463`,
  `6aa31e3`, `52b6039`, `c9c8cd9`, `2e5f4fe`, ...).
- RC database-identity fail-closed guard (`acf50ec`).

These are reviewed as non-blocking: they harden secrets, dependencies and backups and do not alter
STRATA grading or PARALLAX research semantics. There is no smaller candidate that includes the Trace
Explorer, because the chain is linear. The alternative is the minimal `271162a` (investigation only).

## 5. STRATA user-journey results (local, authenticated)

PASS. Sign-in -> STRATA program + authorized nav shown (no PARALLAX links) -> mission loads (200) ->
SOC workspace opens (200) -> answer-free alert dataset loads (200). Cannot reach PARALLAX via STRATA
membership (research routes + console all 302). Grading rules and Board-1 unchanged (app.py untouched
across PR #11 + #12). Evidence: `test_release_acceptance.py::test_strata_journey_*`.

## 6. PARALLAX user-journey results (local, authenticated)

PASS except the live model trial (see below). Research Console opens in the Ranger shell ->
Investigation opens with campaign selection, timeline, findings and server-side per-record evidence
verification -> Trace Explorer loads actual recorded events (master-detail, real trust zones and the
canary_emission candidate) -> signed evidence persisted, retrieved and signature-verified -> cannot
reach STRATA via PARALLAX membership. Candidate-vs-confirmed and validation limitations preserved.
Evidence: `test_release_acceptance.py::test_parallax_journey_*`.

**Live model trial: OUTSTANDING (not a local pass).** A real backend (Qwen2.5-0.5B Q4_K_M via ollama,
Apache-2.0) is deployed in nonprod (`parallax-inference`, deployment SUCCESS). It is on Railway's
private network and unreachable from the test environment; the local/default backend is a stub
(`is_real=false`, shown as "simulated"). Per the mandate, the stub is NOT presented as a live run, so
live-trial acceptance must be performed on the deployed candidate. Verified invariant:
`test_live_model_backend_not_simulated_locally`.

## 7. Authentication and isolation results (security gate, section 8)

PASS. STRATA-only, PARALLAX-only, dual-entitled, unentitled, and revoked-membership all enforced
(re-checked every request); cross-owner evidence access returns identical 404 (no existence oracle);
cross-program data access blocked; CSRF rejects untokened POST; XSS escaped and bidi/zero-width
display-spoofing neutralized; invalid signatures and tampered/incomplete/malformed evidence detected
by the verifier and bundle tooling; deny-by-default export redaction with sensitive-key handling. No
critical access-control failure found (no NO-GO condition).

## 8. Test counts and failures

Full applicable suite on `fda512e`: **240 passed, 0 failed, 0 error**. No xfail tests (evaluator canary
code not in candidate). Suites: agent-trace, trust-analysis, trust-authorization-audit, investigation-
bundle (+privacy), measurement-integrity (x2), strata view/timeline/investigation-ui, trace view/ui,
program separation, program nav, security adversarial, research checkpoint/execution/provenance,
evidence verifier, parallax ui, release acceptance.

## 9. Screenshots (real browser sessions)

Captured with CSS loaded, authenticated PARALLAX user, headless Chromium: Research Console (baseline),
Investigation, Trace Explorer at 1280px, and Trace Explorer at 430px (responsive). All share the same
Ranger shell, dark-purple sidebar, active nav state, and design system. (Delivered in chat.)

## 10. Actual model-execution results

None performed locally (no reachable real backend from the test environment; stub only). The real
backend exists and is deployed; a live generation must be run on the deployed candidate as the first
staging-acceptance step.

## 11. Deployment environment validation (section 7)

Inspected read-only; secrets not displayed (Railway returned redacted values). Present in nonprod
portal config: dedicated nonproduction `DATABASE_URL` (service `parallax-postgres`), GitHub OAuth
(`GITHUB_OAUTH_CLIENT_ID/_SECRET`, `PORTAL_BASE_URL` for the callback), `SECRET_KEY` (session/CSRF),
PARALLAX feature flags (`RANGER_PARALLAX_LABA`, `RANGER_PARALLAX_LABA_ENV`), `RANGER_SIGNING_KEY`
(evidence signing), model-backend config (`RANGER_RESEARCH_MODEL_URL/_HOSTS/_ID/_RUNTIME`), reviewer
IDs. Health endpoint `/healthz` returns 200 (db:true). Deployed nonprod revision: `eb9e925e` =
`b0f1588` (baseline; does NOT yet contain investigation/trace/UI). Rollback available (Railway redeploy
of `eb9e925e`). The candidate boots locally with gunicorn and the intended dependencies.

## 12. Blocking defects

None at the local gate. The two gating-for-pilot items are approvals/operational, not code defects:
(a) deployment authorization for PR #12 integration; (b) live-model-trial acceptance on the deployed
candidate.

## 13. Deployment manifest (for explicit approval - NOT executed)

- Target: Railway project `qwalora-ranger`, environment `parallax-nonprod`, service `parallax-portal`
  (`8913f277`).
- Revision to deploy: `fda512e` (materially changed vs the approved minimal `271162a`; requires explicit
  approval - it is not the previously approved artifact).
- Start command (unchanged): `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60`.
- Config: no new variables required; confirm `RANGER_PARALLAX_LABA=1`,
  `RANGER_PARALLAX_LABA_ENV` nonprod, `RANGER_RESEARCH_MODEL_URL` pointing at `parallax-inference`.
- No paid infrastructure or production config changes.

### Smoke-test checklist (run on the deployed candidate, authenticated safe accounts)

1. `/healthz` 200, db:true.
2. STRATA user: `/me` shows STRATA nav; `/me/mission` 200; `/me/workspace` 200; dataset loads; PARALLAX
   routes 302.
3. PARALLAX user: `/parallax/workspace` 200 in the shell; run a benign control against the REAL backend
   and confirm a live generation (not simulated); `/parallax/research/investigations` and
   `/parallax/research/traces` 200 with real recorded events; evidence verifies.
4. Cross-program: STRATA-only cannot reach PARALLAX and vice versa; revoked membership denied.
5. Legacy `/parallax/strata/*` redirect to `/parallax/research/*` for authorized users only.

### Rollback procedure

- Immediate: Railway redeploy the last-good deployment `eb9e925e` (`b0f1588`) on
  `parallax-portal`/`parallax-nonprod` (one action; `canRollback=true`). No DB migration is introduced
  by the candidate, so rollback is code-only and safe.
- If a data issue is suspected: the two protected real records (`run-f0d33a285717`, `run-e07852969609`)
  are read-only and unchanged; no destructive migration exists to reverse.

## 14. User onboarding readiness (controlled pilot)

- Eligibility: PARALLAX = approved AI-security researchers; STRATA = approved SOC-training candidates.
- Entitlement assignment: an admin sets `ProgramMembership(program, status='active')` per user; only
  'active' grants access; programs are assigned independently (no cross-grant).
- First login: GitHub OAuth -> dashboard shows only entitled programs; dual users get a program switcher.
- STRATA onboarding (short): sign in -> Mission brief -> SOC workspace -> triage the alert queue ->
  submit report -> grading per Board-1.
- PARALLAX onboarding (short): sign in -> Research Console -> pick a legitimate task + optional attacker
  document -> run a benign control, then an adversarial trial -> review model output + evaluation ->
  open Investigation -> inspect evidence + Trace Explorer.
- Known limitations / acceptable use: trust analysis is heuristic (candidate, not confirmed, not
  independently validated); synthetic research corpus only, no real PII or out-of-scope targets;
  bundle redaction is best-effort, not a guarantee.
- Support / issue reporting: route through the operator's existing support channel (no user auto-enrol,
  invite or contact is performed here).
- Pilot success criteria: entitled users complete their program journey; isolation holds; signed
  evidence verifies; a real PARALLAX trial produces a live generation. Failure criteria: any cross-
  program access, evidence tamper not detected, or inability to complete a core journey.

## 15. Exact remaining approvals

1. Deployment authorization to deploy `fda512e` to `parallax-nonprod/parallax-portal` (materially
   changed vs the approved `271162a`).
2. Live-model-trial acceptance executed on the deployed candidate (benign control + adversarial trial
   against the real `parallax-inference` backend).

Once both are satisfied and the smoke test passes on the running service, the decision moves to READY
FOR CONTROLLED PILOT. No deployment, merge, production change, or user enrolment has been performed.
