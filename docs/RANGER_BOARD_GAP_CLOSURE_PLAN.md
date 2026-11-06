---
title: Ranger Board Gap-Closure Plan
subtitle: Porting the v4.0 Candidate Execution Manual's rigor into built, auto-graded portal boards
status: planning (nonproduction); no policy, grading, or qualification change is made by this document
audience: platform owner / governance
relates_to:
  - docs/handbook/RANGER_CANDIDATE_HANDBOOK.md
  - docs/HANDBOOK_AUDIT_DISCREPANCY_REGISTER.md
  - the deployed PARALLAX board template (parallax/pid_blueprint.py, pid_evaluator.py, pid_sandbox.py,
    pid_submission.py, pid_instance.py, pid_assessment.py; grader/worker.py; submission_gateway.py)
---

# Ranger Board Gap-Closure Plan

## 1. Premise

The v4.0 Candidate Execution Manual specifies a 26-week / 130-day examination across six gated boards.
Its rigor comes from one repeated discipline, applied to every day:

> **Gate → Perform → Submit(exact path) → machine-verifiable PASS → required NEGATIVE CONTROL →
> standards map, reproduced on a clean checkout, under version-gated CI.**

The deployed portal implements a small fraction of that body of work as *graded* surfaces (STRATA
Board 1; PARALLAX PX-D1/PX-D2). The gap is in the **system**, not the handbook. This plan maps the
manual's boards onto the board template we have already proven, states which parts are deterministically
deliverable by that template, and is explicit about what requires infrastructure or governance that a
build alone cannot supply.

## 2. The reusable board template (already proven)

PX-D1/PX-D2 established a complete, reusable pipeline:

- **Blueprint** (`*_blueprint.py`): competency, pass bar, critical-failure conditions, decision policy.
- **Deterministic evaluator** (`*_evaluator.py`): a reproducible, signed score behind a protected truth
  handle; candidate never supplies truth.
- **Sealed harness / sandbox** (`research/harness.py`, `pid_sandbox.py`): runs the candidate's work
  (declarative config, or real code in a fail-closed isolated subprocess) against a sealed check set.
- **Submission contract** (`pid_submission.py`): checklist, submit-time validation, static safety check.
- **Per-instance differentiation** (`pid_instance.py`): keyed per-cohort/per-candidate seeds, rotating
  secret token; anti-transfer, anti-gaming.
- **Governed assessment + signing** (`pid_assessment.py`, `siem/assessment_contract.py`): signed grade
  bound to the exact submitted commit; independently verifiable at `/submit/verify/<id>`.
- **Candidate surface** (`/me` board card, selector, provisioned workspace + starter kit).

**The invariant every ported board must preserve** (this is what makes it "as strong as the old
manual"): a machine-verifiable PASS, a **required negative control** encoded as a critical-failure gate
(the old manual's "prove it fails when it should" = PX's TCR-floor / ASR-ceiling pattern), a sealed
answer key, reproducibility, and an Ed25519-signed record. No LLM-as-judge for the authoritative score.

## 3. Deliverability of the old manual, by task shape

The 130 days fall into shapes with very different deliverability:

| Task shape (examples from the manual) | Deliverable by the template? | How |
|---|---|---|
| **API/authorization** — BOLA 200/403 (D047, D053), authn invalidation (D048) | **Yes, cleanly** | Candidate submits a repo with the fix; sealed harness runs owner/non-owner requests, asserts 200-then-403, and the negative control (unfixed → 200) must fail. This is a near-exact PX-D2 analog. |
| **Secure SDLC / CI-CD** — failing-test-blocks-merge (D062), secret-scan (D017/D064), signed artifact verify (D068), IaC second-apply-noop (D086), drift (D087) | **Yes** | Candidate repo + a sealed runner that executes their tests/gates, injects the negative control (bad code/secret/drift), and requires it to fail closed. Same sandbox discipline as PX-D2. |
| **Detection engineering** — rule fires on positive, silent on benign (D029, D073, D078) | **Yes** | Submit a rule; grade against sealed positive+benign fixtures; negative control = benign must not alert. |
| **Architecture / docs with testable claims** — ADR with tested tradeoff (D085), control→test mapping (D092, D097), threat model with mitigations (D043) | **Partly** | The *testable* parts grade deterministically; the narrative quality is advisory (model rubric, as in PX-D1), never authoritative. |
| **SIEM-hosted analysis** — SOC triage/correlation/containment (Board 1/2 family) | **Yes, portal-hosted** | Deliver as a seeded portal surface (the way Board 1 already works), not a candidate-built Wazuh cluster. Answer-free, server-side, seed-derived. |
| **Live-infra dependent** — self-built Wazuh cluster, Suricata on real traffic, GOAD AD range over WireGuard, candidate-owned Windows/WSL2 | **Not by a build alone** | Needs provisioned infrastructure and a live broker. Can be *reframed* as portal-hosted seeded surfaces (lower fidelity, higher availability) — a scope decision for you. |
| **Public portfolio deploy** (Week 23) | **Not by me** | A production Vercel deploy + governance; out of scope for nonprod board grading. |

## 4. Board-by-board map

| Manual board | Competency | Portal delivery | Deterministic core | Needs infra/gov | Effort |
|---|---|---|---|---|---|
| **Board 1** (W04, infra defense) | Reproducible infra restore | Extend existing portal SOC surface | Restore + health asserts + negative control (injected break fails) | No | **S** (Board 1 exists) |
| **Board 2** (W08, SOC milestone) | Detection + incident end-to-end | Portal-hosted seeded SOC (like Board 1) | Rule/correlation checks on sealed fixtures | Seeded dataset only | **M** |
| **Board 3** (W12, pentest) | Owner-vs-non-owner, BOLA, retest | New code board (PX-D2 analog) against a hosted vulnerable target | 200/403 authz, fix-then-regression, negative control | Hosted target app (portal-run) | **M** |
| **Board 4** (W16, DevSecOps/purple) | Secure release, CI gates, regression | New code board: candidate repo + sealed runner | failing-test-blocks, secret-scan, drift, artifact verify | No (sandboxed runner) | **M–L** |
| **Board 5** (W20, architecture) | Secure operational design | Hybrid board: tested controls + advisory ADR rubric | ACL/TLS/authn tests + negative test per control | Partial | **L** |
| **Capstone** (W21–26) | Red/blue/purple + blind sims | Composite of the above boards + blind fixture sets | Per-exercise deterministic checks | Highest | **L–XL** |

Effort: **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ multi-week, **XL** ≈ a program increment. Each assumes
reusing the template, writing the board's sealed harness + fixtures + negative controls + starter kit,
tests, and a nonprod live-proof loop like the one PX-D2 passed.

## 5. What I can deliver vs. what needs you

**I can build, end to end, on the proven template:**
- Boards 3 and 4 (pentest authz + DevSecOps/secure-SDLC) — these are the highest-leverage, lowest-infra,
  and map almost one-to-one onto PX-D2 (run candidate code/config + a required negative control, score
  deterministically, sign). They convert the largest block of the manual's days (Weeks 9–16: API
  security, secure SDLC, CI-CD supply chain, detection) into real graded boards.
- Board 2 as a portal-hosted seeded detection/SOC surface.
- Per-board sealed harnesses, fixtures, negative controls, starter kits, tests, and nonprod live proofs.

**Needs your decision or ops/governance (not a build problem):**
- Live infrastructure fidelity: real Wazuh/Suricata/GOAD/WireGuard vs. portal-hosted seeded surfaces.
  (Recommendation: seeded surfaces first; they're available, gradeable, and honest, as Board 1 already is.)
- The "no AI, ever" integrity clause vs. PARALLAX's AI-in-the-loop charter — a policy reconciliation, not code.
- Production/public actions (portfolio deploy, publishing the handbook) remain authorization-gated.
- Whether to keep the manual's 95% bar and 100-point weighting, or the PARALLAX composite/≥75 model — a
  grading-policy decision to set per board before build.

## 6. Recommended build order

1. **Board 3 — Pentest / API-security (authz, BOLA, retest).** Closest to PX-D2; highest proof value;
   needs only a portal-run vulnerable target. Delivers Weeks 9–12 as a real board.
2. **Board 4 — DevSecOps / secure SDLC.** Sandboxed runner over a candidate repo; converts the CI-CD /
   supply-chain / secure-coding block (Weeks 13–16) with negative controls throughout.
3. **Board 2 — Detection/SOC (seeded surface).**
4. **Board 5 + Capstone** once 2–4 are proven, since the capstone composes them.

## 7. First milestone I can start now

Board 3 (Pentest / API-security), delivered exactly like PX-D2 was: blueprint + deterministic evaluator
+ sealed harness over a portal-run vulnerable target + submission contract with a required negative
control (unfixed BOLA must score 0) + starter kit + full test suite + a nonprod submit→grade→verify
live proof, landed on `feat/parallax-submission` and deployed to `parallax-nonprod` only.

That single board is the proof that the old manual's rigor is reproducible at board scale beyond
prompt-injection. From there, the remaining boards are the same pattern with different sealed harnesses.
