---
title: Qwalora Ranger Candidate Handbook
subtitle: Unified portal platform — STRATA and PARALLAX
doc_version: 1.0 (draft, nonproduction)
applies_to_programs: [strata, parallax]
status: candidate-facing documentation for the DEPLOYED portal
authority_note: >
  This handbook describes what the deployed Ranger portal actually provides. It is the
  single version-controlled source for the candidate handbook. The legacy 26-week,
  GitHub-PR-driven "Candidate Execution Manual v4.0" is NOT automatically authoritative
  for the current portal workflow. Where the discrepancy register records an unresolved
  governance decision, this handbook marks it "PENDING POLICY REVIEW" and does not silently
  redefine the policy. See docs/HANDBOOK_AUDIT_DISCREPANCY_REGISTER.md.
---

# Qwalora Ranger Candidate Handbook

> **Scope and authority.** Ranger is **one portal-hosted cybersecurity research and assessment
> platform** with two independently authorized programs. This handbook documents the deployed
> platform. Items marked **PENDING POLICY REVIEW** are legacy requirements whose applicability to
> the portal is unresolved; they are preserved for an explicit decision and are neither enforced
> nor discarded here. No grading, qualification, entitlement, or signature policy is changed by
> this document.

## 1. Ranger platform overview

Qwalora Ranger is a single hosted platform you sign into. It contains two independently authorized
programs that share one Ranger identity, one administrative system, and one cryptographic signing
authority:

- **RANGER STRATA** — cybersecurity operations, detection, incident response, threat hunting, and
  advanced security assessments.
- **RANGER PARALLAX** — adversarial AI-security research, model evaluations, prompt-injection
  investigations, and signed research evidence.

Admission is selective: requesting consideration or authenticating with GitHub does not grant
access, a cohort seat, or qualification. Every result is recorded as an Ed25519-signed evidence
record. The platform never hosts a public attack surface, and assessment answer keys and grader
internals always remain server-side.

Program authorizations are independent: a candidate authorized for one program does not receive the
other program's labs, records, documentation, or API access.

## 2. RANGER STRATA program

STRATA is a six-board cybersecurity assessment. Each board has a codename, a professional role, and
a mission brief:

| Board | Codename | Role | What you do |
|---|---|---|---|
| 1 | Sentinel | SOC Analyst (Tier 1) | SOC alert triage: adjudicate a seeded alert queue (verdict + severity; technique + IOCs for true positives). An additional, non-graded incident-investigation exercise is available. |
| 2 | Tracker | Threat hunter / SOC investigator | Enterprise SOC investigation in a private OpenSearch SIEM (per-candidate index) via the Ranger SOC gateway. |
| 3 | Warden | Detection engineer | Detection engineering. |
| 4 | Reclaimer | Incident responder | Incident response and forensic reconstruction. |
| 5 | Raider | Red-teamer | Authorized Active Directory red-team assessment in an isolated GOAD range. |
| 6 | Vanguard | Capstone | Capstone: multi-forest Active Directory compromise in an isolated range. |

The STRATA objective standard is **95 percent** per board (unchanged). Clearing a board requires the
objective score **and** an approved written report (see §10, §12).

## 3. RANGER PARALLAX program

PARALLAX is a separate advanced track for AI-security practitioners. It is currently
**assessment-only and in development**: **no pathway qualification or credential issuance is
authorized**, and every assessment is recorded as not-qualifying by construction. Candidate activity
is a bounded, model-backed research console (for example a preregistered prompt-injection study
against a configured model backend) producing signed research evidence. PARALLAX access requires an
active PARALLAX membership and a signed governance approval, and runs only in authorized
nonproduction environments.

## 4. GitHub authentication and admissions

- **Authentication is GitHub OAuth only.** GitHub is used to sign in and to assure identity
  (verified email, two-factor, a minimum account age at enrollment). The OAuth scope is limited to
  reading your profile and email (`read:user user:email`). **GitHub is not used as a submission
  repository** — you do not submit work as pull requests; you submit inside the portal (see §8).
- **Admission is by administrator review.** Applying or signing in creates a candidate in a
  **pending** state with nothing provisioned. An administrator **approves** (your account becomes
  **active** and Board 1 opens) or **declines** (**rejected**). Approval unlocks a candidate
  account; it is not a pass.
- **Program access is requested and granted separately** from your Account → Program access page;
  requesting a program does not grant it.

## 5. Candidate workspace and navigation

The left navigation is your Ranger shell. For an active STRATA candidate on Board 1 it shows:

- **Dashboard** (`/me`) — your progress, next action, assignment & lab card, and resources.
- **SOC workspace** (`/me/workspace`) — the Board-1 alert-triage surface.
- **Incident investigation** (`/me/workspace/incident`) — the additional Board-1 reconstruction
  exercise.
- **Mission brief** (`/me/mission`) — the full approved mission for your current board.
- **Program access** (`/account`) — your identity and per-program entitlement status.
- **Handbook** — this document, published as the Ranger manual.

A PARALLAX candidate sees the **Research console** (`/parallax/workspace`) instead of the STRATA
items. A dual-program candidate gets a program switcher. Navigation never exposes the other
program's protected surfaces.

## 6. Board and assessment assignments

Each board has an approved **mission brief** (`/me/mission`) with: business context, your assigned
role, objectives, authorized scope, the environment and access model, expected deliverables,
evidence and integrity requirements, submission and acceptance, evaluation expectations, and
professional references. Mission instructions are candidate-safe: they describe the mission, not how
to solve it, and never disclose the answer key.

## 7. Lab environments and launch procedures

Each assignment states its real environment and how to reach it. The portal never invents a lab URL
or shows a launch control for an environment that is not genuinely available.

| Assignment | Environment | Launch | Availability |
|---|---|---|---|
| Board 1 (Sentinel) | **Portal-hosted SOC workspace** — runs in your browser on a per-candidate seeded dataset. **No external SIEM, OpenSearch, Docker, VPN, or local install is required.** | "Launch SOC workspace" + "Incident investigation" on the dashboard | Available to an active STRATA candidate |
| Board 2 (Tracker) | **Private OpenSearch SOC** with Dashboards, reached through the Ranger SOC gateway with your authorized identity. You do not install OpenSearch or receive cluster credentials. | Opened on assignment once the gateway and your index are provisioned | **Not available in nonproduction** until genuinely accessible; the dashboard labels it "Not available yet" and shows no launch |
| Boards 3–4 | Portal-hosted analysis workspace (seeded dataset) | Portal | Board-gated by progression |
| Boards 5–6 (Raider/Vanguard) | **Isolated GOAD range** over a per-candidate WireGuard tunnel | "Start lab" (range boards only), then "Download WireGuard" | Available only when the range broker is live |
| PARALLAX | **Model-backed research workspace** (research console) | "Open the research console" | Authorized nonproduction only, with PARALLAX membership + signed approval |

You should never have to guess whether to use OpenSearch, the portal SOC workspace, GitHub, or an
external lab: the dashboard and mission brief state the platform, its availability, and the exact
launch control for your current board.

## 8. Evidence and submissions

- **You submit inside the portal**, not through GitHub. Board-1 triage is submitted from the SOC
  workspace; the Board-1 incident investigation, Board-2 cases, written reports, and PARALLAX runs
  each have their own in-portal submission.
- **Grading is answer-free and server-side.** The answer key is re-derived on the server from your
  own dataset seed and is never sent to the browser.
- **Evidence is Ed25519-signed.** Signed records are produced for Board-1 incident assessments,
  Board-2 case evidence, and PARALLAX research/governance records, and are independently verifiable.

## 9. Draft saving and final submission

- **Autosave.** In the Board-1 SOC workspace your in-progress inputs (verdict, severity, technique,
  IOCs) are saved to the server automatically as you work. Your work is restored after navigation,
  refresh, logout/login, and session changes. The workspace shows **Saving**, **Saved**, and
  **Save failed** states, and an explicit **Save progress** button.
- **A draft is never a submission.** Saving a draft never grades your work, never records an
  objective, never changes qualification, and never issues a credential. It cannot be submitted as
  completed work on its own.
- **Final adjudication is explicit and deliberate.** You submit your adjudication with the
  **Submit adjudication** action; only then is it graded against the 95% objective standard.
- **Your drafts are private to you** and scoped to your program, board, case, and dataset attempt.
  They are never shared across candidates or programs.

*(Draft autosave currently covers the Board-1 SOC triage. The incident investigation, written
report, and PARALLAX workspaces are tracked for the same treatment; see
docs/DRAFT_PERSISTENCE_AUDIT.md.)*

## 10. Reviewer workflows

Boards are cleared on two channels: an **objective** score (answer-free, server-side, ≥ 95%) and an
**administrator/reviewer-approved written report**. You submit your report from the dashboard; a
reviewer marks it **pending**, **needs changes**, **approved**, or **rejected**, and may leave
notes. A board is cleared only when the objective is at the standard **and** the report is approved.
Reviewer actions are authorization-gated; candidates cannot review their own or others' work.

## 11. Technical prerequisites

- A current web browser and a GitHub account that meets the enrollment identity bar (verified
  email, two-factor enabled, minimum account age).
- Board 1 needs **nothing else** — it is portal-hosted. Later boards' environments (OpenSearch SOC,
  isolated GOAD ranges) are provisioned and reached through the portal/gateway/VPN as described in
  §7; you do not stand them up yourself.
- **PENDING POLICY REVIEW:** the legacy manual's self-directed prerequisites (candidate-owned
  Windows 11 + WSL2 + Docker + a locally deployed Wazuh SIEM) describe a different delivery model
  than the portal. Their applicability is an unresolved governance decision and is preserved for
  review, not enforced here.

## 12. Grading and qualification policies

- **STRATA objective standard: 95 percent per board** (unchanged). Board clearance requires the
  objective at the standard and an approved report. Qualification requires clearing every board and
  passing every mandatory safety gate.
- **PARALLAX** is **assessment-only**: no pathway qualification or credential issuance is
  authorized.
- **PENDING POLICY REVIEW:** the legacy manual's specific 100-point rubric weights
  (Functional 30 / Security 25 / Detection 20 / Documentation 15 / Live defense 10) and the strict
  "no AI, ever" integrity clause describe the self-directed model; how they map to the portal's
  per-board scoring and to the PARALLAX AI-security pathway is an unresolved governance decision,
  preserved for review and not redefined here.

## 13. Support and troubleshooting

- **Environment states.** If a board shows **"Not available yet"**, its environment is not
  candidate-accessible in this deployment; mission instructions remain available for preparation.
  This is expected for Board 2 in nonproduction.
- **Work not saved.** The SOC workspace shows a save state; if it reads "Save failed", it retries
  automatically, and you can use **Save progress**. Your in-progress values are kept in the page
  until a save succeeds.
- **Resources.** Board-relevant reference material is available in the in-portal resource library
  (`/resources`) and from the Handbook link.
- **Access questions.** Program authorization is managed from Account → Program access; approval is
  by administrator review.

---

*Single-source note: this Markdown is the version-controlled source for the candidate handbook. A
navigable web handbook and a downloadable PDF are intended to be generated from this one source.
Public publication to ranger.qwalora.com is a separate, authorization-gated deployment of the
`qwalora-cyber-range` repository (see docs/RELEASE_DOC_VALIDATION.md); it is not performed here.*
