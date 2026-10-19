# Qwalora Ranger Manual v4.0 — Audit & Discrepancy Register

Audit date: 2026-10-19
Auditor scope: published candidate manual vs deployed control-plane reality.
Classification of this document: **AUDIT (analysis only).** It does not change any
policy, rewrite the manual, or convert old requirements into new ones. Several findings
require an explicit **program-architecture / policy decision** and are flagged as such.

## Sources compared

| Artifact | Location | Role |
|---|---|---|
| Published manual v4.0 | `ranger.qwalora.com/downloads/Qwalora-Ranger-Manual.pdf` (316,811 bytes) | Public, candidate-facing examination standard |
| Manual source (authoritative) | `qwalora/qwalora-cyber-range` → `portfolio/site/src/downloads/Qwalora-Ranger-Manual.md` (1352 lines; identical to top-level `CANDIDATE_MANUAL.md`) | Markdown the PDF is generated from; `dist/` copy is byte-identical and matches the live PDF size |
| Deployed portal | `qwalora/qwalora-ranger-control` (this repo); prod `portal.qwalora.com`, nonprod `parallax-portal` | The platform candidates actually sign into and are assessed on |

The published PDF, the repo `dist/` PDF, and the `src/` PDF are all 316,811 bytes — the
Markdown source is confirmed to be the content of the live manual.

---

## Headline finding (CRITICAL)

**The published manual v4.0 describes a different program delivery model than the one the
portal implements, and does not describe the deployed platform at all.**

The manual documents the *original self-directed* program: the candidate runs the entire
lab in their **own** `qwalora-cyber-range` GitHub repository (Windows 11 + WSL2 + Docker +
a locally deployed Wazuh SIEM), submits work as **GitHub pull requests** (one per day, a
weekly integration PR, a monthly board), under a strict **"no AI, ever"** rule, across
**26 weeks / 130 days** and **6 monthly boards**.

The deployed portal is a **hosted assessment platform**: the candidate signs in with GitHub
**OAuth**, is admitted by an **administrator**, and is assessed inside the portal on
**server-seeded datasets** (STRATA Board 1) and a **portal-brokered OpenSearch SIEM**
(STRATA Board 2), with **Ed25519-signed evidence**, across **two independent pathways —
STRATA and PARALLAX**.

Word-occurrence check in the published manual source (1352 lines):

| Term | Occurrences in manual | Portal reality |
|---|---|---|
| `portal` | 0 | The platform is a portal |
| `OAuth` / `sign in` | 0 | GitHub OAuth is the only way in |
| `PARALLAX` | 0 | One of the two pathways |
| `OpenSearch` / `Dashboards` | 0 | Board 2 SIEM |
| `SOC workspace` | 0 | Board 1 investigation surface |
| `Ed25519` | 0 | Evidence signing scheme |
| `ranger.qwalora.com` / `portal.qwalora.com` | 0 | The two live domains |

This is not a set of line-edits; it is a **model mismatch**. Per the task constraint
("Do not silently convert old policies into new ones … Preserve authoritative requirements
until a separate policy decision is approved" and "This is not an authorization to redesign
the platform again"), reconciling the two models is a **POLICY DECISION that must be made
explicitly by the Qwalora Security Engineering Board**, not silently inside this document.
The recommended corrections below describe *what the portal does* so the decision can be
made from fact; they are not applied to the manual.

---

## Discrepancy register (section by section)

Legend for **Recommendation**: `DECISION` = needs an explicit policy/architecture ruling;
`CORRECT` = factual correction safe to make once the model decision is settled;
`KEEP` = manual statement still authoritative and implemented.

### R1 — Program model & submission (Manual §1, §2, §8, §12, §14)
- **Manual says:** every assignment lives in the candidate's own private `qwalora-cyber-range`
  repo; "One pull request per day; one weekly integration PR per week; one board per month.
  Nothing merges to `main` without green CI and review" (§2.5, §8, §12).
- **Verified behavior:** submissions are portal routes, not PRs — Board 1 `POST /me/workspace/submit`
  (`app.py:4086-4124`); Board 1 incident `POST /me/workspace/incident/submit` (`app.py:4202-4238`);
  Board 2 `POST /case/<id>/draft|verify|submit` (`case_routes.py:268,289,302-345`); PARALLAX
  `POST /parallax/research/run` (`parallax_routes.py:352-353`). GitHub is **authentication only**
  (`githuboauth.py:1-18`, scope `read:user user:email` at `githuboauth.py:30`). No PR/commit
  grading path exists in code. (A stray marketing line in a resource KB entry,
  `catalog.py:482-488`, claims grading is "driven by commits and pull requests" — that is also
  inaccurate and should be corrected.)
- **Recommendation:** `DECISION`. If the portal is now the delivery mechanism, the manual's
  PR-submission model is obsolete and must be rewritten; if the self-directed repo model is
  still authoritative, the portal is a partial/parallel delivery and that must be stated.

### R2 — Board definitions & names (Manual §12, §13)
- **Manual says:** Board 1 = **Infrastructure and networking** (Wk4); Board 2 = **SOC
  operations and investigation** (Wk8, Wazuh); Board 3 = Ethical hacking/OWASP; Board 4 =
  Secure pipeline/purple team; Board 5 = Architecture/resilience; Board 6 = capstone (§13).
- **Verified behavior:** 6 boards (`program.py:18-25`) with codenames and activities:
  1 **Sentinel** — SOC alert triage (portal dataset) `strata_missions.py:61-63`;
  2 **Tracker** — Enterprise SOC investigation (OpenSearch) `strata_missions.py:118-123`;
  3 **Warden** — Detection engineering `strata_missions.py:182-186`;
  4 **Reclaimer** — Incident response & forensic reconstruction `strata_missions.py:243-247`;
  5 **Raider** — Authorized AD red-team (GOAD) `strata_missions.py:297-301`;
  6 **Vanguard** — Capstone multi-forest AD compromise `strata_missions.py:361-363`.
- **Mismatch:** The manual's Board 1 (infrastructure) is **not** the portal's Board 1 (SOC
  triage); the portal's Board-1 SOC activity resembles the manual's Board 2. The entire board
  sequence and codename vocabulary differs.
- **Internal portal note:** `program.py:20` labels Board 2 "Tracker/threat-hunter/threat-hunt"
  while its implemented mission/catalog is "Enterprise SOC investigation" (`strata_missions.py:118`,
  `strata_catalog.py:30`) — a minor internal vocabulary inconsistency to reconcile.
- **Recommendation:** `DECISION` on which board model is authoritative, then `CORRECT`.

### R3 — Environment & tooling (Manual §4, §5, §6, §10, §14)
- **Manual says:** candidate-owned Windows 11 + Ubuntu 24.04 WSL2 + Docker Desktop; a locally
  deployed **Wazuh 4.x** single-node SIEM (§4, §10); OWASP Juice Shop + a local FastAPI target.
- **Verified behavior:** Board 1 runs entirely **portal-hosted** on server-seeded datasets
  (`ENV_DATASET`, `strata_missions.py:41,64`; served by `GET /me/workspace/data` via
  `scenarios.dataset(n,seed)`, `app.py:4058-4084`, `scenarios.py:1130-1132`). No candidate
  machine, Docker, WSL, or Wazuh is involved. Board 2 uses **OpenSearch + Dashboards** via the
  Ranger SOC gateway (`soc_gateway.py`), not Wazuh.
- **Recommendation:** `DECISION`/`CORRECT`. The SIEM technology (Wazuh vs OpenSearch) and the
  "bring your own laptop lab" premise do not match the portal.

### R4 — Integrity / "no AI, ever" (Manual §3)
- **Manual says:** "You may not use any AI assistant … to produce, debug, or explain any part
  of any submission … a false attestation is automatic, non-recoverable failure" (§3).
- **Verified behavior:** this is a **policy statement**, not something the portal code asserts or
  contradicts. PARALLAX is explicitly an *AI-security* research pathway that *uses* a model
  backend for adversarial evaluation (`parallax/research/model_backend.py`), which is a different
  activity than "using AI to produce your submission," but the surface tension should be
  reconciled in writing.
- **Recommendation:** `DECISION`. Preserve the integrity rule as authoritative unless the Board
  rules otherwise; clarify how it applies to the PARALLAX pathway.

### R5 — PARALLAX pathway (Manual: absent)
- **Manual says:** nothing. PARALLAX does not appear anywhere in the manual.
- **Verified behavior:** PARALLAX is a second, independent pathway, **assessment-only / not
  awardable** — every assessment returns `qualified=False` and "No approved PARALLAX portfolio
  exists, so pathway qualification is impossible by construction" (`parallax/__init__.py:20-30,49`).
  Candidate surface is a bounded prompt-injection **research console** against a configured model
  backend (real Ollama in nonprod via `RANGER_RESEARCH_MODEL_URL`; deterministic **stub** by
  default, recorded as `simulated`/`is_empirical_finding=False`) (`parallax_routes.py:316-353`,
  `model_backend.py:149-204`). Fail-closed gating: `RANGER_PARALLAX_LABA` + non-prod env assertion
  + active PARALLAX membership + a **signed** governance approval (`parallax_routes.py:1-39,75-116`).
- **Recommendation:** `DECISION`. The published manual must document PARALLAX (as in-development,
  assessment-only) or explicitly scope the manual to STRATA only.

### R6 — Grading & the 95% bar (Manual §9, §13)
- **Manual says:** 100-point rubric (Functional 30 / Security reasoning 25 / Detection 20 /
  Documentation 15 / Live defense 10); qualification requires weighted **≥95%**, every monthly
  board **≥95**, all safety gates (§9); each board "Hard pass (≥95)" (§13).
- **Verified behavior:** `PASS_BAR = 95.0` (`program.py:15`), reused unchanged in
  `strata_qualification.py:43`; pass is `score >= PASS_BAR` with no critical failure
  (`:371,485`); each mission restates "95 percent" (`strata_missions.py:104-109,165-169`).
  Board-1 triage is **gating** (`app.py:4116-4124`); the additive Board-1 incident investigation
  is **non-gating** by design (`app.py:4126-4151,4235-4238`).
- **Recommendation:** `KEEP` the 95% standard (implemented and consistent). The *rubric weights*
  (30/25/20/15/10) describe the self-directed model's deliverables; whether they map to the
  portal's per-board scoring is a `DECISION`.

### R7 — Evidence & signatures (Manual §8, §12)
- **Manual says:** daily evidence files, machine-verifiable PASS, CI run URL + commit SHA; "A
  screenshot never replaces executable verification" (§8).
- **Verified behavior:** evidence is **Ed25519-signed** server-side (`signing.py`): Board-1
  incident assessments (`app.py:4147-4151`), Board-2 case evidence
  (`case_routes.py:329-345`, `evidence_signed:True`), PARALLAX records (`parallax/__init__.py:9-12`).
  The manual's "commit SHA / CI URL" evidence anchors are repo-model artifacts, not portal ones.
- **Recommendation:** `DECISION`/`CORRECT`. The evidence/attestation model differs
  (signed portal records vs repo CI artifacts).

### R8 — Hosting & publication (Manual §14)
- **Manual says:** private `qwalora-cyber-range` repo; Vercel portfolio at `portfolio/site`,
  `npm run build`, output `dist`; "No public Vercel host for any attack surface" (§14).
- **Verified behavior:** accurate for the **public site** (`qwalora-cyber-range/portfolio/site`,
  `vercel.json` buildCommand `npm run build`, outputDirectory `dist`). The **portal** itself is a
  separate Railway deployment (gunicorn, `railway.json`, `Procfile`), with prod services
  portal/Postgres/opensearch/dashboards and a `parallax-nonprod` environment (no OpenSearch).
- **Recommendation:** `CORRECT` to add the portal/Railway control plane; the portfolio/Vercel
  statement itself is `KEEP`.

---

## Environment availability truth table (for §D/§E of the task)

| Assignment | Real environment | Candidate-accessible now? | Launch surface |
|---|---|---|---|
| STRATA Board 1 (Sentinel) — SOC triage | Portal-hosted seeded dataset (Flask); **no OpenSearch** | **Yes** (portal) | SOC workspace `/me/workspace`; Incident investigation `/me/workspace/incident` |
| STRATA Board 1 — incident investigation (additive) | Portal-hosted seeded incident; **non-gating** | Yes (portal) | `/me/workspace/incident` |
| STRATA Board 2 (Tracker) — SOC investigation | Live OpenSearch + Dashboards via SOC gateway | **No** — gated off (`RANGER_CASE_UI`, `/soc` needs JWT+OS creds, `RANGER_B2_*`); **no OpenSearch in parallax-nonprod**; prod OpenSearch exists but candidate access is closed | None should be shown until a real authorized path exists |
| STRATA Boards 3–4 | Portal-hosted dataset | Board-gated by progression | Portal |
| STRATA Boards 5–6 (Raider/Vanguard) | GOAD isolated range (Ludus broker) | Only when broker `is_live()`; default **unavailable** (`strata_missions.py:514-547`) | "Start lab" when available |
| PARALLAX — research console | Portal; real model backend in nonprod (Ollama), stub in prod | Nonprod only, PARALLAX membership + signed approval | `/parallax/workspace` |

**Key candidate-clarity defect (acceptance failure #2):** the dashboard currently offers a
generic "Start lab" control alongside "Launch SOC workspace" on Board 1, where **no lab needs
provisioning** (Board 1 is portal-hosted). And nothing states that OpenSearch is *not* required
for Board 1, nor that Board 2's OpenSearch lab is not yet candidate-accessible. These are the
concrete items corrected in the portal (nonprod) UI work accompanying this audit.

---

## Publishing-dependency finding (for §C of the task)

Updating the **public** manual is **BLOCKED** from this portal repo and from my current
authorization:

1. The manual source + PDF live in the **separate `qwalora-cyber-range` repo**
   (`portfolio/site/src/downloads/`), not in the portal repo.
2. The PDF is a **pre-generated binary** committed to the repo. The site build (`build.mjs`,
   49 lines) only copies `src/ → dist/`; **no PDF-generation tool is committed** (no pandoc,
   weasyprint, puppeteer, etc.). Regenerating the PDF therefore requires an **external tool**
   that is not part of either repo.
3. Publication is a **Vercel deploy** of `qwalora-cyber-range`, triggered by **merge to its
   `main`** — which the standing constraints forbid ("do not merge to main", "deploy only to
   parallax-nonprod unless a separate public documentation publication is explicitly authorized").

**Therefore:** a newly generated PDF is NOT a published handbook. Public publication requires
(a) a policy decision on the manual's content model (headline finding), (b) a committed,
reproducible MD→PDF generation step, and (c) explicit authorization to merge `qwalora-cyber-range`
to `main` and deploy to Vercel. Until the live URL serves the corrected version, status is
**BLOCKED**, not published.

---

## Recommended decision set (for the Security Engineering Board)

1. **Program-model ruling (blocks everything else):** Is Ranger now the **portal-hosted**
   assessment, the **self-directed repo** program, or a defined hybrid? This decides whether the
   manual is rewritten to the portal, the portal is documented as a delivery channel, or both.
2. **PARALLAX in the handbook:** document it (assessment-only, in development) or scope the manual
   to STRATA explicitly.
3. **SIEM technology of record:** Wazuh (manual) vs OpenSearch (portal Board 2).
4. **Publication authorization:** approve (or not) the cyber-range publication path, and adopt a
   committed MD→PDF generation step so the PDF is reproducible from source.

Pending (1), this audit recommends: keep the published manual authoritative **as the examination
standard text**, correct the candidate-facing **portal** guidance to describe what the portal
actually does (done, nonprod), and do not alter graded requirements, the 95% bar, entitlements,
or signatures.
