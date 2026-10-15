# Board 2 Enterprise Shadow Grading & Calibration — Milestone 3 (as built)

Status: **shadow only, OFF by default**. This milestone adds a richer, versioned
enterprise evaluator and its calibration suite. It does **not** change
qualification. The live `score_board2` path, `program.PASS_BAR = 95.0`,
`BoardResult.objective_*`, the Ed25519 signing, the authorization boundary, and
the rule that hidden truth never reaches a candidate are all preserved and
regression-tested (`siem/tests/test_shadow_regression.py`).

Everything here is gated behind `RANGER_SHADOW_GRADER` (default off) and runs only
for finalized submissions, invoked by a reviewer. Candidate access and act-as
remain governed by their own flags (`RANGER_CASE_UI`, `RANGER_SOC_ACTAS_ENABLED`),
untouched.

---

## 1. Evidence relevance — three non-interchangeable properties

Implemented in `siem/case_contract.py` (`verify_evidence`, `_assess_claim`). A
citation is assessed on three independent properties. **None substitutes for
another, and membership in a hidden incident never, by itself, earns credit.**

| Property | Name | What it answers | Truth needed? | Candidate-visible? |
|---|---|---|---|---|
| A | reference validity (`reference_valid`) | Does the cited event exist in the candidate's **own** authorized index and does the candidate's exact query reproduce it (in scope)? | no | yes (verify-before-submit) |
| B | claim support (`claim_support`, `relevance`) | Given the **role** the candidate assigned the citation and the incident's **disposition**, does the evidence actually support *that* claim? | yes (grade time) | no |
| C | malicious-activity determination (`malicious_activity`, `incident_family`) | Is the event in fact part of a real incident, and which one? A fact about the event, independent of the candidate's claim. | yes (grade time) | no |

Citation **roles** (`cc.ROLES`) and how B is decided:

| Role | Meaning | Confirmed-incident disposition | No-incident disposition |
|---|---|---|---|
| `primary` | direct proof of the disposition | member ⇒ supported (1.0); benign ⇒ **unsupported** + `PRIMARY_EVIDENCE_INCONSISTENT_WITH_DISPOSITION` | benign ⇒ supported; member ⇒ unsupported + same flag |
| `corroborating` | strengthens the finding | member ⇒ supported (1.0); benign ⇒ partial (0.4) | member ⇒ **misclassified** + `BENIGN_DISPOSITION_CITES_MALICIOUS_EVENT`; benign ⇒ supported |
| `precursor` | earlier stage of the chain | member ⇒ supported; benign ⇒ partial (0.4) | as corroborating |
| `baseline` | normal-behaviour reference | benign ⇒ supported (1.0); member ⇒ **misclassified** + `MALICIOUS_EVENT_CITED_AS_BENIGN_REFERENCE` | benign ⇒ supported; member ⇒ misclassified + flag |
| `exclusion` | used to rule something out | benign ⇒ supported; member ⇒ misclassified + flag | benign ⇒ supported; member ⇒ misclassified + flag |
| `alternative` | an alternative hypothesis | reviewer judgment (0.5) | reviewer judgment (0.5) |
| `context` | background colour | reviewer judgment (0.3) | reviewer judgment (0.3) |
| any role, disposition `inconclusive` | — | reviewer judgment (0.5) | — |

The practical consequence, and the point the M3 brief insists on: a benign event
*correctly* used as a baseline or exclusion is **fully credited**, while a real
attack event mis-filed as a "benign baseline" is **misclassified** (B fails)
despite being malicious (C true). Legitimate baseline/precursor/corroborating/
exclusion evidence is credited on its merits; nobody gets full credit "merely
because an event belongs to a hidden malicious incident."

Candidate-safe verification (`candidate_verification`) computes **property A
only**. It never consults truth and the result object carries no B/C keys or
counters — verified in `test_evidence_properties.py` and `test_shadow_regression.py`.

---

## 2. Evidence preservation (verifiable after the source is gone)

`preserve_and_sign` (`PRESERVATION_VERSION = 2`) records, per distinct cited event
that exists:

- **provenance**: the authorized `index`, the candidate's own `query`, the `role`;
- **content digest**: SHA-256 of the canonical `_source`;
- **snapshot**: the full `_source` (embeddable; the candidate index carries no
  truth labels, so a snapshot leaks nothing about the scenario);
- a `preserved` boolean so an un-preservable citation is recorded honestly.

The whole record is Ed25519-signed (origin + tamper-evidence). Integrity ≠
correctness; the signature says the record is authentic and unaltered, never that
the investigation was right.

Verification paths:

- `verify_evidence_record(record, sig)` — signature over the canonical record.
- `verify_record_self_consistent(record)` — **offline**: recompute each digest
  from the embedded snapshot. Needs no cluster, so it works after the candidate
  index is reclaimed between cohorts.
- `reverify_integrity(record, reader)` — against the **live** index; when the
  index is unavailable it falls back to the snapshots and reports
  `index_unavailable` + `verified_offline` instead of a flood of false "missing".

Retention / access / integrity model (documented in-module and enforced by the
storage + HTTP layers):

- **Where**: `CaseSubmission.evidence_record` / `.evidence_sig` in Postgres,
  beside the submission. Never in any candidate-readable index or tenant.
- **Retention**: lifetime of the supporting `BoardResult` plus the appeal/audit
  window; it outlives the OpenSearch index, which the snapshots make
  self-verifying.
- **Access**: Super Admin / reviewers only. A candidate may learn their evidence
  was preserved and that the signature is valid; they never read another
  candidate's record and there is no hidden-truth field in it by construction.

---

## 3. The shadow evaluator — `score_board2_enterprise`

`siem/enterprise_grader.py`, `ENTERPRISE_GRADER_VERSION = 1`, `RUBRIC_VERSION = 2`.
Pure function of `(truth, submission, reader, candidate_index)`; reads no env, DB,
or clock. Evidence verification reuses `case_contract.verify_evidence` — no second
verification system. The protected v2 weights are preserved exactly:

| # | Component | Weight | What is assessed (server-side, against hidden truth) |
|---|---|---|---|
| 1 | incident_identification | 30 | F1 of precision/recall on incident **membership + disposition**. Candidate confirmed incidents are matched one-to-one to truth incidents by cited-member overlap; zero-overlap confirmed incidents are false leads (precision), unmatched truth incidents are misses (recall). |
| 2 | evidence_quality | 20 | Per matched incident: 0.5·chain-coverage + 0.3·mean claim-support **relevance** (property B) + 0.2·reference-validity (property A). Padding with benign/irrelevant citations does not help and is flagged. |
| 3 | attribution | 15 | 0.4·primary-identity + 0.4·ATT&CK technique recall + 0.2·affected-asset recall, derived from the matched incident's true member sources. |
| 4 | detection_gap | 15 | **Conditional.** Only when the seed contains a detection-failure incident: 0.5 for locating the missed activity (matching it) + 0.5 for a named gap **and** a concrete proposed detection. When absent, the component is marked not-applicable and excluded from the denominator (weights never change). |
| 5 | timeline_correlation | 10 | 0.6·chronological ordering of cited member events against true `@timestamp` order + 0.4·cross-source linkage (cited members span ≥2 datasets). |
| 6 | judgment | 10 | 0.5·confidence calibration (Brier over confirmed incidents: correct = matched a real incident) + 0.2·stated limitations + 0.3·response recommendations present. |

**Composite**: `normalized = Σ(points of applicable components) / Σ(weights of
applicable components)`, `score = round(100 · normalized, 1)`. Because incident
identification alone is 30 points, a candidate who misses a real incident cannot
reach 95 by polishing everything else — preserving the v1 spirit.

**Scoring anchors** per component: `full` (≥0.85), `partial` (≥0.40), `none`
(<0.40), attached to each component in the result for reviewer reading.

**Human-review triggers** (in `result["review_flags"]`), in addition to the
per-citation flags surfaced by `verify_evidence`:

| Trigger | Fires when |
|---|---|
| `NEAR_PASS_BAR_REVIEW` | 90 ≤ score < 97 — any result near the bar is read by a human |
| `CONFIDENT_BUT_INCOMPLETE` | a confirmed incident at confidence ≥80 while real incidents were missed |
| `POSSIBLE_EVIDENCE_PADDING` | a matched incident carries ≥4 low-relevance citations (volume that does not advance the claim) |
| `FALSE_INCIDENT_CLAIMED` | a confirmed incident has zero overlap with any real incident |
| `INCONCLUSIVE_ON_TRUE_POSITIVE` | an `inconclusive` disposition cites real incident events |
| `MISSED_DETECTION_GAP` | a detection-failure scenario exists but was not located/named |
| `CITATION_REVIEW_FLAG` | any citation raised a per-citation review flag |

Shadow-only invariants (regression-tested): the grader never imports the
qualification write-path, never writes an objective grade or clearance, and its
output lands only on `CaseSubmission.shadow_score` / `shadow_breakdown` /
`review_flags`. The reviewer endpoint returns scores/anchors/flags **without** the
raw `matching` detail, so truth event_uids are never echoed to a client.

---

## 4. Reviewer rules (versioned, justified, attributable, auditable)

- The shadow score is **advisory**. It never sets pass/fail. Qualification stays
  on `score_board2` + the 95 bar + the signed objective result.
- A reviewer runs the shadow grade with `POST /admin/cases/submission/<id>/shadow`
  (reviewer session + `RANGER_SHADOW_GRADER=1`). The call stores the grade and the
  stamping reviewer is the session admin; re-running recomputes deterministically.
- Reviewer **feedback** (`/feedback`) is the only free-text a reviewer writes; it
  never alters the signed evidence record, the shadow score fields, or any
  objective grade (enforced in `case_routes.py`, tested in `test_case_routes.py`).
- Every review trigger above is a **reason** a submission is surfaced; a reviewer
  resolves `NEAR_PASS_BAR_REVIEW`, `POSSIBLE_EVIDENCE_PADDING`, and citation flags
  before any human decision is recorded.
- Any future reviewer score **adjustment** must be versioned (rubric_version is
  stored per submission), carry a justification, be attributable to the reviewer
  id, and be auditable — it is an addition to, never a mutation of, the signed
  record.

---

## 5. Calibration suite + anti-gaming

`siem/calibration.py` builds nine submission archetypes and two anti-gaming probes
from the protected truth of a seed, grades each, and records expected band / actual
score / agreement / review flags / reason. Full results across five seeds:
**`siem/BOARD2_CALIBRATION_RESULTS.md`**. Asserted by `test_calibration.py`.

Nine archetypes: `fully_correct`, `technically_correct_alternative`,
`partially_correct`, `missed_incidents`, `false_positive`,
`unsupported_fabricated_evidence`, `correct_evidence_incorrect_conclusion`,
`correct_conclusion_insufficient_evidence`, `strong_analysis_weak_response`.

Headline findings (every seed):

- **Only** `fully_correct` (100) and `technically_correct_alternative` (96–98)
  reach the 95 bar; the alternative is flagged for human confirmation. Every
  competence-gap archetype stays below the bar.
- `correct_evidence_incorrect_conclusion` ≈ 10–12 **and** raises a citation flag:
  right evidence, wrong conclusion is caught, not rewarded.
- `strong_analysis_weak_response` is capped below the bar (87–94) whether or not
  the seed has a detection-gap scenario.

Anti-gaming (the explicit tests that a candidate cannot earn an undeserved pass):

- `guessing_shotgun` (many confident incidents on random benign events): 2.5–2.9,
  never passes, `FALSE_INCIDENT_CLAIMED`.
- `evidence_padding` (one real incident padded with benign citations): 65–77,
  never passes, `POSSIBLE_EVIDENCE_PADDING`. Padding adds volume, not credit,
  because property-B relevance gates it.

### Example breakdowns

**Fully correct** (seed `smoke`, 3 incidents incl. a detection-failure): score
**100.0**; components all `full`; no review flags. Every real incident matched,
whole chain cited with reproducing queries, correct identities/techniques/assets,
true-ordered timeline across ≥2 datasets, detection gap located and named,
calibrated confidence with limitations and response.

**Correct evidence, incorrect conclusion** (seed `smoke`): score **10.0**. The
candidate cites the true malicious chain but dispositions it `no_incident`.
incident_identification 0 (no confirmed incident matched), the member citations
are `misclassified` under a benign disposition →
`BENIGN_DISPOSITION_CITES_MALICIOUS_EVENT` + `CITATION_REVIEW_FLAG`;
`MISSED_DETECTION_GAP` because the missed activity was not reported as an incident.

**Evidence padding** (seed `q1-2026`): score **77.2**, below bar. One real incident
fully and correctly evidenced, then padded with 12 benign events cited as
`primary`; each pad is `unsupported` (property B), dragging evidence_quality and
raising `POSSIBLE_EVIDENCE_PADDING`. Recall over the other (unfound) incidents caps
the composite well under 95.

---

## 6. M2 browser-validation workflow (feature-gated, not general candidates)

Purpose: validate the end-to-end candidate experience (Board 2 → assigned case →
Open SOC → investigate → document → verify → submit) and the reviewer shadow path,
**without** opening Board 2 to the cohort.

Preconditions (operator):

1. On the `portal` service set `RANGER_CASE_UI=1`. Keep `RANGER_SOC_ACTAS_ENABLED`
   unset and `RANGER_SHADOW_GRADER` unset for the candidate half of the test.
2. Use a single **synthetic** test candidate (the existing `board2-test` identity),
   `status=active`, `current_board=2`, in the pilot cohort. No real candidate is
   enrolled onto Board 2.
3. Confirm the test candidate's `ranger-<cohort>-<slug>-b2` index is seeded from
   `enterprise.generate(slug, 2, seed, "B")` (same seed the case stores).

Candidate-path checks (as the test candidate, in the built-in browser):

1. `GET /case` → overview renders; brief shows **no** incident count / structure /
   answer. Lifecycle `assigned`.
2. `GET /case/<id>` → workspace opens; lifecycle advances to `investigating`.
3. "Open SOC" → `/soc/launch` reaches Dashboards Discover on `ranger-*` (the Stage-1
   gateway path, already validated).
4. Draft an incident → `POST /case/<id>/draft` autosaves; validation surfaces
   mandatory-field errors; lifecycle → `evidence_collected`.
5. "Verify evidence" → `POST /case/<id>/verify` returns **property A only**
   (`truth_consulted:false`, no claim_support/malicious keys).
6. Try to submit a citation from another index or a fabricated uid → `422` at the
   evidence stage (reference validity enforced).
7. Submit a clean investigation → `200`, `evidence_signed:true`, case `submitted`
   and **locked**; re-draft / re-submit → `409`.

Reviewer-path checks (as an admin session):

8. `GET /admin/cases` and `/admin/cases/<id>` → read-only; evidence signature
   validates; `shadow_score` is `null` until shadow is run.
9. Set `RANGER_SHADOW_GRADER=1`, `RANGER_B2_PROFILE=B`. `POST
   /admin/cases/submission/<sid>/shadow` → `200`, shadow score + components + flags
   returned **without** raw matching; `evidence_sig` unchanged; no objective grade
   written. Unset `RANGER_SHADOW_GRADER` afterwards.
10. Confirm a candidate session gets `403` on the shadow endpoint and `404` when the
    flag is off.

Automated equivalents of every step above run offline in
`siem/tests/test_case_routes.py` (24→29 checks) against the real `create_app()`
with an injected in-memory reader, so the browser pass is a confirmation, not the
only evidence.

---

## 7. Deliverables index

| Deliverable | Location |
|---|---|
| Versioned shadow evaluator | `siem/enterprise_grader.py` (`score_board2_enterprise`, v1) |
| Three-property evidence model + relevance | `siem/case_contract.py` (`verify_evidence`, `_assess_claim`) |
| Evidence preservation + integrity | `siem/case_contract.py` (`preserve_and_sign`, `verify_record_self_consistent`, `reverify_integrity`) |
| Scoring spec + anchors + reviewer rules | this document, §3–§4 |
| Calibration suite | `siem/calibration.py` |
| Calibration results | `siem/BOARD2_CALIBRATION_RESULTS.md` |
| Evidence-property + preservation tests | `siem/tests/test_evidence_properties.py` (17) |
| Shadow grader tests | `siem/tests/test_enterprise_grader.py` (15) |
| Calibration + anti-gaming tests | `siem/tests/test_calibration.py` (75) |
| Security + regression invariants | `siem/tests/test_shadow_regression.py` (12) |
| Reviewer shadow endpoint (gated) | `case_routes.py` (`/admin/cases/submission/<id>/shadow`) |

---

## 8. Explicit production blockers (must clear before any activation)

The enterprise grader is **not** cleared to drive qualification. Before it could
ever be considered for production use, all of the following must be satisfied and
signed off:

1. **Written authorization** to activate — this milestone delivers shadow only; no
   approval to grade candidates for qualification has been given or is assumed.
2. **Real-cohort shadow run**: at least one full cohort graded in shadow alongside
   `score_board2`, with disagreements reviewed. No activation on synthetic data
   alone.
3. **Reviewer adjudication of every near-bar / flagged case** in that shadow run,
   with the agreement rate and every disagreement's reason recorded.
4. **Operational telemetry plane not started**: M4 (continuous ingestion /
   detector scheduling) and its workload/retention/concurrency/cost report are a
   separate, unapproved milestone. The grader currently reads bounded per-seed
   datasets, not a live stream.
5. **No second qualification path**: activation must keep a single bar at 95 and
   must not create an easier route to passing. The composite maps to the same
   0..1 the live path uses; this must be re-confirmed at activation.
6. **Rollback proven**: with `RANGER_SHADOW_GRADER` off (and any future rubric flag
   off) Board 2 grades byte-for-byte as today — asserted by the regression suite
   and to be re-run at activation.
7. **Candidate access + act-as stay disabled** for general candidates during all
   validation; only the synthetic `board2-test` identity exercises the path.
8. **Key hygiene**: `RANGER_SIGNING_KEY` set in production (not the SECRET_KEY-
   derived dev fallback) before any signed shadow record is treated as an artifact
   of record.

Until every item above is cleared in writing, the grader stays shadow-only and off.
