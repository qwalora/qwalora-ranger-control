# Board 2 SOC candidate experience and assessment contract (revised design for approval)

Status: DESIGN ONLY. No grader, endpoint, model, UI, or scoring behavior implemented.
Candidate access and act-as remain DISABLED. Revised per review: adds the two data
planes, three workflows, detailed rubric anchors, the full submission contract, and a
strengthened evidence contract. Preserves per-candidate isolation (index + DLS +
private tenant), hidden scenario truth, `program.PASS_BAR = 95.0`, the live
`scenarios.py::score_board2` grader, current `BoardResult` behavior, and existing
qualification rules. The enterprise rubric stays versioned and in shadow mode until
independently reviewed and approved.

---

## 0. Grounding in current code

- Dataset generator: `enterprise.generate(candidate_id, board, seed, profile="B")` →
  `(events, truth)`, PURE in the seed. Events indexed with NO labels (`_malicious`
  stripped); each carries `ranger.event_uid`, ECS fields, `@timestamp`, and
  `event.ingested` (out-of-order). Profile B = 8000 benign / 3 incidents / 14 days.
- Hidden truth (never indexed; recomputable from the seed server-side):
  `{"profile","incidents":[{"family","event_uids","techniques","verdict","actor_ip","primary_identity"}],"counts":{...}}`.
  Families: privileged-identity-compromise, data-exfiltration,
  compromised-service-identity, endpoint-lateral-movement, detection-failure.
- Detectors: `siem/detection.run_rules(events)` + `correlate(findings)`, deterministic.
  `dns-c2-known-domain` is deliberately narrow (the gap behind detection-failure).
- Grade channel: `models.BoardResult` (one row per candidate+board):
  `objective_score`, `objective_passed`, `objective_sig`, `report_id`, `report_status`,
  `cleared`, `signature`. No separate Submission/Attempt table today.
- Threshold + gate: `program.PASS_BAR = 95.0`; `_record_objective` sets
  `objective_passed = score >= PASS_BAR`; `_evaluate_gate` clears only if
  `objective_passed AND report_status == "approved"`.
- Signing: `signing.py` Ed25519 — `canonical`, `sign`, `verify`, `public_key_b64`.
  Proves INTEGRITY and ORIGIN of a recorded claim; it is NOT a measure of investigative
  correctness.
- Isolation: `authz.index_name` = `ranger-<cohort>-<slug>-b<board>`, role `cand_<slug>`
  read-only, DLS on `ranger.candidate_id`, private Dashboards tenant. Org =
  `valyria-financial`.

---

## 1. Two data planes

Ranger runs two distinct planes. Candidates experience current operational activity
without that activity touching qualification fairness, because the planes are separate
indices, separately labeled, and only the qualification plane is graded.

### 1a. Operational SOC plane (continuous, ungraded)

- Purpose: a living SOC to monitor, triage, and hunt in. Supports skill-building and
  the "assigned investigation" workflow.
- Data: continuously arriving, clearly labeled synthetic/lab telemetry. Every document
  carries `data.synthetic: true` and a new `data.plane: "operational"`. Nothing is
  presented as real production activity.
- Generation: a bounded, rate-limited stream job appends new events (benign baseline
  plus occasional seeded incidents) with near-current timestamps to a per-candidate
  operational index `ranger-ops-<cohort>-<slug>` (proposed name). Built from the same
  `enterprise` building blocks but as a rolling feed rather than a single batch.
- Detection: `detection.run_rules` + `correlate` execute on a schedule over newly
  arrived operational events, producing REAL findings written to an alerts store
  (`ranger-ops-alerts-<cohort>-<slug>` or Postgres). No fabricated alerts.
- Metrics: MEASURED from the actual pipeline (section 2), e.g. events ingested per
  interval, detector findings produced, and detection latency measured as
  `detector_run_ts − event.ingested`. Not invented.
- Grading: NONE. The operational plane never contributes to `BoardResult`.
- Cost note: continuous ingest + scheduled detection adds steady load to the always-on
  SIEM node and is rate-bounded to stay inside budget. Standing it up needs explicit
  infrastructure sign-off before build (no new paid service is created by this design).

### 1b. Qualification plane (deterministic, versioned, isolated, graded)

- Purpose: the formal Board 2 assessment surface.
- Data: the existing deterministic dataset, `enterprise.generate(slug, 2, seed, "B")`,
  a fixed snapshot over a fixed window, in a per-candidate index
  `ranger-qual-<cohort>-<slug>-b2` (proposed name; today's `ranger-<cohort>-<slug>-b2`
  is this plane). Documents carry `data.plane: "qualification"`.
- Versioning: the plane is pinned to a `scenario_version` and the grading to a
  `rubric_version`, both recorded on every submission and result, so a candidate is
  always graded by the exact dataset+rubric they faced.
- Hidden truth: never indexed; recomputed from the seed at grade time. Grading is
  server-side only.
- Isolation: per-candidate index + role + DLS + private tenant, unchanged.

Candidates move between planes in the UI with an unmistakable banner stating which
plane they are in ("Operational SOC — synthetic, not graded" vs "Qualification case —
graded"). Qualification work is never mixed with operational data in the same view.

---

## 2. Operational metric provenance

Two source classes, never fabricated: real data in the plane's indices, and the Ranger
control plane recording real actions/results. Operational metrics are MEASURED from the
actual generation+detection pipeline; qualification "metrics" are stats of the fixed
dataset. Every tile names its plane and its freshness.

| Metric | Plane | Authoritative source | Calculation | Interval | Freshness | Permissions | Missing-data |
|---|---|---|---|---|---|---|---|
| Events ingested | Operational | `ranger-ops-<cohort>-<slug>` | count over window | measured per stream batch | `last_ingest_ts` | own via DLS; SOC admin oversight | "No recent ingest" |
| Ingest rate | Operational | stream job telemetry (Postgres) | events / interval, measured | per batch | `last_batch_ts` | own; admin | "Stream idle" |
| Detector findings | Operational | `detection.run_rules` output store | count by rule/severity, measured | per scheduled run | `last_detector_run_ts` | own; admin | "No findings this window" |
| Detection latency | Operational | finding.`detected_ts − event.ingested` | measured per finding | per run | derived from real timestamps | own; admin | n/a if no findings |
| Correlation clusters | Operational | `detection.correlate` output | measured | per run | `last_detector_run_ts` | own; admin | empty |
| Scenario window | Qualification | `ranger-qual-…-b2` min/max `@timestamp` | min/max agg | on load | static snapshot, labeled | own; admin | "No events" |
| Events in case | Qualification | `ranger-qual-…-b2` | `_count` | on load | `dataset_generated_at` | own; admin | "Not provisioned" |
| Case/triage progress | Both | Postgres `Case`/`CaseAnnotation` | counts of real actions | on action | `updated_at` | own; admin | genuine zero |
| Submission status/score | Qualification | Postgres `CaseSubmission`/`BoardResult` | stored | on submit/grade | `submitted_at`,`graded_at` | own; admin | "Not submitted" |

No tile shows invented org performance (no team MTTR, no synthetic peers, no fake
"other analysts"). Absent data renders as an explicit empty state.

---

## 3. Three workflows

| Workflow | Plane | Candidate must do | Optional practice | Submitted? | Graded? |
|---|---|---|---|---|---|
| A. SOC operations & practice | Operational | Monitor the feed, triage real detector alerts, run queries, practice hunts | All of it is optional practice; self-assessed practice cases available | No (practice cases can be self-checked, not recorded as results) | No |
| B. Assigned incident investigations | Operational or a dedicated investigation dataset | Complete assigned structured investigations and submit them | Extra self-directed hunts | Yes (to the reviewer channel) | Formative only: reviewer feedback; may inform the subjective `Report`; NOT the objective qualification score |
| C. Formal Board 2 qualification | Qualification | Investigate the deterministic case and submit the structured incident report | None (this is the exam) | Yes (to `CaseSubmission`) | Yes: objective via `score_board2_enterprise` (shadow until approved) + subjective `Report` approval; 95% gate |

Mandatory to qualify: complete workflow C (objective pass at 95% AND report approved).
Workflow A is always optional. Workflow B is required practice where a cohort plan
assigns it, but it feeds readiness/feedback, not the objective gate.

---

## 4. Case lifecycle

`Case` (new Postgres model) represents a workflow-B or workflow-C assignment.

| State | Trigger | Automatic or reviewer |
|---|---|---|
| assigned | Entry to board 2 (workflow C) or cohort-plan assignment (workflow B); seed from `ScenarioAssignment`; `Case` created referencing plane + index + seed + `scenario_version` | Automatic |
| authorized | Candidate `active` and `current_board == 2`; `/soc` gateway grants scoped JWT | Automatic (server-side gate) |
| investigating | Candidate opens the case; `started_at` stamped | Automatic |
| evidence_collected | Candidate saves cited `event_uid`s + queries to the case | Automatic |
| draft | Candidate saves the form without submitting | Automatic |
| submitted | Candidate submits; case locks; evidence snapshotted + signed | Automatic |
| under_review | Items flagged for human review (section 8 triggers) await a reviewer | Reviewer |
| evaluated | Automated objective score computed vs hidden truth; `BoardResult` recorded + signed; v2 in shadow | Automatic |
| feedback | Per-component feedback returned (no key leak); reviewer may add notes | Automatic + reviewer |
| closed | Board cleared (objective pass AND report approved) → promotion; or wash-out per attempt policy | Automatic for pass; reviewer for wash-out/override |

Reviewer-only: `Report` approval, resolving `under_review` items, shadow-v2 review,
wash-out/override, granting re-attempts.

---

## 5. Submission contract (Ranger-native)

A Ranger portal form posting to a new authenticated endpoint; the record is Postgres
(`CaseSubmission`), never a Dashboards saved object, so grading never depends on tenant
state. Linear/line-style icons, no AI checkmarks.

### 5a. UI (layout)

- Header: plane banner ("Qualification case — graded"), case id, assessment window,
  attempt number, autosave/draft status, submit button (disabled until mandatory
  validation passes).
- Section Baseline: free text — environment baseline and anomalies noticed.
- Repeatable Incident block, one per identified incident:
  - Disposition (select), Severity (select), Confidence (0-100 slider, calibrated).
  - ATT&CK techniques (multi-select against the ATT&CK catalog).
  - Affected identities (user.name values) and systems (host.name values).
  - Timeline builder: ordered rows, each an `event_uid` + time + note; rows are added by
    pasting a uid copied from Discover.
  - Evidence table: each row = `event_uid` + the exact OpenSearch DSL query run +
    time context; inline validation status per row (exists / reproduces / in-scope /
    supports).
  - Detection effectiveness: did a detector fire; the gap; a proposed, testable
    detection.
  - Containment and remediation recommendations.
  - Analyst conclusion: narrative reasoning for this incident.
- Section Analyst conclusions (overall): summary judgment, stated limitations and
  uncertainty.
- Reviewer feedback and submission status: read-only to the candidate; shows
  submission status and, after review, reviewer feedback and per-component results.

### 5b. JSON schema (`CaseSubmission.payload`), with field obligations

```json
{
  "case_id": "string            // mandatory",
  "plane": "qualification        // mandatory, server-set",
  "scenario_version": "int       // mandatory, server-set",
  "rubric_version": "int         // mandatory, server-set",
  "attempt": "int                // mandatory, server-set",
  "baseline_summary": "string    // mandatory",
  "incidents": [                 // mandatory, >=1
    {
      "label": "string           // mandatory",
      "disposition": "confirmed_incident|no_incident|inconclusive  // mandatory",
      "severity": "low|medium|high|critical                        // mandatory",
      "confidence": "int 0..100                                    // mandatory",
      "attack_techniques": ["Txxxx"],                            //  optional but scored
      "primary_identity": "user.name                               // mandatory if confirmed_incident",
      "actor_ip": "source.ip                                       // optional",
      "affected_assets": ["host.name"],                          //  mandatory if confirmed_incident
      "timeline": [                                              //  optional but scored
        {"event_uid": "…", "ts": "ISO", "note": "…"}
      ],
      "cited_evidence": [                                        //  mandatory if confirmed_incident, >=1
        {"event_uid": "…", "index": "ranger-qual-…-b2",
         "query": { }, "time_context": {"gte":"ISO","lte":"ISO"},
         "supports_claim": "string // what this event proves for THIS incident"}
      ],
      "detection_assessment": {                                  //  optional but scored
        "detector_should_have_fired": "bool",
        "gap": "string", "proposed_detection": "string"
      },
      "response_recommendations": ["string"],                    //  optional but scored
      "analyst_conclusion": "string                               // mandatory if confirmed_incident"
    }
  ],
  "overall_conclusion": "string  // mandatory",
  "stated_limitations": "string  // optional but scored (judgment)"
}
```

Reviewer-owned fields, stored separately on `CaseSubmission` (never candidate-writable):
`submission_status`, `reviewer_feedback`, `per_component_result`, `reviewer_id`,
`reviewed_at`.

### 5c. Validation errors (server-side, surfaced inline)

- `EVIDENCE_UID_NOT_FOUND`: cited `event_uid` not present in the candidate's authorized
  index.
- `EVIDENCE_OUT_OF_SCOPE`: index not the candidate's own `ranger-qual-…-b2`.
- `QUERY_DOES_NOT_REPRODUCE`: the submitted DSL does not return the cited uid in the
  stated time context.
- `MISSING_MANDATORY_FIELD`: a mandatory field is empty (lists the path).
- `CONFIDENCE_OUT_OF_RANGE`, `BAD_TECHNIQUE_ID`, `EMPTY_EVIDENCE_FOR_CONFIRMED`: shape
  checks.
A submission with any `EVIDENCE_*` or `MISSING_MANDATORY_FIELD` error cannot be
submitted (only saved as draft).

### 5d. Drafts, locking, reassessment

- Draft: autosaves to the `Case`; unlimited edits; no grading.
- Submission locking: on submit, the case transitions to `submitted`, the payload and
  the evidence snapshot are frozen and signed, and the form becomes read-only.
- Reassessment: re-attempts are reviewer-granted and policy-bounded (default: limited
  attempts per board). A re-attempt issues a NEW seed via `ScenarioAssignment` (no
  scenario repeat), so memorizing one case does not help. Each attempt is its own
  `CaseSubmission`; `BoardResult` keeps the governing objective score per existing
  behavior.

---

## 6. Evidence verification contract

Candidate prose, screenshots, and claimed values are UNTRUSTED. Credit flows only from
reproducible queries against the candidate's authorized index and comparison to the
hidden truth recomputed from the seed. A valid document reference alone earns NOTHING
if the event does not support the candidate's conclusion.

### 6a. Independent automated checks (server-side, at submission/grade)

1. Existence: each cited `event_uid` exists in the candidate's own
   `ranger-qual-<cohort>-<slug>-b2`.
2. Scope: citation index equals the candidate's own index; out-of-scope is rejected
   (DLS makes foreign uids non-existent for them anyway).
3. Reproducibility: the submitted DSL, re-executed read-only in the stated time
   context, actually returns the cited uid. Non-reproducing citations earn no evidence
   credit. Reproducibility boundary: queries are run with a bounded timeout, result
   size, and the candidate's own role/DLS; a query that errors, times out, or exceeds
   the cap is treated as non-reproducing for that citation (the candidate is told).
4. Support (the key check): the cited event must actually SUPPORT the stated
   conclusion. Automated support = (a) the uid is a member of the truth incident the
   candidate attributes it to (`event_uid ∈ truth.incidents[i].event_uids`), AND (b)
   the event's own fields are consistent with the claimed technique/disposition (for
   example, an event cited as T1059.001 evidence must carry the PowerShell
   execution signal the generator emitted for that step). A cited event that exists and
   reproduces but is a benign/unrelated document earns no incident credit and reduces
   precision.
5. Preservation + integrity: at submit, Ranger snapshots each cited event as
   `{event_uid, sha256(canonical(_source))}`, builds a case evidence record
   `{candidate, board, cohort, seed, scenario_version, case_id, index, cited:[…],
   submitted_at}`, and `signing.sign(...)` it (Ed25519). Re-verification recomputes the
   hashes and `signing.verify(...)` the record.

### 6b. What signatures do and do not mean

The Ed25519 signature proves INTEGRITY (the recorded submission, evidence snapshot, and
score were not altered after the fact) and ORIGIN (they came from Ranger). It is NOT
evidence of investigative correctness. Correctness is established only by the automated
truth comparison (6a.4) and reviewer judgment (section 8), never by the signature.

### 6c. Human-review triggers

Route a `CaseSubmission` to `under_review` when: a technically justified alternative
conclusion is plausible (e.g., the candidate groups the chain differently but covers
the true incident); a citation exists and reproduces but its support is ambiguous; the
objective score lands in a defined band around the 95% gate; the candidate disputes an
automated result; or the detection-gap proposal needs quality judgment. Automated
scoring stands for the unambiguous majority; reviewers adjudicate the flagged minority.

---

## 7. Candidate responsibilities (Board 2 = threat-hunter)

Monitor and baseline the environment; triage detector findings and self-found
anomalies with disposition/severity/calibrated confidence; investigate and reconstruct
each real incident by `event_uid` (identity, actor IP, assets, techniques, timeline
despite out-of-order ingestion); hunt the detector-missed incident; and assess the
detection gap with a concrete, testable proposal. A complete qualification attempt
addresses every real incident in the dataset, including the missed one, with supporting
cited evidence.

---

## 8. Grading design (shadow; not activated)

New server-side grader `score_board2_enterprise(truth, verified_submission) ->
(score_0_100, breakdown, per_incident, review_flags)`. It runs ONLY in shadow
(computed and stored, not used for promotion) until a reviewed one-cohort comparison
supports a flag flip. `score_board2`, `BoardResult` behavior, and `PASS_BAR = 95.0` are
unchanged meanwhile.

### 8a. Components, weights, automated vs reviewer, anchors, partial credit

| # | Component | Wt | Mostly automated or reviewer | Full credit | Partial | Zero |
|---|---|---|---|---|---|---|
| 1 | Incident identification | 30 | Automated (precision/recall on incident membership via supported citations) | All true incidents identified with sufficient supporting evidence, no spurious incidents | recall-scaled; each true incident contributes `30/N` × its support ratio; spurious confirmed incidents reduce precision | No true incident supported |
| 2 | Evidence quality | 20 | Automated (reproducibility + support) | Every cited event exists, reproduces, and supports its claim; incident membership well covered | per-citation average of {reproduces AND supports}; unreproduced or unsupported citations score 0 and drag precision | No supported, reproducible citations |
| 3 | Attribution | 15 | Automated with reviewer fallback | Correct `primary_identity`, `actor_ip`, and exact techniques for each incident | per-incident: identity/IP exact match; technique exact = full, parent-of-correct (e.g. T1059 for T1059.001) = half, wrong = 0 | None correct |
| 4 | Detection-gap finding | 15 | Split: automated (missed incident located) + reviewer (proposal quality) | Missed incident's events cited AND the gap correctly named AND a sound proposed detection | locating the missed incident = up to 10 (automated); proposal quality = up to 5 (reviewer) | Missed incident not found |
| 5 | Timeline & correlation | 10 | Automated | Order matches the true chain; cross-source linkage present | order similarity (rank correlation vs true order) scaled; linkage partial | No coherent ordering |
| 6 | Judgment under uncertainty | 10 | Reviewer with automated calibration input | Calibrated confidence (high on correct, low on uncertain), explicit limits, no overclaim | automated calibration signal informs a reviewer score; overclaiming a wrong incident at high confidence caps this | Systematic overclaim |

Composite maps to 0..100 exactly like `score_board2`, feeding
`BoardResult.objective_score` and `objective_passed = score >= 95.0` via the existing
`_record_objective`. Component 1 at 30 points guarantees that missing a real incident
cannot reach 95.

### 8b. Evidence sufficiency

An incident earns identification/attribution credit only if backed by a minimum of
supporting, reproducible citations (proposed: at least two distinct supported
`event_uid`s spanning at least two stages of the chain). One tangential citation is
insufficient and yields no incident credit even if the disposition label is correct,
preventing "guess the label, cite one event" from scoring.

### 8c. Alternative technically justified conclusions

Where a candidate's grouping or technique choice differs from the key but is defensible
(e.g., citing a correct but broader technique, or splitting one chain into two
incidents that together cover the true membership), automated scoring awards the
mechanical partial credit and raises a `review_flag`; a reviewer may restore full
credit. The truth key is the default; reviewer judgment is the escape valve for
legitimate alternatives, and every override is recorded.

### 8d. Worked pass/fail examples

Passing (illustrative): finds all 3 incidents including the detector-missed one;
citations reproduce and support; techniques/attribution exact; timeline ordered;
calibrated. Component scores 30 + 19 + 15 + 14 + 9 + 9 = 96 → `objective_passed` true.

Failing by missing the hunt (illustrative): finds the 2 alerted incidents well, misses
the detector-missed one. Component 1 caps near `30 × 2/3 = 20`; component 4 scores 0
(missed incident not found); even with strong 2/3/5 elsewhere the ceiling is roughly
20 + 20 + 10 + 0 + 7 + 7 = 64 → fails 95. This is the intended property: an
alert-triager who does not hunt cannot qualify.

Failing by unsupported evidence (illustrative): correct labels but citations are
benign/unrelated or do not reproduce. Component 2 → ~0, component 1 loses the support
ratio, so the composite falls well below 95 despite "right-looking" answers.

---

## 9. Assessment fairness

- Qualification evidence is static and reproducible: `enterprise.generate(slug,2,seed,
  "B")` is pure over a fixed window, versioned by `scenario_version`. Any candidate, any
  time, on seed S sees the same events and the same hidden truth; grading is server-side
  against that truth.
- Operational activity never affects qualification: it lives in a separate plane and
  index, is never graded, and is clearly labeled. Candidates practice freely without
  advantage or jeopardy to their exam.
- Consistency: identical rubric and weights; identical difficulty profile B; seeds
  never repeat (`ScenarioAssignment` unique on `(github_id, board, seed)`); outcome is
  independent of wall-clock time and session length because the graded data is fixed.

---

## 10. SOC operational model (real pipeline, no invented activity)

- Shift = a bounded monitoring/hunting session on the operational plane; the feed is a
  real rate-bounded synthetic stream, not an always-on illusion and not real-org data.
- Alerts = real `detection.run_rules` findings over the operational stream; the
  qualification detector-missed incident has no alert by design.
- Escalation = real `detection.correlate` clusters plus candidate action.
- Supervisor review = `ranger_soc_admin` (read-only oversight) approves the subjective
  `Report` and reviews shadow v2. No fabricated supervisor metrics.
- Measured metrics only (section 2). Explicitly excluded: invented MTTR/MTTD,
  leaderboards, synthetic peers, or any number not measured from the real pipeline or
  the candidate's real actions.

---

## 11. Security and release gates

- Preserve: JWT authorization through the `/soc` gateway, per-candidate indices, DLS,
  private tenants, protected (never-indexed, server-recomputed) scenario truth, and
  `ranger_soc_admin` read-only oversight.
- Candidate access and act-as stay DISABLED.
- No implementation and no grading-behavior change until this revised design is
  approved. The enterprise grader ships versioned and shadow-only even after build,
  pending a reviewed cohort comparison before any flag flip.

---

## 12. End-to-end candidate example (candidate-facing; no answer key)

Board 2 qualification case for candidate A in cohort 2026-A, seed S. The candidate
never sees how many incidents exist, which families, or any truth field.

- Entering the SOC: A opens `/soc/launch`, lands on the Operational SOC with a banner
  "Operational SOC — synthetic, not graded," and a continuous feed with live detector
  findings and measured tiles (events ingested, findings, detection latency). A can
  practice here freely.
- Starting the exam: A opens the Board 2 qualification case. The banner switches to
  "Qualification case — graded." Discover is scoped to `ranger-qual-2026-A-<slug>-b2`
  over the fixed assessment window.
- Available telemetry: the full profile-B dataset (benign baseline plus the embedded
  incidents) and whatever the deterministic detectors surface for this seed. Some
  malicious activity is NOT alerted and must be hunted. No labels are present.
- Ranger instructions (verbatim intent, no key): "Investigate activity in
  valyria-financial across the assessment window. Identify and document any security
  incidents. For each, provide disposition, severity, calibrated confidence, affected
  identities and systems, ATT&CK techniques, a reconstructed timeline, and cited
  evidence (event_uid plus the exact query). Assess detection coverage and name any
  gaps with a proposed detection. Submit when complete."
- What A must discover independently: which events are malicious; how many distinct
  incidents there are; the chain, identity, actor IP, assets, and techniques of each;
  the timeline despite out-of-order ingestion; and the activity no detector surfaced.
- What A submits in Ranger: the structured form of section 5 — baseline, one incident
  block per identified incident (disposition, severity, confidence, techniques,
  identities, assets, timeline, cited evidence with queries, detection assessment,
  response, analyst conclusion), overall conclusion, and stated limitations.
- What OpenSearch evidence must be cited: for each incident, supporting `event_uid`s
  from A's own `ranger-qual-…-b2`, each with the exact DSL query and time context that
  reproduces it; citations must support the stated conclusion, not merely exist.
- What the evaluator checks (server-side): each cited uid exists, is in scope,
  reproduces, and supports its claim (member of the attributed truth incident with
  consistent fields); incident precision/recall; technique and attribution matches;
  whether the detector-missed incident was found and the gap correctly named; timeline
  order; calibration; then signs the evidence record and writes the objective score
  (shadow) and signed attestation; the 95% gate and report approval decide clearance.
- Outcome bands:
  - Incomplete: mandatory fields missing, or confirmed incidents without supported
    reproducible evidence; blocked at submission or scored near zero on evidence.
  - Incorrect: labels or attributions that do not match truth and are not defensible on
    review; low incident/attribution credit.
  - Qualified: all real incidents (including the detector-missed one) identified with
    supported evidence, correct attribution, coherent timeline, and calibrated
    judgment, reaching the 95% objective bar with an approved report.

---

## 13. What this design intentionally does NOT do yet

- No grader, endpoints, models, UI, stream job, or detector scheduler are built.
- No `BOARD2_RUBRIC_V2` flag is flipped; the enterprise score would run shadow-only.
- No candidate access or act-as is enabled.
- The operational plane is not stood up (needs infra sign-off).
- `scenarios.py::score_board2`, `BoardResult` behavior, and `PASS_BAR = 95.0` are
  unchanged and authoritative until a reviewed shadow comparison supports a change.
