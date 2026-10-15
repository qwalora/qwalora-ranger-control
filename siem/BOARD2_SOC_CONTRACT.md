# Board 2 SOC candidate experience and assessment contract (design for approval)

Status: DESIGN ONLY. No scoring behavior implemented, no candidate access enabled.
Preserves: per-candidate isolation (index + DLS + private tenant), hidden scenario
truth, `program.PASS_BAR = 95.0`, the existing graders, and the signed-evidence
mechanism (`signing.py`, Ed25519). Any new rubric ships in shadow mode.

This contract defines the missing piece: a candidate-submission grader and
operational experience for the ENTERPRISE SIEM telemetry (`siem/enterprise.py` →
per-candidate OpenSearch index via `soc_gateway.py`). It does not change the live
`scenarios.py::score_board2` hunt grader, which keeps running unchanged.

---

## 0. Grounding in current code (what exists today)

- Dataset: `enterprise.generate(candidate_id, board, seed, profile="B")` → `(events, truth)`,
  a PURE function of the seed. Events are indexed with NO labels (`_malicious` stripped);
  every event carries `ranger.event_uid` (sha256-derived) plus ECS fields and
  `@timestamp` / `event.ingested` (out-of-order simulation). Board 2 uses profile B
  (8000 benign, 3 incidents, 14-day window).
- Hidden truth (never indexed, recomputable from the seed server-side):
  `{"profile", "incidents": [{"family","event_uids","techniques","verdict","actor_ip","primary_identity"}], "counts": {...}}`.
  `SCENARIO_FAMILIES = [privileged-identity-compromise, data-exfiltration,
  compromised-service-identity, endpoint-lateral-movement, detection-failure]`.
  `verdict ∈ {true_positive, true_positive_missed_by_detector}`.
- Detectors: `siem/detection.run_rules(events)` + `correlate(findings)` are deterministic.
  The `dns-c2-known-domain` rule is deliberately narrow (matches only `cdn-metrics.ru`),
  which is the intended gap behind the `detection-failure` incident.
- Grade channel: `models.BoardResult` (one row per candidate+board) holds
  `objective_score`, `objective_passed`, `objective_sig`, `signature`. There is no
  separate Submission/Attempt table; a hunt submission is graded transiently in
  `/grade/submit` and only the result persists.
- Threshold: `program.PASS_BAR = 95.0`, applied in `_record_objective` and the gate
  `_evaluate_gate` (objective_passed AND report approved).
- Signing: `signing.py` — `canonical(payload)`, `sign(payload)`, `verify(payload, sig, pub?)`,
  `public_key_b64()`. Ed25519 over canonical JSON of arbitrary claims. `validate_live.py`
  F9 already signs a case snapshot `{candidate, board, index, findings, ts}` and proves
  tamper-detection — the pattern this contract productionizes.
- Isolation: `authz.index_name` = `ranger-<cohort>-<slug>-b<board>`, per-candidate role
  `cand_<slug>` read-only with DLS on `ranger.candidate_id`, private Dashboards tenant.
- Org/topology: `enterprise.ORG = "valyria-financial"` with departments, service
  accounts, admins, hosts, benign and suspicious externals.

---

## 1. Metric provenance

Principle: every SOC metric is COMPUTED from a real authoritative source and never
fabricated. Two source classes only: (a) the candidate's own OpenSearch index (the
fixed scenario snapshot), and (b) the Ranger control plane (Postgres) recording the
candidate's own real actions and results. No invented organizational activity, no
synthetic "team performance," no made-up live feed.

| Metric | Authoritative source | Calculation | Collection interval | Freshness indicator | Permissions | Missing-data behavior |
|---|---|---|---|---|---|---|
| Events in scope | OpenSearch `ranger-<cohort>-<slug>-b2` | `_count` | On page load / manual refresh | `dataset_generated_at` (seed provisioning time) + `last_queried_at`; dataset is a fixed snapshot, labeled "scenario snapshot (not live)" | Candidate: own index via JWT+DLS. SOC admin: ranger-* read | "Dataset not provisioned" state; never a zero fabricated as activity |
| Time coverage | OpenSearch min/max `@timestamp` agg | min/max | On load | Static window (e.g. 2026-03-01..03-14) shown explicitly | same | "No events" banner |
| Detector findings (alerts) | `siem/detection.run_rules(events)` over the candidate's own dataset | deterministic rule pass | On load (recomputed from the same seed, so reproducible) | derived from seed; stable | Candidate: own. SOC admin: oversight | "No detector findings" (legitimate for a quiet window) |
| Correlated clusters | `siem/detection.correlate(findings)` | group_by user.name, 120-min window | On load | derived from seed | same | empty set |
| Open/assigned cases | Ranger Postgres `Case` (new) | count by status for this candidate | On action | `updated_at` | Candidate: own cases; SOC admin: all | "No case assigned" |
| Triage progress | Ranger Postgres `CaseAnnotation` (candidate's own real triage actions) | reviewed / flagged counts | On action | `updated_at` | Candidate: own | zero = genuinely none done |
| Time on case | Ranger Postgres `Case.started_at` → now/submitted_at | elapsed | On action | live clock | Candidate: own | n/a before start |
| Submission status / score | Ranger Postgres `CaseSubmission` + `BoardResult` | stored values | On submit | `submitted_at`, `graded_at` | Candidate: own; SOC admin: oversight | "Not submitted" |

"Continuously changing" values are limited to class (b): the candidate's OWN activity
counters (events reviewed, queries run, time on case) and recomputed detector views.
The graded dataset itself does NOT change (it is the fixed snapshot), which is the
fairness anchor (section 6). Any dashboard tile that looks live is a view over the
fixed window and/or the candidate's real actions, and is labeled as such. Absent data
is always rendered as an explicit empty/unprovisioned state, never a fabricated number.

---

## 2. Candidate responsibilities (Board 2 = threat-hunter)

Mapped to the five scenario families actually generated.

- Monitoring: establish the environment baseline (valyria-financial: departments,
  service accounts, admins, normal external endpoints) from the SIEM surface, and
  recognize deviations. Deliverable signal: a stated baseline and the anomalies noticed.
- Triage: for each surfaced detector finding and each self-found anomaly, assign a
  disposition, severity, and calibrated confidence. Omission = treated as benign.
- Incident investigation: reconstruct each real incident chain end to end by
  `event_uid`, identify the `primary_identity`, `actor_ip`, affected assets (hosts),
  and the ATT&CK techniques, and rebuild the timeline despite out-of-order ingestion
  (`event.ingested` ≠ `@timestamp`).
- Threat hunting: proactively find the incident that NO detector surfaced
  (`detection-failure` family: DNS C2 to a domain the narrow rule misses). This is the
  component that separates a hunter from an alert-triager.
- Detection engineering (assessment, not board-3 authoring): name the specific
  detection gap (which rule/telemetry failed and why) and propose a concrete,
  testable improvement. Full rule authoring/evaluation stays a Board 3 concern; here it
  is assessed as a written detection recommendation tied to real events.

A complete Board 2 attempt must address all three real incidents in the profile-B
dataset, including the detector-missed one, with cited evidence.

---

## 3. Case lifecycle

A `Case` represents the candidate's assigned investigation of their board-2 dataset.
States and who drives each transition:

| State | Trigger | Automatic or reviewer |
|---|---|---|
| assigned | Candidate enters board 2 (`_promote` → current_board=2); seed already in `ScenarioAssignment`; `Case` created referencing the candidate's index + seed | Automatic |
| authorized | Candidate is `active` and `current_board == 2`; `/soc` gateway grants scoped JWT | Automatic (server-side gate) |
| investigating | Candidate opens the case; `started_at` stamped | Automatic on first open |
| evidence_collected | Candidate accumulates cited `event_uid`s + queries (saved to the case) | Automatic as they save |
| draft | Candidate saves the incident submission form without submitting | Automatic |
| submitted | Candidate submits; the case locks; evidence snapshotted and signed | Automatic |
| evaluated | Objective grader runs server-side against the hidden truth; `BoardResult` recorded + signed; v2 computed in shadow | Automatic |
| feedback | Per-component feedback returned (what was found/missed, without leaking the key) | Automatic; reviewer may add notes |
| closed | Board cleared (`objective_passed` AND report approved) → promotion; or washed_out after the attempt policy | Automatic for pass; reviewer for wash-out/override |

Reviewer-only actions: approving the subjective `Report` (`report_status`), reviewing
shadow v2 vs v1 before any flag flip, manual override / wash-out, and granting any
re-attempt. Everything else is automatic and server-side.

---

## 4. Submission interface (Ranger-native incident form)

A Ranger-native form (not a Dashboards saved object) posted to a new authenticated
endpoint. One submission may contain multiple incidents. Canonical JSON schema
(`CaseSubmission.payload`):

```json
{
  "case_id": "string",
  "rubric_version": 2,
  "baseline_summary": "string (candidate's environment baseline + anomalies)",
  "incidents": [
    {
      "label": "candidate's short name for the incident",
      "disposition": "confirmed_incident | no_incident | inconclusive",
      "severity": "low | medium | high | critical",
      "confidence": 0,
      "attack_techniques": ["T1078", "T1059.001"],
      "primary_identity": "user.name value",
      "actor_ip": "source.ip value",
      "affected_assets": ["host.name", "..."],
      "timeline": [
        {"event_uid": "…", "ts": "ISO-8601", "note": "what happened"}
      ],
      "cited_evidence": [
        {
          "event_uid": "…",
          "index": "ranger-<cohort>-<slug>-b2",
          "query": { "…OpenSearch DSL the candidate ran…" },
          "time_context": {"gte": "ISO", "lte": "ISO"}
        }
      ],
      "detection_assessment": {
        "detector_should_have_fired": true,
        "gap": "which rule/telemetry missed it and why",
        "proposed_detection": "concrete, testable rule idea"
      },
      "response_recommendations": ["containment", "eradication", "..."]
    }
  ]
}
```

Form UX (Ranger portal, not Dashboards): structured fields with pickers for
disposition/severity/technique (ATT&CK), a confidence slider (calibrated), a timeline
builder that accepts `event_uid`s pasted from Discover, an evidence table where each
row requires an `event_uid` and the exact query used, and free-text for baseline,
detection assessment, and response. Linear/line-style icons, no AI checkmarks. The
form validates client-side for completeness, but all authority checks are server-side
(section 5). Draft autosaves to the candidate's own `Case` record (Postgres), not to a
tenant saved object, so grading never depends on Dashboards state.

---

## 5. Evidence verification contract

Ranger treats candidate prose, screenshots, and claimed event details as UNTRUSTED.
Authority comes only from the real documents in the candidate's index and the hidden
truth recomputed from the seed. At submission, server-side:

1. Existence: each cited `event_uid` MUST exist in the candidate's own index
   (`ranger-<cohort>-<slug>-b2`), fetched by the broker scoped to that index. A uid not
   present is rejected (fabricated/foreign citation).
2. Scope: citations outside the candidate's own index pattern are impossible to
   satisfy (DLS + index scoping) and are rejected. A uid from another candidate's
   dataset will not exist in theirs.
3. Query reproducibility: the submitted DSL `query` is re-executed read-only against
   the candidate's index; Ranger confirms the cited `event_uid`s are actually returned
   by that query in that time context. Claimed-but-unreproducible citations are flagged
   and do not earn evidence credit.
4. Timestamp integrity: the cited event's `@timestamp` (and `event.ingested`) are read
   from the index, not from the candidate; any candidate-provided time is ignored for
   scoring and only compared for the candidate's timeline-reconstruction credit.
5. Preservation + integrity: at submission Ranger snapshots each cited event as
   `{event_uid, sha256(canonical(_source))}`, assembles a case evidence record
   `{candidate, board, cohort, seed, case_id, index, cited: [...], submitted_at}`, and
   signs it with `signing.sign(...)` (Ed25519). Re-verification later recomputes the
   hashes and `signing.verify(...)` the record, proving the graded evidence was not
   altered. This reuses the exact pattern already demonstrated in `validate_live.py` F9.
6. Truth comparison: incident membership is checked by intersecting cited `event_uid`s
   with `truth["incidents"][i]["event_uids"]`; techniques against `truth…["techniques"]`;
   attribution against `primary_identity` / `actor_ip`. The truth is recomputed
   server-side from the seed (`enterprise.generate` is pure) and never sent to the
   browser or stored in the index.

No step trusts a screenshot or a candidate-stated field value as authoritative.

---

## 6. Assessment fairness

Separation of concerns:

- Graded evidence is REPRODUCIBLE and STATIC. The dataset is
  `enterprise.generate(slug, 2, seed, "B")`, a pure function of the seed over a fixed
  window. It does not stream or mutate. Any candidate, at any time, investigating seed
  S sees exactly the same events and the same hidden truth. Grading is server-side
  against that truth.
- Live-looking telemetry is PRESENTATION only. Dashboards/metrics render views over
  the fixed snapshot plus the candidate's own real actions; they never alter the graded
  dataset or the truth. "Live" tiles are computed over the scenario window, explicitly
  labeled as a snapshot, so no candidate is advantaged by wall-clock timing.
- Consistency across candidates: identical rubric and weights; identical difficulty
  profile (B: 8000 benign / 3 incidents / 14 days / same five-family structure); seeds
  never repeat across people or cohorts (`ScenarioAssignment` unique on
  `(github_id, board, seed)`), so answers cannot be shared and every candidate faces an
  equivalent-difficulty, non-identical scenario. Time-of-day and session length do not
  affect the available evidence because the data is fixed.

---

## 7. Grading integration (preserve 95%, shadow the new rubric)

New server-side grader, additive and shadowed, analogous to `score_board2`:

```
score_board2_enterprise(truth, submission) -> (score_0_100, breakdown, per_incident)
```

- Inputs: the recomputed hidden `truth` for the candidate's seed, and the verified
  `CaseSubmission` (only reproducible, existing, in-scope citations count).
- v2 composite (from `BOARD2_RUBRIC_V2.md`, weights sum to 100): incident
  identification 30, evidence quality 20, attribution 15, detection-gap finding 15,
  timeline & correlation 10, judgment under uncertainty 10. Component 1 at 30 points
  means missing a real incident cannot reach 95%, preserving the gate's meaning.
- Output maps to 0..100 exactly like `score_board2`, so the existing arithmetic is
  untouched: `BoardResult.objective_score`, `objective_passed = score >= PASS_BAR`
  (95.0), `objective_sig = signing.sign({"kind":"objective",...})` via the existing
  `_record_objective`. The gate `_evaluate_gate` (objective_passed AND report approved)
  is unchanged.
- Shadow mode (required before any flag flip): for real submissions, compute the v2
  enterprise score ALONGSIDE the current objective channel, store it with
  `rubric_version` and the component breakdown, and DO NOT use it for promotion. Compare
  v1 vs v2 for at least one cohort, reviewer-reviewed, before flipping a single
  `BOARD2_RUBRIC_V2` flag (default off). The live `scenarios.py` hunt grader and the
  95% threshold remain the source of truth until then.
- Signed evidence: the case evidence record (section 5.5) is signed and linked to the
  `BoardResult`, so a credential can be independently re-verified at `/verify/<handle>`
  using the existing Ed25519 public key.

No new scoring behavior is activated by this design; it specifies the shadowed path.

---

## 8. SOC operational model (no invented activity)

- Shift = a bounded investigation session on the assigned case; there is no fake
  always-on feed. The candidate's queue is their board-2 case (three real incidents in
  the fixed dataset).
- Alerts = the deterministic `detection.run_rules` findings over the candidate's own
  dataset (real, reproducible). The detector-missed incident deliberately has no alert,
  which the candidate must hunt.
- Escalation = correlation (`detection.correlate`, group-by user, 120-min window) and
  the candidate marking an incident critical / submitting. Real, computed, not invented.
- Supervisor review = the SOC administrator (`ranger_soc_admin`, read-only oversight
  tenant) approves the subjective `Report` and reviews shadow v2 vs v1. No fabricated
  supervisor metrics or team performance.
- Explicitly excluded: invented MTTR/MTTD, team leaderboards, synthetic "other
  analysts," or any number not computed from the candidate's real actions or the fixed
  dataset. Operational realism comes from the scenario structure, not from faked org
  activity.

---

## 9. Security model

- Candidate isolation: per-candidate index + `cand_<slug>` role (read-only) + DLS on
  `ranger.candidate_id` + private Dashboards tenant. Unchanged by this design.
- Private saved objects: the candidate's Discover/saved-search objects live in their
  own tenant; grading never depends on them (submissions are Ranger Postgres records).
- Hidden truth: never indexed, never sent to the browser; recomputed server-side from
  the seed at grade time. The answer key cannot be queried from the SIEM.
- Administrative oversight: `ranger_soc_admin` has read-only oversight across `ranger-*`
  and cannot write candidate data or see the hidden truth.
- Explicit authorization: every investigative action goes through the `/soc` gateway
  (session + active + board-2 gate + short-lived JWT); submission endpoints require the
  candidate's own authenticated session; act-as stays admin-only and disabled by
  default. Signed evidence prevents post-hoc tampering of graded citations.

---

## End-to-end walkthrough: one financial-sector incident

Scenario family: `privileged-identity-compromise` in valyria-financial
(techniques T1078 → T1098 → T1059.001 → T1213). Seed S, profile B.

1. Access: candidate signs in with GitHub, is `active` on board 2, opens
   `/soc/launch`; the gateway provisions their index + data view and proxies them into
   Discover scoped to `ranger-<cohort>-<slug>-b2` over the scenario window. A `Case` is
   in state `assigned` → `investigating`.
2. Monitoring/baseline: the candidate reviews ~8000 benign events across 14 days and
   states the baseline (normal admins, service accounts, external endpoints).
3. Triage: a detector finding flags an anomalous privileged logon (T1078) from an
   unusual `source.ip`. The candidate dispositions it `confirmed_incident`, severity
   `high`, confidence 70.
4. Investigation: pivoting on the identity and IP, the candidate reconstructs the
   chain by `event_uid`: account manipulation (T1098), PowerShell execution
   (T1059.001), access to an information repository (T1213). They rebuild the timeline
   using `@timestamp` while noting an out-of-order `event.ingested`, and record the
   `primary_identity` (the admin account) and affected hosts.
5. Hunt: the candidate separately finds the `detection-failure` incident (DNS C2 to a
   domain the narrow `dns-c2-known-domain` rule does not match), which produced no
   alert.
6. Detection assessment: they name the gap (rule only matches `cdn-metrics.ru`; the
   real beacon domain differs) and propose a broader, testable detection.
7. Submission: they complete the Ranger incident form (disposition, severity,
   confidence, timeline of `event_uid`s, affected assets, cited evidence with the exact
   DSL queries, detection assessment, response recommendations) and submit. The case
   locks.

Exact expected deliverables (per the section 4 schema): a `baseline_summary`; for the
privileged-identity incident, `disposition=confirmed_incident`, `severity=high`,
calibrated `confidence`, `attack_techniques=[T1078,T1098,T1059.001,T1213]`,
`primary_identity` and `actor_ip` matching truth, `affected_assets`, a `timeline` of
the real `event_uid`s in correct order, `cited_evidence` with reproducible queries, a
correct `detection_assessment` for the C2 gap on the hunt incident, and
`response_recommendations`; and a separate incident entry for the detector-missed C2.

What the evaluator independently verifies (server-side, against hidden truth and the
real index):

- Each cited `event_uid` exists in the candidate's index and the submitted query
  reproduces it (sections 5.1-5.3).
- Cited uids intersect `truth["incidents"][i]["event_uids"]` → incident identification
  and evidence-quality credit; non-member citations reduce precision.
- `attack_techniques` match `truth…["techniques"]`; `primary_identity` and `actor_ip`
  match truth → attribution credit.
- The `detection-failure` incident was found and the gap correctly named → detection-
  gap credit (impossible to earn from alerts alone).
- Timeline order and cross-source linkage are scored against the true chain.
- The evidence record is hashed and Ed25519-signed; the score is written to
  `BoardResult` with a signed objective attestation; v2 is recorded in shadow; the 95%
  gate and report-approval gate decide clearance.

No screenshot, claimed count, or prose assertion is trusted; only reproducible queries
against the candidate's real index and comparison to the recomputed hidden truth.

---

## What this design intentionally does NOT do yet

- No grader code, endpoints, models, or UI are implemented.
- No `BOARD2_RUBRIC_V2` flag is flipped; the enterprise v2 score would run in shadow.
- No candidate access or act-as is enabled.
- The live `scenarios.py::score_board2` grader and `program.PASS_BAR = 95.0` are
  unchanged and remain authoritative until a reviewed shadow comparison supports a flip.
