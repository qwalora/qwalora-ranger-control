# Board 2 Enterprise SOC rubric — v2 (PROPOSAL, not active)

Status: **draft for approval**. This does not change grading. The live grader and
the 95% qualification threshold are unchanged and remain authoritative until you
approve activation in writing. v2 is additive and versioned so it can be reviewed,
staged behind a flag, and rolled back without touching v1 results.

## Non-negotiable invariants (unchanged from v1)

- `score_board2` stays the single source of truth for pass/fail, answer-free, with
  the hidden key never present in indexed telemetry.
- The qualification threshold stays **95%**. v2 does not lower it and does not add a
  second, easier path to passing.
- Deterministic per-seed generation and no cross-cohort repeat are unchanged.
- Credit is for demonstrated competence, never for running queries, time in
  Dashboards, or opening alerts.

## Why a v2 is proposed

The enterprise telemetry (8k+ events, overlapping incidents, benign noise, delayed
and out-of-order arrival, a genuine detection-failure case) supports a richer
investigation deliverable than the v1 hunting submission. v2 describes how that
richer work could be scored **without** weakening the bar, so the decision to adopt
it is yours and reversible.

## Versioning and compatibility

- `RUBRIC_VERSION = 2`, stored per submission. Existing submissions stay v1.
- A single feature flag (`BOARD2_RUBRIC_V2`, default off) selects which grader path
  a new submission uses. Off = today's behavior, byte-for-byte.
- v2 maps onto the same 0..1 normalized score `score_board2` already returns, so the
  95% gate arithmetic is untouched. v2 only changes how that 0..1 is composed.
- Compatibility tests (added to the scratchpad suite) assert: v1 submissions grade
  identically with the flag off; the v2 composite still returns 0..1; the threshold
  constant is still 95; and a v1-perfect submission does not regress under v2.

## v2 scoring composite (proposal)

All components are answer-free: each is checked against the hidden truth model
server-side (incident membership by `event_uid`, techniques, verdicts), never by
revealing anything to the candidate. Weights sum to 100 and are the point of review.

| # | Component | What is checked (server-side, against hidden truth) | Weight |
|---|---|---|---|
| 1 | Incident identification | Did the candidate flag the real incident(s) and not the benign look-alikes (precision/recall on incident membership)? | 30 |
| 2 | Evidence quality | Are the cited `event_uid`s actually part of the incident, with the exact queries that surface them? | 20 |
| 3 | Attribution | Correct identities, assets, and ATT&CK techniques for each incident. | 15 |
| 4 | Detection-gap finding | For the detection-failure scenario: did they locate the missed activity and name the rule/telemetry gap? | 15 |
| 5 | Timeline & correlation | Reconstructed order across sources despite delayed/out-of-order arrival; cross-source linkage by identity. | 10 |
| 6 | Judgment under uncertainty | Calibrated confidence, stated limitations, no overclaim on ambiguous benign activity. | 10 |

Passing still requires the composite to reach 95%. Because component 1 alone is 30
points, a candidate who misses the real incident cannot reach 95% by polish
elsewhere, preserving the v1 spirit.

## What v2 does NOT do

- It does not add partial credit for activity without a correct conclusion.
- It does not expose detectors or answers to earn points.
- It does not let a candidate change shared detectors or affect other candidates;
  any detection-engineering sub-task runs against an isolated development copy or a
  backend-controlled validation path.

## Activation path (requires your approval)

1. Approve the weights above (or revise).
2. Land v2 behind `BOARD2_RUBRIC_V2=off`; ship compatibility tests green.
3. Shadow-grade: compute v2 alongside v1 for real submissions without using it, and
   compare, for at least one cohort.
4. Only on your written go-ahead, flip the flag for new submissions, with v1
   retained for rollback.

Until step 4, Board 2 grades exactly as it does today.
