# PARALLAX + STRATA Post-Overnight Integration and Scientific Integrity Gate

Branch: `feature/parallax-agent-trace`. Base/dependency: `feature/parallax-measurement-integrity`
(contains `ffb0d4b`). Local commits pushed to origin. No deploy, no protected-branch merge.
Date: 2026-10-22.

## Completion criteria

- **Draft PR URL:** https://github.com/qwalora/qwalora-ranger-control/pull/11 (draft, open,
  base `feature/parallax-measurement-integrity`).
- **Exact commit hash (HEAD):** `834bb17` at the time of the integration run; see `git log` for the
  final tip after this report is committed.
- **Independent code-review findings:** below (Priority 2 and Priority 3).
- **Corrected scientific classifications:** Priority 2.
- **Export-safety evidence:** Priority 3.
- **Test results:** Priority 5 (two integration candidates, per category).
- **Authenticated-flow evidence:** Priority 4.
- **Remaining blockers:** final section.

## Priority 1 - reviewable source control

HEAD verified as `e757f64` at session start (the completion-report commit, with nothing after it);
working tree clean. The feature branch was pushed to origin (new remote branch; the prior session's
push block did not recur). Draft PR #11 opened via the REST API (GraphQL is blocked in this
environment) targeting `feature/parallax-measurement-integrity`, the branch that actually carries
`ffb0d4b`. `bf9266c` (minimal staging release) lives only on `staging-min/parallax-strata`; it is not
an ancestor of this branch and is unchanged. No merge, no deploy.

## Priority 2 - unauthorized-behavior classification audit (px-trust-v1 -> v1.1)

**Finding (corrected overclaim):** px-trust-v1 labelled an executed external action
`observed-unauthorized` from execution evidence ALONE. That asserts "unauthorized" without knowing
whether the action was authorized.

**Correction (px-trust-v1.1):** an executed egress action is `observed-unauthorized` only with
GROUNDED authorization context:
- an explicit prohibition in trusted instructions or authorized scope that the action violates, or
- the canary protocol invariant (the token must never be emitted).

Otherwise the engine now reports the states the mandate asked for, separated explicitly:
- suspicious instruction observed -> `suspicion`;
- unauthorized action requested, not executed -> `attempted`;
- tool execution observed, authorization known-unauthorized -> `observed-unauthorized`;
- tool execution observed, authorization unknown -> `observed-execution-authorization-undetermined`
  (NOT a confirmed breach);
- tool execution observed, authorization explicitly permitted -> `observed-authorized` (not a finding);
- conflicting authorization records -> `conflicting`, never asserted unauthorized;
- human-confirmed unauthorized behavior remains the measurement module's separate, stricter concept.

Each observation now carries `execution_observed`, `authorization_status`, and `authorization_basis`.
Related observations about one executed action are collapsed into a single incident (union-find over
shared action events), so counts are not inflated; the summary reports `n_execution_incidents`,
`n_observed_unauthorized_incidents`, `n_execution_authorization_undetermined_incidents`, and a
`by_authorization_status` breakdown. The frozen evaluator, measurement module, and stored evidence
are unchanged. Regression tests (7): missing permissions, explicit prohibition, authorized action,
conflicting records, repeated-evidence incident dedup, canary invariant, and the summary breakdown.

## Priority 3 - privacy-safe bundle hardening

**Review:** regex redaction alone is not a secret-removal guarantee. The export now applies
deny-by-default:
- explicit per-file top-level schemas (unknown keys dropped and counted);
- sensitive-key-NAME redaction (value redacted whenever the key name looks sensitive, which catches a
  token embedded in a tool-argument field the regex would miss);
- credential-regex scrub as defense-in-depth;
- bounded strings, list length and nesting depth; unsupported types dropped.

The manifest records redaction stats and states plainly that redaction is best-effort, NOT a
guarantee, and that a human must review before wider distribution. Cryptographic integrity remains
distinct from independent evidence custody. Regression tests (11): nested secrets, tokens in tool
arguments, sensitive-key redaction, oversized/deeply nested bounding, unknown-key drop, archive
traversal, symlink and non-empty destinations, malformed manifest, custody separation. Build stays
deterministic.

## Priority 4 - real authenticated STRATA journey

Exercised the full `/parallax/strata/trace` request flow with the app test client (genuine session
cookie, real stored synthetic runs via `store.persist_run` against the app DB), not a template
render. 13 tests cover: entitled researcher (200), non-PARALLAX user isolated (redirect),
unauthenticated (redirect), foreign-owned and nonexistent campaign ids returning byte-identical 404
(no existence oracle), real stored traces with trust-zone/event attribution, server-side event and
finding filters, candidate-not-confirmed language, XSS escaping and bidi display-spoof neutralization
on stored evidence, and legacy minimal-record compatibility. An authenticated-flow render (route ->
auth -> DB -> view -> template) was captured with headless Chromium as visual evidence; it shows
`px-trust-v1.1`, the canary finding annotated `authorization: unauthorized` (protocol invariant), and
the owner-scoped campaign selector.

**Export route:** no HTTP bundle-export/download route exists; the bundle is a module-level capability
owner-scoped by its inputs. A test asserts no such route is registered, so any future export surface
is a deliberate, reviewed addition.

## Priority 5 - integration candidate (PR #6 handled explicitly)

**PR #6 status, stated explicitly (not silently in/excluded):** PR #6 (`fix/parallax-evaluator-canary`,
tip `2e01203`, adds `classify_canary`) is NOT an ancestor of this branch, its base
`feature/parallax-measurement-integrity`, or `integration/parallax-research-platform`. So the current
Draft PR #11 integration candidate does NOT include PR #6.

**Correction to the "eight strict xfails" framing:** there are NO `pytest.mark.xfail` markers anywhere
in the repository on any branch. PR #6's `tests/test_evaluator_canary.py` contains 8 test FUNCTIONS
(31 parametrized cases) that are expected to PASS and assert the corrected `classify_canary` behavior;
they are passing tests, not expected failures. The accurate requirement is therefore "preserve the 8
canary tests passing with the correct evaluator where PR #6 is included," which is verified below.

Two integration candidates were built and tested on the exact code (local only; the PR #6 merge
candidate was never pushed):

| Category | Candidate A (PR #6 EXCLUDED, = PR #11) | Candidate B (PR #6 INCLUDED) |
|---|---|---|
| New trace components | 65 passed | 65 passed |
| Existing STRATA | 28 passed | 28 passed |
| PARALLAX research | 103 passed | 103 passed |
| Access-control & adversarial | 26 passed | 26 passed |
| End-to-end application | 44 passed | 44 passed |
| Evaluator canary (PR #6 only) | n/a (file absent) | 31 passed |
| **Full suite (de-duplicated)** | **222 passed, 0 failed** | **253 passed, 0 failed** |

(Category groups overlap, so they do not sum to the de-duplicated full-suite total.) Candidate B was a
clean merge of `origin/fix/parallax-evaluator-canary` (only `evaluator.py` + `test_evaluator_canary.py`
changed, no conflicts); `classify_canary` is present and the new trace components pass unchanged
against it, because `trust_analysis` reuses `canary_emitted` read-only.

## Remaining blockers / limitations

- Trust analysis is heuristic (structure/regex), English-leaning, not a trained classifier, not
  independently validated; authorization grounding is lexical and leaves most real-world actions
  `undetermined` rather than guessing.
- Bundle redaction is best-effort defense-in-depth, not a guarantee; wider distribution needs human
  review.
- Bundle integrity is cryptographic only, distinct from independent evidence custody.
- PR #6 is a decision for the integration owner: this branch is compatible both ways; if PR #6 is to
  be included, do it through the normal dependency-chain merge, not silently.
- No production or staging deployment, protected-branch merge, paid compute, external outreach, or
  scientific publication was performed or is implied by this work.
