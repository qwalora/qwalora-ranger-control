# PARALLAX + STRATA Overnight Engineering Report
## Research-Grade AI-Agent Security Investigation Platform

Branch: `feature/parallax-agent-trace` (based on `ffb0d4b`, the latest verified development
integration, NOT the minimal staging branch). Local-only; not pushed, not deployed.
Date: 2026-10-22. Author: cloudcwfranck.

---

### 1. Executive summary

This session extended the existing PARALLAX/STRATA research platform with a cohesive,
evidence-first capability for investigating a single AI-agent execution: ingest a normalized
trace, analyze where untrusted content attempted to cross a trust boundary, distinguish
suspicion from attempted from actually-observed unauthorized behavior, surface it in an
owner-scoped investigation workspace, and export a deterministic, privacy-safe, verifiable
bundle. Six commits add four new modules, one new read-only route + template, and 64 new tests
(92 pass including the existing STRATA suites). No existing frozen module (evaluator, measurement,
store, strata_view, strata_investigation) was modified; `bf9266c` and production were not touched;
nothing was deployed. Central honesty invariant held throughout: a heuristic detection is a
CANDIDATE for human review, never a confirmed compromise, and cryptographic/structural consistency
is never represented as independent human validation.

### 2. Verified baseline (what already existed, confirmed working)

- Flask + Jinja portal with a nonprod-gated PARALLAX research platform under `parallax/research/`.
- Frozen evaluator (`evaluator.py`), measurement integrity (`measurement.py`, `px-measure-v1`,
  six adjudication states, `candidate_asr` vs `confirmed_asr=not_established`), signed evidence
  (`signing.py`, Ed25519+SHA-256), `evidence_verifier.py`, `checkpoint.py`, owner-scoped `store.py`,
  `strata_view.py`, and the STRATA investigation page (`/parallax/strata/investigation`).
- Confirmed unchanged by this session via `git diff --stat ffb0d4b..HEAD` (empty for all frozen
  core files). Existing STRATA suites still pass (28).

### 3. Implemented features (this session)

| Workstream | Module | Schema | Tests |
|---|---|---|---|
| A ingestion/normalization | `parallax/research/agent_trace.py` | `px-trace-v1` | 18 |
| B trust-boundary analysis | `parallax/research/trust_analysis.py` | `px-trust-v1` | 12 |
| E reproducible bundles | `parallax/research/investigation_bundle.py` | `px-ibundle-v1` | 10 |
| C investigation workspace | `parallax/strata_trace_view.py` + template + route | (view model) | 6 |
| F adversarial/security | `tests/test_parallax_security_adversarial.py` | - | 13 |
| D measurement integrity | `tests/test_parallax_measurement_integrity.py` | - | 5 |

- **A**: two adapters (PARALLAX run record + one external open-agent-trace format). Trust zones,
  nine event types, observed-vs-inferred flags, event/ingestion/review timestamps, recorded gaps
  for absent fields (never fabricated tool calls/results/timestamps/authorization), deterministic
  `trace_hash`, NFKC + control-char normalization, bounded parsing (`MAX_EVENTS`,
  `MAX_CONTENT_CHARS`, `MAX_TOTAL_INPUT_BYTES`), credential scrubbing for fixtures.
- **B**: per-observation source, claimed authority, intended redirection, target action, policy
  boundary, supporting/missing evidence, and a severity ladder suspicion -> attempted ->
  observed-unauthorized. Observed-unauthorized is emitted ONLY with recorded execution/emission
  evidence. Reuses the frozen evaluator read-only; documents its limitations (including the eight
  tracked canary xfails that belong to PR #6, which this branch's base deliberately lacks).
- **C**: read-only `/parallax/strata/trace` page: filterable trace explorer (event type / trust
  zone / finding / evidence), bounded + HTML-escaped evidence excerpts with bidi/zero-width
  neutralization, observed boundary-crossing relationships labelled structural (not causation),
  and a deterministic investigation summary.
- **E**: deterministic privacy-safe export (manifest, events, analysis, review, coverage,
  machine-readable summary, checksums, verification instructions) + `verify_bundle` detecting
  tampered/incomplete/mismatched/unverifiable bundles.
- **D/F**: regression suites pinning the measurement contract and hardening the new surfaces.

### 4. Architecture

Each new module is additive and composes over the existing owner-scoped store:

```
stored run (owner-scoped)                   external trace (one documented format)
        |                                            |
        v                                            v
   agent_trace.from_parallax_record        agent_trace.from_open_agent_trace / ingest
        \__________________  px-trace-v1  __________/
                               |
                               v
                     trust_analysis.analyze  --> px-trust-v1 (observations, crossings, limitations)
                               |
            ___________________|________________________
           |                                            |
           v                                            v
  strata_trace_view.assemble_trace_view        investigation_bundle.build_bundle / verify_bundle
  (route /parallax/strata/trace, read-only)     (px-ibundle-v1, deterministic, verifiable)
```

`build_summary` is shared by the view and the bundle, so the workspace and the exported artifact
report identical scientific status. No parallel datastore is introduced; all run access goes
through `store.get_run` / `store.overview_for`, which are owner-scoped.

### 5. Security review (Workstream F)

Probed and locked with regression tests:
- **Access control / IDOR**: an explicitly requested campaign outside the viewer's set raises
  `CampaignNotFound` (identical 404 for a foreign-owner id and a nonexistent id; no existence oracle).
- **Route gate**: `/parallax/strata/trace` returns 404 in production and 302 to login when
  unauthenticated in nonprod (verified with the Flask test client).
- **XSS**: evidence excerpts are Jinja-autoescaped; a `<script>` payload renders as `&lt;script&gt;`
  (verified in a real render).
- **Display spoofing (defect fixed)**: untrusted evidence containing bidi-override (U+202E) or
  zero-width characters previously reached excerpts verbatim and could visually spoof an
  exfiltration URL. Fix neutralizes them in the DISPLAY excerpt only (made visible, with a reviewer
  notice); stored trace content and its hash are never altered.
- **Resource exhaustion**: oversized input and pathologically deep JSON (60k levels) surface as
  handled `TraceValidationError`, never an uncaught `RecursionError`; event count is bounded.
- **Bundle path safety**: refuses symlinked and non-empty destinations and `..`/absolute archive
  members (reuses `evidence_verifier` hardening).
- **Error leakage**: route failures return generic messages, never internals.

### 6. Scientific integrity (Workstream D)

- The six adjudication states, `candidate_asr`, and `confirmed_asr=not_established` are preserved;
  verified by running the REAL `measurement.summarize` / `augment_metrics` (not mocked) against a
  candidate-only run.
- The new interface agrees: `independent_validation = none claimed`, inferential findings
  `disabled_pending_external_statistical_review`, canary emission labelled a candidate pending human
  adjudication. No heuristic is promoted to confirmed; AI analysis is never called independent human
  adjudication.
- The eight evaluator xfails are a PR #6 concern (classify_canary), which this branch's base lacks;
  they are referenced as a documented frozen-evaluator limitation, not fabricated or "resolved" here.

### 7. Verification commands, counts, and browser evidence

```
# new-module suites
.venv-ui/bin/python -m pytest tests/test_agent_trace.py tests/test_trust_analysis.py \
  tests/test_investigation_bundle.py tests/test_strata_trace_view.py \
  tests/test_parallax_security_adversarial.py tests/test_parallax_measurement_integrity.py -q
# -> 64 passed

# with existing STRATA suites
... tests/test_strata_investigation_ui.py tests/test_strata_timeline_verify.py tests/test_strata_view.py -q
# -> 92 passed
```

Browser evidence: the trace-explorer template was rendered with headless Chromium
(`/opt/pw-browsers/chromium-1194`) from a realistic view model; the screenshot shows the four-event
trace, trust-zone badges, the `canary_emission` finding labelled observed-unauthorized with a
"(candidate)" caption, empty relationships (honest for PARALLAX data), and the "does not assert
confirmed compromise / independent validation: none claimed" summary. This is a LOCAL TEMPLATE
RENDER for layout verification, not a live or production test.

### 8. Reproducibility demo (bundle build + verify)

An external trace with an injection AND a confirming exfiltration tool-result was ingested,
analyzed (two observed-unauthorized findings, correct because execution evidence was recorded),
and bundled:
- `verify_bundle` on the clean bundle: `ok=true`, 8 files checked.
- Rebuilding to a second directory produced an identical `bundle_hash` (determinism).
- Tampering `summary.json` was detected: `checksum mismatch (tampered): summary.json`.
- Verification output states consistently that it proves internal consistency only, not independent
  custody or independent human validation.

### 9. Source control

Six descriptive commits on `feature/parallax-agent-trace` (off `ffb0d4b`):
`b5bd200` (A), `35b7ee9` (B), `f9725e5` (E), `5ba75a1` (C), `dc8173f` (F), `079e627` (D).
No history rewrite, no force-push, no protected-branch merge. `bf9266c` is only on
`staging-min/parallax-strata`; it is not an ancestor of this branch and was not touched. The branch
is local only (not pushed); any Draft PRs remain open and unchanged.

### 10. Railway status

Checked read-only this session. Project `qwalora-ranger`; env `parallax-nonprod`; service
`parallax-portal` current deployment `eb9e925e` = SUCCESS on commit `b0f1588`
(`feature/parallax-p1-architecture-foundations`), deployed 2026-10-20, unchanged by this session.
Nothing from the overnight branch was deployed. (An `environment-status` call returned a transient
viewer-role error; `list-deployments` confirmed health.)

### 11. Remaining limitations

- Trust analysis is a structure/regex heuristic, English-leaning, NOT a trained classifier and NOT
  independently validated; multilingual injections may be missed.
- The external-trace adapter covers one documented shape (open-agent-trace-v0); others would need
  their own adapters.
- Relationships are structural/temporal adjacencies, explicitly not proven causation.
- Investigation-bundle consistency is cryptographic only; independent custody and independent human
  validation are out of scope and never claimed.
- The eight canary xfails and PR #6's `classify_canary` are not on this branch's base.

### 12. Next milestone

Open a Draft PR for `feature/parallax-agent-trace` for independent review; add adapters for
additional external trace formats; add signed-evidence bundling that reuses `checkpoint.py` chain
folding so a bundle can carry a verifiable campaign-chain anchor (still distinct from independent
custody); and, only on separate explicit authorization, consider a nonprod deployment under the
existing minimal-release conditions (this session does not broaden that authorization).
