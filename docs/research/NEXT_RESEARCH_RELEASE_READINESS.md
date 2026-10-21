# PARALLAX next research release: readiness assessment and PR #4 integration plan

Scope: review the research integration branch and PR #4, state what is implemented/tested/
incomplete, record the scientific-rigor weaknesses and the safe improvements made, and give a
controlled integration plan for PR #4 without merging or deploying it.

Branches: review on `integration/parallax-research-platform` (`2dd429e`); rigor work implemented
on `feature/parallax-research-statistics`; design work on `feature/parallax-design-completion`
(PR #4, open, unmerged).

## 1. Research stack: implemented / tested / incomplete

Implemented and tested (on `integration/parallax-research-platform`):
- Preregistered protocol (`protocol.py`): research question, fixed legitimate tasks, basic and
  advanced attack taxonomies, fixed outcome categories and conditions.
- Deterministic rule-based evaluator (`evaluator.py`) with refusal/negation stripping; no
  LLM-judge.
- Harness (`harness.py`): controlled trials, provenance on every record (infrastructure_backed vs
  simulated), infra/eval failures never scored as results, metrics with explicit denominators and
  exclusions; trial cap and per-trial timeout.
- Backends (`model_backend.py`): host-authorized real HTTP/transformers backends (loopback or
  allow-listed only), a disclosed deterministic stub, weights-digest capture, and validated-model
  gating via `RANGER_RESEARCH_VALIDATED_MODELS`.
- Reproducibility (`reproduce.py`): canonical-JSON artifacts, SHA-256 artifact index, normalized
  records for byte-for-byte scientific reproducibility.
- Signed evidence and provenance taxonomy (`store.py`): Ed25519 + SHA-256, owner-scoped,
  per-record finding-eligibility (validated model AND measured). Reviewer-only adjudication.
- Test coverage: `siem/tests/test_parallax_research*.py`, `tests/test_research_execution.py`
  (55 passed together with the new statistics suite).

Incomplete before this change:
- No interval estimates, significance test, or control comparison in the reported metrics.
- Repetitions pooled as if independent (pseudoreplication); the per-repetition breakdown promised
  in the docstring was not computed.
- No aggregate finding-eligibility (even validated, measured records were not tested for adequate
  power or a significant effect before being presentable as a finding).
- No explicit negative-result reporting and no written scientific-limitations statement.

## 2. Scientific-rigor weaknesses and the safe fixes made

Implemented on `feature/parallax-research-statistics` (additive; no change to signing, the
per-record taxonomy, historical evidence, or infrastructure):
- `parallax/research/statistics.py`: Wilson confidence intervals; Fisher's exact test and a
  Newcombe risk-difference interval for attack vs control; cell-level (independent-unit) estimation
  that collapses correlated repetitions; per-category and per-repetition breakdowns; an aggregate
  finding-eligibility verdict (plumbing_only / proof_of_concept / underpowered / negative_result /
  finding_supported); and a plain-language interpreter with explicit negative-result wording.
- `reproduce.py`: emits a new deterministic `statistics.json` artifact (metrics.json unchanged for
  continuity) and prints the eligibility verdict and interpretation.
- `tests/test_research_statistics.py` (14 tests): Wilson endpoints and a known value, Fisher exact
  against hand-computed p-values, cell-level pseudoreplication handling, per-category breakdown, and
  every eligibility verdict. Full research regression: 55 passed.

Remaining weaknesses (documented, not yet addressed; require design expansion, not code):
- Low statistical power: the fixed stimulus set yields few independent cells, so most single-model
  runs are `underpowered` by design. Powering a finding needs an expanded preregistered task/variant
  pool, which is a protocol change to be preregistered separately.
- Single behavior, single corpus, single template: external validity is limited (see the protocol's
  limitations section).

## 3. Readiness assessment for the next research release

- Methodology and reproducibility: READY. The pipeline now produces interval estimates, a control
  comparison with an exact test, pseudoreplication-aware estimates, genuine negative results, and a
  written limitations statement.
- Empirical findings: NOT YET. No validated capable model has been run through this pipeline here
  (model acquisition is an environment/ops matter, deliberately out of scope for this change), and
  the current stimulus set is underpowered for a defensible finding. The honest release posture is:
  methodology and negative-result reporting are release-ready; any positive finding requires a
  validated model and an expanded, preregistered stimulus pool.
- Integrity and security: unchanged and preserved. Signing, owner-scoping, reviewer boundaries,
  entitlement isolation, and the per-record provenance taxonomy are untouched.

## 4. Controlled integration plan for PR #4 (no merge, no deploy)

PR #4 (`feature/parallax-design-completion` into `integration/parallax-research-platform`) is the
researcher-experience design/accessibility completion. It is independent of the research-methodology
work here and of the RC release line. Controlled integration, to be executed only on explicit
authorization:

1. Keep PR #4 open and unmerged; do not deploy it. It carries no runtime dependency, schema change,
   or new route (CSS/templates + tests + evidence only).
2. Review gate: confirm the PR diff remains design/accessibility/security-test/evidence only (no
   `store.py`, `model_backend.py`, `harness.py`, `parallax_routes.py`, `app.py`, signing-key, or
   historical-evidence changes). This was verified at commit `63aabd6`.
3. Sequencing: land the research-methodology branch (`feature/parallax-research-statistics`) first
   via its own PR into `integration/parallax-research-platform`, since it touches only
   `parallax/research/*` and tests and cannot conflict with PR #4's CSS/templates.
4. Merge PR #4 into `integration/parallax-research-platform` only (never a protected branch),
   after its CI gate (axe 0, 25 tests, 10/10 journey) and a human review. Do not fast-forward to
   `parallax-nonprod`, `parallax-rc`, or production.
5. Post-integration, before any deploy: run the combined suite on the integration branch and a
   fresh accessibility pass, then stop. Deployment remains separately authorized.

## 5. Deliverables in this change

- Code: `parallax/research/statistics.py`, `reproduce.py` (additive wiring).
- Tests: `tests/test_research_statistics.py` (14), research regression 55 passed.
- Docs: `PARALLAX_EVALUATION_PROTOCOL.md` (reproducible protocol + explicit limitations), this
  readiness assessment and PR #4 integration plan.
- No fabricated experiments, findings, or measurements; no infrastructure; no signing/baseline/
  historical changes; PR #4 left open and unmerged.
