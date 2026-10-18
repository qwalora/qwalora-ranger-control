# PARALLAX Phase 2B - Engineering Report

**Real-model enablement and empirical AI-security research**

Starting branch: `feature/parallax-p1-architecture-foundations` · Phase 2A handoff: `be46bae`
`main`: unchanged at `431a183` · Railway hold: intact · Both PARALLAX qualification flags: OFF

Verdict vocabulary: **PASS** (implemented + executed tests), **PARTIAL** (some verification, critical
conditions unavailable), **OPEN** (cannot currently be established), **BLOCKED** (a required gate could
not be passed), **FAIL** (demonstrably fails). Skipped is never PASS.

**Phase verdict: PARTIAL (model-execution gate BLOCKED).** A genuine language model could not be
executed under the approved resources, so no empirical AI-security findings were produced and none are
claimed. The directive's first instruction was to establish real-model execution before any further
development; that was attempted thoroughly and determined infeasible here, with the exact blocker and a
concrete unblock procedure documented. The genuine work delivered this phase is narrow and honest:
verification of the harness's real model-backend code path against an actual inference endpoint, a
reassessed and fully characterized egress map, and an operator-actionable staging specification. No
substitute simulation was created, and no stub output is presented as a result.

---

## 1. Executive summary

Phase 2A built a model-agnostic prompt-injection research harness but executed no real model. Phase 2B's
mandate was to pass the real-model gate first and run a genuine campaign. The gate could not be passed:
the egress allowlist reachable from this environment (PyPI and GitHub only) excludes every reachable
source of open-weight instruction models (all are Hugging Face-hosted, which is refused), no model is
cached locally, Ranger exposes no local inference endpoint, and even the CPU-only `torch` wheel index is
blocked while the PyPI `torch` wheel forces a ~2 GB CUDA stack that fails to load on a GPU-less box.
Rather than simulate, the phase reports real experimentation as OPEN and the model-execution gate as
BLOCKED, and delivers the exact artifact + environment change an operator needs to unblock it.

The genuine, non-simulated engineering delivered: the `HTTPBackend` real network path is verified
end-to-end against a live loopback HTTP endpoint (request transmission, response parsing, timeout, 5xx
failure, non-loopback host refusal, and `infrastructure_backed` provenance), which is exactly how a
staged model will be driven. STRATA is unchanged, both qualification flags remain OFF, the Railway hold
is intact, and `main` is untouched.

## 2. Starting repository state

Branch `feature/parallax-p1-architecture-foundations`, HEAD `be46bae` (Phase 2A), upstream in sync,
worktree clean. `main` at `431a183` (local and remote). Phase 2A reports and the `parallax/research/`
package present. Both flags OFF. Disposable PostgreSQL 16.15 available on 127.0.0.1:55433 with the
`ranger_test_sentinel` authorizing database. Phase 2A baseline: 412 passed / 16 skipped / 0 failed
(PG-on).

## 3. Model feasibility investigation

Reassessed from scratch, not assumed. Resources: 2 CPU, 7.8 GB RAM, ~30 GB free disk, no GPU. Egress
probed directly through the agent proxy:

| Host | Result |
|---|---|
| `pypi.org`, `files.pythonhosted.org` | reachable (allowlisted) |
| `github.com`, `raw.githubusercontent.com`, `codeload.github.com`, `objects.githubusercontent.com`, `api.github.com` | reachable |
| `huggingface.co`, `cas-bridge.xethub.hf.co` | refused (`connect_rejected`) |
| `hf-mirror.com`, `gpt4all.io`, `download.pytorch.org` | refused (`connect_rejected`) |

Options in the directive's priority order:
- **A - local caches:** none found on disk.
- **B - redistributable small model from a reachable source:** none. Qwen2.5-0.5B-Instruct, SmolLM2,
  TinyLlama and their GGUF builds are Hugging Face-hosted (blocked); none is mirrored to a reachable
  GitHub release or bundled in a PyPI package. The GitHub API is gated per-repo (via `add_repo`) and
  `raw.githubusercontent.com` only serves blobs under ~100 MB, below any usable instruction model.
  Using an out-of-allowlist mirror to bypass the block is circumvention and was not done.
- **C - authorized local inference endpoint:** none running in Ranger.
- **D - staged artifact:** the required procedure is specified (Section 5 here and Section 11 of the
  findings report). No artifact was downloaded, so no checksum is asserted.

Determination: **real-model execution is BLOCKED; real experimentation is OPEN.**

## 4. Actual inference verification

`transformers==5.20.1` and `tokenizers==0.23.3` install cleanly from PyPI and import. `torch` could not
be made to run: the PyPI `torch==2.14.1` wheel loads `libcudart.so.13` at import and declares
`cuda-toolkit==13.0.3` plus cuDNN/cuSPARSELt/NCCL/NVSHMEM (~2 GB) even for CPU-only use, while the
CPU-only wheel index (`download.pytorch.org/whl/cpu`) is blocked. Installing `torch` without its CUDA
dependencies leaves it unable to import (`OSError: libcudart.so.13`). The non-importable `torch` was
removed to keep the environment honest.

Because no trained model and no working `torch` are available, the harness's real path was instead
verified where it genuinely can be: the `HTTPBackend`, driven against a real loopback HTTP inference
endpoint (Section 7). The `TransformersBackend` execution test is present but SKIPS here with the
documented reason (no CPU `torch`); it will run once an operator provides a model directory.

## 5. Research environment configuration (unchanged + staging spec)

The Phase 2A research environment (corpus, retrieval, trust-fenced prompt assembly, protocol, evaluator,
metrics, signed persistence, Ranger routes) is intact and model-agnostic. To make it produce real
findings, an operator stages one of:
1. a local inference endpoint on loopback (`RANGER_RESEARCH_MODEL_URL`) - recommended, and the path the
   conformance tests exercise;
2. a local transformers model directory (`RANGER_RESEARCH_MODEL_DIR`).

Recommended artifact: **Qwen/Qwen2.5-0.5B-Instruct**, Apache-2.0, ~1 GB bf16 (or ~0.4-0.5 GB GGUF), CPU-
runnable within these limits. Full staging + verification steps are in the findings report, Section 11.

## 6. Experimental protocol

Preregistered protocol from Phase 2A is unchanged and was not amended: conditions `baseline_benign` /
`experimental_attack`; tasks `t-storage`, `t-export`, `t-pricing`; six attack variants including the
benign negative control `a-benign-controllike`; five outcome categories. No real trials executed, so no
success criteria were touched (the directive's prohibition on retroactively altering criteria is moot
here and was honored).

## 7. Executed control and adversarial trials

Against a real model: NONE (gate BLOCKED). What WAS executed is genuine backend conformance, not a
campaign and not findings:

`siem/tests/test_parallax_research_realpath.py` stands up a real HTTP server on 127.0.0.1 and drives
`HTTPBackend` against it:
- the backend transmits the assembled trust-fenced prompt and parses a real HTTP JSON response;
- a 5xx response becomes a `ModelBackendError` (recorded as `infrastructure_failure`, never faked);
- a slow endpoint trips the timeout and becomes a `ModelBackendError`;
- a non-loopback host (`api.openai.com`) is refused at construction; an explicitly allow-listed host is
  accepted;
- `from_config` selects `HTTPBackend` (is_real=True) for a loopback URL.

These prove the harness will correctly drive, time out, fail, and attribute a genuine model the moment
one is staged. The fixture is a protocol conformance server, explicitly not a language model, not the
`DeterministicStubBackend`, and never run as an experiment. A `TransformersBackend` test that builds a
tiny UNTRAINED model locally and runs a real torch forward pass exists but skips here (no CPU torch); it
is engine verification only and, by construction, produces gibberish that is never evaluated or
persisted.

## 8. Evidence integrity

No empirical records were produced, so none were persisted as findings. The Phase 2A evidence path is
unchanged and remains the mechanism for genuine trials: per-trial machine-readable records with
provenance and an `evidence_hash`, signed+audited run persistence (Ed25519 + hash-chained audit),
owner-scoped access, and a `backend_provenance` that is `infrastructure_backed` only for a real backend.
The §7 record schema of the directive is already largely satisfied; two fields (model artifact hash and
explicit generation parameters) become populated only when a real backend runs and are noted as the
first follow-up when a model is staged (Section 18). They were not added speculatively, to avoid
untestable scaffolding.

## 9. Measured results and limitations

No results. ASR/TCR/FPR are undefined (zero valid real-model trials); reporting any value would be
fabrication. The binding limitation is the absence of an executable trained model. Secondary
limitations (small synthetic corpus/task set, single model/template, OpenSearch and audit anchoring
OPEN) are carried from Phase 2A and are not required for the bounded initial experiment.

## 10. Ranger application integration

Unchanged from Phase 2A and reverified by regression: the two nonproduction-gated endpoints
(`POST /parallax/research/run`, `GET /parallax/research/run/<id>`) initiate bounded runs and return
owner-scoped signed results that are labeled `simulated` / not-a-finding while no real model is
configured, and are assessment/qualification-neutral. No new routes were added this phase.

## 11. Real PostgreSQL verification

The research-run persistence remains verified against genuine PostgreSQL 16.15 (the Phase 2A standalone
durability check: persist, restart, signature-verify, owner-scope, single durable row) and the full
PG-on regression (Section 13) runs the PG-gated suites. No schema change was made this phase.

## 12. Adversarial QA

The Phase 2A adversarial QA (tampered evidence, forged success labels, infra-failure-not-scored,
non-local host refusal, cross-researcher denial, signature tamper, auth/gate) remains green. Phase 2B
adds adversarial coverage of the real network backend: server error, timeout, and non-loopback host
rejection are all surfaced as errors rather than silent or faked successes.

## 13. Full regression results

PG-on full regression (disposable PostgreSQL 16.15, `ranger_test_sentinel` boundary):
**417 passed / 17 skipped / 0 failed / 0 errors**. The Phase 2A baseline (412 passed / 16 skipped) is preserved; the new
`test_parallax_research_realpath.py` adds 5 passing backend-conformance tests and 1 skip (the
`TransformersBackend` execution test, skipped because CPU torch is unavailable). **Tests that exercised
a genuine trained model: 0.** Unit-test success is reported separately from model-execution evidence,
of which there is none.

## 14. Infrastructure blockers

1. **Model weights unreachable (critical, new detail).** Egress allowlist excludes Hugging Face and all
   reachable model-weight hosts; no mirror is reachable within policy.
2. **CPU inference engine unreachable.** The CPU-only `torch` wheel index is blocked; the PyPI `torch`
   wheel requires a GPU-oriented ~2 GB CUDA stack and will not import on CPU without it.
3. **OpenSearch 2.17.1** (12 infra tests unexecuted) and **independent audit anchoring** remain OPEN,
   as in prior phases. Neither is required for the bounded initial real-model experiment, so they are
   preserved as known limitations rather than expanded here.

## 15. Security and qualification posture

STRATA unchanged (95% bar intact). Lab A remains a labeled simulation. Research runs are not
qualification assessments. No portfolio approved, no credentials issued. Reviewer authorization and
signed evidence remain enforced. Both `RANGER_PARALLAX_QUALIFICATION_ACTIVE` and
`RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE` remain OFF. No production migration, no key rotation, no
new lab, no paid inference, no third-party model targeting.

## 16. Remaining research limitations

The research question is unanswered against any real model. Until the gate is passed, PARALLAX can
demonstrate a genuine, controlled, reproducible research *apparatus* and a verified real model-backend
path, but not an empirical result. Generalization to commercial-scale systems is explicitly out of
reach even once a small CPU model runs.

## 17. Git commit and push evidence

Work committed on `feature/parallax-p1-architecture-foundations`, authored `cloudcwfranck
<yakengne@gmail.com>`, no attribution trailers, no merge, no deploy. Commit hash and push confirmation
recorded at the end of this phase (see the final response / git log). `main` remains `431a183`.

## 18. Next recommended research milestone

1. **Unblock the model gate** (operator action): allowlist Hugging Face or stage Qwen2.5-0.5B-Instruct
   on disk or behind a loopback endpoint (findings report Section 11). This is the single prerequisite
   for all empirical work.
2. On first real model: run the genuine inference baseline (§4 of the directive) and a bounded pilot
   campaign; populate the two remaining §7 record fields (model artifact hash, generation parameters).
3. Then scale the campaign (more repetitions with dependence-aware uncertainty, larger corpus/task set)
   and only afterward broaden scope beyond prompt injection.
