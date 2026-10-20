# PARALLAX operational research platform — milestone report

Integration branch `integration/parallax-research-platform` (merges the researcher UI
`feature/parallax-research-platform-ui` and real-inference `feature/parallax-real-inference`; both
source branches preserved). No change to `acf50ec`, `parallax-nonprod`, the `parallax-rc` database,
historical evidence, signing keys, or OAuth. Not deployed.

## 1. Integration

The real-inference branch was created from the UI branch, so it already contains it; the integration
branch is `feature/parallax-real-inference`'s tree with an explicit no-op merge of the UI branch
recorded (both sources preserved as `b739896` and `71649a8`). Combined regression + authorization
suite: **21 passed** (14 UI/authorization + 6 execution/isolation + 1 provenance-taxonomy).

## 2. Corrected provenance presentation (four honest levels)

The UI no longer conflates real execution with an empirical finding. Each run is classified and
displayed as:

1. **Execution** — `real-model` vs `simulated` (deterministic stub).
2. **Infrastructure-backed evidence** — a real run whose Ed25519 signature verifies.
3. **Measurement** — a scorable outcome (`boundary_preserved` / `successful_unauthorized_behavior`)
   vs `inconclusive` / `excluded`.
4. **Finding status** — `finding-eligible` only when a **validated** model (in
   `RANGER_RESEARCH_VALIDATED_MODELS`) produced a **measured** outcome; a proof-of-concept / unlisted
   model is `proof-of-concept` and is **never** a validated AI-security finding.

The Evidence Center and command center now show "real model / measured / inconclusive / simulated"
(not "empirical"), a caveat banner for non-validated real-model runs, and a per-record "Finding
status: proof-of-concept model — NOT a validated AI-security finding". Verified by
`test_provenance_taxonomy_does_not_call_poc_a_finding` and by screenshot.

## 3. Capable open-weight model — feasibility, license, verification

Recommended model: **Qwen2.5-0.5B-Instruct** — Apache-2.0 license, open weights, small enough for
CPU, instruction-tuned. Pin the exact revision and verify weights before use:

- Repo `Qwen/Qwen2.5-0.5B-Instruct`, pin a specific commit SHA (revision), fetch `config.json`,
  `model.safetensors`, `tokenizer.json`/`tokenizer_config.json`, and record each file's SHA-256;
  the worker reports a combined weights digest (`/api/version`) that is pinned into every evidence
  record (`model.digest`).
- License: Apache-2.0 (documented and redistributable). Alternatives of similar size/licensing:
  Llama-3.2-1B-Instruct (Llama license — review terms), SmolLM2-360M-Instruct (Apache-2.0).

Runtime feasibility (empirical, this environment — 7.8 GB RAM, 2 vCPU):

Measured in-container with a Qwen2.5-0.5B-Instruct-shaped model (0.63B params, config `hidden=896,
layers=24, heads=14, kv=2, vocab=151936`) built with RANDOM weights (no download), CPU-only:

- fp32 weights ~2.52 GB, bf16 ~1.26 GB; **peak RSS 3.14 GB** of 7.8 GB — RAM-feasible with headroom.
- model load 6.7 s; single forward (64 tokens) 0.88 s; generate 8 tokens 1.39 s → **~0.17 s/token** on
  2 vCPU.

(Random-weights timing measures compute/memory, not output quality; the real weights have identical
shape and cost. Machine-readable: measured values recorded in the milestone run.)

Interpretation: RAM is **not** the constraint (a 0.5B model's fp32 weights are ~2 GB, bf16 ~1 GB,
well within 7.8 GB). CPU latency on 2 vCPU is usable for small, sequential research batches (seconds
per short generation), not for large sweeps; a small GPU or more vCPUs would be needed for scale.
The **only** blocker to running it here is egress: `huggingface.co` and `cdn-lfs.huggingface.co` are
policy-blocked (gateway 403), re-verified this session. Allowlisting them (or staging the pinned
weights by another approved channel) makes a meaningful run immediately possible — no code change.

## 4. Isolated inference worker (researcher workloads out of the web process)

`scripts/research/inference_worker/worker.py` is a separate process; the web app reaches it only over
loopback via `HTTPBackend`. Hardening (verified by smoke test):

- Resource limits: `RLIMIT_AS` (address space / memory) and optional `RLIMIT_CPU` via `setrlimit`.
  Note: for production, container/cgroup memory limits are the robust control; `RLIMIT_AS` bounds
  virtual address space, which suits CPU inference here. Memory limiting was validated at 6 GB.
- Execution timeout: each generation runs in a worker thread with a wall-clock cap (default 30 s);
  a timeout returns HTTP 504 and is recorded as a failure, never a fabricated output.
- Concurrency limit: a bounded semaphore (default 1); over-limit returns HTTP 429.
- Controlled network: binds `127.0.0.1` only; the worker makes no outbound calls.
- Model-version tracking: `/api/version` reports model id + weights SHA-256 + config + active limits;
  `/api/generate` echoes the weights digest, pinned into every signed evidence record.
- Model-agnostic: supports the in-repo char-GPT proof-of-concept now and a HuggingFace-format
  transformers model dir (the production path) with no code change.

The experiment runner (`run_real_experiment.py`) launches this worker, so the genuine runs executed
through the isolated worker, not the web process.

## 5. Genuine paired experiment (via the isolated worker)

Executed 13 real trials (paired benign/adversarial, 3 reps, 2 tasks, 3 attack variants) through the
isolated worker and the existing `/parallax/research/trial` endpoint. All `infrastructure_backed`,
all Ed25519 signatures verify, each record pinned to the model weights digest
`bae88d84608cb7e2…`. Result: **13 inconclusive, 0 injections** — an honest null result dominated by
the proof-of-concept model's incapacity, explicitly **not** a trust-boundary finding (now labeled
`proof-of-concept`, never empirical). Machine-readable: `docs/research/real_experiment_results.json`.
No invented findings.

## 6. Integrated surfaces against actual records

Research Console, Evidence Center, and researcher authorization were exercised against the real
records: evidence read-back (HTTP 200), owner-scoped export (200), cross-owner read (404), reviewer
adjudicate (403 for a researcher). Screenshots show the corrected provenance on real data.

## 7. Operational infrastructure requirements, costs, blockers

- To run a capable model here now: allowlist `huggingface.co` + `cdn-lfs.huggingface.co` (or stage
  pinned weights), set `RANGER_RESEARCH_MODEL_DIR=<dir>` (TransformersBackend) **or** run the worker
  and set `RANGER_RESEARCH_MODEL_URL=http://127.0.0.1:<port>`, and add the model id to
  `RANGER_RESEARCH_VALIDATED_MODELS` only after a validation review. No code change.
- Cost: the container itself runs a 0.5B model on CPU at no extra infra cost (RAM-feasible). For
  throughput/larger models, a small always-on GPU worker (e.g. a single modest cloud GPU) is the main
  cost lever; estimate at provisioning time against the team's $300/mo infra budget.
- Remaining blockers: (a) egress policy blocks model weights (identified, re-verified); (b) a
  scientifically meaningful finding additionally needs a validation review of the chosen model and an
  adequate, pre-registered sample. Until (a) and (b), outputs remain honestly labeled infrastructure-
  backed measurements, not findings.

## Reproduction

    python scripts/research/local_runtime/train_tiny_model.py /tmp/qwalora-tiny-model
    REPS=3 python scripts/research/run_real_experiment.py       # launches the isolated worker
    # swap in a capable model: set MODEL_DIR to a transformers dir (worker auto-detects), or point
    # RANGER_RESEARCH_MODEL_URL at the worker; add the id to RANGER_RESEARCH_VALIDATED_MODELS after review.
