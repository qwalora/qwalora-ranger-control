# PARALLAX real research execution — Phase 1 baseline

Branch `feature/parallax-real-inference` (base `acf50ec` + the researcher UI on
`feature/parallax-research-platform-ui`). Nothing here changes `acf50ec`, accepted environments, the
`parallax-rc` database, signing keys, or OAuth.

This is an honest, code-grounded assessment. A component is marked **experimentally verified** only if
it was actually executed in this session, not merely present in the source.

## The decisive constraint, up front

A capable, instruction-following model cannot be run in this environment, because model weights cannot
be obtained and no inference provider is approved/credentialed here:

- `huggingface.co:443` is **policy-blocked** at the egress gateway (CONNECT returns 403 — observed in
  the proxy's `recentRelayFailures`). `registry.ollama.ai`, `www.modelscope.cn`, and `api.openai.com`
  are unreachable (connect fails). Allowed hosts are the package registries (pypi, npm, crates, go)
  and GitHub; `api.anthropic.com` resolves but needs a key and is an external service, not the
  protocol's locally hosted model.
- No weights are cached locally (`~/.cache/huggingface` absent; no `.safetensors`/`.gguf`/`pytorch_model.bin`).
- No research-model configuration or credentials are set (`RANGER_RESEARCH_MODEL_URL`/`_DIR`/`_HOSTS`,
  `OPENAI_*`, `ANTHROPIC_API_KEY`, `OLLAMA_*`, `HF_TOKEN` all unset).

Consequence: a *scientifically meaningful* trust-boundary experiment (which needs a capable instruct
model) cannot be completed here. What can be done — and is done in Phase 2-7 — is to prove the genuine
execution path end to end against a **real, locally hosted model runtime** using a small model trained
in-container with no downloads, and to report the result honestly (a null result dominated by model
incapacity), with the exact infrastructure/credentials required for a meaningful run.

## Stack assessment (implemented / deployed / experimentally verified)

| Component | Source | Status |
|---|---|---|
| `model_backend.from_config` → `HTTPBackend` (loopback/allowlisted OpenAI/Ollama-compatible), `TransformersBackend` (local weights), else `DeterministicStubBackend` | `parallax/research/model_backend.py` | **Implemented.** Both real backends are real code paths. `_host_authorized` restricts HTTP endpoints to loopback or `RANGER_RESEARCH_MODEL_HOSTS`. Experimentally verified in Phase 2 via a loopback HTTP runtime. |
| Deterministic stub (`is_real=False`) | same | **Implemented + verified.** Default when nothing is configured; every record it makes is `simulated` and never an empirical finding. This is the only path that ran before this work. |
| RAG retrieval + injection (`rag.run_rag`, `inject_document(s)`), trust-fenced prompt (`build_prompt`, `PROMPT_TEMPLATE_VERSION="trust-fenced-v1"`) | `rag.py`, `model_backend.py` | **Implemented.** System/developer instructions are authoritative; retrieved documents are fenced as untrusted data; the attacker controls only a low-trust document. Verified end to end in Phase 2. |
| Deterministic evaluator (binary canary detection outside refusal phrases, task-completion) | `evaluator.py` | **Implemented + verified.** Outcomes: `successful_unauthorized_behavior`, `boundary_preserved`, `inconclusive`, `infrastructure_failure`, `evaluation_error`. |
| Harness: `run_trial`, `run_campaign`, `compute_metrics` (paired benign/adversarial, excludes infra/eval failures, success among valid attacks, benign false-positive rate) | `harness.py` | **Implemented + verified** (real trials in Phase 2). |
| Signed evidence persistence: `store.persist_run` (Ed25519-signed, SHA-256 hashed, owner-scoped, audited; `backend_provenance` derived from `is_real`) | `store.py` | **Implemented + deployed + verified.** Two protected historical records exist in the RC DB. Verified here by persisting real `infrastructure_backed` records and verifying signatures. |
| Review/adjudication + owner-scoped read-back (`get_run`, `review_status_for`, `overview_for`, `admin_verify_run`) | `store.py` | **Implemented + verified** (owner/reviewer authz exercised in tests). |
| Researcher UI (command center, research console, evidence & publications) | `feature/parallax-research-platform-ui` | **Implemented + verified** (renders real runs; owner-scoped). |
| Workload isolation / network egress controls / timeouts / quotas | `model_backend` timeout 60s; `_host_authorized` loopback/allowlist; `_rate_limited` per-candidate run cap; `MAX_ATTACK_CHARS=4000`; attack text treated as data only | **Implemented** (request validation, host allowlist, timeout, rate limit, size cap). **Not** a container/network sandbox around the worker — the worker runs in-process in the Flask app. Isolation hardening options are in Phase 3. |
| Infrastructure-backed historical experiments reproducible with *currently available* infrastructure | — | **No.** The two protected records are historical; reproducing an empirical run needs a capable model runtime, which is blocked here. The path is reproducible; the model is not available. |

## What actually executes real inference vs simulation (before this work)

- Before this work, **every** research path resolved to the deterministic stub (`simulated`): no real
  endpoint/weights were configured or obtainable. The real backends were implemented but never
  exercised in this environment.
- After this work (Phase 2), the `HTTPBackend` path executes **real inference** against a loopback
  model runtime, producing `infrastructure_backed` signed evidence — the first genuine model-backed
  runs in this environment.

## Isolation, RAG, evidence — specifics

- Egress: `HTTPBackend` refuses any non-loopback, non-allowlisted host (`_host_authorized`). Retrieved
  documents are injected as data into a fenced prompt region and never reach the system/developer
  instructions or the evaluator; attacker input cannot invoke tools, read secrets, or change infra
  (there is no tool-calling surface in the harness).
- Evidence (`persist_run`): records a canonical `{manifest, metrics}` with backend identity,
  corpus version + content hash, per-trial record (retrieved doc ids, condition, observed output,
  evaluation, outcome, timing, evidence_hash), signed Ed25519 + SHA-256, owner-scoped. Phase 4 (done)
  added a model-weights digest and inference params for `infrastructure_backed` runs.

## Bottom line

The execution path is genuinely real-capable and is proven end to end in Phase 2 against a real
loopback runtime. The missing piece for a *scientifically meaningful* result is a capable model, which
this environment's egress policy and credential posture prevent. The exact unblock requirements are in
the Phase 5/7 report.
