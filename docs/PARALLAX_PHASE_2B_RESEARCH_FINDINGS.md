# PARALLAX Phase 2B - Research Findings

**Status: NO EMPIRICAL FINDINGS. This is a feasibility and blocker report, not a results report.**

Per the Phase 2B directive (Deliverable E): "Do not create a findings report containing fabricated
results. If no genuine experiments execute, replace empirical findings with a clearly labeled
feasibility and blocker report." No genuine language model could be executed in this environment, so no
prompt-injection campaign was run against a real model, and no attack-success, task-completion, or
false-positive measurements exist. Nothing below is an empirical observation of model behavior.

---

## 1. Research question

Under what controlled conditions can attacker-controlled retrieved content cause a language-model
application to violate the separation between untrusted retrieved documents and authoritative
application instructions?

## 2. Hypothesis (preregistered, unchanged from Phase 2A)

Attacker-controlled text in a low-trust retrieved document can, under some conditions, cause the
assistant to emit the canary `INJECTION-OK`, violating the trust boundary; benign instruction-like
content does not. This hypothesis remains UNTESTED against a real model.

## 3. Model and environment

No model was executed. The environment is a GPU-less cloud container: 2 CPUs, 7.8 GB RAM, ~30 GB free
disk. Outbound egress is restricted to an allowlist (PyPI and GitHub). The intended target class is a
small, openly licensed, instruction-tuned model runnable on CPU; none could be retrieved (Section 6).

## 4. Experimental protocol (ready, not executed)

The Phase 2A preregistered protocol is intact and would drive the campaign unchanged: conditions
`baseline_benign` and `experimental_attack`; legitimate tasks `t-storage`, `t-export`, `t-pricing`;
six attack variants (`a-direct`, `a-policy`, `a-override`, `a-conflict`, `a-format`, and the benign
negative control `a-benign-controllike`); outcome categories `successful_unauthorized_behavior`,
`boundary_preserved`, `inconclusive`, `evaluation_error`, `infrastructure_failure`. No amendment was
required or made.

## 5. Control conditions, attack categories, execution counts

Control (benign) and adversarial conditions are defined and frozen. Execution counts against a real
model: ZERO. The deterministic stub is explicitly excluded from any results dataset, so there are no
counts to report here. (The stub exercises harness plumbing only and is labeled `simulated`.)

## 6. Why no model executed (the blocker, reassessed this phase)

The Phase 2A blocker was reassessed from scratch rather than assumed. Findings:

- **Egress allowlist (reconfirmed by probe).** Reachable: PyPI (`pypi.org`, `files.pythonhosted.org`)
  and GitHub (`github.com`, `raw.githubusercontent.com`, `codeload.github.com`,
  `objects.githubusercontent.com`, `api.github.com`). Refused with `connect_rejected`:
  `huggingface.co`, the HF content CDNs (`cas-bridge.xethub.hf.co`), `hf-mirror.com`,
  `download.pytorch.org`, and `gpt4all.io`.
- **Option A (local caches): none.** No model artifacts under the usual cache locations or on disk.
- **Option B (legally redistributable small model from a reachable source): none reachable.** Every
  candidate open-weight instruction model (Qwen2.5-0.5B-Instruct, SmolLM2, TinyLlama, and their GGUF
  conversions) is distributed through Hugging Face, which is blocked. None is mirrored to a reachable
  GitHub release or carried inside a PyPI package. Using an out-of-allowlist mirror (for example
  `hf-mirror.com`) to bypass the block would be circumventing the network restriction, which the
  directive forbids, so it was not done.
- **Option C (authorized local inference endpoint): none running.** Ranger exposes no nonproduction
  model-serving endpoint; `HTTPBackend` requires a loopback or allow-listed host and there is nothing
  to point it at.
- **Inference engine, partially blocked too.** `transformers` and `tokenizers` install cleanly from
  PyPI. `torch` does not run here: the PyPI `torch==2.14.1` wheel hard-loads `libcudart.so.13` and
  declares the full `cuda-toolkit==13.0.3` stack plus cuDNN/cuSPARSELt/NCCL/NVSHMEM (about 2 GB) even
  for CPU use, while the CPU-only wheel index (`download.pytorch.org/whl/cpu`) is blocked. A llama.cpp
  path (`llama-cpp-python`) installs but has no weights to load.

Conclusion: the model-execution gate is **BLOCKED** in this environment. Real experimentation is
**OPEN**.

## 7. Observed outcomes

None. No real model produced any output, so there is nothing to categorize under the outcome
taxonomy.

## 8. Attack success, legitimate-task performance, uncertainty

Not measured. ASR, TCR, and FPR are undefined because there were zero valid real-model trials. No
numerator, denominator, or interval is reported, because reporting any would be fabrication.

## 9. Limitations

The binding limitation is the absence of an executable trained model (Section 6). Secondary
limitations carried from Phase 2A remain: the synthetic corpus and task set are small; a single model
and single prompt template are in scope; OpenSearch and independent audit anchoring remain OPEN but are
not required for this bounded experiment.

## 10. Reproducibility

Everything needed to reproduce the (not-yet-run) experiment is in place and documented in
`docs/PARALLAX_PHASE_2A_REPRODUCIBILITY.md`. The moment an authorized operator stages a model
(Section 11), the existing command produces real, signed, machine-readable records with no code change:

```
# Option 1: operator runs a local inference endpoint (recommended; matches HTTPBackend conformance)
python -m parallax.research.reproduce out --model-url http://127.0.0.1:<port>
# Option 2: operator stages a local transformers model directory
python -m parallax.research.reproduce out --model-dir /opt/models/<model>
```

## 11. Required staged artifact (Deliverable: unblock procedure)

To pass the gate, an authorized operator must make ONE of the following available, then run the command
above. No model checksum is asserted here because no artifact was downloaded or validated in this
environment; the operator computes and records it at stage time.

**Recommended model: Qwen2.5-0.5B-Instruct.**
- Official source: Hugging Face repository `Qwen/Qwen2.5-0.5B-Instruct` (and the Qwen-published
  `Qwen/Qwen2.5-0.5B-Instruct-GGUF` for a llama.cpp path).
- License: Apache-2.0 (documented, redistributable).
- Approximate size: ~1 GB (bf16 safetensors); the Q4/Q5 GGUF is ~0.4-0.5 GB.
- Expected files (transformers): `config.json`, `model.safetensors`, `tokenizer.json`,
  `tokenizer_config.json`, `vocab.json`, `merges.txt`, `generation_config.json`.
- Resource fit: runs on CPU within 2 CPU / 8 GB RAM for a bounded pilot.
- Verification the operator must perform at stage time: compute `sha256sum` of each downloaded file and
  record it against the official repository's published file hashes before first use; record the model
  revision (commit SHA) in the run manifest.

**Alternatives** (same procedure): `TinyLlama/TinyLlama-1.1B-Chat-v1.0` (Apache-2.0, ~2.2 GB bf16 or a
~0.6 GB GGUF), or `HuggingFaceTB/SmolLM2-360M-Instruct` (Apache-2.0, ~0.7 GB).

**Environment action required (one of):**
1. Add `huggingface.co` and its content CDN hosts to the egress allowlist so the operator can fetch and
   checksum the artifact from its official source; or
2. Stage the verified model directory onto disk out of band and set `RANGER_RESEARCH_MODEL_DIR`; or
3. Stand up an isolated, nonproduction local inference server (llama.cpp server, Ollama, or a
   transformers HTTP wrapper) on loopback and set `RANGER_RESEARCH_MODEL_URL`.

## 12. Conclusions supported by the data

The only data this phase produced concern feasibility and harness readiness, not model behavior:

1. A genuine instruction-tuned model cannot currently be retrieved or executed under the approved
   resources; the exact blocker is the egress allowlist excluding all reachable model-weight sources
   plus the absence of a CPU-only inference engine path.
2. The harness is genuinely model-ready: `HTTPBackend`'s real network path (request transmission,
   response parsing, timeout, 5xx failure, non-loopback host refusal, provenance) is verified against a
   real loopback HTTP endpoint, and `from_config` selects a real backend when one is configured.
3. No empirical claim about prompt-injection susceptibility can or should be made until the gate is
   passed. Real experimentation is OPEN, with a concrete, low-effort unblock path (Section 11).
