# PARALLAX Phase 2A - Reproducibility Manifest

This document specifies exactly how to reproduce and verify a PARALLAX Phase 2A prompt-injection
research run. It is deliberately executable: every claim below maps to a command and a machine-readable
artifact with a recorded SHA-256.

**Honesty gate (read first).** No genuine LLM can be executed in the current build/CI environment
(model CDNs are egress-blocked, no GPU, paid inference prohibited - see the Phase 2A Engineering Report,
§ real-model feasibility). With no authorized real model configured, every command below runs the
**deterministic stub backend**. Stub output is harness *plumbing*, labeled `backend_provenance:
"simulated"` and `findings_available: false`, and is **never** an empirical AI-security finding. Real
experimentation is **OPEN**. The procedure for a real model is identical except for one flag (§5).

---

## 1. Environment

| Item | Value (this environment) | How to confirm |
|---|---|---|
| Python | 3.13.16 | `python --version` |
| Flask | 3.0.3 | `python -c "import flask,importlib.metadata as m;print(m.version('flask'))"` |
| SQLAlchemy | 2.0.36 | `python -c "import importlib.metadata as m;print(m.version('sqlalchemy'))"` |
| cryptography | 50.0.1 | Ed25519 signing (`signing` module) |
| Harness version | `2A.1` | `parallax.research.HARNESS_VERSION` |
| Protocol version | `px2a-protocol-v1` | `parallax.research.protocol.PROTOCOL_VERSION` |
| Prompt template | `trust-fenced-v1` | `parallax.research.model_backend.PROMPT_TEMPLATE_VERSION` |
| Corpus version | `synthetic-trust-v1` | `parallax.research.corpus.CORPUS_VERSION` |

A full fingerprint is emitted to `environment.json` by the reproduce command (§3).

## 2. Dataset generation (synthetic, no external data)

The corpus is five synthetic "Aurora Notes" benign documents generated in-process by
`parallax.research.corpus.default_corpus()`. No external or user data is used. The corpus is identified
by a content hash:

```
python -c "from parallax.research import corpus as c; k=c.default_corpus(); print(k.version, k.content_hash())"
# synthetic-trust-v1 5ec83203da2490b103a6f1588f02686e086c3fe94b7879279d72771f38f545b7
```

The content hash is stable across runs and machines; a changed hash means the corpus changed.

## 3. One-command reproduction

```
python -m parallax.research.reproduce <output_dir> [--repetitions N]
```

Writes the following artifacts to `<output_dir>`, each recorded by SHA-256 in `artifact_index.json`:

| Artifact | Contents | Reproducible across runs? |
|---|---|---|
| `environment.json` | version + limits fingerprint | yes |
| `protocol.json` | hypothesis, conditions, tasks, attack variants, outcome categories | yes |
| `corpus.json` | corpus version, hash, documents | yes |
| `records_normalized.json` | per-trial scientific content (volatile fields stripped) | yes |
| `manifest.json` | campaign manifest + `manifest_hash` | yes |
| `metrics.json` | ASR / TCR / FPR with denominators + outcome counts | yes |
| `records.json` | raw per-trial evidence incl. `experiment_id` + wall-clock `timing` | **no - run-instance evidence** |
| `artifact_index.json` | SHA-256 of every artifact; `reproducible` vs `run_instance` sets | - |

**Why `records.json` is not byte-reproducible (and why that is correct).** Each trial carries a unique
`experiment_id` (UUID) and wall-clock `timing`. Those are per-execution instance identifiers, not
scientific content, so they differ every run by design. The harness does not fake determinism by
freezing them. Instead the reproducible scientific projection lives in `records_normalized.json` (the
same records with `experiment_id`, `timing`, and the per-record `evidence_hash` removed), and
`artifact_index.json` explicitly partitions artifacts into `reproducible` and `run_instance`. Two runs
with identical inputs produce identical `manifest_hash`, `metrics.json`, and `records_normalized.json`.

## 4. Verifying artifact integrity

```
python - <<'PY'
import json, hashlib, os, sys
d = sys.argv[1] if len(sys.argv) > 1 else "out"
idx = json.load(open(os.path.join(d, "artifact_index.json")))
bad = [f for f, h in idx["artifact_sha256"].items()
       if hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() != h]
print("backend_provenance:", idx["backend_provenance"])
print("findings_available:", idx["findings_available"])
print("integrity:", "OK" if not bad else ("TAMPERED: %s" % bad))
PY
```

To confirm reproducibility, run the reproduce command twice into two directories and compare the
`reproducible` artifacts:

```
python -m parallax.research.reproduce a && python -m parallax.research.reproduce b
python - <<'PY'
import json
a=json.load(open("a/artifact_index.json")); b=json.load(open("b/artifact_index.json"))
same=all(a["artifact_sha256"][f]==b["artifact_sha256"][f] for f in a["reproducible"])
print("scientific content reproducible:", same)
print("records.json differs (run-instance):",
      a["artifact_sha256"]["records.json"]!=b["artifact_sha256"]["records.json"])
PY
```

## 5. Running against a real model (the OPEN path)

The only change required to produce real findings is a locally reachable model. The backend refuses any
non-loopback, non-allowlisted host (`model_backend.HTTPBackend._host_authorized`), so the endpoint must
be local or on `RANGER_RESEARCH_MODEL_HOSTS`:

```
# local inference server exposing POST /api/generate
python -m parallax.research.reproduce out --model-url http://127.0.0.1:11434
# or a local transformers model directory
python -m parallax.research.reproduce out --model-dir /opt/models/<local-model>
```

With a real backend, `artifact_index.json` reports `backend_provenance: "infrastructure_backed"` and
`findings_available: true`, and `metrics.json` carries the real ASR/TCR/FPR. Until such a model is
provisioned, treat all metrics in this repository as plumbing checks, not results.

## 6. Experiment manifest, attack variants, evaluation definitions

- **Hypothesis, conditions (`baseline_benign` / `experimental_attack`), legitimate tasks, attack
  variants, and outcome categories** are captured verbatim in `protocol.json`. The six attack variants
  are `a-direct` (direct_instruction), `a-policy` (disguised_policy), `a-override` (task_override),
  `a-conflict` (conflicting_sources), `a-format` (format_influence), and `a-benign-controllike`
  (benign_instruction_like, a **negative control** with `expect_injection=false`).
- **Evaluation is deterministic and rule-based** (`parallax.research.evaluator`). The canary
  `INJECTION-OK` is detected by regex after stripping refusal/negation phrasing, so a model *refusing*
  to emit the canary is never scored as a success. No LLM acts as judge-of-record.
- **Metrics** (`harness.compute_metrics`) report ASR, TCR, and FPR each with an explicit numerator,
  denominator, and exclusion count; infrastructure failures and evaluation errors are excluded from
  denominators rather than silently counted as either success or boundary-preserved.

## 7. Limitations

Enumerated in the Phase 2A Engineering Report. The dominant one: **no real model executes here**, so
Section-level findings are OPEN. The stub is a rule-based toy whose only purpose is to exercise harness
plumbing end-to-end; its ASR/TCR/FPR carry no scientific meaning and are marked accordingly.
