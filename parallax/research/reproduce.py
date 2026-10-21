"""Deterministic reproducibility entrypoint for the PARALLAX Phase 2A research harness.

Run:  python -m parallax.research.reproduce <output_dir> [--repetitions N] [--model-url URL | --model-dir DIR]

Writes machine-readable artifacts (corpus, protocol, raw trial records, campaign manifest, metrics,
environment fingerprint, and a SHA-256 artifact index) so a third party can reproduce and verify a
run byte-for-byte. With no --model-* flag it uses the deterministic stub backend: the resulting
metrics are PLUMBING ONLY (backend_provenance=simulated, findings_available=false), never empirical
AI-security findings. A real run requires a locally reachable model endpoint or a local model
directory (see docs/PARALLAX_PHASE_2A_ENGINEERING_REPORT.md for the environment blocker).

This script performs no network calls of its own and writes nothing outside <output_dir>.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
from typing import Any, Dict

from . import HARNESS_VERSION
from . import protocol as P
from . import corpus as C
from . import rag, model_backend as mb, harness


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _write(path: str, obj: Any) -> str:
    """Write obj as canonical JSON (sorted keys, no insignificant whitespace) and return its sha256."""
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as fh:
        fh.write(data)
    return _sha256_bytes(data)


def _env_fingerprint() -> Dict[str, Any]:
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "harness_version": HARNESS_VERSION,
        "protocol_version": P.PROTOCOL_VERSION,
        "prompt_template_version": mb.PROMPT_TEMPLATE_VERSION,
        "corpus_version": C.CORPUS_VERSION,
        "canary": P.CANARY,
        "limits": {"max_docs": rag.MAX_DOCS, "max_tokens": rag.MAX_TOKENS,
                   "max_trials_per_campaign": harness.MAX_TRIALS_PER_CAMPAIGN,
                   "per_trial_timeout_s": harness.PER_TRIAL_TIMEOUT_S},
    }


def _protocol_snapshot(advanced: bool = False) -> Dict[str, Any]:
    variants = P.ADVANCED_ATTACK_VARIANTS if advanced else P.ATTACK_VARIANTS
    return {
        "protocol_version": P.ADVANCED_PROTOCOL_VERSION if advanced else P.PROTOCOL_VERSION,
        "hypothesis": harness.HYPOTHESIS,
        "canary": P.CANARY,
        "conditions": [P.CONDITION_BASELINE, P.CONDITION_EXPERIMENTAL],
        "outcome_categories": list(P.OUTCOME_CATEGORIES),
        "legitimate_tasks": P.LEGIT_TASKS,
        "attack_variants": [{k: v for k, v in var.items()} for var in variants],
    }


def _corpus_snapshot(corpus: C.Corpus) -> Dict[str, Any]:
    return {"corpus_version": corpus.version, "corpus_hash": corpus.content_hash(),
            "documents": corpus.docs}


# Fields that are legitimately per-run instance metadata, not reproducible scientific content:
# a fresh experiment_id (uuid) and wall-clock timing differ on every execution by design. The
# normalized projection strips them so the SCIENTIFIC content of a run is byte-for-byte reproducible,
# while the raw records.json retains them as unique per-trial evidence.
# `provenance` is per-run instance metadata (timestamps, runtime/library versions, hardware) that
# varies run-to-run and across machines, so it is excluded from the byte-for-byte-reproducible
# normalized projection, exactly like experiment_id and timing. The raw records.json retains the full
# provenance block as per-trial evidence; the scientifically reproducible fields (model digest,
# inference params, protocol/corpus/prompt versions) remain in the normalized record.
_VOLATILE_RECORD_FIELDS = ("experiment_id", "timing", "evidence_hash", "provenance")


def _normalize_records(records):
    return [{k: v for k, v in sorted(r.items()) if k not in _VOLATILE_RECORD_FIELDS} for r in records]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="parallax.research.reproduce")
    ap.add_argument("output_dir")
    ap.add_argument("--repetitions", type=int, default=1)
    ap.add_argument("--model-url", default=None, help="local model endpoint (loopback/allowlisted only)")
    ap.add_argument("--model-dir", default=None, help="local transformers model directory")
    ap.add_argument("--advanced", action="store_true",
                    help="run the preregistered ADVANCED attack family (incl. cross-document split payload)")
    args = ap.parse_args(argv)

    os.makedirs(args.output_dir, exist_ok=True)
    cfg: Dict[str, Any] = {}
    if args.model_url:
        cfg["model_url"] = args.model_url
    if args.model_dir:
        cfg["model_dir"] = args.model_dir
    backend = mb.from_config(cfg)

    corpus = C.default_corpus()
    _variants = P.ADVANCED_ATTACK_VARIANTS if args.advanced else P.ATTACK_VARIANTS
    _pv = P.ADVANCED_PROTOCOL_VERSION if args.advanced else P.PROTOCOL_VERSION
    campaign = harness.run_campaign(backend, corpus, repetitions=args.repetitions,
                                    variants=_variants, protocol_version=_pv)
    metrics = harness.compute_metrics(campaign["records"])

    index: Dict[str, str] = {}
    index["environment.json"] = _write(os.path.join(args.output_dir, "environment.json"), _env_fingerprint())
    index["protocol.json"] = _write(os.path.join(args.output_dir, "protocol.json"), _protocol_snapshot(args.advanced))
    index["corpus.json"] = _write(os.path.join(args.output_dir, "corpus.json"), _corpus_snapshot(corpus))
    index["records.json"] = _write(os.path.join(args.output_dir, "records.json"), campaign["records"])
    index["records_normalized.json"] = _write(os.path.join(args.output_dir, "records_normalized.json"),
                                              _normalize_records(campaign["records"]))
    index["manifest.json"] = _write(os.path.join(args.output_dir, "manifest.json"), campaign["manifest"])
    index["metrics.json"] = _write(os.path.join(args.output_dir, "metrics.json"), metrics)

    # The index binds every artifact by hash; a verifier recomputes each file's sha256 and compares.
    # `reproducible` names the artifacts whose hashes are stable run-to-run for identical inputs;
    # records.json is excluded because each trial carries a unique id + wall-clock timing by design.
    index_obj = {"artifact_sha256": index,
                 "reproducible": sorted(k for k in index if k != "records.json"),
                 "run_instance": ["records.json"],
                 "backend_is_real": backend.is_real,
                 "backend_provenance": "infrastructure_backed" if backend.is_real else "simulated",
                 "findings_available": metrics["findings_available"]}
    _write(os.path.join(args.output_dir, "artifact_index.json"), index_obj)

    prov = "infrastructure_backed" if backend.is_real else "simulated (PLUMBING ONLY - not a finding)"
    print("wrote %d artifacts to %s" % (len(index) + 1, args.output_dir))
    print("backend_provenance: %s" % prov)
    print("findings_available: %s" % metrics["findings_available"])
    print("manifest_hash: %s" % campaign["manifest"]["manifest_hash"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
