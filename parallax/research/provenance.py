"""Comprehensive, honest run-metadata capture for PARALLAX experiments.

Every new experiment record carries a `provenance` block built here: exact model/tokenizer identity
and digests, effective decoding parameters, chat-template identity, runtime and hardware/precision
metadata, and the study protocol/evaluator/corpus/prompt-template versions, plus the experiment id,
timestamps, outcome, and failure classification.

Principles:
- Honesty over completeness. A value that is not available is recorded as null with an explicit
  `source` of "unavailable" (or "model_default_unknown" for a decode parameter the server was not
  told and did not report). Nothing is invented.
- Configured vs inherited. Every value carries a `source`: "configured" (the harness set it),
  "backend_reported" (the backend/runtime reported it), "inherited_default", "model_default_unknown",
  or "unavailable".
- Secrets never leave. `redact()` nulls secret-looking keys and strips credentials from URLs before
  the block is stored or exported.
- Backward compatible. This adds a NEW top-level `provenance` field to new records only; historical
  signed records are never modified or re-evaluated, and their signatures verify unchanged.

Pure Python; optional libraries (torch, transformers) are imported lazily and their absence is
recorded honestly, never as an error.
"""
from __future__ import annotations

import hashlib
import importlib
import inspect
import platform
import re
from typing import Any, Dict, List, Optional

import signing

PROVENANCE_SCHEMA = "px-provenance-v1"

_SECRET_KEY_RE = re.compile(r"(key|token|secret|password|passwd|authorization|auth|credential|cookie|"
                            r"api[-_]?key|bearer|session)", re.IGNORECASE)
_URL_CRED_RE = re.compile(r"://[^/@\s]*:[^/@\s]*@")   # scheme://user:pass@host -> strip the creds


def _module_version(name: str) -> Optional[str]:
    try:
        return getattr(importlib.import_module(name), "__version__", None)
    except Exception:
        return None


def runtime_versions() -> Dict[str, Any]:
    cuda: Dict[str, Any] = {"available": None, "version": None}
    try:
        import torch  # noqa: F401
        cuda = {"available": bool(torch.cuda.is_available()),
                "version": getattr(getattr(torch, "version", None), "cuda", None)}
    except Exception:
        pass
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "transformers": _module_version("transformers"),
        "torch": _module_version("torch"),
        "numpy": _module_version("numpy"),
        "cuda": cuda,
    }


def evaluator_identity() -> Dict[str, Any]:
    """Version the evaluator by hashing its source, so a change in canary/refusal logic is recorded."""
    try:
        from . import evaluator as _ev
        src = inspect.getsource(_ev).encode("utf-8")
        return {"module": "parallax.research.evaluator",
                "source_sha256": hashlib.sha256(src).hexdigest(),
                "version": getattr(_ev, "EVALUATOR_VERSION", None)}
    except Exception:
        return {"module": "parallax.research.evaluator", "source_sha256": None, "version": None}


def _tag(value: Any, source: str) -> Dict[str, Any]:
    return {"value": value, "source": ("unavailable" if value is None and source != "model_default_unknown"
                                       else source)}


def decoding_params(gen_meta: Dict[str, Any], configured: Dict[str, Any]) -> Dict[str, Any]:
    """Effective decoding parameters. `configured` holds values the harness explicitly set; anything
    not in `configured` and not reported by the backend is an unknown model/server default."""
    gm = gen_meta or {}
    out: Dict[str, Any] = {}
    for k in ("temperature", "max_tokens"):
        if k in configured and configured[k] is not None:
            out[k] = _tag(configured[k], "configured")
        elif gm.get(k) is not None:
            out[k] = _tag(gm.get(k), "backend_reported")
        else:
            out[k] = {"value": None, "source": "model_default_unknown"}
    for k in ("top_p", "top_k", "repetition_penalty", "seed"):
        if k in configured and configured[k] is not None:
            out[k] = _tag(configured[k], "configured")
        elif gm.get(k) is not None:
            out[k] = _tag(gm.get(k), "backend_reported")
        else:
            out[k] = {"value": None, "source": "model_default_unknown"}
    return out


def redact(obj: Any) -> Any:
    """Recursively null secret-looking VALUES (by key name) and strip credentials from URL strings.
    Structure and keys are preserved so completeness checks still pass."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _SECRET_KEY_RE.search(k) and not isinstance(v, (dict, list)):
                out[k] = None if v is None else "[REDACTED]"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, str):
        return _URL_CRED_RE.sub("://[REDACTED]@", obj)
    return obj


def canonical_hash(obj: Any) -> str:
    return hashlib.sha256(signing.canonical(obj)).hexdigest()


def failure_classification(outcome: Optional[str], infra_error: Optional[str]) -> str:
    if infra_error:
        if "model_backend_error" in infra_error:
            return "model_backend_error"
        if "harness_error" in infra_error:
            return "harness_error"
        return "infrastructure_error"
    if outcome in ("infrastructure_failure", "evaluation_error"):
        return outcome
    return "none"


def build_provenance(*, backend_identity: Dict[str, Any], gen_meta: Optional[Dict[str, Any]],
                     configured_decoding: Optional[Dict[str, Any]], study_versions: Dict[str, Any],
                     experiment_id: Optional[str], started: Optional[float], finished: Optional[float],
                     outcome: Optional[str], infra_error: Optional[str]) -> Dict[str, Any]:
    gm = gen_meta or {}
    bi = backend_identity or {}
    weight_digests = {k: gm.get(k) for k in ("weights_sha256", "digest", "model_digest") if gm.get(k)}
    prov: Dict[str, Any] = {
        "schema": PROVENANCE_SCHEMA,
        "experiment_id": experiment_id,
        "timestamps": {"started": started, "finished": finished},
        "model": {
            "id": bi.get("model_id"),
            "runtime": bi.get("runtime"),
            "backend": bi.get("backend"),
            "is_real": bi.get("is_real"),
            "revision": gm.get("revision") or gm.get("model_version"),
            "weight_digests": (weight_digests or None),
            "digests_source": ("backend_reported" if weight_digests else "unavailable"),
        },
        "tokenizer": {
            "id": gm.get("tokenizer_id"),
            "revision": gm.get("tokenizer_revision"),
            "config_hash": gm.get("tokenizer_config_hash"),
            "vocab_hash": gm.get("tokenizer_vocab_hash"),
            "source": ("backend_reported" if gm.get("tokenizer_id") or gm.get("tokenizer_config_hash")
                       else "unavailable"),
        },
        "chat_template": {
            "id": gm.get("chat_template_id"),
            "hash": gm.get("chat_template_hash"),
            "source": ("backend_reported" if gm.get("chat_template_hash") else "unavailable"),
        },
        "decoding": decoding_params(gm, configured_decoding or {}),
        "runtime": runtime_versions(),
        "hardware": {
            "device": gm.get("device"),
            "dtype": gm.get("dtype"),
            "quantization": gm.get("quantization"),
            "source": ("backend_reported" if any(gm.get(k) for k in ("device", "dtype", "quantization"))
                       else "unavailable"),
        },
        "study_versions": dict(study_versions or {}),
        "evaluator": evaluator_identity(),
        "outcome": outcome,
        "failure_classification": failure_classification(outcome, infra_error),
    }
    prov = redact(prov)
    # the hash covers the provenance content excluding the hash field itself
    prov["provenance_hash"] = canonical_hash(prov)
    return prov


# Fields whose absence makes a provenance block INCOMPLETE (present-with-null is allowed and honest;
# a MISSING key is not). Used by validation/tests.
REQUIRED_TOP_LEVEL: List[str] = ["schema", "experiment_id", "timestamps", "model", "tokenizer",
                                 "chat_template", "decoding", "runtime", "hardware", "study_versions",
                                 "evaluator", "outcome", "failure_classification", "provenance_hash"]


def is_complete(prov: Dict[str, Any]) -> bool:
    return all(k in prov for k in REQUIRED_TOP_LEVEL)
