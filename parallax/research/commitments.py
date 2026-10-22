"""Three distinct cryptographic commitments over an experiment record.

Reproducibility normalization (reproduce.py) deliberately drops nondeterministic timestamps and
runtime metadata when comparing scientific content. That keeps content comparisons meaningful, but it
must NOT weaken integrity: the full original record, including provenance, stays independently
verifiable. This module makes the three different claims explicit, each with its own digest, so no one
digest is mistaken for another.

- full_record_sha256: SHA-256 over the canonical FULL record (every field, including provenance,
  timestamps, and runtime versions).
  Equality PROVES: the two records are byte-for-byte identical in every field.
  Does NOT prove anything weaker on its own; inequality is expected across runs because timestamps and
  runtime versions differ even for an otherwise identical experiment.

- reproducible_content_sha256: SHA-256 over the canonical NORMALIZED record (the volatile per-run
  instance fields - experiment_id, timing, evidence_hash, provenance - removed).
  Equality PROVES: the two runs produced the same scientific content (same outcome, model digest,
  inference params, retrieved context, protocol/corpus/prompt versions).
  Does NOT prove: that they ran on the same machine, at the same time, or with the same runtime library
  versions; and it does NOT by itself prove the full material configuration matched (use the config
  digest for that).

- config_identity_sha256: SHA-256 over the canonical MATERIAL-CONFIGURATION projection (model identity
  and weight digest, tokenizer identity and hashes, chat-template hash, effective decoding parameters,
  prompt-template version, evaluator source hash, protocol version, corpus hash).
  Equality PROVES: the two runs used the same material configuration, so comparing their outcomes is a
  like-for-like comparison.
  Does NOT prove: that the outcomes matched (outcomes are not in this projection), nor that the runtime
  environment matched.

A change to any material field (model, tokenizer, prompt, evaluator, protocol, corpus, or an effective
decoding setting) changes config_identity_sha256, which is what prevents an invalid cross-run
equivalence claim. None of this reads or rewrites historical signed records; it is computed over
records in hand and leaves their own signatures untouched.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

import signing

# Mirrors reproduce._VOLATILE_RECORD_FIELDS: these are per-run instance fields, not scientific content.
VOLATILE_FIELDS = ("experiment_id", "timing", "evidence_hash", "provenance")


def _sha(obj: Any) -> str:
    return hashlib.sha256(signing.canonical(obj)).hexdigest()


def full_record_digest(record: Dict[str, Any]) -> str:
    return _sha(record)


def normalized_content(record: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in record.items() if k not in VOLATILE_FIELDS}


def reproducible_content_digest(record: Dict[str, Any]) -> str:
    return _sha(normalized_content(record))


def config_identity(record: Dict[str, Any]) -> Dict[str, Any]:
    """Material configuration projection, drawn from the provenance block when present and otherwise
    from the record's top-level fields (backward compatible with pre-provenance records)."""
    prov = record.get("provenance") or {}
    model_p = prov.get("model") or {}
    tok_p = prov.get("tokenizer") or {}
    tmpl_p = prov.get("chat_template") or {}
    dec_p = prov.get("decoding") or {}
    ev_p = prov.get("evaluator") or {}

    def _dec(name):
        v = dec_p.get(name)
        if isinstance(v, dict):
            return v.get("value")
        # fall back to the flat inference_params for records without provenance
        return (record.get("inference_params") or {}).get(name)

    model_top = record.get("model") or {}
    return {
        "model": {
            "id": model_p.get("id") or model_top.get("id"),
            "revision": model_p.get("revision"),
            "backend": model_p.get("backend") or model_top.get("backend"),
            "runtime": model_p.get("runtime") or model_top.get("runtime"),
            "weight_digests": model_p.get("weight_digests") or (
                {"digest": model_top.get("digest")} if model_top.get("digest") else None),
        },
        "tokenizer": {"id": tok_p.get("id"), "revision": tok_p.get("revision"),
                      "config_hash": tok_p.get("config_hash"), "vocab_hash": tok_p.get("vocab_hash")},
        "chat_template_hash": tmpl_p.get("hash"),
        "decoding": {k: _dec(k) for k in ("temperature", "max_tokens", "top_p", "top_k",
                                          "repetition_penalty", "seed")},
        "prompt_template_version": record.get("prompt_template_version"),
        "evaluator_source_sha256": ev_p.get("source_sha256"),
        "protocol_version": record.get("protocol_version"),
        "corpus_hash": record.get("corpus_hash"),
    }


def config_identity_digest(record: Dict[str, Any]) -> str:
    return _sha(config_identity(record))


def commitments(record: Dict[str, Any]) -> Dict[str, str]:
    """All three digests for one record."""
    return {
        "full_record_sha256": full_record_digest(record),
        "reproducible_content_sha256": reproducible_content_digest(record),
        "config_identity_sha256": config_identity_digest(record),
    }


def same_configuration(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """True iff two records share the same material configuration (not outcomes, not runtime)."""
    return config_identity_digest(a) == config_identity_digest(b)


def same_reproducible_content(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    return reproducible_content_digest(a) == reproducible_content_digest(b)
