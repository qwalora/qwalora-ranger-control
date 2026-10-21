"""Deterministic tests for parallax.research.provenance (run-metadata capture).

Covers: completeness, canonical serialization, missing/unavailable values, model/runtime
differences, secret redaction, backward compatibility with records that lack provenance, and
reproducibility across identical configurations. No model or network required.
"""
import copy

import pytest

import signing
from parallax.research import provenance as PR
from parallax.research import corpus as C, model_backend as mb, harness


STUDY = {"protocol_version": "px2a-protocol-v1", "harness_version": "hv1",
         "prompt_template_version": "trust-fenced-v1", "corpus_version": "cv1", "corpus_hash": "deadbeef"}

REAL_META = {"weights_sha256": "a" * 64, "revision": "r1", "temperature": 0.0, "max_tokens": 256,
             "tokenizer_id": "tok-x", "tokenizer_config_hash": "b" * 64, "chat_template_hash": "c" * 64,
             "device": "cpu", "dtype": "float32", "latency_s": 0.2}

REAL_ID = {"model_id": "cap-model", "runtime": "http", "backend": "http", "is_real": True}
STUB_ID = {"model_id": "stub/rule-v1", "runtime": "in-process", "backend": "deterministic_stub", "is_real": False}


def _build(ident=REAL_ID, meta=REAL_META, eid="exp-1", started=1.0, finished=2.0,
           outcome="boundary_preserved", infra_error=None):
    return PR.build_provenance(backend_identity=ident, gen_meta=meta,
                               configured_decoding={"temperature": meta.get("temperature"),
                                                    "max_tokens": meta.get("max_tokens")},
                               study_versions=STUDY, experiment_id=eid, started=started,
                               finished=finished, outcome=outcome, infra_error=infra_error)


# ---------------------------------------------------------------- completeness

def test_completeness_all_required_fields():
    p = _build()
    assert PR.is_complete(p)
    for k in PR.REQUIRED_TOP_LEVEL:
        assert k in p
    assert p["schema"] == PR.PROVENANCE_SCHEMA
    assert p["model"]["weight_digests"] == {"weights_sha256": "a" * 64}
    assert p["tokenizer"]["source"] == "backend_reported"
    assert p["evaluator"]["source_sha256"] is not None   # evaluator versioned by source hash


# ---------------------------------------------------------------- canonical serialization

def test_canonical_serialization_and_hash():
    p = _build()
    # canonical bytes are stable and the recorded hash matches a recompute over the block sans hash
    body = {k: v for k, v in p.items() if k != "provenance_hash"}
    assert p["provenance_hash"] == PR.canonical_hash(body)
    assert signing.canonical(p) == signing.canonical(copy.deepcopy(p))   # deterministic


# ---------------------------------------------------------------- missing / unavailable values

def test_missing_values_are_honest_not_invented():
    p = _build(ident=STUB_ID, meta={"note": "deterministic stub; not a model"})
    assert p["model"]["weight_digests"] is None and p["model"]["digests_source"] == "unavailable"
    assert p["tokenizer"]["source"] == "unavailable" and p["tokenizer"]["id"] is None
    assert p["chat_template"]["source"] == "unavailable"
    # decode params the stub never set and did not report are honest "model_default_unknown", not 0
    assert p["decoding"]["temperature"]["source"] == "model_default_unknown"
    assert p["decoding"]["top_p"] == {"value": None, "source": "model_default_unknown"}
    assert p["hardware"]["source"] == "unavailable"


def test_configured_vs_inherited_distinguished():
    p = _build()  # harness set temperature/max_tokens
    assert p["decoding"]["temperature"] == {"value": 0.0, "source": "configured"}
    assert p["decoding"]["max_tokens"] == {"value": 256, "source": "configured"}
    # top_p etc. not configured and not reported -> model default unknown
    assert p["decoding"]["top_p"]["source"] == "model_default_unknown"


# ---------------------------------------------------------------- model / runtime differences

def test_model_and_runtime_differences_change_hash():
    base = _build()
    other_model = _build(meta={**REAL_META, "weights_sha256": "f" * 64})
    assert base["provenance_hash"] != other_model["provenance_hash"]
    # runtime versions are captured and present
    rt = base["runtime"]
    assert rt["python"] and "cuda" in rt and ("torch" in rt) and ("transformers" in rt)


# ---------------------------------------------------------------- secret redaction

def test_secret_redaction_keys_and_urls():
    dirty = {"api_key": "sk-123", "nested": {"authorization": "Bearer t", "ok": 1},
             "endpoint": "https://user:pass@host:5432/db", "list": [{"token": "zzz"}]}
    clean = PR.redact(dirty)
    assert clean["api_key"] == "[REDACTED]"
    assert clean["nested"]["authorization"] == "[REDACTED]" and clean["nested"]["ok"] == 1
    assert "user:pass@" not in clean["endpoint"] and "[REDACTED]@host" in clean["endpoint"]
    assert clean["list"][0]["token"] == "[REDACTED]"


def test_build_provenance_output_has_no_obvious_secret_leak():
    p = _build(meta={**REAL_META, "endpoint": "https://u:p@h/db"})  # stray creds in meta are not copied
    flat = signing.canonical(p).decode("utf-8")
    assert "u:p@h" not in flat


# ---------------------------------------------------------------- backward compatibility

def test_provenance_is_additive_and_non_mutating():
    meta = copy.deepcopy(REAL_META)
    ident = copy.deepcopy(REAL_ID)
    _build(ident=ident, meta=meta)
    assert meta == REAL_META and ident == REAL_ID            # inputs not mutated

    # a historical-style record WITHOUT provenance remains valid and canonicalizes independently;
    # adding provenance to new records does not change how an old record serializes.
    old_record = {"experiment_id": "old-1", "outcome": "boundary_preserved", "evidence_hash": "x"}
    before = signing.canonical(old_record)
    _ = _build()                                             # building new provenance elsewhere
    assert signing.canonical(old_record) == before


@pytest.mark.parametrize("with_prov", [False, True])
def test_sign_verify_roundtrip_with_and_without_provenance(with_prov):
    try:
        signing.assert_signing_ready()
    except Exception:
        pytest.skip("no active signing key configured in this environment")
    rec = {"experiment_id": "e", "outcome": "boundary_preserved"}
    if with_prov:
        rec["provenance"] = _build()
    sig = signing.sign(rec)
    assert signing.verify(rec, sig)                          # both verify -> backward compatible


# ---------------------------------------------------------------- reproducibility

def test_reproducible_across_identical_configuration():
    p1 = _build(eid="same", started=10.0, finished=11.0)
    p2 = _build(eid="same", started=10.0, finished=11.0)
    assert p1 == p2 and p1["provenance_hash"] == p2["provenance_hash"]

    # identical CONFIG but different per-run instance fields -> identical non-volatile content
    a = _build(eid="run-a", started=1.0, finished=2.0)
    b = _build(eid="run-b", started=3.0, finished=4.0)
    volatile = ("experiment_id", "timestamps", "provenance_hash")
    na = {k: v for k, v in a.items() if k not in volatile}
    nb = {k: v for k, v in b.items() if k not in volatile}
    assert na == nb


# ---------------------------------------------------------------- harness integration

def test_harness_record_carries_complete_provenance():
    backend = mb.DeterministicStubBackend()
    rec = harness.run_trial(backend, C.default_corpus(),
                            task={"task_id": "t-storage", "task": "q", "expected_contains": ["2 gb"]},
                            variant=None, condition="baseline_benign", repetition=1)
    assert "provenance" in rec and PR.is_complete(rec["provenance"])
    assert rec["provenance"]["model"]["is_real"] is False
    assert rec["provenance"]["failure_classification"] == "none"
    assert "evidence_hash" in rec
