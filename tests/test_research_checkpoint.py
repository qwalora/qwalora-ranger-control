"""Adversarial tests for campaign checkpointing, resumability, failure accounting, and the three
cryptographic commitments.

Covers: the three digests and what each proves; config changes preventing cross-run equivalence;
clean completion; idempotent resume with no duplicates; interrupt-and-resume; refusal to resume a
changed spec; truncated/corrupt/tampered checkpoint recovery; missing records not marked complete;
backend failure ledgering; exclusions not inflating rates; clean-vs-resumed content equality;
signature round-trip and backward compatibility; deterministic ordering; evidence-chain continuity.
"""
import json
import os

import pytest

import signing
from parallax.research import checkpoint as CK
from parallax.research import commitments as CM
from parallax.research import corpus as C, model_backend as mb, harness, protocol as P


TASKS = [{"task_id": "t-storage", "task": "How much storage?", "expected_contains": ["2 gb"]},
         {"task_id": "t-export", "task": "What formats?", "expected_contains": ["markdown"]}]
VARIANTS = [P.ATTACK_VARIANTS[0], P.ATTACK_VARIANTS[1]]   # 2 attack variants
# plan = 1 rep x (2 baseline + 2 tasks x 2 variants) = 6 units


def _runner(d, backend=None, **kw):
    return CK.CampaignRunner(d, backend=backend or mb.DeterministicStubBackend(), corpus=C.default_corpus(),
                             repetitions=1, tasks=TASKS, variants=VARIANTS, **kw)


# --------------------------------------------------------------- commitments

def _rec(backend=None):
    return harness.run_trial(backend or mb.DeterministicStubBackend(), C.default_corpus(),
                             task=TASKS[0], variant=None, condition=P.CONDITION_BASELINE, repetition=1)


def test_three_commitments_distinct_meaning():
    r = _rec()
    c = CM.commitments(r)
    assert set(c) == {"full_record_sha256", "reproducible_content_sha256", "config_identity_sha256"}
    # same scientific content + config, different per-run instance fields -> reproducible & config equal,
    # full-record differs
    import copy
    r2 = copy.deepcopy(r)
    r2["experiment_id"] = "different"
    r2["timing"] = {"started": 999.0, "duration_s": 9.9}
    r2["provenance"] = {**r["provenance"], "timestamps": {"started": 999.0, "finished": 1000.0}}
    r2["evidence_hash"] = "x"
    assert CM.reproducible_content_digest(r) == CM.reproducible_content_digest(r2)
    assert CM.config_identity_digest(r) == CM.config_identity_digest(r2)
    assert CM.full_record_digest(r) != CM.full_record_digest(r2)


def test_config_change_prevents_equivalence():
    import copy
    r = _rec()
    base = CM.config_identity_digest(r)
    for mutate in (
        lambda x: x["provenance"]["model"].update({"id": "other-model"}),
        lambda x: x.update({"prompt_template_version": "other-template"}),
        lambda x: x.update({"protocol_version": "other-protocol"}),
        lambda x: x["provenance"]["evaluator"].update({"source_sha256": "0" * 64}),
        lambda x: x["provenance"]["decoding"].update({"temperature": {"value": 0.7, "source": "configured"}}),
    ):
        r2 = copy.deepcopy(r)
        mutate(r2)
        assert CM.config_identity_digest(r2) != base   # material change breaks the equivalence claim


# --------------------------------------------------------------- clean + idempotent

def test_clean_campaign_completes_and_chain_verifies(tmp_path):
    r = _runner(str(tmp_path / "c1"))
    out = r.run()
    assert out["state"] == CK.COMPLETED and out["completed"] == 6 and out["remaining"] == 0
    assert r.verify_chain() is True
    recs, problems = r.load_records()
    assert len(recs) == 6 and not problems


def test_resume_is_idempotent_no_duplicates(tmp_path):
    d = str(tmp_path / "c2")
    _runner(d).run()
    before, _ = _runner(d).load_records()
    out = _runner(d).run()            # resume a completed campaign
    after, _ = _runner(d).load_records()
    assert out["state"] == CK.COMPLETED and len(after) == len(before) == 6


# --------------------------------------------------------------- interrupt + resume

def test_interrupt_then_resume_completes(tmp_path):
    d = str(tmp_path / "c3")
    out1 = _runner(d, deadline_s=0.0).run()        # deadline hit immediately -> interrupted, 0 done
    assert out1["state"] == CK.INTERRUPTED and out1["completed"] == 0
    out2 = _runner(d).run()                          # resume, no deadline
    assert out2["state"] == CK.COMPLETED and out2["completed"] == 6
    recs, _ = _runner(d).load_records()
    keys = ["|".join(str(x) for x in (r["repetition"], r["condition"], r.get("legitimate_task_id"),
            r.get("adversarial_input_id") or "none")) for r in recs]
    assert len(keys) == len(set(keys)) == 6          # no duplicates after resume


# --------------------------------------------------------------- changed spec refused

def test_changed_spec_refuses_resume(tmp_path):
    d = str(tmp_path / "c4")
    _runner(d, deadline_s=0.0).run()                 # create manifest
    changed = CK.CampaignRunner(d, backend=mb.DeterministicStubBackend(), corpus=C.default_corpus(),
                                repetitions=2, tasks=TASKS, variants=VARIANTS)   # repetitions changed
    with pytest.raises(CK.ResumeSpecMismatch):
        changed.run()


# --------------------------------------------------------------- corrupt / tamper recovery

def test_truncated_trailing_line_recovered(tmp_path):
    d = str(tmp_path / "c5")
    _runner(d).run()
    with open(os.path.join(d, "records.jsonl"), "a") as fh:
        fh.write('{"partial": true, "no_newline_or_close')   # simulated crash mid-append
    recs, problems = _runner(d).load_records()
    assert len(recs) == 6 and any("discarded" in p for p in problems)   # partial line dropped


def test_tampered_record_detected_and_rerun(tmp_path):
    d = str(tmp_path / "c6")
    _runner(d).run()
    path = os.path.join(d, "records.jsonl")
    lines = open(path).readlines()
    rec = json.loads(lines[0]); rec["outcome"] = "successful_unauthorized_behavior"   # tamper
    lines[0] = json.dumps(rec) + "\n"
    open(path, "w").writelines(lines)
    recs, problems = _runner(d).load_records()
    assert len(recs) == 5 and any("evidence_hash mismatch" in p for p in problems)
    out = _runner(d).run()                            # the discarded unit is re-run
    assert out["state"] == CK.COMPLETED and out["completed"] == 6


# --------------------------------------------------------------- missing trial not marked complete

def test_missing_trial_yields_incomplete_not_complete(tmp_path, monkeypatch):
    d = str(tmp_path / "c7")
    real = harness.run_trial
    def flaky(backend, corpus, *, task, variant, condition, repetition, **kw):
        if task["task_id"] == "t-export" and condition == P.CONDITION_BASELINE:
            raise RuntimeError("persistent harness failure for this unit")
        return real(backend, corpus, task=task, variant=variant, condition=condition,
                    repetition=repetition, **kw)
    monkeypatch.setattr(harness, "run_trial", flaky)
    out = _runner(d, max_retries=1).run()
    assert out["state"] == CK.INCOMPLETE and out["completed"] == 5   # the failing unit has NO record
    assert any(e.get("failure_category") == CK.CAT_HARNESS and e.get("status") == "excluded"
               for e in _runner(d).read_ledger())


# --------------------------------------------------------------- backend failure ledgering + exclusions

def test_dead_backend_failures_are_ledgered_and_excluded(tmp_path):
    d = str(tmp_path / "c8")
    dead = mb.HTTPBackend("http://127.0.0.1:1", model_id="dead")   # connection refused -> model_backend_error
    out = _runner(d, backend=dead, max_retries=1).run()
    recs, _ = _runner(d, backend=dead).load_records()
    assert all(r["outcome"] == "infrastructure_failure" for r in recs)   # failures recorded, not dropped
    ledger = _runner(d, backend=dead).read_ledger()
    assert any(e.get("failure_category") == CK.CAT_MODEL for e in ledger)
    # exclusions do not inflate rates: compute_metrics excludes them with an explicit excluded count
    m = harness.compute_metrics(recs)
    rb = m["real_backend"]
    assert rb.get("ASR") is None and rb.get("ASR_excluded", 0) >= 1


# --------------------------------------------------------------- clean vs resumed content equality

def test_clean_vs_resumed_same_reproducible_content(tmp_path):
    clean = _runner(str(tmp_path / "clean")); clean.run()
    d = str(tmp_path / "resumed")
    _runner(d, deadline_s=0.0).run(); _runner(d).run()
    cr, _ = clean.load_records(); rr, _ = _runner(d).load_records()
    def key(r):
        return (r["repetition"], r["condition"], r.get("legitimate_task_id"), r.get("adversarial_input_id"))
    cmap = {key(r): r for r in cr}; rmap = {key(r): r for r in rr}
    assert set(cmap) == set(rmap)
    for k in cmap:
        assert CM.reproducible_content_digest(cmap[k]) == CM.reproducible_content_digest(rmap[k])
        # full records differ (per-run provenance timestamps / experiment id)
        assert CM.full_record_digest(cmap[k]) != CM.full_record_digest(rmap[k])


# --------------------------------------------------------------- signature + backward compat

def test_persisted_record_signature_and_backward_compat(tmp_path):
    try:
        signing.assert_signing_ready()
    except Exception:
        pytest.skip("no active signing key configured")
    d = str(tmp_path / "c9"); _runner(d).run()
    recs, _ = _runner(d).load_records()
    sig = signing.sign(recs[0])
    assert signing.verify(recs[0], sig)
    legacy = {k: v for k, v in recs[0].items() if k != "provenance"}   # pre-provenance shape
    assert signing.verify(legacy, signing.sign(legacy))


# --------------------------------------------------------------- deterministic ordering

def test_plan_is_deterministic_and_ordered(tmp_path):
    r = _runner(str(tmp_path / "c10"))
    p1, p2 = r.plan(), r.plan()
    assert p1 == p2
    assert p1[0]["condition"] == P.CONDITION_BASELINE            # baselines first
    assert p1[2]["condition"] == P.CONDITION_EXPERIMENTAL
    assert len(p1) == 6
