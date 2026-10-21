"""Adversarial tests for the standalone read-only evidence verifier and sanitized export.

Covers, against synthetic evidence only (no real models, no network): clean PASS; the five signature
states (unsigned / valid / invalid / incomplete / unverifiable); corrupted and substituted records;
duplicate and reordered records; a broken checkpoint chain; incomplete campaigns and exclusion
reconciliation (unaccounted / double-counted / off-plan); tampered commitments; completion-vs-
eligibility separation; and export-security hardening (path traversal, symlink destinations, non-empty
destinations, zip-slip member names, auditable redaction, signature preservation only on unchanged
bytes, refusal to export tampered evidence, and failures never dropped from the exported accounting).
"""
import base64
import copy
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as _ser

import signing
from parallax.research import checkpoint as CK, commitments as CM, evidence_verifier as V
from parallax.research import corpus as C, model_backend as mb, protocol as P


TASKS = [{"task_id": "t-a", "task": "How much storage?", "expected_contains": ["2 gb"]},
         {"task_id": "t-b", "task": "What formats?", "expected_contains": ["markdown"]}]
VARIANTS = [P.ATTACK_VARIANTS[0], P.ATTACK_VARIANTS[1]]   # plan = 2 baseline + 2x2 experimental = 6


@pytest.fixture(autouse=True)
def _signing_key(monkeypatch):
    seed = base64.b64encode(Ed25519PrivateKey.generate().private_bytes(
        _ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption())).decode()
    monkeypatch.setenv("RANGER_SIGNING_KEY", seed)
    monkeypatch.delenv("RANGER_SIGNING_KEYS", raising=False)
    signing._reset_registry()
    yield
    signing._reset_registry()


def _build(tmp_path, name="camp"):
    cdir = str(tmp_path / name)
    r = CK.CampaignRunner(cdir, backend=mb.DeterministicStubBackend(), corpus=C.default_corpus(),
                          repetitions=1, tasks=TASKS, variants=VARIANTS)
    r.run()
    recs, _ = r.load_records()
    plan = [[u["repetition"], u["condition"], u["task_id"], u["variant_id"] or "none"] for u in r.plan()]
    return cdir, r, recs, plan


def _sign_all(recs):
    kid = signing.active_kid()
    pub = signing.public_key_b64()
    sigs = {rec["evidence_hash"]: {"signature_b64": signing.sign(rec), "kid": kid} for rec in recs}
    trusted = [{"kid": kid, "public_b64": pub}]
    return sigs, trusted, kid, pub


def _commit_all(recs):
    return {rec["evidence_hash"]: CM.commitments(rec) for rec in recs}


def _rewrite_records(cdir, records):
    with open(os.path.join(cdir, "records.jsonl"), "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def _resync_state(cdir, records):
    """Recompute state.json's chain_head over the given records, as a real producer would leave it.
    Used only for scenarios representing LEGITIMATELY produced evidence (not tamper tests)."""
    head = V._chain_fold([r.get("evidence_hash", "") for r in records])
    sp = os.path.join(cdir, "state.json")
    st = json.load(open(sp))
    st["chain_head"] = head
    json.dump(st, open(sp, "w"))


# --------------------------------------------------------------------------- clean baseline

def test_clean_campaign_passes(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    coms = _commit_all(recs)
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan,
                            committed_commitments=coms)
    assert rep["overall"] == "PASS"
    assert rep["verdicts"]["integrity_ok"] is True
    assert rep["verdicts"]["campaign_complete"]["complete"] is True
    assert rep["signatures"]["summary"][V.SIG_VALID] == 6
    assert rep["commitments"]["checked"] == 6
    assert rep["commitments"]["reproducible_content_mismatch"] == []


# --------------------------------------------------------------------------- R6 completion vs eligibility

def test_complete_but_not_eligible_on_simulated_backend(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    # complete, but simulated plumbing is never a scientific finding
    assert rep["verdicts"]["campaign_complete"]["complete"] is True
    assert rep["verdicts"]["result_eligible"]["eligible"] is False
    assert any("simulated" in reason for reason in rep["verdicts"]["result_eligible"]["reasons"])


# --------------------------------------------------------------------------- R3 five signature states

def test_unsigned_records(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    _, trusted, _, _ = _sign_all(recs)
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures={}, expected_plan=plan)
    assert rep["signatures"]["summary"][V.SIG_UNSIGNED] == 6
    # unsigned does not by itself fail integrity/overall
    assert rep["overall"] == "PASS"


def test_invalid_signature_wrong_key(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, _, kid, _ = _sign_all(recs)
    other_pub = signing.public_key_b64()  # placeholder, replaced below
    # a DIFFERENT trusted key: signatures were made by the active key, we trust an unrelated key under
    # the SAME kid so the verifier checks and fails (invalid, not unverifiable)
    wrong = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes(
        _ser.Encoding.Raw, _ser.PublicFormat.Raw)).decode()
    trusted = [{"kid": kid, "public_b64": wrong}]
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert rep["signatures"]["summary"][V.SIG_INVALID] == 6
    assert rep["overall"] == "FAIL"           # invalid signatures break integrity_ok


def test_unverifiable_untrusted_kid(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, _, _, _ = _sign_all(recs)
    # the sidecar names the real kid, but the verifier trusts a DIFFERENT kid -> refuse to verify
    trusted = [{"kid": "some-other-kid", "public_b64": signing.public_key_b64()}]
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert rep["signatures"]["summary"][V.SIG_UNVERIFIABLE] == 6
    assert rep["signatures"]["summary"][V.SIG_INVALID] == 0


def test_unverifiable_no_trusted_keys(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, _, _, _ = _sign_all(recs)
    rep = V.verify_campaign(cdir, trusted_keys=[], signatures=sigs, expected_plan=plan)
    assert rep["signatures"]["summary"][V.SIG_UNVERIFIABLE] == 6


def test_incomplete_signature_material(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, kid, _ = _sign_all(recs)
    # corrupt one signature into non-base64 -> incomplete (not invalid)
    first = recs[0]["evidence_hash"]
    sigs[first] = {"signature_b64": "!!!not base64!!!", "kid": kid}
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert rep["signatures"]["summary"][V.SIG_INCOMPLETE] == 1
    assert rep["signatures"]["summary"][V.SIG_VALID] == 5


# --------------------------------------------------------------------------- R1/R5 corruption & tamper

def test_corrupted_record_detected(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    tampered = copy.deepcopy(recs)
    tampered[0]["outcome"] = "successful_unauthorized_behavior"   # evidence_hash now stale
    _rewrite_records(cdir, tampered)
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert rep["integrity"]["corrupted"]            # the tampered line is flagged
    assert rep["verdicts"]["integrity_ok"] is False
    assert rep["overall"] == "FAIL"


def test_unparseable_trailing_line(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    with open(os.path.join(cdir, "records.jsonl"), "a", encoding="utf-8") as fh:
        fh.write('{"partial": true, no close')
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert any("unparseable" in p for p in rep["load_problems"])
    assert rep["overall"] == "FAIL"


def test_duplicate_record_detected(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    _rewrite_records(cdir, recs + [recs[0]])   # duplicate the first unit
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert rep["integrity"]["duplicates"]
    assert rep["overall"] == "FAIL"


def test_reordered_records_break_chain(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    reordered = [recs[1], recs[0]] + recs[2:]
    _rewrite_records(cdir, reordered)
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert rep["integrity"]["chain"]["continuous"] is False
    assert rep["integrity"]["chain"]["reordering_detected"] is True   # same multiset, different order
    assert rep["verdicts"]["campaign_complete"]["complete"] is False


def test_tampered_state_chain_head(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    sp = os.path.join(cdir, "state.json")
    st = json.load(open(sp)); st["chain_head"] = "0" * 64
    json.dump(st, open(sp, "w"))
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert rep["integrity"]["chain"]["continuous"] is False
    assert rep["overall"] == "FAIL"


# --------------------------------------------------------------------------- R4 commitments tamper

def test_tampered_commitment_detected(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    coms = _commit_all(recs)
    first = recs[0]["evidence_hash"]
    coms[first]["reproducible_content_sha256"] = "f" * 64   # a lie about the content
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan,
                            committed_commitments=coms)
    assert first in rep["commitments"]["reproducible_content_mismatch"]


# --------------------------------------------------------------------------- R5/R7 reconciliation

def test_missing_trial_is_unaccounted(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    _rewrite_records(cdir, recs[:-1])   # drop one planned trial, nothing ledgered
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert rep["reconciliation"]["unaccounted"]
    assert rep["verdicts"]["campaign_complete"]["complete"] is False
    assert rep["overall"] == "FAIL"


def test_excluded_trial_reconciles_when_ledgered(tmp_path):
    # a trial absent from records but present in the ledger as excluded is accounted, not unaccounted
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    dropped = recs[-1]
    _rewrite_records(cdir, recs[:-1])
    with open(os.path.join(cdir, "ledger.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "repetition": dropped["repetition"], "condition": dropped["condition"],
            "task_id": dropped["legitimate_task_id"],
            "variant_id": dropped["adversarial_input_id"] or "none",
            "failure_category": CK.CAT_MODEL, "status": "excluded", "error": "model_backend_error"}) + "\n")
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert rep["reconciliation"]["unaccounted"] == []
    assert rep["reconciliation"]["excluded"] == 1


def test_double_counted_record_and_exclusion(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    kept = recs[0]
    with open(os.path.join(cdir, "ledger.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "repetition": kept["repetition"], "condition": kept["condition"],
            "task_id": kept["legitimate_task_id"],
            "variant_id": kept["adversarial_input_id"] or "none",
            "failure_category": CK.CAT_MODEL, "status": "excluded", "error": "x"}) + "\n")
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert rep["reconciliation"]["double_counted"]
    assert rep["overall"] == "FAIL"


def test_exclusion_off_plan(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    with open(os.path.join(cdir, "ledger.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "repetition": 99, "condition": "experimental", "task_id": "ghost",
            "variant_id": "none", "failure_category": CK.CAT_MODEL, "status": "excluded",
            "error": "x"}) + "\n")
    rep = V.verify_campaign(cdir, trusted_keys=trusted, signatures=sigs, expected_plan=plan)
    assert rep["reconciliation"]["exclusions_off_plan"]


# --------------------------------------------------------------------------- R10 export path safety

def test_export_refuses_inside_source(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    with pytest.raises(V.UnsafeExportPath):
        V.build_sanitized_export(cdir, os.path.join(cdir, "nested_export"),
                                 signatures=sigs, trusted_keys=trusted, expected_plan=plan)


def test_export_refuses_symlinked_destination(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    real = tmp_path / "real_target"; real.mkdir()
    link = tmp_path / "link_export"
    os.symlink(str(real), str(link))
    with pytest.raises(V.UnsafeExportPath):
        V.build_sanitized_export(cdir, str(link), signatures=sigs, trusted_keys=trusted, expected_plan=plan)


def test_export_refuses_symlinked_parent(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    real_parent = tmp_path / "realdir"; real_parent.mkdir()
    link_parent = tmp_path / "linkdir"
    os.symlink(str(real_parent), str(link_parent))
    with pytest.raises(V.UnsafeExportPath):
        V.build_sanitized_export(cdir, os.path.join(str(link_parent), "exp"),
                                 signatures=sigs, trusted_keys=trusted, expected_plan=plan)


def test_export_refuses_nonempty_destination(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    dest = tmp_path / "exp"; dest.mkdir(); (dest / "existing.txt").write_text("x")
    with pytest.raises(V.UnsafeExportPath):
        V.build_sanitized_export(cdir, str(dest), signatures=sigs, trusted_keys=trusted, expected_plan=plan)


def test_archive_member_guard_rejects_zip_slip():
    for bad in ("../escape", "/abs/path", "a/../../b", "C:\\x", "sub/../../../etc/passwd"):
        with pytest.raises(V.UnsafeExportPath):
            V.assert_safe_archive_member(bad)
    V.assert_safe_archive_member("records_sanitized.json")   # a safe name is accepted


# --------------------------------------------------------------------------- R8/R10 export refuses tamper

def test_export_refuses_tampered_evidence(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    tampered = copy.deepcopy(recs); tampered[0]["outcome"] = "successful_unauthorized_behavior"
    _rewrite_records(cdir, tampered)
    with pytest.raises(V.RedactionFailure):
        V.build_sanitized_export(cdir, str(tmp_path / "exp"), signatures=sigs, trusted_keys=trusted,
                                 expected_plan=plan)


# --------------------------------------------------------------------------- redaction + signature binding

def test_redaction_is_logged_and_breaks_signature_preservation(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    # inject an infra leak into a NON-protected free-text field of the first record, then re-hash so the
    # record stays self-consistent (simulating evidence that legitimately carried an internal hostname)
    leaked = copy.deepcopy(recs)
    leaked[0]["observed_behavior"] = "connect to parallax.railway.internal and /home/franck/run.sh"
    from parallax.research.harness import _hash
    leaked[0]["evidence_hash"] = _hash({k: v for k, v in leaked[0].items() if k != "evidence_hash"})
    _rewrite_records(cdir, leaked)
    _resync_state(cdir, leaked)   # legitimate evidence: producer left state consistent
    fresh, _ = CK.CampaignRunner(cdir, backend=mb.DeterministicStubBackend(),
                                 corpus=C.default_corpus(), repetitions=1,
                                 tasks=TASKS, variants=VARIANTS).load_records()
    sigs = {rec["evidence_hash"]: {"signature_b64": signing.sign(rec), "kid": signing.active_kid()}
            for rec in fresh}
    trusted = [{"kid": signing.active_kid(), "public_b64": signing.public_key_b64()}]
    # rebuild plan from fresh records' keys (same plan, just re-derived)
    man = V.build_sanitized_export(cdir, str(tmp_path / "exp"), signatures=sigs, trusted_keys=trusted,
                                   expected_plan=plan)
    redacted = [b for b in man["records"] if b["redactions"]]
    assert redacted, "the injected internal hostname / operator path must be redacted"
    labels = {p for b in redacted for log in b["redactions"] for p in log["patterns"]}
    assert "internal_host" in labels and "operator_home" in labels
    # the redacted record must NOT claim its original signature is preserved
    assert redacted[0]["signature"]["original_signature_preserved"] is False
    # an UNmodified record keeps its original signature, which still verifies against original bytes
    preserved = [b for b in man["records"] if not b["redactions"]]
    assert preserved and preserved[0]["signature"]["original_signature_preserved"] is True
    orig = [x for x in fresh if x["evidence_hash"] == preserved[0]["original_evidence_hash"]][0]
    assert signing.verify(orig, sigs[orig["evidence_hash"]]["signature_b64"],
                          public_key_b64_str=signing.public_key_b64()) is True


def test_high_confidence_secret_in_protected_content_fails(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    poisoned = copy.deepcopy(recs)
    poisoned[0]["outcome"] = "ghp_" + "A" * 36       # a token smuggled into a protected field
    from parallax.research.harness import _hash
    poisoned[0]["evidence_hash"] = _hash({k: v for k, v in poisoned[0].items() if k != "evidence_hash"})
    _rewrite_records(cdir, poisoned)
    fresh, _ = CK.CampaignRunner(cdir, backend=mb.DeterministicStubBackend(),
                                 corpus=C.default_corpus(), repetitions=1,
                                 tasks=TASKS, variants=VARIANTS).load_records()
    with pytest.raises(V.RedactionFailure):
        V.build_sanitized_export(cdir, str(tmp_path / "exp"), expected_plan=plan)


def test_export_carries_failures_and_checksums(tmp_path):
    cdir, r, recs, plan = _build(tmp_path)
    sigs, trusted, _, _ = _sign_all(recs)
    # ledger a failure; it must survive into the export accounting, never be dropped
    dropped = recs[-1]
    _rewrite_records(cdir, recs[:-1])
    _resync_state(cdir, recs[:-1])   # legitimate: the 5 recorded trials form the committed chain
    with open(os.path.join(cdir, "ledger.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "repetition": dropped["repetition"], "condition": dropped["condition"],
            "task_id": dropped["legitimate_task_id"],
            "variant_id": dropped["adversarial_input_id"] or "none",
            "failure_category": CK.CAT_MODEL, "status": "excluded",
            "error": "model_backend_error at parallax.railway.internal"}) + "\n")
    man = V.build_sanitized_export(cdir, str(tmp_path / "exp"), signatures=sigs, trusted_keys=trusted,
                                   expected_plan=plan)
    ledger = json.load(open(os.path.join(man["export_dir"], "failure_ledger.json")))
    assert len(ledger) == 1 and ledger[0]["status"] == "excluded"
    assert "railway.internal" not in json.dumps(ledger)   # infra leak scrubbed from the ledger too
    # every emitted file is checksummed
    cs = json.load(open(os.path.join(man["export_dir"], "CHECKSUMS.sha256.json")))
    for name, digest in cs["files"].items():
        import hashlib
        data = open(os.path.join(man["export_dir"], name), "rb").read()
        assert hashlib.sha256(data).hexdigest() == digest
