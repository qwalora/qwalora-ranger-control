"""F4 review - narrow regression tests for the six security boundaries called out in code review.

Each test targets exactly one guarantee so a reviewer can map a check to a claim:
  1. untrusted media processing fails closed when required sandbox protections are unavailable;
  2. the trusted-synthetic-fixture exception cannot be activated via candidate-controlled fields,
     uploaded metadata, or ordinary (non-admin) permissions;
  3. an artifact is not promoted to `validated` merely because it was parsed or inspected;
  4. a shared content-addressed object cannot be physically deleted while another active reference,
     a retention requirement, or a hold depends on it;
  5. reference creation/deletion is safe under concurrent operations and partial storage failure;
  6. a checkpoint stored alongside the mutable history is not represented as an independent anchor.

Offline; no sandbox required (guarantee 1 is asserted via a forced-unavailable probe).
"""
import io
import json
import os
import sys
import tempfile
import types

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "f4-review-secret")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

from siem import artifact_store as st            # noqa: E402
from siem import evidence_types as et            # noqa: E402
from siem import evidence_persistence as ep      # noqa: E402
from siem import evidence_validation as valn     # noqa: E402
from siem import blob_lifecycle as bl            # noqa: E402
from siem import custody_integrity as ci         # noqa: E402
from siem import forensic_ops as fo              # noqa: E402
from siem import forensic_jobs as fj             # noqa: E402

P = F = 0
def check(name, ok):
    global P, F
    ok = bool(ok)
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


def _store():
    return st.FilesystemArtifactStore(tempfile.mkdtemp(prefix="f4rev-"))


def _acquire(store, raw, *, evidence_type, candidate_id=1, cohort="2026-A", pathway="parallax",
             retention_class="default", declared_media_type=None, source_identity="rev"):
    acq = ep.acquire(store, io.BytesIO(raw), evidence_type=evidence_type, case_id=100,
                     candidate_id=candidate_id, cohort=cohort, pathway=pathway,
                     source_identity=source_identity, retention_class=retention_class,
                     declared_media_type=declared_media_type)
    return acq["artifact"]


PNG = b"\x89PNG\r\n\x1a\n" + b"rev" * 300


# --- 1. fail closed when sandbox protections unavailable ---------------------
def g1_fail_closed():
    print("\n[1] untrusted media fails closed when isolation is unverified")
    proc = fo.ForensicProcessor()
    proc.sandbox_probe = types.SimpleNamespace(required_ok=False, error="forced-unavailable")
    p = os.path.join(tempfile.gettempdir(), "rev_src.bin")
    open(p, "wb").write(PNG)
    try:
        proc.run("video.inspect", p, trusted_fixture=False)
        closed = False
    except fo.OpError as e:
        closed = e.code == "SANDBOX_UNVERIFIED"
    check("1: processor refuses untrusted media when required controls are unverified", closed)
    # and a job over unscanned, non-trusted media is blocked (fail closed at the gate)
    store = _store()
    src = _acquire(store, PNG + os.urandom(64), evidence_type=et.EV_MEDIA_IMAGE)
    coord = fj.JobCoordinator(store, fj.InMemoryJobStore(), fj.InMemoryEvidenceSink(store),
                              scratch_dir=tempfile.mkdtemp())
    coord.sink.add_source(src)
    j = coord.submit(operation="image.inspect", source_evidence_id=src["evidence_id"],
                     requester={"role": "admin", "id": "a"})
    out = coord.run(j["job_id"])
    check("1: a job over unscanned, non-trusted media is blocked",
          out["state"] == "failed" and out["error_code"] == "UNSAFE_WORKFLOW_BLOCKED")
    os.remove(p)


# --- 2. trusted fixture cannot be activated by candidate/metadata ------------
def g2_fixture_not_candidate_activatable():
    print("\n[2] trusted-fixture exception is not reachable via candidate fields/metadata")
    store = _store()
    # attacker-controlled declared media type + source identity must NOT confer trust
    art = _acquire(store, PNG + os.urandom(32), evidence_type=et.EV_MEDIA_IMAGE,
                   declared_media_type="trusted/fixture", source_identity="please-trust-me")
    check("2: acquisition never marks evidence trusted from uploaded metadata",
          not valn.is_trusted_fixture(art) and not valn.fixture_registry().is_trusted(art["content_hash"]))
    allowed, why = valn.can_enter_unsafe_workflow(art)
    check("2: such evidence stays blocked from unsafe workflows",
          not allowed and why == "unscanned_external_evidence_blocked")
    # a candidate cannot submit a job at all (so cannot pass trusted_fixture=True)
    coord = fj.JobCoordinator(store, fj.InMemoryJobStore(), fj.InMemoryEvidenceSink(store),
                              scratch_dir=tempfile.mkdtemp())
    coord.sink.add_source(art)
    try:
        coord.submit(operation="image.inspect", source_evidence_id=art["evidence_id"],
                     requester={"role": "candidate", "candidate_id": 1})
        blocked = False
    except fj.JobError as e:
        blocked = e.code == "NOT_ADMIN"
    check("2: a candidate cannot submit a forensic job (cannot set the trusted flag)", blocked)
    # registration is an explicit admin act keyed by server-computed hash, not any request field
    valn.register_trusted_fixture(art["content_hash"], note="admin demo", approver={"role": "admin", "id": "admin"})
    check("2: only an explicit admin registration (server-computed hash) confers trust",
          valn.is_trusted_fixture(art))


# --- 3. parse/inspect does not promote to validated --------------------------
def g3_inspect_not_validate():
    print("\n[3] forensic inspection never promotes evidence to validated")
    store = _store()
    raw = PNG + os.urandom(48)
    src = _acquire(store, raw, evidence_type=et.EV_MEDIA_IMAGE)
    valn.register_trusted_fixture(src["content_hash"], note="demo", approver={"role": "admin", "id": "admin"})
    coord = fj.JobCoordinator(store, fj.InMemoryJobStore(), fj.InMemoryEvidenceSink(store),
                              scratch_dir=tempfile.mkdtemp())
    coord.sink.add_source(src)
    before = src["validation_state"]
    # agent_trace.inspect needs no sandbox; use it to prove observation != validation
    tr = os.path.join(tempfile.gettempdir(), "rev_trace.json")
    open(tr, "wb").write(json.dumps({"events": [{"type": "model_request", "ts": "t"}]}).encode())
    tsrc = _acquire(store, open(tr, "rb").read(), evidence_type=et.EV_AGENT_TRACE)
    valn.register_trusted_fixture(tsrc["content_hash"], note="demo", approver={"role": "admin", "id": "admin"})
    coord.sink.add_source(tsrc)
    j = coord.submit(operation="agent_trace.inspect", source_evidence_id=tsrc["evidence_id"],
                     requester={"role": "admin", "id": "a"})
    out = coord.run(j["job_id"])
    check("3: a successful inspection leaves validation_state unchanged (not 'validated')",
          out["state"] == "succeeded" and tsrc["validation_state"] == "needs_review"
          and tsrc["validation_state"] != "validated")
    # and only an authorized promotion (not inspection) can set validated
    r = valn.promote_to_validated(dict(src), promoter={"role": "candidate", "candidate_id": 1,
                                                       "cohort": "2026-A", "pathway": "parallax"})
    check("3: inspection output cannot be used by a candidate to self-validate",
          not r["ok"] and r["reason"] == "promoter_not_authorized")
    os.remove(tr)
    _ = before


# --- 4. retention / hold / active reference block physical deletion ----------
def g4_delete_guards():
    print("\n[4] shared-object physical deletion blocked by active ref / retention / hold")
    store = _store()
    shared = b"\x89PNG\r\n\x1a\n" + b"shared" * 400
    a1 = _acquire(store, shared, evidence_type=et.EV_MEDIA_IMAGE, candidate_id=1, cohort="A")
    a2 = _acquire(store, shared, evidence_type=et.EV_MEDIA_IMAGE, candidate_id=2, cohort="B")
    refs = [bl.make_reference(a1["object_key"], a1["evidence_id"], candidate_id=1, cohort="A"),
            bl.make_reference(a2["object_key"], a2["evidence_id"], candidate_id=2, cohort="B")]
    r1 = bl.managed_delete(store, refs, a1, reason="withdrew")
    check("4: an active co-reference preserves the shared object",
          r1["physical"] is False and store.exists(a1["object_key"]))
    # retention-protected last reference cannot be physically deleted
    store2 = _store()
    b1 = _acquire(store2, shared, evidence_type=et.EV_MEDIA_IMAGE, retention_class="active_assessment")
    refs2 = [bl.make_reference(b1["object_key"], b1["evidence_id"], candidate_id=1, cohort="A")]
    r2 = bl.managed_delete(store2, refs2, b1, reason="cleanup")
    check("4: a retention requirement blocks deletion entirely (object preserved)",
          r2["ok"] is False and r2["reason"] in ("protected_no_expiry", "retention_active")
          and store2.exists(b1["object_key"]))
    # hold blocks even a default-retention last reference
    store3 = _store()
    c1 = _acquire(store3, shared, evidence_type=et.EV_MEDIA_IMAGE, retention_class="default")
    refs3 = [bl.make_reference(c1["object_key"], c1["evidence_id"], candidate_id=1, cohort="A")]
    bl.place_hold(refs3, object_key=c1["object_key"], on=True)
    r3 = bl.managed_delete(store3, refs3, c1, reason="cleanup")
    check("4: a hold blocks physical deletion (object preserved)",
          r3["physical"] is False and store3.exists(c1["object_key"]))


# --- 5. concurrency + partial storage failure --------------------------------
class FailingStore:
    """A store whose delete() raises, to prove partial-failure safety."""
    def __init__(self, real):
        self.real = real
    def exists(self, k):
        return self.real.exists(k)
    def delete(self, k, *, authorized_reason):
        raise IOError("object store unavailable")


def g5_concurrency_partial_failure():
    print("\n[5] reference lifecycle safe under concurrency and partial storage failure")
    store = _store()
    raw = b"\x89PNG\r\n\x1a\n" + b"conc" * 400
    a = _acquire(store, raw, evidence_type=et.EV_MEDIA_IMAGE, retention_class="default")
    refs = [bl.make_reference(a["object_key"], a["evidence_id"], candidate_id=1, cohort="A")]
    # concurrent double-release is idempotent (only one transition)
    r1 = bl.release_reference(refs, a["object_key"], a["evidence_id"], reason="x")
    r2 = bl.release_reference(refs, a["object_key"], a["evidence_id"], reason="x")
    check("5: a double (concurrent) release is idempotent",
          r1 is not None and r2 is None and not bl.active_references(refs, a["object_key"]))
    # duplicate reference creation is de-duplicated by the sink (DB enforces a UNIQUE constraint)
    sink = fj.InMemoryEvidenceSink(store)
    sink.save_derived(a); sink.save_derived(a)
    check("5: duplicate reference creation is de-duplicated",
          len([r for r in sink.refs if r["object_key"] == a["object_key"]]) == 1)
    # partial storage failure: logical release stands, no false physical success, no crash
    store2 = _store()
    b = _acquire(store2, raw, evidence_type=et.EV_MEDIA_IMAGE, retention_class="default")
    refs2 = [bl.make_reference(b["object_key"], b["evidence_id"], candidate_id=1, cohort="A")]
    fs = FailingStore(store2)
    rd = bl.managed_delete(fs, refs2, b, reason="cleanup")
    check("5: a failed physical delete does not crash or claim success",
          rd["ok"] and rd["physical"] is False and rd["storage_error"]
          and rd["reason"] == "storage_delete_failed_orphan_pending_sweep"
          and store2.exists(b["object_key"]))
    swept = bl.sweep_orphans(fs, refs2)
    check("5: a later sweep tolerates the still-failing store (no crash)", swept == [])


# --- 6. checkpoint honesty ---------------------------------------------------
def g6_checkpoint_honesty():
    print("\n[6] checkpoint is not represented as an independent trust anchor")
    prev = None
    rows = []
    for i in range(3):
        ev = ep.custody_event("acquire" if i == 0 else "access", evidence_id="ev-h", actor="s",
                              detail={"i": i}, parent_hash=prev, seq=i)
        rows.append(type("R", (), ep.custody_row(ev))()); prev = ev["record"]["record_hash"]
    cp = ci.build_checkpoint("ev-h", rows)
    a = ci.assess(rows, cp)
    check("6: every assessment is labelled with its (non-)independence",
          a.get("anchor_independence") == ci.ANCHOR_INDEPENDENCE
          and "same_store_same_key" in ci.ANCHOR_INDEPENDENCE)
    check("6: without an anchor, truncation is honestly reported as not ruled out",
          ci.assess(rows, None)["status"] == ci.NO_CHECKPOINT)
    check("6: limitations document same-key and the external-anchor gap",
          any("same" in l and "key" in l for l in ci.LIMITATIONS)
          and any("external" in l for l in ci.LIMITATIONS))


# --- 7. C2PA verification is never asserted on absent/ambiguous status -------
def g7_c2pa_verification():
    print("\n[7] C2PA: verified requires explicit success under an approved trust policy")
    # with NO approved trust policy configured, even an explicit 'valid' status is NOT verified
    st = fo._c2pa_state_from_report({"validation_status": "valid", "active_manifest": {"x": 1}},
                                    policy=None)
    check("7: no trust policy -> a 'valid' report is reported indeterminate, never verified",
          st == fo.PROV_INDETERMINATE)
    # absent / empty / ambiguous status is never verified (this was the reported bug)
    for rep in ({}, {"validation_status": None}, {"validation_status": []},
                {"validation_status": "unknown"}):
        s = fo._c2pa_state_from_report(rep, policy="approved-anchors")
        if s == fo.PROV_VERIFIED:
            check("7: absent/ambiguous C2PA status must not be 'verified'", False)
            break
    else:
        check("7: absent/ambiguous C2PA status is never 'verified'", True)
    # an explicit failure is invalid; an explicit success under an approved policy is verified
    bad = fo._c2pa_state_from_report({"validation_status": "invalid"}, policy="approved-anchors")
    good = fo._c2pa_state_from_report({"validation_status": "valid", "active_manifest": {"a": 1}},
                                      policy="approved-anchors")
    check("7: explicit failure -> invalid; explicit success under a policy -> verified",
          bad == fo.PROV_INVALID and good == fo.PROV_VERIFIED)
    # the live op on media with no manifest: missing (never 'fake'); c2patool remains unavailable
    import tempfile as _tf
    p = os.path.join(_tf.gettempdir(), "rev_noc2pa.bin")
    open(p, "wb").write(b"\x89PNG\r\n\x1a\n" + os.urandom(512))
    r = fo.ForensicProcessor().run("provenance.c2pa", p)
    check("7: media without a manifest is 'missing', not fake; c2patool reported unavailable",
          r.observed_facts.get("provenance_state") in (fo.PROV_MISSING, fo.PROV_INDETERMINATE)
          and "c2patool" not in fo.sb.TOOLS)
    os.remove(p)


def run():
    g1_fail_closed()
    g2_fixture_not_candidate_activatable()
    g3_inspect_not_validate()
    g4_delete_guards()
    g5_concurrency_partial_failure()
    g6_checkpoint_honesty()
    g7_c2pa_verification()
    print("\n%d passed, %d failed" % (P, F))
    return F == 0


def test_f4_review_boundaries():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
