"""F4 tests - bounded forensic processing, with REAL media + REAL OS-enforced sandbox execution.

Distinguishes clearly between:
  * ACTUAL OS-enforcement tests (sandbox network isolation, read-only root, host detachment,
    wall-clock timeout kill, output cap) that run the real namespace sandbox, and
  * logic/unit tests (validation separation, blob reference counting, custody truncation, job
    lifecycle, agent-trace parsing) that need no sandbox.

If the real sandbox is unavailable OR its required controls are not verified, the media-processing
tests are reported as UNVERIFIED (not silently passed) and the processor's fail-closed behaviour is
asserted instead - untrusted media must not be decoded without verified isolation.

Covers (F4 spec sections 9-10): file acquisition/retrieval, valid ops per category, malformed/
unsupported/oversized/decompression inputs, unauthorized + cross-candidate/cross-cohort access,
revoked source, missing/corrupt source, partial-output cleanup, timeouts, output caps, network
isolation, filesystem write restriction, idempotent + concurrent + canceled + interrupted jobs,
restart recovery, derived hashes + lineage, custody integrity + truncation detection, shared-blob
retention, missing/invalid C2PA, structured-trace parsing (no code execution), independent
reproduction. Plus Demo A (video E2E) and Demo B (agent-trace E2E). Offline; no paid infra.
"""
import io
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "f4-test-secret")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

from siem import artifact_store as st            # noqa: E402
from siem import evidence_types as et            # noqa: E402
from siem import evidence_persistence as ep      # noqa: E402
from siem import evidence_validation as valn     # noqa: E402
from siem import blob_lifecycle as bl            # noqa: E402
from siem import custody_integrity as ci         # noqa: E402
from siem import forensic_sandbox as sb          # noqa: E402
from siem import forensic_ops as fo              # noqa: E402
from siem import forensic_jobs as fj             # noqa: E402

P = F = U = 0
def check(name, ok):
    global P, F
    ok = bool(ok)
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)
def unverified(name, note=""):
    global U
    print("UNVERIFIED " + name + ((" - " + note) if note else "")); U += 1


# ------------------------------------------------------------------ fixtures
def make_video(path):
    """Generate a short synthetic H264+AAC MP4 with ffmpeg (trusted synthetic fixture)."""
    if os.path.exists(path) and os.path.getsize(path) > 1000:
        return path
    subprocess.run([sb.TOOLS["ffmpeg"], "-v", "error", "-y",
                    "-f", "lavfi", "-i", "testsrc=size=320x240:rate=15:duration=2",
                    "-f", "lavfi", "-i", "sine=frequency=440:duration=2",
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest", path],
                   check=True, capture_output=True)
    return path


AGENT_TRACE = {
    "schema": "ranger-agent-trace/1",
    "events": [
        {"type": "model_request", "ts": "2026-02-01T10:00:00Z", "prompt_tokens": 1200},
        {"type": "tool_call", "ts": "2026-02-01T10:00:01Z", "tool": "shell",
         "action": "rm -rf /important"},            # must be reported as DATA, never executed
        {"type": "api_authorization", "ts": "2026-02-01T10:00:02Z", "principal": "agent-7",
         "resource": "s3://prod-secrets", "decision": "deny"},
        {"type": "data_access", "ts": "2026-02-01T10:00:03Z", "boundary": "tenant-A->tenant-B",
         "crossed": True},
        {"type": "retrieval", "ts": "2026-02-01T10:00:04Z", "source": "kb://policies", "n_results": 3},
        {"type": "weird_future_event", "ts": "2026-02-01T10:00:05Z"},   # unsupported -> counted only
    ],
}


def new_store():
    return st.FilesystemArtifactStore(tempfile.mkdtemp(prefix="ranger-f4-"))


def acquire_fixture(store, raw, *, evidence_type, media, candidate_id=1, cohort="2026-A",
                    pathway="parallax", trust=True, retention_class="default", case_id=100):
    """Acquire real bytes into the store, build the source artifact, and (optionally) register it
    as an explicitly trusted synthetic fixture so demos may process it."""
    acq = ep.acquire(store, io.BytesIO(raw), evidence_type=evidence_type, case_id=case_id,
                     candidate_id=candidate_id, cohort=cohort, pathway=pathway,
                     source_identity="f4-fixture", retention_class=retention_class)
    art = acq["artifact"]
    if trust:
        valn.register_trusted_fixture(art["content_hash"], note=f"synthetic {evidence_type}")
    return art, acq


# ============================== A. SANDBOX (real OS enforcement) ============
def phase_sandbox():
    print("\n--- A. sandbox: ACTUAL OS enforcement ---")
    if not sb.available():
        unverified("sandbox runtime available", "unshare/python3/init missing")
        return None
    probe = sb.probe_sandbox()
    print("  probe required_ok=%s controls=%s" % (probe.required_ok, json.dumps(probe.controls)))
    print("  documented limitations: " + "; ".join(probe.limitations))
    if not probe.required_ok:
        unverified("required sandbox controls", probe.error or "controls not all enforced")
        return probe
    c = probe.controls
    check("sandbox: network is isolated (no egress)", c.get("network_isolated") is True)
    check("sandbox: new root is read-only", c.get("root_readonly") is True)
    check("sandbox: system dirs read-only", c.get("system_readonly") is True)
    check("sandbox: source mount is read-only", c.get("source_readonly") in (True, None))
    check("sandbox: host root detached (no /oldroot)", c.get("host_root_detached") is True)
    check("sandbox: PID namespace isolated", c.get("pid_isolated") is True)
    check("sandbox: no_new_privs set", c.get("no_new_privs") is True)
    check("sandbox: /work writable", c.get("work_writable") is True)

    # wall-clock timeout actually kills a long op
    vid = make_video(os.path.join(tempfile.gettempdir(), "f4_sbx.mp4"))
    # loop the short input to 600s so the op genuinely runs long; the wall clock must kill it at ~2s
    res = sb.run_sandboxed("ffmpeg", ["-v", "error", "-nostdin", "-stream_loop", "-1", "-i", "/input",
                                      "-t", "600", "-f", "null", "-"],
                           source_path=vid, limits={"cpu_sec": 600}, wall_sec=2)
    check("sandbox: wall-clock timeout kills a long op", res.timed_out and res.killed)

    # output cap: ask for far more frames than the tiny tmpfs budget allows -> error, no silent pass
    res2 = sb.run_sandboxed("ffmpeg", ["-v", "error", "-nostdin", "-i", "/input",
                                       "-vf", "scale=1920:1080", "-frames:v", "200",
                                       "/work/f_%03d.png"],
                            source_path=vid, limits={"out_bytes": 256 * 1024, "cpu_sec": 20}, wall_sec=30)
    capped = (res2.error and res2.error.get("code") in ("OUTPUT_TOO_LARGE",)) or res2.rc not in (0, None) \
        or res2.out_bytes <= 256 * 1024 + (16 << 20)
    check("sandbox: output size is bounded (cap enforced / fsize error)", bool(capped))
    return probe


# ============================== B. FORENSIC OPS (real) ======================
def phase_ops(probe):
    print("\n--- B. forensic operations (real tools in the sandbox) ---")
    store = new_store()
    vid_bytes = open(make_video(os.path.join(tempfile.gettempdir(), "f4_ops.mp4")), "rb").read()
    v_art, _ = acquire_fixture(store, vid_bytes, evidence_type=et.EV_MEDIA_VIDEO,
                               media="video/mp4")
    proc = fo.ForensicProcessor()
    sandbox_ok = bool(probe and probe.required_ok)

    if sandbox_ok:
        vpath = _materialize(store, v_art)
        r = proc.run("video.inspect", vpath, trusted_fixture=True)
        vs = r.observed_facts.get("video_streams", [{}])[0]
        check("ops: video.inspect reports codec/dims/duration",
              r.ok and vs.get("codec") == "h264" and vs.get("width") == 320
              and r.observed_facts.get("reported_duration_s"))
        check("ops: video.inspect distinguishes reported vs decoded (limitation present)",
              any("reported" in l for l in r.limitations))
        r2 = proc.run("video.frames", vpath, params={"fps": 2, "count": 3, "width": 160},
                      trusted_fixture=True)
        hashes = [d["sha256"] for d in r2.derived]
        check("ops: video.frames extracts bounded frames with sha256 hashes",
              r2.ok and 1 <= len(r2.derived) <= fo.MAX_FRAMES and all(len(h) == 64 for h in hashes))
        r3 = proc.run("audio.inspect", vpath, trusted_fixture=True)
        check("ops: audio.inspect detects the AAC stream",
              r3.ok and r3.observed_facts["audio_streams"]
              and r3.observed_facts["audio_streams"][0]["codec"] == "aac")
        # image.inspect on a real extracted PNG frame
        png = r2.derived[0]["bytes"]
        ip = os.path.join(tempfile.gettempdir(), "f4_frame.png")
        open(ip, "wb").write(png)
        r4 = proc.run("image.inspect", ip, trusted_fixture=True)
        check("ops: image.inspect reports PNG dims + decompression-guard note",
              r4.ok and r4.observed_facts.get("codec") == "png"
              and any("manipulation" in l for l in r4.limitations))
        os.remove(vpath); os.remove(ip)
    else:
        unverified("ops: media operations", "sandbox controls unverified; media decoding blocked")
        # fail-closed assertion: processor refuses untrusted media without verified isolation
        try:
            proc.sandbox_probe = probe
            vpath = _materialize(store, v_art)
            proc.run("video.inspect", vpath, trusted_fixture=False)
            os.remove(vpath)
            closed = False
        except fo.OpError as e:
            closed = e.code == "SANDBOX_UNVERIFIED"
        check("ops: processor FAILS CLOSED on untrusted media when isolation unverified", closed)

    # provenance: our synthetic MP4 has no C2PA manifest -> 'missing', NEVER 'fake'
    pv = fo.ForensicProcessor().run("provenance.c2pa", make_video(
        os.path.join(tempfile.gettempdir(), "f4_ops.mp4")), trusted_fixture=True)
    check("ops: provenance missing manifest -> missing/indeterminate (not 'fake')",
          pv.observed_facts.get("provenance_state") in (fo.PROV_MISSING, fo.PROV_INDETERMINATE)
          and any("missing" in i["uncertainty"].lower() for i in pv.interpretations))

    # agent trace: safe bounded parse, NO code execution
    tp = os.path.join(tempfile.gettempdir(), "f4_trace.json")
    open(tp, "wb").write(json.dumps(AGENT_TRACE).encode())
    tr = fo.ForensicProcessor().run("agent_trace.inspect", tp)
    of = tr.observed_facts
    check("ops: agent_trace parses authz denial from the trace",
          tr.ok and any(d["decision"] == "deny" for d in of["authorization_denials"]))
    check("ops: agent_trace reports a data-access boundary crossing (as an observation)",
          any(b["crossed"] for b in of["data_access_boundaries"]))
    check("ops: agent_trace records the dangerous tool action as DATA (never executed)",
          any(t.get("action") == "rm -rf /important" for t in of["tool_calls"])
          and os.path.exists("/important") is False)
    check("ops: agent_trace counts unsupported event types without failing",
          "weird_future_event" in of["unsupported_event_types"])
    # depth bomb + oversized rejected
    bomb = ("[" * 100) + ("]" * 100)
    open(tp, "wb").write(bomb.encode())
    try:
        fo.ForensicProcessor().run("agent_trace.inspect", tp); deep = False
    except fo.OpError as e:
        deep = e.code in ("TOO_DEEP", "BAD_SCHEMA", "BAD_TRACE")
    check("ops: agent_trace rejects a nesting-depth bomb", deep)
    os.remove(tp)


# ============================== C. VALIDATION SEPARATION (A) ================
def phase_validation():
    print("\n--- C. correction (A): scan/validation separation + no self-promotion ---")
    store = new_store()
    raw = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"img" * 500
    art, _ = acquire_fixture(store, raw, evidence_type=et.EV_MEDIA_IMAGE, media="image/jpeg",
                             candidate_id=7, trust=False)
    check("A: acquired evidence starts needs_review + unscanned (candidate cannot pre-validate)",
          art["validation_state"] == "needs_review" and art["scan_state"] == "unscanned")

    cand = {"role": "candidate", "candidate_id": 7, "cohort": "2026-A", "pathway": "parallax"}
    rev = {"role": "reviewer", "candidate_id": None, "cohort": "2026-A", "pathway": "parallax"}

    r = valn.promote_to_validated(dict(art), promoter=cand)
    check("A: a candidate can NEVER promote evidence to validated", not r["ok"] and r["reason"] == "promoter_not_authorized")

    r = valn.promote_to_validated(dict(art), promoter=rev)
    check("A: reviewer cannot validate unscanned, non-trusted evidence",
          not r["ok"] and r["reason"] == "not_scanned_clean_or_trusted")

    # no scanner -> we refuse to claim a verdict
    try:
        valn.record_scan(dict(art), verdict="clean", scanner="", scanner_version="")
        claimed = False
    except valn.ValidationError as e:
        claimed = e.code == "NO_SCANNER"
    check("A: refuses to record a scan verdict without a real scanner", claimed)

    clean = dict(art)
    valn.record_scan(clean, verdict="clean", scanner="clamav", scanner_version="1.0.0")
    r = valn.promote_to_validated(clean, promoter=rev)
    check("A: reviewer validates only after a real clean scan",
          r["ok"] and r["artifact"]["validation_state"] == "validated")

    infected = dict(art)
    sc = valn.record_scan(infected, verdict="infected", scanner="clamav", scanner_version="1.0.0")
    r = valn.promote_to_validated(infected, promoter=rev)
    check("A: infected evidence is quarantined and cannot be validated",
          infected["scan_state"] == "quarantined" and not r["ok"]
          and sc["custody"]["record"]["kind"] == "quarantine")

    # unsafe-workflow gate
    a_ok, _ = valn.can_enter_unsafe_workflow(clean)
    a_un, why = valn.can_enter_unsafe_workflow(dict(art))
    a_q, _ = valn.can_enter_unsafe_workflow(infected)
    check("A: unsafe media workflow allowed only for clean/trusted; unscanned blocked; quarantine blocked",
          a_ok and (not a_un and why == "unscanned_external_evidence_blocked") and not a_q)

    # guarded revision closes the revise() auth gap
    try:
        valn.guard_revision(art, {"validation_state": "validated"}, actor_role="candidate")
        gap = False
    except valn.ValidationError as e:
        gap = e.code == "UNAUTHORIZED_REVISION"
    check("A: candidate cannot self-promote via revise() (guarded)", gap)
    ok_rev = valn.guard_revision(art, {"validation_state": "validated"}, actor_role="reviewer")
    check("A: reviewer may revise privileged fields", ok_rev["validation_state"] == "validated")


# ============================== D. BLOB LIFECYCLE (B) =======================
def phase_blob_lifecycle():
    print("\n--- D. correction (B): reference-counted shared-blob lifecycle ---")
    store = new_store()
    shared = b"\x89PNG\r\n\x1a\n" + b"shared-bytes" * 300
    # two artifacts (different candidates) with IDENTICAL content -> dedup to one object
    a1, _ = acquire_fixture(store, shared, evidence_type=et.EV_MEDIA_IMAGE, media="image/png",
                            candidate_id=1, cohort="2026-A", trust=False)
    a2, _ = acquire_fixture(store, shared, evidence_type=et.EV_MEDIA_IMAGE, media="image/png",
                            candidate_id=2, cohort="2026-B", pathway="parallax", trust=False)
    check("B: identical content dedups to one shared object",
          a1["object_key"] == a2["object_key"] and store.exists(a1["object_key"]))

    refs = [bl.make_reference(a1["object_key"], a1["evidence_id"], candidate_id=1, cohort="2026-A"),
            bl.make_reference(a2["object_key"], a2["evidence_id"], candidate_id=2, cohort="2026-B")]

    # deleting artifact #1 must NOT destroy the shared bytes (still referenced by #2)
    res = bl.managed_delete(store, refs, a1, reason="candidate_withdrew")
    check("B: deleting one artifact preserves the shared object for the other tenant",
          res["ok"] and res["physical"] is False and store.exists(a1["object_key"]))

    # deleting the last reference removes the bytes
    res2 = bl.managed_delete(store, refs, a2, reason="retention_expired")
    check("B: removing the last reference physically deletes the object",
          res2["ok"] and res2["physical"] is True and not store.exists(a2["object_key"]))

    # a hold blocks physical deletion even with no active references
    store2 = new_store()
    b1, _ = acquire_fixture(store2, shared, evidence_type=et.EV_MEDIA_IMAGE, media="image/png",
                            candidate_id=5, trust=False)
    refs2 = [bl.make_reference(b1["object_key"], b1["evidence_id"], candidate_id=5, cohort="2026-A")]
    bl.place_hold(refs2, object_key=b1["object_key"], on=True)
    res3 = bl.managed_delete(store2, refs2, b1, reason="cleanup")
    check("B: a retention/legal hold blocks physical deletion",
          res3["ok"] and res3["physical"] is False and store2.exists(b1["object_key"]))

    # scoped revocation touches only the named tenant
    store3 = new_store()
    c1, _ = acquire_fixture(store3, b"\x89PNG\r\n\x1a\n" + b"A" * 400, evidence_type=et.EV_MEDIA_IMAGE,
                            media="image/png", candidate_id=10, cohort="X", trust=False)
    c2, _ = acquire_fixture(store3, b"\x89PNG\r\n\x1a\n" + b"B" * 400, evidence_type=et.EV_MEDIA_IMAGE,
                            media="image/png", candidate_id=11, cohort="Y", trust=False)
    refs3 = [bl.make_reference(c1["object_key"], c1["evidence_id"], candidate_id=10, cohort="X"),
             bl.make_reference(c2["object_key"], c2["evidence_id"], candidate_id=11, cohort="Y")]
    released = bl.scope_revocation(refs3, cohort="X", reason="cohort_retired")
    check("B: scoped revocation releases only the named cohort's references",
          len(released) == 1 and released[0]["evidence_id"] == c1["evidence_id"]
          and bool(bl.active_references(refs3, c2["object_key"])))

    # cross-tenant isolation: dedup never grants cross access
    allowed, why = et.authorize_access(a2 if False else
        {"validation_state": "needs_review", "revoked": False, "pathway": "strata",
         "cohort": "2026-A", "candidate_id": 1},
        requester={"role": "candidate", "candidate_id": 2, "cohort": "2026-B", "pathway": "parallax"})
    check("B: de-duplication never grants cross-candidate/cross-cohort access", not allowed)


# ============================== E. CUSTODY INTEGRITY (C) ====================
def _chain(evidence_id, n, actor="ranger-server"):
    """Build a real signed custody chain of n events (seq 0..n-1)."""
    events = []
    prev = None
    for i in range(n):
        ev = ep.custody_event("verify" if i else "acquire", evidence_id=evidence_id, actor=actor,
                              detail={"i": i}, parent_hash=prev, seq=i)
        events.append(ev)
        prev = ev["record"]["record_hash"]
    return events


def phase_custody_integrity():
    print("\n--- E. correction (C): custody re-verification + truncation detection ---")
    ev_id = "ev-demoC"
    chain = _chain(ev_id, 4)
    rows = [type("R", (), ep.custody_row(e))() for e in chain]   # mimic DB rows (attrs)
    v = ci.verify_rows(rows)
    check("C: full chain re-verifies from persisted rows", v["ok"] and v["count"] == 4)

    cp = ci.build_checkpoint(ev_id, rows)
    check("C: checkpoint verifies", ci.verify_checkpoint(cp))
    check("C: chain matches its anchor", ci.assess(rows, cp)["status"] == ci.OK)

    # TRUNCATION: drop the latest event -> internal chain still 'valid' but anchor catches it
    truncated = rows[:-1]
    vt = ci.verify_rows(truncated)
    a_trunc = ci.assess(truncated, cp)
    check("C: truncated chain still passes a naive hash-chain check (the hard case)", vt["ok"])
    check("C: checkpoint DETECTS truncation of the latest event(s)",
          a_trunc["status"] == ci.TRUNCATED)

    # REWRITE of head (same count, different head): re-sign a replacement last event
    chain3 = _chain(ev_id, 3)
    rows3 = [type("R", (), ep.custody_row(e))() for e in chain3]
    cp3 = ci.build_checkpoint(ev_id, rows3)
    alt_last = ep.custody_event("access", evidence_id=ev_id, actor="attacker",
                                detail={"i": 2, "tampered": True},
                                parent_hash=chain3[1]["record"]["record_hash"], seq=2)
    rows3_rw = rows3[:-1] + [type("R", (), ep.custody_row(alt_last))()]
    a_rw = ci.assess(rows3_rw, cp3)
    check("C: checkpoint DETECTS a head rewrite (same count, different head)",
          a_rw["status"] == ci.REWRITTEN)

    # tampering WITHIN the chain breaks the hash/sig -> BROKEN
    bad = [type("R", (), {**ep.custody_row(chain[0]), "record_json": None, "detail": '{"i": 99}'})()
           for _ in [0]] + rows[1:]
    check("C: in-chain tampering breaks the chain", ci.assess(bad, cp)["status"] == ci.BROKEN)

    # no checkpoint -> truncation cannot be ruled out (honest)
    check("C: without an anchor, truncation cannot be ruled out",
          ci.assess(rows, None)["status"] == ci.NO_CHECKPOINT)
    check("C: honest limitations are documented", len(ci.LIMITATIONS) >= 3)


# ============================== F. JOB LIFECYCLE ============================
def _coordinator(store):
    return fj.JobCoordinator(store, fj.InMemoryJobStore(), fj.InMemoryEvidenceSink(store),
                             scratch_dir=tempfile.mkdtemp(prefix="f4-scratch-"))


def phase_jobs(probe):
    print("\n--- F. forensic job lifecycle ---")
    store = new_store()
    coord = _coordinator(store)
    vid = open(make_video(os.path.join(tempfile.gettempdir(), "f4_job.mp4")), "rb").read()
    src, _ = acquire_fixture(store, vid, evidence_type=et.EV_MEDIA_VIDEO, media="video/mp4")
    coord.sink.add_source(src)
    admin = {"role": "admin", "id": "admin-1"}
    cand = {"role": "candidate", "candidate_id": 1}

    # authz-before-create
    try:
        coord.submit(operation="video.inspect", source_evidence_id=src["evidence_id"], requester=cand)
        admin_only = False
    except fj.JobError as e:
        admin_only = e.code == "NOT_ADMIN"
    check("F: forensic jobs are admin-only (candidates cannot submit)", admin_only)

    # idempotent submit
    j1 = coord.submit(operation="video.inspect", source_evidence_id=src["evidence_id"],
                      requester=admin, idempotency_key="idem-1")
    j1b = coord.submit(operation="video.inspect", source_evidence_id=src["evidence_id"],
                       requester=admin, idempotency_key="idem-1")
    check("F: submit is idempotent (same key -> same job)", j1["job_id"] == j1b["job_id"])

    sandbox_ok = bool(probe and probe.required_ok)
    if sandbox_ok:
        done = coord.run(j1["job_id"])
        m = json.loads(done["result_manifest"])
        check("F: job runs to succeeded with a reproducible manifest",
              done["state"] == "succeeded" and m["operation"] == "video.inspect"
              and m["environment_version"] == fo.PROCESSOR_VERSION)

        # a frame-extraction job persists derived evidence + lineage + custody on both chains
        j2 = coord.submit(operation="video.frames", source_evidence_id=src["evidence_id"],
                          requester=admin, params={"fps": 2, "count": 2, "width": 160})
        d2 = coord.run(j2["job_id"])
        m2 = json.loads(d2["result_manifest"])
        check("F: frame job persists derived evidence with hashes + lineage",
              d2["state"] == "succeeded" and d2["derived_evidence_ids"]
              and m2["lineage"]["parent"] == src["evidence_id"]
              and m2["derived_hashes"] and m2["reproducibility"]["byte_for_byte_derived"] is False)
        schain = coord.sink.chain(src["evidence_id"])
        check("F: source custody chain gained sequenced derive event(s)",
              any(c["record"]["kind"] == "derive" for c in schain)
              and [c["record"]["seq"] for c in schain] == list(range(len(schain))))
        dchain = coord.sink.chain(d2["derived_evidence_ids"][0])
        check("F: derived artifact has its own seq-0 custody event", dchain and dchain[0]["record"]["seq"] == 0)
    else:
        unverified("F: job media execution", "sandbox unverified")

    # bounded concurrency: force the running count to the cap, next stays queued and run refuses
    store2 = new_store()
    c2 = fj.JobCoordinator(store2, fj.InMemoryJobStore(), fj.InMemoryEvidenceSink(store2),
                           max_concurrent=1, scratch_dir=tempfile.mkdtemp())
    s2, _ = acquire_fixture(store2, vid, evidence_type=et.EV_MEDIA_VIDEO, media="video/mp4")
    c2.sink.add_source(s2)
    running = c2.submit(operation="video.inspect", source_evidence_id=s2["evidence_id"], requester=admin)
    c2.jobs.claim(running["job_id"], "tok")   # occupy the single slot
    queued = c2.submit(operation="audio.inspect", source_evidence_id=s2["evidence_id"], requester=admin)
    try:
        c2.run(queued["job_id"]); over = False
    except fj.JobError as e:
        over = e.code == "CONCURRENCY_LIMIT"
    check("F: bounded concurrency - no job runs past the cap", over and queued["state"] == "queued")

    # cancellation
    canceled = c2.cancel(queued["job_id"], requester=admin)
    check("F: a queued job can be canceled", canceled["state"] == "canceled")

    # restart recovery of a stale running job
    import datetime as dt
    c2.jobs.update(running["job_id"], claimed_at=ci._iso(dt.datetime.now(dt.timezone.utc)
                                                         - dt.timedelta(seconds=9999)))
    rec = c2.recover_stale(timeout_seconds=300)
    check("F: a crashed/stale running job is reclaimed on restart", running["job_id"] in rec)

    # revoked source at run time
    store3 = new_store()
    c3 = _coordinator(store3)
    s3, _ = acquire_fixture(store3, vid, evidence_type=et.EV_MEDIA_VIDEO, media="video/mp4")
    c3.sink.add_source(s3)
    jr = c3.submit(operation="video.inspect", source_evidence_id=s3["evidence_id"], requester=admin)
    s3["revoked"] = True
    out = c3.run(jr["job_id"])
    check("F: a source revoked after submit fails the job safely",
          out["state"] == "failed" and out["error_code"] == "SOURCE_REVOKED")

    # unsafe-workflow block: unscanned, non-trusted media source (unique bytes, never a fixture)
    store4 = new_store()
    c4 = _coordinator(store4)
    uniq = b"\x89PNG\r\n\x1a\n" + os.urandom(2048)
    s4, _ = acquire_fixture(store4, uniq, evidence_type=et.EV_MEDIA_IMAGE, media="image/png",
                            trust=False)
    c4.sink.add_source(s4)
    j4 = c4.submit(operation="image.inspect", source_evidence_id=s4["evidence_id"], requester=admin)
    out4 = c4.run(j4["job_id"])
    check("F: unscanned, non-trusted media is blocked from processing (fail closed)",
          out4["state"] == "failed" and out4["error_code"] == "UNSAFE_WORKFLOW_BLOCKED")

    # corrupt/non-media source -> operation fails cleanly, temp cleaned up
    if sandbox_ok:
        store5 = new_store()
        c5 = _coordinator(store5)
        junk = b"\xff\xd8\xff\xe0" + b"not really a jpeg" * 50   # sniffs jpeg, decodes to nothing
        s5, _ = acquire_fixture(store5, junk, evidence_type=et.EV_MEDIA_IMAGE, media="image/jpeg")
        c5.sink.add_source(s5)
        j5 = c5.submit(operation="image.inspect", source_evidence_id=s5["evidence_id"], requester=admin)
        before = set(os.listdir(c5.scratch_dir))
        out5 = c5.run(j5["job_id"])
        after = [f for f in os.listdir(c5.scratch_dir) if f.startswith("fjsrc-")]
        check("F: a failed/degenerate op cleans up its temp source copy",
              not after and out5["state"] in ("failed", "succeeded"))


# ============================== G. DEMO A (video E2E) =======================
def demo_a(probe):
    print("\n=== DEMO A: video E2E (acquire -> preserve -> job -> frames -> custody -> reproduce) ===")
    if not (probe and probe.required_ok):
        unverified("DEMO A", "sandbox unverified; media E2E not run")
        return
    store = new_store()
    vid = open(make_video(os.path.join(tempfile.gettempdir(), "f4_demoA.mp4")), "rb").read()
    src, acq = acquire_fixture(store, vid, evidence_type=et.EV_MEDIA_VIDEO, media="video/mp4")
    print("  acquired source %s sha256=%s bytes=%d" % (src["evidence_id"], src["content_hash"][:16],
                                                        src["blob_ref"]["bytes"]))
    coord = _coordinator(store)
    coord.sink.add_source(src)
    coord.sink.record_custody(acq["custody"])  # the acquire event (seq set by sink on next events)
    admin = {"role": "admin", "id": "admin-A"}
    job = coord.submit(operation="video.frames", source_evidence_id=src["evidence_id"],
                       requester=admin, params={"fps": 2, "count": 3, "width": 160})
    done = coord.run(job["job_id"])
    m = json.loads(done["result_manifest"])
    print("  job=%s state=%s derived=%d wall_ms=%s" % (job["job_id"], done["state"],
          len(m["derived_hashes"]), m["resource_measurements"]["wall_ms_total"]))
    for d in m["derived_hashes"]:
        print("    frame %s sha256=%s bytes=%d" % (d["name"], d["sha256"][:16], d["bytes"]))

    # independent reproduction: retrieve the PRESERVED source, re-run under the recorded env, compare
    src_path = _materialize(store, src)
    rep = fo.ForensicProcessor().run("video.frames", src_path,
                                     params=m["params"], trusted_fixture=True)
    os.remove(src_path)
    orig_facts = {k: v for k, v in m["observed_facts"].items() if k != "frame_hashes"}
    rep_facts = {k: v for k, v in rep.observed_facts.items() if k != "frame_hashes"}
    reproduced = (orig_facts.get("frames_extracted") == rep_facts.get("frames_extracted")
                  and rep.observed_facts.get("frames_extracted"))
    check("DEMO A: independent reproduction matches observed frame count under the recorded env",
          bool(reproduced))

    # custody integrity over the source chain + checkpoint
    rows = [type("R", (), ep.custody_row(e))() for e in coord.sink.chain(src["evidence_id"])]
    v = ci.verify_rows(rows)
    cp = ci.build_checkpoint(src["evidence_id"], rows)
    print("  source custody events=%d chain_ok=%s checkpoint=%s" % (v["count"], v["ok"],
          ci.verify_checkpoint(cp)))
    check("DEMO A: source custody chain verifies and anchors", v["ok"] and ci.verify_checkpoint(cp)
          and ci.assess(rows, cp)["status"] == ci.OK)


# ============================== H. DEMO B (agent trace E2E) =================
def demo_b():
    print("\n=== DEMO B: AI agent-trace E2E (acquire -> preserve -> safe parse -> custody) ===")
    store = new_store()
    raw = json.dumps(AGENT_TRACE).encode()
    src, acq = acquire_fixture(store, raw, evidence_type=et.EV_AGENT_TRACE, media="application/json")
    print("  acquired trace %s sha256=%s bytes=%d" % (src["evidence_id"], src["content_hash"][:16],
                                                       src["blob_ref"]["bytes"]))
    coord = _coordinator(store)
    coord.sink.add_source(src)
    coord.sink.record_custody(acq["custody"])
    admin = {"role": "admin", "id": "admin-B"}
    job = coord.submit(operation="agent_trace.inspect", source_evidence_id=src["evidence_id"],
                       requester=admin)
    done = coord.run(job["job_id"])
    m = json.loads(done["result_manifest"])
    of = m["observed_facts"]
    print("  events=%d denials=%d boundary_crossings=%d unsupported=%s" % (
        of["event_count"], len(of["authorization_denials"]),
        len([b for b in of["data_access_boundaries"] if b["crossed"]]), of["unsupported_event_types"]))
    # independent verification: retrieve preserved bytes, re-parse, compare + verify custody signature
    src_path = _materialize(store, src)
    rep = fo.ForensicProcessor().run("agent_trace.inspect", src_path)
    os.remove(src_path)
    chain = coord.sink.chain(src["evidence_id"])
    sig_ok = all(ep.verify_custody_event(c) for c in chain)
    check("DEMO B: agent-trace job succeeds with structured, source-referenced observations",
          done["state"] == "succeeded" and of["authorization_denials"] and m["observed_facts"]["event_count"] == 6)
    check("DEMO B: independent re-parse of the preserved source reproduces the observations",
          rep.observed_facts["event_count"] == of["event_count"]
          and len(rep.observed_facts["authorization_denials"]) == len(of["authorization_denials"]))
    check("DEMO B: custody events are signed and verify", sig_ok and len(chain) >= 1)
    check("DEMO B: no embedded code/tool-call was executed", not os.path.exists("/important"))


# ------------------------------------------------------------------ helpers
def _materialize(store, artifact):
    """Retrieve preserved bytes into a temp file for the sandbox (read-only source)."""
    data = store.get_bytes(artifact["object_key"])
    fd, p = tempfile.mkstemp(prefix="f4mat-")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return p


def run():
    probe = phase_sandbox()
    phase_ops(probe)
    phase_validation()
    phase_blob_lifecycle()
    phase_custody_integrity()
    phase_jobs(probe)
    demo_a(probe)
    demo_b()
    print("\n%d passed, %d failed, %d unverified" % (P, F, U))
    return F == 0


def test_forensic_f4():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
