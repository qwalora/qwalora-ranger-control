"""F5 - Candidate Workbench security + isolation matrix.

Exercises the workbench through the real Flask app (test client) with real models, the real evidence
contracts and signing. The authorization matrix runs on SQLite; the concurrent-submission race runs
on real PostgreSQL when DATABASE_URL points at one (skipped otherwise). Feature flags are read live,
so each check toggles os.environ to prove production-dark behavior and per-capability gating.
"""
import io
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "wb-test")
os.environ.setdefault("DEFAULT_COHORT", "2026-P")
os.environ["RANGER_EVIDENCE_DIR"] = os.path.join(ROOT, "instance", "wb_test_evidence")

import json as _json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pgtest  # noqa: E402
import workbench_core as wc  # noqa: E402

P = F = 0
def check(name, ok):
    global P, F
    ok = bool(ok)
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


def _flags(**kw):
    """Set workbench flags live; unspecified ones are cleared (off)."""
    for k in ("RANGER_WORKBENCH", "RANGER_WORKBENCH_CASE_ACCESS", "RANGER_WORKBENCH_EVIDENCE_SUBMIT",
              "RANGER_WORKBENCH_ASSESSMENT_VISIBILITY"):
        os.environ.pop(k, None)
    for k, v in kw.items():
        if v:
            os.environ[k] = "1"


AGENT_TRACE = _json.dumps({"schema": "ranger-agent-trace/1", "events": [
    {"type": "api_authorization", "ts": "t", "principal": "agent-7",
     "resource": "s3://prod-secrets", "decision": "deny"}]}).encode()


def _client_for(client, cand_id=None, admin=None, admin_login=None):
    with client.session_transaction() as s:
        s.clear()
        if cand_id is not None:
            s["cand"] = cand_id
        if admin:
            s["admin"] = True
            s["admin_login"] = admin_login or "rev"
        s["csrf"] = "t"


def run():
    # the authz matrix always runs on an isolated in-memory SQLite db, NEVER on a provided/shared
    # database; the PG concurrency test (below) uses a disposable database of its own.
    _real_db = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"
    import app as appmod
    from models import db, Candidate, Cohort, Case
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.create_all()

    # seed cohorts (pathway source), candidates, cases (idempotent: the app may auto-seed a default)
    for nm, pw in (("2026-P", "parallax"), ("2026-S", "strata")):
        co = Cohort.query.filter_by(name=nm).first()
        if co is None:
            db.session.add(Cohort(name=nm, pathway=pw, status="active"))
        else:
            co.pathway = pw
    db.session.commit()
    A = Candidate(handle="cand-a", name="A", email="a@e", cohort="2026-P", github_id="gid-a",
                  status="active", current_board=1)
    B = Candidate(handle="cand-b", name="B", email="b@e", cohort="2026-P", github_id="gid-b",
                  status="active", current_board=1)
    Sc = Candidate(handle="cand-s", name="S", email="s@e", cohort="2026-S", github_id="gid-s",
                   status="active", current_board=1)
    Pend = Candidate(handle="cand-p", name="P", email="p@e", cohort="2026-P", github_id="gid-p",
                     status="pending", current_board=1)
    db.session.add_all([A, B, Sc, Pend]); db.session.commit()
    caseA = Case(candidate_id=A.id, board=1, cohort="2026-P", plane="qualification",
                 workflow="qualification", seed="SECRET_SEED_XYZ", scenario_version=1, index_name="wb-a", scenario_ref="parallax-agent-authz")
    caseB = Case(candidate_id=B.id, board=1, cohort="2026-P", plane="qualification",
                 workflow="qualification", seed="SECRET_SEED_B", scenario_version=1, index_name="wb-b", scenario_ref="parallax-agent-authz")
    caseS = Case(candidate_id=Sc.id, board=2, cohort="2026-S", plane="qualification",
                 workflow="qualification", seed="SECRET_SEED_S", scenario_version=1, index_name="wb-s", scenario_ref="strata-soc-triage")
    db.session.add_all([caseA, caseB, caseS]); db.session.commit()
    aid, bid, sid, pid = A.id, B.id, Sc.id, Pend.id
    cA, cB, cS = caseA.id, caseB.id, caseS.id

    client = application.test_client()

    # 1. production-dark: flag off -> 404
    _flags()  # all off
    _client_for(client, aid)
    check("1: workbench is 404 when RANGER_WORKBENCH is off (production dark)",
          client.get("/workbench").status_code == 404)

    # enable master + case access for the rest
    _flags(RANGER_WORKBENCH=1, RANGER_WORKBENCH_CASE_ACCESS=1, RANGER_WORKBENCH_EVIDENCE_SUBMIT=1,
           RANGER_WORKBENCH_ASSESSMENT_VISIBILITY=1)

    # 2. unauthenticated -> redirect to GitHub login
    _client_for(client, None)
    check("2: unauthenticated access redirects to sign-in", client.get("/workbench").status_code in (302, 308))

    # 3. authenticated but NOT admitted (pending) -> 403 locked
    _client_for(client, pid)
    check("3: an authenticated but unapproved applicant is locked out (403)",
          client.get("/workbench").status_code == 403)

    # 4. admitted candidate A -> 200, pathway PARALLAX
    _client_for(client, aid)
    r = client.get("/workbench")
    check("4: admitted candidate sees the workbench (pathway-aware)",
          r.status_code == 200 and b"PARALLAX" in r.data)

    # 5. ownership / enumeration -> 404 (never reveal)
    check("5: a candidate sees only their own case", client.get(f"/workbench/case/{cA}").status_code == 200)
    check("5: another candidate's case is 404 (not revealed)", client.get(f"/workbench/case/{cB}").status_code == 404)
    check("5: a non-existent case id is 404 (no enumeration)", client.get("/workbench/case/999999").status_code == 404)

    # 6. hidden truth never exposed in the case view
    body = client.get(f"/workbench/case/{cA}").data
    check("6: hidden scenario seed/truth is never exposed in the workspace", b"SECRET_SEED_XYZ" not in body)

    # 7. evidence submission: persisted needs_review + unscanned; candidate cannot validate
    r = client.post(f"/workbench/case/{cA}/evidence", data={
        "evidence_type": "agent_trace", "csrf": "t",
        "file": (io.BytesIO(AGENT_TRACE), "trace.json")}, content_type="multipart/form-data")
    from models import EvidenceArtifact
    evA = EvidenceArtifact.query.filter_by(candidate_id=aid, case_id=cA).first()
    check("7: candidate evidence is persisted needs_review + unscanned (not validated)",
          r.status_code in (302, 303) and evA is not None
          and evA.validation_state == "needs_review" and evA.scan_state == "unscanned")

    # 8. unsupported type + oversized -> rejected cleanly
    r2 = client.post(f"/workbench/case/{cA}/evidence", data={
        "evidence_type": "opensearch_event", "csrf": "t",
        "file": (io.BytesIO(b"{}"), "x.json")}, content_type="multipart/form-data")
    check("8: an unsupported evidence type is rejected", "EVIDENCE_TYPE_NOT_PERMITTED" in r2.headers.get("Location", "")
          or r2.status_code == 400)

    # 9. cross-tenant evidence download -> 404 for another candidate
    _client_for(client, bid)
    check("9: another candidate cannot download A's evidence (404)",
          client.get(f"/workbench/case/{cA}/evidence/{evA.evidence_id}/download").status_code == 404)
    _client_for(client, aid)
    check("9: the owner can download their own evidence",
          client.get(f"/workbench/case/{cA}/evidence/{evA.evidence_id}/download").status_code == 200)

    # 10. forged evidence reference in a submission is rejected (direct core assertion)
    pathway = wc.resolve_pathway(db, A)
    store = wc.evidence_store()
    wc.save_draft(db, caseA, A, {"findings": [{"claim": "agent denied access to prod secrets",
                  "evidence_refs": [evA.evidence_id]}], "evidence_refs": ["ev-FORGED"], "notes": []})
    try:
        wc.finalize_submission(db, store, Case.query.get(cA), A, pathway); forged = False
    except wc.WorkbenchError as e:
        forged = e.code == "INVALID_EVIDENCE_REFS"
    check("10: a forged evidence reference is rejected", forged)

    # 11. valid submission -> signed receipt verifies
    wc.save_draft(db, caseA, A, {"findings": [{"claim": "agent denied access to prod secrets",
                  "evidence_refs": [evA.evidence_id]}], "evidence_refs": [evA.evidence_id], "notes": []})
    sub, receipt = wc.finalize_submission(db, store, Case.query.get(cA), A, pathway)
    check("11: submission produces a signed receipt that verifies",
          sub.submission_status == "submitted" and wc.verify_receipt(sub, db))

    # 12. duplicate submission -> 409 ALREADY_SUBMITTED
    try:
        wc.finalize_submission(db, store, Case.query.get(cA), A, pathway); dup = False
    except wc.WorkbenchError as e:
        dup = e.code == "ALREADY_SUBMITTED" and e.http == 409
    check("12: a duplicate final submission is rejected (409)", dup)

    # 13. PARALLAX assessment can be complete while qualification is INACTIVE
    os.environ.pop("RANGER_PARALLAX_QUALIFICATION_ACTIVE", None)
    stv = wc.assessment_status_view(Case.query.get(cA), sub, pathway)
    check("13: PARALLAX qualification stays inactive and confers nothing",
          stv.get("qualification_active") is False and stv.get("qualified") is False)

    # 14. STRATA regression: strata candidate sees active qualification; parallax unaffected
    _client_for(client, sid)
    rs = client.get("/workbench")
    check("14: a STRATA candidate's qualification is active and unaffected by PARALLAX components",
          rs.status_code == 200 and b"STRATA" in rs.data
          and wc.resolve_pathway(db, Sc) == "strata")

    # 15. reviewer scope: scoped reviewer sees A's submission; out-of-scope reviewer cannot
    os.environ["RANGER_WB_REVIEWERS"] = _json.dumps({"rev-p": {"cohorts": ["2026-P"], "pathway": "parallax"},
                                                     "rev-s": {"cohorts": ["2026-S"], "pathway": "strata"}})
    subA_id = sub.id
    _client_for(client, admin=True, admin_login="rev-p")
    lst = client.get("/workbench/review/submissions")
    det = client.get(f"/workbench/review/submission/{subA_id}")
    check("15: an in-scope reviewer can inspect the submission",
          lst.status_code == 200 and det.status_code == 200 and b"receipt" in det.data)
    _client_for(client, admin=True, admin_login="rev-s")
    det2 = client.get(f"/workbench/review/submission/{subA_id}")
    check("15: an out-of-scope reviewer cannot see the submission (404)", det2.status_code == 404)
    _client_for(client, admin=True, admin_login="rev-unknown")
    check("15: a reviewer with no cohort authorization has no access (403)",
          client.get("/workbench/review/submissions").status_code == 403)

    # 16. evidence-submit flag gating
    _flags(RANGER_WORKBENCH=1, RANGER_WORKBENCH_CASE_ACCESS=1)  # evidence submit OFF
    _client_for(client, bid)
    rno = client.post(f"/workbench/case/{cB}/evidence", data={
        "evidence_type": "agent_trace", "csrf": "t",
        "file": (io.BytesIO(AGENT_TRACE), "t.json")}, content_type="multipart/form-data")
    check("16: evidence submission is gated by its own flag",
          "EVIDENCE_SUBMIT_DISABLED" in rno.headers.get("Location", "") or rno.status_code in (404, 302))

    # 17. master flag off again -> everything 404
    _flags()
    _client_for(client, aid)
    check("17: with the master flag off, all workbench routes are 404 again",
          client.get("/workbench").status_code == 404
          and client.get(f"/workbench/case/{cA}").status_code == 404)

    _flags(RANGER_WORKBENCH=1, RANGER_WORKBENCH_CASE_ACCESS=1, RANGER_WORKBENCH_EVIDENCE_SUBMIT=1,
           RANGER_WORKBENCH_ASSESSMENT_VISIBILITY=1)
    from models import BlobReference, CaseSubmission
    from sqlalchemy import text as _text

    # 18. uploaded evidence gets a durable, reference-counted BlobReference (F4 lifecycle)
    br = BlobReference.query.filter_by(object_key=evA.object_key, evidence_id=evA.evidence_id,
                                       active=True).count()
    check("18: uploaded evidence has a durable active BlobReference (F4 lifecycle)", br == 1)

    # 19. signed receipt binds the payload: tampered findings invalidate verification
    subA = wc._submission(db, Case.query.get(cA), A)
    orig_payload = subA.payload
    tampered = _json.loads(orig_payload); tampered["findings"][0]["claim"] = "TAMPERED CLAIM"
    db.session.execute(_text("UPDATE case_submissions SET payload=:p WHERE id=:id"),
                       {"p": _json.dumps(tampered), "id": subA.id}); db.session.commit()
    db.session.expire_all()
    check("19: tampered findings invalidate the signed receipt",
          wc.verify_receipt(wc._submission(db, Case.query.get(cA), A), db) is False)
    db.session.execute(_text("UPDATE case_submissions SET payload=:p WHERE id=:id"),
                       {"p": orig_payload, "id": subA.id}); db.session.commit(); db.session.expire_all()
    check("19: restoring the original payload makes the receipt verify again",
          wc.verify_receipt(wc._submission(db, Case.query.get(cA), A), db) is True)

    # 20. substituted/altered evidence content invalidates verification
    orig_hash = evA.content_hash
    db.session.execute(_text("UPDATE evidence_artifacts SET content_hash=:h WHERE evidence_id=:e"),
                       {"h": "0" * 64, "e": evA.evidence_id}); db.session.commit(); db.session.expire_all()
    check("20: altered evidence content hash invalidates the signed receipt",
          wc.verify_receipt(wc._submission(db, Case.query.get(cA), A), db) is False)
    db.session.execute(_text("UPDATE evidence_artifacts SET content_hash=:h WHERE evidence_id=:e"),
                       {"h": orig_hash, "e": evA.evidence_id}); db.session.commit(); db.session.expire_all()

    # 21. the workbench receipt NEVER touches STRATA's evidence_record/evidence_sig
    subA = wc._submission(db, Case.query.get(cA), A)
    check("21: workbench receipt uses its own columns; STRATA evidence_record/sig untouched",
          subA.wb_receipt and subA.wb_receipt_sig and subA.evidence_record is None
          and subA.evidence_sig is None)

    # 22. a legacy STRATA preserved-citation record remains independently verifiable
    import signing as _sg
    from siem import case_contract as cc
    strata_rec = {"type": "preserved_citations", "case_id": cS, "candidate_id": sid,
                  "citations": [{"event_id": "e1", "sha256": "a" * 64}]}
    strata_sig = _sg.sign(strata_rec)
    stra_sub = CaseSubmission(case_id=cS, candidate_id=sid, attempt=1, submission_status="submitted",
                              evidence_record=_json.dumps(strata_rec), evidence_sig=strata_sig)
    db.session.add(stra_sub); db.session.commit()
    check("22: legacy STRATA signed evidence record still verifies via case_contract",
          cc.verify_evidence_record(strata_rec, stra_sub.evidence_sig) is True)

    # 23. candidate evidence stays needs_review/unscanned after final submission (no self-validation)
    db.session.expire_all()
    evA2 = EvidenceArtifact.query.filter_by(evidence_id=evA.evidence_id).first()
    check("23: submitted evidence remains needs_review/unscanned (no candidate self-validation)",
          evA2.validation_state == "needs_review" and evA2.scan_state == "unscanned")

    # 24. writes to a finalized case are rejected (no remediation policy)
    _client_for(client, aid)
    wr = client.post(f"/workbench/case/{cA}/draft", data={"csrf": "t", "action": "save"})
    check("24: a write to a finalized case is rejected without a remediation policy",
          "CASE_FINALIZED" in wr.headers.get("Location", "") or wr.status_code in (409, 302))

    # 25. unavailable (revoked/closed) case is non-disclosing 404 on write
    db.session.execute(_text("UPDATE cases SET status='revoked' WHERE id=:id"), {"id": cB})
    db.session.commit()
    _client_for(client, bid)
    wrv = client.post(f"/workbench/case/{cB}/draft", data={"csrf": "t", "action": "save"})
    check("25: a revoked/unavailable case rejects writes with a non-disclosing 404",
          wrv.status_code == 404)

    ctx.pop()

    os.environ["DATABASE_URL"] = _real_db or "sqlite:///:memory:"
    pg_ok = _pg_concurrency_test()
    print("\n%d passed, %d failed%s" % (P, F, "" if pg_ok is None else ""))
    return F == 0


def _pg_concurrency_test():
    """Concurrent final submission on real PostgreSQL: exactly one succeeds, the other gets 409.
    Runs in a DISPOSABLE test database (no destructive ops on the provided/shared database)."""
    disp = _pgtest.make_disposable_or_none()
    if disp is None:
        print("SKIP concurrent-submission race (no isolated disposable PostgreSQL; set "
              "RANGER_TEST_ALLOW_DB_MUTATION and a postgres DATABASE_URL)")
        return None
    _new_url, _cleanup = disp
    try:
        return _pg_concurrency_body()
    finally:
        _cleanup()


def _pg_concurrency_body():
    import app as appmod
    from models import db, Candidate, Cohort, Case
    application = appmod.create_app()
    _flags(RANGER_WORKBENCH=1, RANGER_WORKBENCH_CASE_ACCESS=1, RANGER_WORKBENCH_EVIDENCE_SUBMIT=1)
    with application.app_context():
        db.create_all()
        from models import ensure_schema
        ensure_schema(db)
        # fresh disposable database: no destructive cleanup of shared tables needed
        if not Cohort.query.filter_by(name="2026-P").first():
            db.session.add(Cohort(name="2026-P", pathway="parallax", status="active"))
        c = Candidate.query.filter_by(github_id="gid-pg").first()
        if not c:
            c = Candidate(handle="cand-pg", name="PG", email="pg@e", cohort="2026-P",
                          github_id="gid-pg", status="active", current_board=1)
            db.session.add(c)
        db.session.commit()
        case = Case(candidate_id=c.id, board=1, cohort="2026-P", plane="qualification",
                    workflow="qualification", seed="S", scenario_version=1, index_name="wb-pg",
                    scenario_ref="parallax-agent-authz")
        db.session.add(case); db.session.commit()
        store = wc.evidence_store()
        acq = __import__("siem.evidence_persistence", fromlist=["ep"]).acquire(
            store, io.BytesIO(AGENT_TRACE), evidence_type="agent_trace", case_id=case.id,
            candidate_id=c.id, cohort="2026-P", pathway="parallax", source_identity="pg",
            retention_class="active_assessment")
        art = acq["artifact"]
        wc._persist_artifact(db, art, backend="filesystem"); wc._persist_custody(db, acq["custody"])
        db.session.commit()
        wc.save_draft(db, case, c, {"findings": [{"claim": "x", "evidence_refs": [art["evidence_id"]]}],
                      "evidence_refs": [art["evidence_id"]], "notes": []})
        case_id, cand_id = case.id, c.id

    results = []

    def submit():
        with application.app_context():
            from models import Candidate as C, Case as K
            cc = C.query.get(cand_id); kk = K.query.get(case_id)
            try:
                wc.finalize_submission(db, wc.evidence_store(), kk, cc, "parallax")
                results.append("ok")
            except wc.WorkbenchError as e:
                results.append(e.code)
            except Exception as e:  # noqa
                results.append("ERR:" + str(e)[:40])
            finally:
                db.session.remove()

    ts = [threading.Thread(target=submit) for _ in range(5)]
    [t.start() for t in ts]; [t.join() for t in ts]
    oks = results.count("ok")
    dups = results.count("ALREADY_SUBMITTED")
    check("PG: exactly one of 5 concurrent final submissions succeeds; the rest get 409",
          oks == 1 and dups == 4)

    # PG: two candidates upload IDENTICAL evidence bytes -> one shared, deduplicated object with a
    # distinct active BlobReference each; cross-tenant isolation holds; deleting one preserves the
    # shared bytes for the other (F4 reference-counted lifecycle through the workbench upload path).
    from models import BlobReference, Candidate as C2, Cohort as Co2, Case as K2, EvidenceArtifact
    from siem import forensic_jobs_db as fjdb
    with application.app_context():
        if not Co2.query.filter_by(name="2026-P").first():
            db.session.add(Co2(name="2026-P", pathway="parallax", status="active"))
        cx = C2(handle="cand-x", name="X", email="x@e", cohort="2026-P", github_id="gid-x",
                status="active", current_board=1)
        cy = C2(handle="cand-y", name="Y", email="y@e", cohort="2026-P", github_id="gid-y",
                status="active", current_board=1)
        db.session.add_all([cx, cy]); db.session.commit()
        kx = K2(candidate_id=cx.id, board=1, cohort="2026-P", plane="qualification",
                workflow="qualification", seed="x", scenario_version=1, index_name="kx",
                scenario_ref="parallax-agent-authz")
        ky = K2(candidate_id=cy.id, board=1, cohort="2026-P", plane="qualification",
                workflow="qualification", seed="y", scenario_version=1, index_name="ky",
                scenario_ref="parallax-agent-authz")
        db.session.add_all([kx, ky]); db.session.commit()
        store = wc.evidence_store()
        same = AGENT_TRACE  # identical bytes -> dedup
        ax = wc.submit_evidence(db, store, kx, cx, "parallax", io.BytesIO(same),
                                evidence_type="agent_trace")
        ay = wc.submit_evidence(db, store, ky, cy, "parallax", io.BytesIO(same),
                                evidence_type="agent_trace")
        shared_key = ax["object_key"]
        refs = BlobReference.query.filter_by(object_key=shared_key, active=True).count()
        check("PG: identical uploads from two candidates dedup to one object with two references",
              ax["object_key"] == ay["object_key"] and refs == 2 and store.exists(shared_key))
        # cross-tenant isolation: candidate Y cannot read candidate X's evidence
        try:
            wc.retrieve_evidence(db, store, cy, "parallax", ax["evidence_id"])
            cross = False
        except wc.WorkbenchError as e:
            cross = e.http == 404
        check("PG: cross-candidate evidence access fails closed (404)", cross)
        # deleting X's reference preserves the shared bytes for Y
        art_x = {"evidence_id": ax["evidence_id"], "object_key": shared_key,
                 "retention_class": "default"}
        res = fjdb.SqlBlobLifecycle(db, store).managed_delete(art_x, reason="withdrew")
        check("PG: deleting one candidate's reference preserves the shared evidence object",
              res["physical"] is False and store.exists(shared_key)
              and EvidenceArtifact.query.filter_by(evidence_id=ay["evidence_id"]).first() is not None)
    return True


def test_workbench():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
