"""STRATA S5 acceptance - end-to-end Board 2 enterprise SOC qualification, in isolation.

Exercises the ONE authoritative path through the real modules: strata_board2 (assignment + binding +
OpenSearch provisioning), the real case_contract evidence/signing, siem.enterprise_grader scoring,
and strata_qualification (the governed, release-gated decision + objective award). OpenSearch is
represented by siem.fake_cluster.FakeCluster - a faithful in-process DOUBLE of siem.live.LiveCluster
that enforces the same role/DLS model; results here demonstrate the Ranger-side logic and the
authorization contract and are NOT a substitute for live OpenSearch validation (a separate
requirement, reported in the S5 delivery).

Profile A is used for speed in these tests (an explicit approved test profile); a real qualification
uses Profile B. The 95% objective standard (program.PASS_BAR) is never changed.
"""
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("SECRET_KEY", "s5")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["RANGER_B2_PROFILE"] = "A"      # fast, approved TEST profile; real qual = Profile B
# this process is an explicitly-declared, permitted ISOLATED TEST env for Board 2 qualification
os.environ["RANGER_ALLOW_TEST_QUAL"] = "1"
os.environ["RANGER_ENV"] = "test"

import json as _json  # noqa: E402

import pytest  # noqa: E402

import strata_catalog as cat  # noqa: E402
import strata_assignment as asn  # noqa: E402
import strata_board2 as b2  # noqa: E402
import strata_qualification as sq  # noqa: E402
from siem import case_contract as cc  # noqa: E402
from siem.fake_cluster import FakeCluster  # noqa: E402

COHORTS = {
    # two cohorts, materially different Board 2 investigations (different approved variants)
    "2026-A": ["b2-identity-takeover", "b2-insider-exfil"],
    "2026-B": ["b2-stealth-lateral", "b2-insider-exfil"],
}


def _app():
    import app as appmod
    from models import db, AdminUser, Cohort
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.create_all()
    for nm in COHORTS:
        if not Cohort.query.filter_by(name=nm).first():
            db.session.add(Cohort(name=nm, pathway="strata", status="active"))
    admin = AdminUser(github_id="gid-admin", login="alice", role="reviewer")
    db.session.add(admin); db.session.commit()
    for e in cat.register_all(db, boards=(2,)):   # S5 exercises Board 2 only; keep setup fast
        cat.approve(db, e, admin)
    db.session.commit()
    for cohort, variants in COHORTS.items():
        asn.set_cohort_portfolio(db, cohort, 2, variants, admin=admin)
    return application, db, ctx, admin


def _cand(db, handle, cohort):
    from models import Candidate
    c = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort=cohort,
                  github_id=f"g-{handle}", status="active", current_board=2, token=f"tok-{handle}")
    db.session.add(c); db.session.commit()
    return c


def _reader(cluster):
    from case_routes import LiveReader
    return LiveReader(cluster)


def _submit_signed(db, c, assignment, cluster, payload, *, status="submitted", attempt=1):
    """Create a signed CaseSubmission bound to the assignment, as the real /case submit path does."""
    from models import Case, CaseSubmission
    reader = _reader(cluster)
    # create/pin the case FIRST so the signed record can bind its id (mirrors the real submit path)
    case = Case.query.filter_by(candidate_id=c.id, board=2, plane="qualification").first()
    if case is None:
        case = Case(candidate_id=c.id, board=2, cohort=assignment.cohort, plane="qualification",
                    workflow="qualification", index_name=assignment.index_name, seed=assignment.seed,
                    scenario_version=assignment.spec_version, content_hash=assignment.content_hash,
                    variant_id=assignment.variant_id, binding_id=assignment.binding_id,
                    rubric_version=cc.RUBRIC_VERSION, attempt=attempt, status=status)
        db.session.add(case)
    else:
        case.status = status
    db.session.commit()
    meta = {"candidate": assignment.slug, "board": 2, "cohort": assignment.cohort,
            "scenario_ref": b2.schema.case_ref(assignment.slug, 2, assignment.seed),
            "case_id": case.id, "attempt": attempt, "scenario_version": assignment.spec_version,
            "rubric_version": cc.RUBRIC_VERSION, "submitted_at": "2026-03-02T00:00:00Z"}
    record, sig = cc.preserve_and_sign(payload, reader, assignment.index_name, meta)
    sub = CaseSubmission(case_id=case.id, candidate_id=c.id, attempt=attempt,
                         submission_status=status, rubric_version=cc.RUBRIC_VERSION,
                         payload=_json.dumps(payload),
                         evidence_record=_json.dumps(record), evidence_sig=sig)
    db.session.add(sub); db.session.commit()
    return case, sub


def _correct_submission(assignment, cluster):
    events, truth = b2.generate_world(assignment)
    return b2.board2_reference_submission(events, truth, assignment.index_name)


def _test_activation():
    return sq.build_activation(cc.RUBRIC_VERSION, approved_by="alice", environment="test")


# =============================================================================================
# 7. The full legitimate Board 2 progression (positive), in isolation.
# =============================================================================================
def test_board2_full_legitimate_progression():
    application, db, ctx, admin = _app()
    try:
        from models import BoardResult, Candidate, QualificationDecision
        # 1. eligible candidate on Board 2
        c = _cand(db, "e2e", "2026-A")
        # 2. Ranger binds an approved cohort-specific scenario (authoritative assignment)
        a = b2.resolve_assignment(db, c)
        assert a.variant_id in COHORTS["2026-A"] and a.index_name.endswith("-b2-q1")
        # 3. the correct dataset is prepared + accessible (real provisioning into the qual index)
        cluster = FakeCluster()
        prov = b2.provision(cluster, a)
        assert prov["action"] == "provisioned" and prov["event_count"] > 100
        # 4/5. the candidate investigates + submits a technically complete investigation (signed)
        payload = _correct_submission(a, cluster)
        case, sub = _submit_signed(db, c, a, cluster, payload)
        # 6/7. server-side evidence verification + preservation already happened in submit (signed)
        assert sub.evidence_sig and cc.verify_evidence_record(_json.loads(sub.evidence_record),
                                                              sub.evidence_sig)
        # 8/9. the AUTHORIZED test evaluator produces a valid decision; 95% condition satisfied
        decision = sq.decide(db, case, sub, a, _reader(cluster), principal=admin,
                             mode="authorized", activation=_test_activation())
        assert decision.passed and decision.score >= 95.0 and decision.awarded_objective
        assert sq.verify_decision(decision)
        br = BoardResult.query.filter_by(candidate_id=c.id, board=2).first()
        assert br.objective_passed and br.objective_score >= 95.0
        # 10. human review satisfied separately
        br.report_status = "approved"; db.session.add(br); db.session.commit()
        # 11/12. Board 2 clears and the candidate promotes to Board 3 exactly once - via the real
        # flag-gated reviewer route (reader injected over the cluster double; activation signed).
        import case_routes as _cr
        _cr.set_reader_factory(lambda case: _reader(cluster))
        client = application.test_client()
        with client.session_transaction() as s:
            s["admin"] = True; s["admin_gid"] = admin.github_id; s["csrf"] = "t"
        os.environ["RANGER_B2_QUAL_UI"] = "1"
        import base64
        os.environ["RANGER_B2_QUAL_ACTIVATION"] = base64.b64encode(
            _json.dumps(_test_activation()).encode()).decode()
        hdr = {"X-CSRF-Token": "t"}
        r = client.post(f"/admin/cases/submission/{sub.id}/qualify", headers=hdr)
        body = r.get_json()
        assert r.status_code == 200, body
        assert body["awarded_objective"] is True
        assert body["promoted"] is True and body["current_board"] == 3
        c2 = Candidate.query.get(c.id)
        assert c2.current_board == 3
        # exactly once: a repeat qualify does not re-award or double-promote
        client.post(f"/admin/cases/submission/{sub.id}/qualify", headers=hdr)
        assert Candidate.query.get(c.id).current_board == 3
        assert QualificationDecision.query.filter_by(case_id=case.id, mode="authorized").count() == 1
    finally:
        os.environ.pop("RANGER_B2_QUAL_UI", None)
        os.environ.pop("RANGER_B2_QUAL_ACTIVATION", None)
        ctx.pop()


# =============================================================================================
# 7 (reverse). The negative gates.
# =============================================================================================
def test_objective_pass_without_report_does_not_promote():
    application, db, ctx, admin = _app()
    try:
        from models import Candidate
        c = _cand(db, "noreport", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        case, sub = _submit_signed(db, c, a, cluster, _correct_submission(a, cluster))
        sq.decide(db, case, sub, a, _reader(cluster), principal=admin,
                  mode="authorized", activation=_test_activation())
        # objective passed but NO report approval -> not promoted
        assert Candidate.query.get(c.id).current_board == 2
    finally:
        ctx.pop()


def test_report_without_objective_does_not_promote():
    application, db, ctx, admin = _app()
    try:
        from models import BoardResult, Candidate
        c = _cand(db, "noobj", "2026-A")
        br = BoardResult(candidate_id=c.id, board=2, report_status="approved")
        db.session.add(br); db.session.commit()
        assert not br.objective_passed
        assert Candidate.query.get(c.id).current_board == 2
    finally:
        ctx.pop()


def test_score_below_95_does_not_award():
    application, db, ctx, admin = _app()
    try:
        from models import BoardResult
        c = _cand(db, "weak", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        _events, truth = b2.generate_world(a)
        # a thin submission: confirm one incident with a single citation, no timeline/judgment/etc.
        t0 = truth["incidents"][0]
        weak = {"baseline_summary": "b", "overall_conclusion": "c",
                "incidents": [{"label": t0["family"], "disposition": "confirmed_incident",
                               "severity": "high", "confidence": 60,
                               "attack_techniques": t0["techniques"][:1],
                               "primary_identity": t0["primary_identity"], "affected_assets": [],
                               "cited_evidence": [{"event_uid": t0["event_uids"][0],
                                                   "index": a.index_name,
                                                   "query": {"query": {"match_all": {}}},
                                                   "role": "primary"}]}]}
        case, sub = _submit_signed(db, c, a, cluster, weak)
        d = sq.decide(db, case, sub, a, _reader(cluster), principal=admin,
                      mode="authorized", activation=_test_activation())
        assert d.score < 95.0 and not d.passed and not d.awarded_objective
        assert BoardResult.query.filter_by(candidate_id=c.id, board=2).first() is None or \
            not BoardResult.query.filter_by(candidate_id=c.id, board=2).first().objective_passed
    finally:
        ctx.pop()


def test_unsigned_or_modified_evidence_cannot_qualify():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "tamper", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        case, sub = _submit_signed(db, c, a, cluster, _correct_submission(a, cluster))
        # modify the signed record after signing -> signature no longer verifies
        rec = _json.loads(sub.evidence_record); rec["candidate"] = "someone-else"
        sub.evidence_record = _json.dumps(rec); db.session.commit()
        with pytest.raises(sq.QualificationEvidenceError):
            sq.decide(db, case, sub, a, _reader(cluster), principal=admin,
                      mode="authorized", activation=_test_activation())
    finally:
        ctx.pop()


def test_foreign_or_forged_citation_cannot_qualify():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "forge", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        _events, truth = b2.generate_world(a)
        payload = b2.board2_reference_submission(_events, truth, a.index_name)
        # point one incident's citations at a FOREIGN index
        payload["incidents"][0]["cited_evidence"][0]["index"] = "ranger-someone-else-b2-q1"
        case, sub = _submit_signed(db, c, a, cluster, payload)
        d = sq.decide(db, case, sub, a, _reader(cluster), principal=admin,
                      mode="authorized", activation=_test_activation())
        assert not d.passed and sq.CRIT_FOREIGN_CITATION in _json.loads(d.critical_failures)
        assert not d.awarded_objective
    finally:
        ctx.pop()


def test_wrong_scenario_version_cannot_qualify():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "ver", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        case, sub = _submit_signed(db, c, a, cluster, _correct_submission(a, cluster))
        # the case claims a different pinned content hash than the assignment -> refused
        case.content_hash = "deadbeef" * 8; db.session.commit()
        with pytest.raises(sq.QualificationEvidenceError):
            sq.decide(db, case, sub, a, _reader(cluster), principal=admin,
                      mode="authorized", activation=_test_activation())
    finally:
        ctx.pop()


def test_shadow_and_generic_paths_cannot_promote():
    application, db, ctx, admin = _app()
    try:
        from models import BoardResult
        c = _cand(db, "shadow", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        case, sub = _submit_signed(db, c, a, cluster, _correct_submission(a, cluster))
        # proposed mode computes + signs a decision but NEVER awards objective credit
        d = sq.decide(db, case, sub, a, _reader(cluster), principal=admin, mode="proposed")
        assert d.passed and not d.awarded_objective
        assert BoardResult.query.filter_by(candidate_id=c.id, board=2).first() is None
        # generic candidate routes still refuse Board 2 (S3/S4 chokepoint), flag on or off
        os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
        client = application.test_client()
        g = client.post("/grade/submit", json={"handle": c.handle, "submission": {"incidents": []}},
                        headers={"X-Candidate-Token": c.token})
        assert g.status_code == 409
    finally:
        os.environ.pop("RANGER_STRATA_PORTFOLIOS", None)
        ctx.pop()


def test_authorized_gate_closed_without_activation():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "gate", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        case, sub = _submit_signed(db, c, a, cluster, _correct_submission(a, cluster))
        # no activation -> authorized mode is refused (gate closed by default)
        with pytest.raises(sq.QualificationNotActivated):
            sq.decide(db, case, sub, a, _reader(cluster), principal=admin, mode="authorized")
        # a test activation is refused in every environment except an explicitly permitted test one
        for bad_env in (None, "", "production", "staging", "development", "prod", "qa", "unknown"):
            if bad_env is None:
                os.environ.pop("RANGER_ENV", None)
            else:
                os.environ["RANGER_ENV"] = bad_env
            with pytest.raises(sq.QualificationNotActivated):
                sq.decide(db, case, sub, a, _reader(cluster), principal=admin,
                          mode="authorized", activation=_test_activation())
        # and accepted in a permitted test env
        for good_env in ("test", "ci"):
            os.environ["RANGER_ENV"] = good_env
            d = sq.decide(db, case, sub, a, _reader(cluster), principal=admin,
                          mode="authorized", activation=_test_activation())
            assert d.mode == "authorized"
            from models import QualificationDecision
            QualificationDecision.query.filter_by(case_id=case.id).delete(); db.session.commit()
    finally:
        os.environ["RANGER_ENV"] = "test"   # restore the module default for later tests
        ctx.pop()


def test_repeated_evaluation_is_idempotent():
    application, db, ctx, admin = _app()
    try:
        from models import QualificationDecision
        c = _cand(db, "idem", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        case, sub = _submit_signed(db, c, a, cluster, _correct_submission(a, cluster))
        act = _test_activation()
        d1 = sq.decide(db, case, sub, a, _reader(cluster), principal=admin, mode="authorized", activation=act)
        d2 = sq.decide(db, case, sub, a, _reader(cluster), principal=admin, mode="authorized", activation=act)
        assert d1.id == d2.id
        assert QualificationDecision.query.filter_by(case_id=case.id, mode="authorized").count() == 1
    finally:
        ctx.pop()


def test_gapf2_cached_decision_rejected_when_source_altered_after_award():
    """A legitimate authorized decision is awarded; the stored submission is then altered; the report
    is approved; a reviewer retries qualification. The retry must fail closed on the now-invalid
    source instead of riding the cached decision into promotion."""
    application, db, ctx, admin = _app()
    try:
        from models import BoardResult
        c = _cand(db, "cached", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        case, sub = _submit_signed(db, c, a, cluster, _correct_submission(a, cluster))
        act = _test_activation()
        d1 = sq.decide(db, case, sub, a, _reader(cluster), principal=admin, mode="authorized",
                       activation=act)
        assert d1.passed and d1.awarded_objective
        # tamper the stored payload AFTER the award (leave the signed evidence record untouched)
        tampered = _json.loads(sub.payload)
        tampered["overall_conclusion"] = "there was no incident"
        sub.payload = _json.dumps(tampered); db.session.commit()
        # approve the report (subjective gate) and retry qualification
        br = BoardResult.query.filter_by(candidate_id=c.id, board=2).first()
        br.report_status = "approved"; db.session.add(br); db.session.commit()
        with pytest.raises(sq.QualificationEvidenceError):
            sq.decide(db, case, sub, a, _reader(cluster), principal=admin, mode="authorized",
                      activation=act)
        # unchanged source still returns the cached decision idempotently
        sub.payload = _json.dumps(_correct_submission(a, cluster)); db.session.commit()
        d2 = sq.decide(db, case, sub, a, _reader(cluster), principal=admin, mode="authorized",
                       activation=act)
        assert d2.id == d1.id
    finally:
        ctx.pop()


def test_gapf3_completed_index_rejects_same_count_mutation():
    """A same-count substitution/mutation of a completed index is rejected by the dataset manifest,
    not silently reused."""
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "manifest", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster()
        b2.provision(cluster, a)
        assert b2.provision(cluster, a)["action"] == "reused"   # intact -> reuse ok
        # mutate ONE event's content in place (same document count)
        idx = a.index_name
        some_id = next(iter(cluster._idx[idx]))
        cluster._idx[idx][some_id] = {**cluster._idx[idx][some_id], "message": "mutated by attacker"}
        with pytest.raises(b2.Board2ProvisionError):
            b2.provision(cluster, a)
    finally:
        ctx.pop()


def test_gapf4_case_binding_identity_mismatch_fails_closed():
    """At grading time a Case whose pinned identity disagrees with the assignment fails closed."""
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "ident", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        case, sub = _submit_signed(db, c, a, cluster, _correct_submission(a, cluster))
        # corrupt the case's pinned seed so it no longer matches the assignment
        case.seed = (case.seed or "") + "-tamper"; db.session.commit()
        with pytest.raises(sq.QualificationEvidenceError):
            sq.decide(db, case, sub, a, _reader(cluster), principal=admin, mode="authorized",
                      activation=_test_activation())
    finally:
        ctx.pop()


# =============================================================================================
# 8. Two cohorts, materially different Board 2 investigations (real generated telemetry).
# =============================================================================================
def test_two_cohorts_materially_different_and_isolated():
    application, db, ctx, admin = _app()
    try:
        cluster = FakeCluster()
        # one candidate per cohort, each bound to a single distinguishing variant
        ca = _cand(db, "coha", "2026-A")
        cb = _cand(db, "cohb", "2026-B")
        # restrict each to its DISTINGUISHING variant so the worlds differ materially
        asn.set_cohort_portfolio(db, "2026-A", 2, ["b2-identity-takeover"], admin=admin)
        asn.set_cohort_portfolio(db, "2026-B", 2, ["b2-stealth-lateral"], admin=admin)
        aa = b2.resolve_assignment(db, ca)
        ab = b2.resolve_assignment(db, cb)
        assert aa.variant_id != ab.variant_id
        b2.provision(cluster, aa); b2.provision(cluster, ab)
        # the generated telemetry differs by incident FAMILY (truth), not just labels
        _ea, ta = b2.generate_world(aa)
        _eb, tb = b2.generate_world(ab)
        fam_a = {i["family"] for i in ta["incidents"]}
        fam_b = {i["family"] for i in tb["incidents"]}
        assert fam_a != fam_b, f"cohort families must differ: {fam_a} vs {fam_b}"
        # cross-candidate isolation: candidate A's role cannot read candidate B's index
        cluster.put_role("cand_" + aa.slug, [b2.authz.candidate_index_pattern(aa.cohort, aa.slug)],
                         dls={"ranger.candidate_id": aa.slug})
        cluster.put_rolesmapping("cand_" + aa.slug, users=["cand_" + aa.slug])
        from siem.live import AuthzError
        with pytest.raises(AuthzError):
            cluster.search(ab.index_name, auth=("cand_" + aa.slug, "x"))
        # cross-scenario answer reuse does not pass: grade B's world with A's correct answers
        payload_a = b2.board2_reference_submission(_ea, ta, ab.index_name)  # A answers, B index
        case_b, sub_b = _submit_signed(db, cb, ab, cluster, payload_a)
        d = sq.decide(db, case_b, sub_b, ab, _reader(cluster), principal=admin,
                      mode="authorized", activation=_test_activation())
        assert not d.passed, "cohort A's answers must not auto-pass cohort B's scenario"
    finally:
        ctx.pop()


# =============================================================================================
# 3/10. Provisioning integrity + safe failure.
# =============================================================================================
def test_provision_idempotent_and_refuses_foreign_and_unknown_index():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "prov", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster()
        r1 = b2.provision(cluster, a); r2 = b2.provision(cluster, a)
        assert r1["action"] == "provisioned" and r2["action"] == "reused"
        # FOREIGN: a different assignment's fingerprint claims the same index name -> refuse
        import dataclasses
        foreign = dataclasses.replace(a, dataset_fingerprint="f" * 64)
        with pytest.raises(b2.Board2ProvisionError):
            b2.provision(cluster, foreign)
        # UNKNOWN: an index that exists with NO system-meta claim is never assumed ours -> refuse,
        # and provisioning must not have written to it.
        c2 = _cand(db, "prov2", "2026-A")
        a2 = b2.resolve_assignment(db, c2)
        cluster.create_index(a2.index_name)
        cluster.bulk_index(a2.index_name, [{"_id": "x", "_source": {"junk": True}}])
        with pytest.raises(b2.Board2ProvisionError):
            b2.provision(cluster, a2)
        assert cluster.count(a2.index_name) == 1   # untouched (only the pre-existing junk doc)
    finally:
        ctx.pop()


def test_provision_converges_after_interrupted_ingest():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "retry", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster()
        # a PROPER interruption: the incomplete system-meta claim is written + a partial batch, as
        # provision() itself would leave on a crash (a verified same-assignment incomplete index).
        events, _t = b2.generate_world(a)
        indexed = b2._stamp_plane(events)
        cluster.create_index(b2.SYSTEM_META_INDEX)
        cluster.bulk_index(b2.SYSTEM_META_INDEX, [b2._meta_doc(a, len(indexed), "incomplete")])
        cluster.create_index(a.index_name)
        cluster.bulk_index(a.index_name, indexed[:50])
        m0 = b2.read_index_meta(cluster, a.index_name)
        assert m0["status"] == "incomplete" and m0["fingerprint"] == a.dataset_fingerprint
        # re-provision converges to the full, complete world (idempotent upsert)
        r = b2.provision(cluster, a)
        assert r["action"] == "provisioned" and cluster.count(a.index_name) == len(indexed)
        meta = b2.read_index_meta(cluster, a.index_name)
        assert meta["status"] == "complete" and meta["fingerprint"] == a.dataset_fingerprint
    finally:
        ctx.pop()


def test_provision_rejects_corrupted_completion_record():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "corrupt", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster()
        b2.provision(cluster, a)
        # corrupt the completion inventory: claim more docs than the index actually holds
        cluster.create_index(b2.SYSTEM_META_INDEX)
        bad = b2._meta_doc(a, 999999, "complete")
        cluster.bulk_index(b2.SYSTEM_META_INDEX, [bad])
        with pytest.raises(b2.Board2ProvisionError):
            b2.provision(cluster, a)
    finally:
        ctx.pop()


def test_missing_or_revoked_assignment_fails_closed():
    application, db, ctx, admin = _app()
    try:
        # a cohort with NO Board 2 portfolio -> resolve fails closed
        c = _cand(db, "nopf", "2026-C")
        with pytest.raises(b2.Board2AssignmentError):
            b2.resolve_assignment(db, c)
        # revoke every approved Board 2 variant -> resolve fails closed (never a legacy fallback)
        cr = _cand(db, "revoked", "2026-A")
        for e in cat.eligible(db, 2):
            e.status = "deprecated"; db.session.add(e)
        db.session.commit()
        with pytest.raises(b2.Board2AssignmentError):
            b2.resolve_assignment(db, cr)
    finally:
        ctx.pop()


# =============================================================================================
# 9. Key protection + scenario integrity.
# =============================================================================================
def test_no_seed_in_provisioned_index_or_meta():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "keys", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        blob = _json.dumps(cluster.dump(a.index_name))
        assert a.seed not in blob
        assert "scenario_seed" not in blob and "_malicious" not in blob and '"verdict"' not in blob
    finally:
        ctx.pop()


def test_fingerprint_binds_full_identity_not_just_params():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "fp", "2026-A")
        a = b2.resolve_assignment(db, c)
        from models import ScenarioBinding
        binding = ScenarioBinding.query.get(a.binding_id)
        base = b2.dataset_fingerprint(binding, a.slug, a.rubric_version)
        assert base == a.dataset_fingerprint
        import copy

        def fp_with(**over):
            b = copy.copy(binding)
            for k, v in over.items():
                setattr(b, k, v)
            return b2.dataset_fingerprint(b, a.slug, a.rubric_version)
        # changing any identity component changes the fingerprint (sentinels differ from the originals)
        assert fp_with(seed=a.seed + "-X") != base
        assert fp_with(attempt=a.attempt + 5) != base
        assert fp_with(variant_id=a.variant_id + "-X") != base
        assert fp_with(content_hash=(a.content_hash or "") + "-X") != base
        assert fp_with(spec_version=a.spec_version + 7) != base
        assert b2.dataset_fingerprint(binding, a.slug + "-X", a.rubric_version) != base
        assert b2.dataset_fingerprint(binding, a.slug, a.rubric_version + 9) != base
    finally:
        ctx.pop()


# =============================================================================================
# Integrity-closure regressions (gaps 1,2,3,5) + full HTTP chain (gap 6).
# =============================================================================================
def test_gap1_pinned_contract_survives_variant_revision():
    """generate_world uses the PINNED contract, so a variant edited after assignment does not change
    an existing case's telemetry or truth; a tampered pinned contract fails closed."""
    application, db, ctx, admin = _app()
    try:
        from siem import board_variants as bv
        from models import ScenarioBinding
        c = _cand(db, "pin1", "2026-A")
        a = b2.resolve_assignment(db, c)
        e0, t0 = b2.generate_world(a)
        ids0 = [e["_id"] for e in e0]; fams0 = [i["family"] for i in t0["incidents"]]
        # revise the LIVE variant's families after assignment
        vid = a.variant_id
        orig = bv.VARIANTS[2][vid]["gen_params"]
        bv.VARIANTS[2][vid]["gen_params"] = {**orig, "families": ["detection-failure",
                                                                  "data-exfiltration"]}
        try:
            e1, t1 = b2.generate_world(a)   # still the pinned world
            assert [e["_id"] for e in e1] == ids0
            assert [i["family"] for i in t1["incidents"]] == fams0
        finally:
            bv.VARIANTS[2][vid]["gen_params"] = orig
        # a tampered pinned contract fails closed
        b = ScenarioBinding.query.get(a.binding_id)
        gc = _json.loads(b.gen_contract); gc["gen_params"]["families"] = ["detection-failure"]
        b.gen_contract = _json.dumps(gc); db.session.commit()
        with pytest.raises(b2.Board2ProvisionError):
            b2.generate_world(a)
    finally:
        ctx.pop()


def test_gap2_payload_modified_after_signing_fails_closed():
    """Editing the stored payload (conclusions/timeline/citations) after signing - without touching
    the signed evidence record - must make qualification fail closed (full-payload digest)."""
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "pay", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        payload = _correct_submission(a, cluster)
        case, sub = _submit_signed(db, c, a, cluster, payload)
        # tamper ONLY the stored payload (conclusion), leave the signed evidence_record intact
        tampered = _json.loads(sub.payload)
        tampered["overall_conclusion"] = "actually there was no incident"
        tampered["incidents"][0]["analyst_conclusion"] = "benign"
        sub.payload = _json.dumps(tampered); db.session.commit()
        with pytest.raises(sq.QualificationEvidenceError):
            sq.decide(db, case, sub, a, _reader(cluster), principal=admin,
                      mode="authorized", activation=_test_activation())
    finally:
        ctx.pop()


def test_gap2_record_case_or_version_mismatch_fails_closed():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "mism", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        case, sub = _submit_signed(db, c, a, cluster, _correct_submission(a, cluster))
        # decide against an assignment whose scenario_version differs from the signed record
        import dataclasses
        wrong = dataclasses.replace(a, spec_version=a.spec_version + 1)
        with pytest.raises(sq.QualificationEvidenceError):
            sq.decide(db, case, sub, wrong, _reader(cluster), principal=admin,
                      mode="authorized", activation=_test_activation())
    finally:
        ctx.pop()


def test_gap3_candidate_role_cannot_read_variant_or_fingerprint():
    """The candidate's own scoped OpenSearch role cannot read the integrity metadata (variant/spec/
    fingerprint/family) by document id, search, or index API - it lives in a protected system index
    outside the candidate role pattern, and the candidate index carries none of it."""
    application, db, ctx, admin = _app()
    try:
        from siem.live import AuthzError
        c = _cand(db, "dls", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        # provision the candidate's scoped role exactly as the gateway does
        role = "cand_" + a.slug
        cluster.put_role(role, [b2.authz.candidate_index_pattern(a.cohort, a.slug)],
                         dls={"ranger.candidate_id": a.slug})
        cluster.put_rolesmapping(role, users=[a.slug])
        auth = (a.slug, "pw")
        # (a) the candidate index holds ONLY their events, none carrying variant/spec/fingerprint, and
        # no qual-metadata document (events legitimately carry data.plane="qualification").
        docs = cluster.search(a.index_name, auth=auth)
        blob = _json.dumps(docs)
        assert a.variant_id not in blob, "variant id leaked into candidate-readable events"
        assert a.spec_id not in blob, "spec id leaked into candidate-readable events"
        assert a.dataset_fingerprint not in blob, "fingerprint leaked into candidate-readable events"
        for d in docs:
            assert "qual" not in d, "qual metadata block present in a candidate event"
            assert not (d.get("ranger") or {}).get("meta"), "meta doc readable by the candidate"
        # (b) the protected system meta index is NOT in the candidate role pattern -> 403 on SEARCH
        with pytest.raises(AuthzError):
            cluster.search(b2.SYSTEM_META_INDEX, auth=auth)
        # (c) a direct _doc GET of the meta (by the index-name id) under the candidate's scoped role
        # is ALSO denied (not just search); the candidate must not read the protected metadata.
        with pytest.raises(AuthzError):
            cluster._req("GET", f"/{b2.SYSTEM_META_INDEX}/_doc/{a.index_name}", auth=auth)
        # a _doc GET of the candidate's OWN index for the meta id returns not-found (no meta there)
        code, body = cluster._req("GET", f"/{a.index_name}/_doc/__ranger_qual_meta__", auth=auth)
        assert code == 404 and not body.get("found")
        # the broker (admin) CAN read the protected meta server-side
        meta = b2.read_index_meta(cluster, a.index_name)
        assert meta["variant_id"] == a.variant_id and meta["fingerprint"] == a.dataset_fingerprint
    finally:
        ctx.pop()


def test_gap5_activation_and_principal_hardening():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "act", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        case, sub = _submit_signed(db, c, a, cluster, _correct_submission(a, cluster))
        reader = _reader(cluster)
        # a test activation is refused when the permitted-test flag is absent
        os.environ.pop("RANGER_ALLOW_TEST_QUAL", None)
        try:
            with pytest.raises(sq.QualificationNotActivated):
                sq.decide(db, case, sub, a, reader, principal=admin,
                          mode="authorized", activation=_test_activation())
        finally:
            os.environ["RANGER_ALLOW_TEST_QUAL"] = "1"
        # a production activation fails closed when RANGER_ENV is missing/unrecognized
        prod_act = sq.build_activation(cc.RUBRIC_VERSION, approved_by="alice", environment="production",
                                       deployment_id="dep-1", calibration_ref="c", shadow_run_ref="s")
        os.environ.pop("RANGER_ENV", None)
        try:
            with pytest.raises(sq.QualificationNotActivated):
                sq.decide(db, case, sub, a, reader, principal=admin, mode="authorized",
                          activation=prod_act)
        finally:
            os.environ["RANGER_ENV"] = "test"
        # a service principal without a valid token is rejected (no bare {service, trusted})
        os.environ.pop("RANGER_EVALUATOR_TOKEN", None)
        with pytest.raises(sq.QualificationAuthError):
            sq.decide(db, case, sub, a, reader,
                      principal={"service": "x", "trusted": True}, mode="proposed")
        # with a configured service token, the service identity is accepted
        os.environ["RANGER_EVALUATOR_TOKEN"] = "svc-secret"
        try:
            d = sq.decide(db, case, sub, a, reader,
                          principal={"service": "evaluator", "token": "svc-secret"}, mode="proposed")
            assert d.mode == "proposed"
        finally:
            os.environ.pop("RANGER_EVALUATOR_TOKEN", None)
    finally:
        os.environ["RANGER_ENV"] = "test"
        ctx.pop()


def test_gap6_full_candidate_to_reviewer_http_chain():
    """The complete HTTP chain: candidate session -> /soc/launch (binding provisioning) -> query own
    telemetry -> /case -> draft -> verify -> /case/<id>/submit (signed) -> reviewer qualify route
    (test-only authorized award) -> report approval -> Board 2 clearance -> exactly-once promotion.
    Only infrastructure boundaries are injected (OpenSearch double); candidate+reviewer HTTP behavior
    is exercised, not bypassed."""
    import base64
    import case_routes as _cr
    import soc_gateway as _soc
    cluster = FakeCluster()
    # a real RSA PEM so the gateway's JWT mint works (the Dashboards HTTP call then fails and is
    # swallowed as best-effort); the key is ephemeral and test-only.
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization as _ser
    _pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption())
    # the /soc test-login route and the gateway are registered from env AT create_app() time, so set
    # every flag BEFORE building the app.
    flags = {"RANGER_CASE_UI": "1", "RANGER_B2_BINDING": "1", "RANGER_B2_QUAL_UI": "1",
             "RANGER_SOC_TEST_KEY": "soc-test-key",
             "RANGER_JWT_PRIVATE_B64": base64.b64encode(_pem).decode(),
             "OPENSEARCH_ADMIN_PASSWORD": "x",
             "RANGER_B2_QUAL_ACTIVATION": base64.b64encode(
                 _json.dumps(_test_activation()).encode()).decode()}
    saved = {k: os.environ.get(k) for k in flags}
    os.environ.update(flags)
    import app as appmod
    from models import db, Candidate, Case, CaseSubmission, BoardResult, QualificationDecision
    from models import AdminUser, Cohort
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    _soc.set_cluster_factory(lambda: cluster)
    _cr.set_reader_factory(lambda case: _reader(cluster))
    try:
        db.create_all()
        if not Cohort.query.filter_by(name="2026-A").first():
            db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
        ad = AdminUser(github_id="gid-admin", login="alice", role="reviewer")
        db.session.add(ad); db.session.commit()
        for e in cat.register_all(db, boards=(2,)):
            cat.approve(db, e, ad)
        db.session.commit()
        asn.set_cohort_portfolio(db, "2026-A", 2, COHORTS["2026-A"], admin=ad)
        # pre-create the candidate (name/email) so the test-login route reuses it
        cand = Candidate(handle="chain", name="chain", email="chain@e", cohort="2026-A",
                         github_id="test-chain", status="active", current_board=2, token="tok-chain")
        db.session.add(cand); db.session.commit()
        client = application.test_client()
        # 1. authorized candidate session (test-only bootstrap, still authorized on every request)
        r = client.get("/soc-test/login?key=soc-test-key&cand=chain", follow_redirects=False)
        assert r.status_code in (301, 302)
        cand = Candidate.query.filter_by(handle="chain").first()
        cand.cohort = "2026-A"; db.session.commit()
        # 2. /soc/launch provisions through the S5 binding into the qualification index
        r = client.get("/soc/launch", follow_redirects=False)
        assert r.status_code in (301, 302), r.data
        a = b2.resolve_assignment(db, Candidate.query.get(cand.id))
        assert cluster.index_exists(a.index_name) and cluster.count(a.index_name) > 100
        # 3. candidate queries their OWN telemetry through their scoped role (isolation holds).
        # The gateway maps the role to the candidate's OpenSearch user (cand_<slug>).
        cand_user = b2.authz.user_name(a.slug)
        assert cluster.count(a.index_name, auth=(cand_user, "pw")) > 0
        # 4. /case assignment pinned to the binding
        r = client.get("/case"); assert r.status_code == 200
        case = Case.query.filter_by(candidate_id=cand.id, board=2).first()
        assert case.binding_id == a.binding_id and case.index_name == a.index_name
        # 5-7. draft -> verify -> submit (signed) through the real routes
        with client.session_transaction() as s:
            s["csrf"] = "t"
        hdr = {"X-CSRF-Token": "t", "Content-Type": "application/json"}
        events, truth = b2.generate_world(a)
        payload = b2.board2_reference_submission(events, truth, a.index_name)
        client.get(f"/case/{case.id}")   # move to investigating
        rd = client.post(f"/case/{case.id}/draft", data=_json.dumps(payload), headers=hdr)
        assert rd.status_code == 200, rd.data
        rv = client.post(f"/case/{case.id}/verify", data=_json.dumps(payload), headers=hdr)
        assert rv.status_code == 200, rv.data
        rs = client.post(f"/case/{case.id}/submit", data=_json.dumps(payload), headers=hdr)
        assert rs.status_code == 200, rs.data
        sub = CaseSubmission.query.filter_by(case_id=case.id).order_by(
            CaseSubmission.id.desc()).first()
        assert sub.evidence_sig
        # 8-9. reviewer evaluates through the actual protected route (test-only authorized award)
        with client.session_transaction() as s:
            s.clear(); s["admin"] = True; s["admin_gid"] = ad.github_id; s["csrf"] = "t"
        rq = client.post(f"/admin/cases/submission/{sub.id}/qualify", headers={"X-CSRF-Token": "t"})
        qb = rq.get_json()
        assert rq.status_code == 200, qb
        assert qb["mode"] == "authorized" and qb["awarded_objective"] is True and qb["passed"]
        # objective recorded, but NOT yet promoted (report approval still required)
        assert Candidate.query.get(cand.id).current_board == 2
        # 10. separate human report approval
        br = BoardResult.query.filter_by(candidate_id=cand.id, board=2).first()
        br.report_status = "approved"; db.session.add(br); db.session.commit()
        # 11-12. re-run qualify (idempotent) -> gate now promotes exactly once
        rq2 = client.post(f"/admin/cases/submission/{sub.id}/qualify", headers={"X-CSRF-Token": "t"})
        assert rq2.status_code == 200
        assert Candidate.query.get(cand.id).current_board == 3
        assert QualificationDecision.query.filter_by(case_id=case.id, mode="authorized").count() == 1
    finally:
        _soc.set_cluster_factory(None)
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        ctx.pop()


def test_gapf1_shared_promotion_gate_report_route():
    """The report-approval route (/admin/reports/<id>) shares the promotion boundary with the qualify
    route. (A) a submission altered after a valid award -> approving the report does NOT clear Board 2;
    (B) an intact award -> approving the report promotes to Board 3 exactly once; (missing) objective
    credit without a valid signed decision does not promote."""
    import base64
    import case_routes as _cr
    import soc_gateway as _soc
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization as _ser
    cluster = FakeCluster()
    _pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption())
    flags = {"RANGER_CASE_UI": "1", "RANGER_B2_BINDING": "1", "RANGER_B2_QUAL_UI": "1",
             "RANGER_SOC_TEST_KEY": "soc-test-key", "ADMIN_TOKEN": "test-admin-token",
             "RANGER_JWT_PRIVATE_B64": base64.b64encode(_pem).decode(),
             "OPENSEARCH_ADMIN_PASSWORD": "x",
             "RANGER_B2_QUAL_ACTIVATION": base64.b64encode(
                 _json.dumps(_test_activation()).encode()).decode()}
    saved = {k: os.environ.get(k) for k in flags}
    os.environ.update(flags)
    import app as appmod
    import program as P
    from models import (db, Candidate, Case, CaseSubmission, BoardResult, Report, AdminUser, Cohort)
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    _soc.set_cluster_factory(lambda: cluster)
    _cr.set_reader_factory(lambda case: _reader(cluster))

    def _award(handle, *, alter=False, award=True):
        """Drive a candidate through the HTTP chain to an awarded objective decision; return (cand,
        sub). If alter, mutate the stored payload after the award. If not award, skip the qualify
        step (objective stays unearned)."""
        cand = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort="2026-A",
                         github_id="test-" + handle, status="active", current_board=2,
                         token="tok-" + handle)
        db.session.add(cand); db.session.commit()
        cl = application.test_client()
        cl.get(f"/soc-test/login?key=soc-test-key&cand={handle}")
        cl.get("/soc/launch")
        a = b2.resolve_assignment(db, Candidate.query.get(cand.id))
        with cl.session_transaction() as s:
            s["csrf"] = "t"
        hdr = {"X-CSRF-Token": "t", "Content-Type": "application/json"}
        cl.get("/case")
        case = Case.query.filter_by(candidate_id=cand.id, board=2).first()
        events, truth = b2.generate_world(a)
        payload = b2.board2_reference_submission(events, truth, a.index_name)
        cl.get(f"/case/{case.id}")
        cl.post(f"/case/{case.id}/draft", data=_json.dumps(payload), headers=hdr)
        cl.post(f"/case/{case.id}/submit", data=_json.dumps(payload), headers=hdr)
        sub = CaseSubmission.query.filter_by(case_id=case.id).order_by(
            CaseSubmission.id.desc()).first()
        if award:
            with cl.session_transaction() as s:
                s.clear(); s["admin"] = True; s["admin_gid"] = "gid-admin"; s["csrf"] = "t"
            rq = cl.post(f"/admin/cases/submission/{sub.id}/qualify", headers={"X-CSRF-Token": "t"})
            assert rq.get_json()["awarded_objective"] is True, rq.get_json()
        else:
            # simulate a stale objective_passed with NO valid decision (must not be trusted)
            br = BoardResult.query.filter_by(candidate_id=cand.id, board=2).first() or \
                BoardResult(candidate_id=cand.id, board=2)
            br.objective_passed = True; br.objective_score = 100.0
            db.session.add(br); db.session.commit()
        if alter:
            tam = _json.loads(sub.payload); tam["overall_conclusion"] = "no incident"
            sub.payload = _json.dumps(tam); db.session.commit()
        return cand, case, sub

    def _approve_report(cand):
        r = Report(candidate_id=cand.id, board=P.bstr(2), role=P.role_of(2),
                   body="investigation report", status="pending")
        db.session.add(r); db.session.commit()
        cl = application.test_client()
        with cl.session_transaction() as s:
            s["admin"] = True; s["admin_gid"] = "gid-admin"; s["csrf"] = "t"
        return cl.post(f"/admin/reports/{r.id}", data={"action": "approve", "csrf": "t"},
                       headers={"X-CSRF-Token": "t"})

    try:
        db.create_all()
        if not Cohort.query.filter_by(name="2026-A").first():
            db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
        ad = AdminUser(github_id="gid-admin", login="alice", role="reviewer")
        db.session.add(ad); db.session.commit()
        for e in cat.register_all(db, boards=(2,)):
            cat.approve(db, e, ad)
        db.session.commit()
        asn.set_cohort_portfolio(db, "2026-A", 2, COHORTS["2026-A"], admin=ad)

        # A. award valid decision, ALTER the stored submission, approve report -> NOT cleared
        candA, caseA, subA = _award("ga", alter=True)
        _approve_report(candA)
        assert Candidate.query.get(candA.id).current_board == 2
        assert not (BoardResult.query.filter_by(candidate_id=candA.id, board=2).first().cleared)

        # B. award valid decision, intact, approve report -> promoted to Board 3 exactly once
        candB, caseB, subB = _award("gb", alter=False)
        _approve_report(candB)
        assert Candidate.query.get(candB.id).current_board == 3
        # a second approval does not double-promote
        _approve_report(candB)
        assert Candidate.query.get(candB.id).current_board == 3

        # missing: objective_passed set but NO valid signed decision -> report approval does not clear
        candC, caseC, subC = _award("gc", award=False)
        _approve_report(candC)
        assert Candidate.query.get(candC.id).current_board == 2
    finally:
        _soc.set_cluster_factory(None)
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        ctx.pop()


def test_gapf1b_shared_gate_rejects_bad_decisions():
    """The shared Board 2 boundary (verify_authorized_clearance) rejects missing / unsigned / wrong-
    candidate / wrong-scenario authorized decisions, so objective_passed alone never promotes."""
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "bad", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster(); b2.provision(cluster, a)
        case, sub = _submit_signed(db, c, a, cluster, _correct_submission(a, cluster))
        # missing decision -> not cleared
        ok, _ = sq.verify_authorized_clearance(db, c)
        assert not ok
        # a legitimate authorized decision -> cleared
        d = sq.decide(db, case, sub, a, _reader(cluster), principal=admin, mode="authorized",
                      activation=_test_activation())
        ok, _ = sq.verify_authorized_clearance(db, c)
        assert ok
        # unsigned/invalid signature -> rejected
        good_sig = d.decision_sig
        d.decision_sig = "AAAA"; db.session.add(d); db.session.commit()
        ok, _ = sq.verify_authorized_clearance(db, c)
        assert not ok
        d.decision_sig = good_sig; db.session.add(d); db.session.commit()
        # wrong-scenario (decision pins a different fingerprint) -> rejected
        good_fp = d.scenario_fingerprint
        d.scenario_fingerprint = "f" * 64; db.session.add(d); db.session.commit()
        ok, _ = sq.verify_authorized_clearance(db, c)
        assert not ok
        d.scenario_fingerprint = good_fp; db.session.add(d); db.session.commit()
        assert sq.verify_authorized_clearance(db, c)[0]
    finally:
        ctx.pop()


def _weak_submission(a):
    _events, truth = b2.generate_world(a)
    t0 = truth["incidents"][0]
    return {"baseline_summary": "b", "overall_conclusion": "c",
            "incidents": [{"label": t0["family"], "disposition": "confirmed_incident",
                           "severity": "high", "confidence": 60,
                           "attack_techniques": t0["techniques"][:1],
                           "primary_identity": t0["primary_identity"], "affected_assets": [],
                           "cited_evidence": [{"event_uid": t0["event_uids"][0], "index": a.index_name,
                                               "query": {"query": {"match_all": {}}},
                                               "role": "primary"}]}]}


def test_gapf6_signed_decision_record_is_authoritative():
    """The signed decision record - not the mutable ORM columns - is authoritative. Flipping columns
    (passed/awarded/mode/score) on an originally failed or proposed signed decision, or reusing a
    decision against another submission, is rejected at the shared boundary and at decide()'s cache."""
    application, db, ctx, admin = _app()
    try:
        from models import BoardResult, QualificationDecision
        # 1. a legitimately-signed FAILED authorized decision, then columns flipped to pass + award
        c1 = _cand(db, "f1", "2026-A")
        a1 = b2.resolve_assignment(db, c1); cl1 = FakeCluster(); b2.provision(cl1, a1)
        case1, sub1 = _submit_signed(db, c1, a1, cl1, _weak_submission(a1))
        d1 = sq.decide(db, case1, sub1, a1, _reader(cl1), principal=admin, mode="authorized",
                       activation=_test_activation())
        assert not d1.passed and not d1.awarded_objective
        d1.passed = True; d1.awarded_objective = True; db.session.add(d1)
        br1 = BoardResult(candidate_id=c1.id, board=2, objective_passed=True, objective_score=d1.score,
                          objective_sig=d1.decision_sig, report_status="approved")
        db.session.add(br1); db.session.commit()
        ok, _ = sq.verify_authorized_clearance(db, c1)
        assert not ok, "flipped-column failed decision must not clear"

        # 2. a signed PASSING PROPOSED decision, then mode flipped to authorized + award
        c2 = _cand(db, "f2", "2026-A")
        a2 = b2.resolve_assignment(db, c2); cl2 = FakeCluster(); b2.provision(cl2, a2)
        case2, sub2 = _submit_signed(db, c2, a2, cl2, _correct_submission(a2, cl2))
        d2 = sq.decide(db, case2, sub2, a2, _reader(cl2), principal=admin, mode="proposed")
        assert d2.passed and not d2.awarded_objective and d2.mode == "proposed"
        d2.mode = "authorized"; d2.awarded_objective = True; db.session.add(d2)
        br2 = BoardResult(candidate_id=c2.id, board=2, objective_passed=True, objective_score=d2.score,
                          objective_sig=d2.decision_sig, report_status="approved")
        db.session.add(br2); db.session.commit()
        ok, _ = sq.verify_authorized_clearance(db, c2)
        assert not ok, "proposed decision relabelled authorized must not clear"

        # 3. a legit authorized pass, then a column (score) changed without resigning -> rejected
        c3 = _cand(db, "f3", "2026-A")
        a3 = b2.resolve_assignment(db, c3); cl3 = FakeCluster(); b2.provision(cl3, a3)
        case3, sub3 = _submit_signed(db, c3, a3, cl3, _correct_submission(a3, cl3))
        d3 = sq.decide(db, case3, sub3, a3, _reader(cl3), principal=admin, mode="authorized",
                       activation=_test_activation())
        assert sq.verify_authorized_clearance(db, c3)[0]      # intact -> ok
        good_score = d3.score
        d3.score = 50.0; db.session.add(d3); db.session.commit()
        ok, _ = sq.verify_authorized_clearance(db, c3)
        assert not ok, "score changed without resigning must be rejected"
        d3.score = good_score; db.session.add(d3); db.session.commit()
        assert sq.verify_authorized_clearance(db, c3)[0]      # restored -> ok again

        # 4. reuse a signed decision against ANOTHER candidate's submission -> rejected
        c4 = _cand(db, "f4", "2026-A")
        a4 = b2.resolve_assignment(db, c4); cl4 = FakeCluster(); b2.provision(cl4, a4)
        _case4, sub4 = _submit_signed(db, c4, a4, cl4, _correct_submission(a4, cl4))
        ok, reason = sq.verify_decision_integrity(QualificationDecision.query.get(d3.id),
                                                  case=case3, submission=sub4, assignment=a3,
                                                  rubric_version=case3.rubric_version)
        assert not ok and "different submission" in reason

        # 6. decide()'s cached path validates against the same signed contract
        dd = QualificationDecision.query.get(d3.id)
        dd.passed = False; db.session.add(dd); db.session.commit()
        with pytest.raises(sq.QualificationError):
            sq.decide(db, case3, sub3, a3, _reader(cl3), principal=admin, mode="authorized",
                      activation=_test_activation())
    finally:
        ctx.pop()


# =============================================================================================
# 10. Reviewer/evaluator concurrency - against REAL PostgreSQL (skips if none authorized).
# =============================================================================================
def test_concurrent_authorized_decision_is_idempotent_postgres():
    import _pgtest
    ok, reason = _pgtest.authorization_status()
    if not ok:
        pytest.skip(f"no authorized PG test server: {reason}")
    os.environ["RANGER_EVALUATOR_TOKEN"] = "svc-secret-" + os.urandom(4).hex()
    import app as appmod
    from models import (db, ensure_schema, AdminUser, Cohort, Candidate, Case, CaseSubmission,
                        QualificationDecision, BoardResult)
    with _pgtest.isolated_pg_database():
        application = appmod.create_app()
        with application.app_context():
            assert db.engine.dialect.name == "postgresql"
            db.create_all(); ensure_schema(db)
            if not Cohort.query.filter_by(name="2026-A").first():
                db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
            admin = AdminUser(github_id="gid-admin", login="alice", role="reviewer")
            db.session.add(admin); db.session.commit()
            for e in cat.register_all(db, boards=(2,)):
                cat.approve(db, e, admin)
            db.session.commit()
            asn.set_cohort_portfolio(db, "2026-A", 2, COHORTS["2026-A"], admin=admin)
            c = Candidate(handle="pgc", name="pgc", email="pgc@e", cohort="2026-A",
                          github_id="g-pgc", status="active", current_board=2, token="tok-pgc")
            db.session.add(c); db.session.commit()
            a = b2.resolve_assignment(db, c)
            cluster = FakeCluster(); b2.provision(cluster, a)
            payload = _correct_submission(a, cluster)
            case, sub = _submit_signed(db, c, a, cluster, payload)
            cid, caseid, subid = c.id, case.id, sub.id
        act = _test_activation()
        results = []

        def go():
            with application.app_context():
                try:
                    from case_routes import LiveReader
                    cs = Case.query.get(caseid); su = CaseSubmission.query.get(subid)
                    ca = Candidate.query.get(cid)
                    asg = b2.resolve_assignment(db, ca)
                    d = sq.decide(db, cs, su, asg, LiveReader(cluster),
                                  principal={"service": "test-evaluator",
                                             "token": os.environ["RANGER_EVALUATOR_TOKEN"]},
                                  mode="authorized", activation=act)
                    results.append(d.id)
                except Exception as e:  # noqa
                    results.append("ERR:" + str(e)[:50])
                finally:
                    db.session.remove()
        ts = [threading.Thread(target=go) for _ in range(6)]
        [t.start() for t in ts]; [t.join() for t in ts]
        with application.app_context():
            n = QualificationDecision.query.filter_by(case_id=caseid, mode="authorized").count()
            br = BoardResult.query.filter_by(candidate_id=cid, board=2).first()
            db.session.remove(); db.engine.dispose()
        ids = {r for r in results if isinstance(r, int)}
        assert n == 1, f"concurrent authorized decide created {n} decisions (must be 1): {results}"
        assert len(ids) == 1, f"decide returned multiple ids {ids}"
        assert br is not None and br.objective_passed, "exactly one award recorded"


# =============================================================================================
# Cross-module compatibility (S5 final): candidate-safe scenario disclosure + case-ref separation.
# =============================================================================================
def _b2_prohibited_tokens():
    """Every candidate-PROHIBITED scenario descriptor derivable from the PUBLIC variant library:
    variant ids, their authored titles and business_context, and every incident-family name. These
    are publicly readable, so a candidate-facing projection must expose none of them (knowing any one
    identifies the assigned Board 2 scenario and its hidden detection-gap composition)."""
    from siem import board_variants as bv
    toks = set()
    for vid in bv.variants_for(2):
        toks.add(vid)
        v = bv.get(2, vid) or {}
        for s in (v.get("title"), v.get("business_context")):
            if s:
                toks.add(s)
        for key in (v.get("gen_params", {}), v.get("diversity", {})):
            for fam in key.get("families", []) or []:
                toks.add(fam)
    # the explicit hidden-detection-gap phrasing authored in the insider-exfil variant
    toks.add("whether current detections covered it")
    return {t for t in toks if t}


def test_xmod1_candidate_mission_projection_discloses_no_variant_or_family():
    """strata_missions.for_binding() is a candidate-facing projection and must disclose NO variant id,
    variant title, variant business_context, or incident-family name from the public library. It must
    still carry the generic, approved board mission (legitimate scope/role/deliverables) plus an
    OPAQUE scenario reference (never the spec_id/variant_id)."""
    application, db, ctx, admin = _app()
    try:
        prohibited = _b2_prohibited_tokens()
        # cover BOTH cohorts' approved variants so the assertion is not specific to one assignment
        for handle, cohort in (("mp_a", "2026-A"), ("mp_b", "2026-B")):
            c = _cand(db, handle, cohort)
            a = b2.resolve_assignment(db, c)
            from models import ScenarioBinding
            binding = (ScenarioBinding.query.filter_by(candidate_id=c.id, board=2)
                       .order_by(ScenarioBinding.attempt.desc()).first())
            assert binding is not None
            import strata_missions as sm
            pkg = sm.for_binding(binding)
            assert pkg is not None
            blob = _json.dumps(pkg).lower()
            hits = sorted(t for t in prohibited if t.lower() in blob)
            assert not hits, f"candidate mission projection leaked: {hits}"
            # no variant-identifying keys at all
            assert "variant_id" not in pkg, "variant_id must not be in the candidate projection"
            # scenario_ref is the OPAQUE keyed ref, never the variant spec id
            assert pkg.get("scenario_ref") and pkg["scenario_ref"] != binding.spec_id
            assert pkg["scenario_ref"] != binding.variant_id
            # the professional brief is still useful: generic board mission is present
            assert pkg.get("title") == "Enterprise SOC investigation"
            assert pkg.get("business_context")
            assert pkg.get("scenario_bound") is True
    finally:
        ctx.pop()


def test_xmod1b_me_mission_http_renders_no_prohibited_scenario_info():
    """The candidate HTTP surface GET /me/mission (portfolios ON, bound attempt) renders the mission
    brief WITHOUT any prohibited variant/family/detection-gap disclosure, while remaining a useful
    professional brief."""
    application, db, ctx, admin = _app()
    saved = os.environ.get("RANGER_STRATA_PORTFOLIOS")
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"   # read at request time by _strata_portfolios_on()
    try:
        prohibited = _b2_prohibited_tokens()
        c = _cand(db, "http_mp", "2026-A")
        b2.resolve_assignment(db, c)   # creates the authoritative ScenarioBinding for board 2
        client = application.test_client()
        with client.session_transaction() as s:
            s["cand"] = c.id
        r = client.get("/me/mission")
        assert r.status_code == 200, r.data
        html = r.get_data(as_text=True)
        low = html.lower()
        hits = sorted(t for t in prohibited if t.lower() in low)
        assert not hits, f"/me/mission rendered prohibited scenario info: {hits}"
        # the brief is still present and professional (generic board mission copy is shown)
        assert "Enterprise SOC investigation" in html
    finally:
        if saved is None:
            os.environ.pop("RANGER_STRATA_PORTFOLIOS", None)
        else:
            os.environ["RANGER_STRATA_PORTFOLIOS"] = saved
        ctx.pop()


def test_xmod2_case_ref_separated_from_f5_scenario_ref():
    """Driving the REAL case_routes._ensure_case (via HTTP GET /case, S5 binding flag ON): the opaque
    case correlation is written to Case.case_ref, while Case.scenario_ref keeps its F5
    approved-scenario-metadata meaning (left None for an S5 cohort case, so F5 reports instructions via
    the mission rather than resolving the opaque value as a bogus catalog lookup). A genuine F5
    workbench case is unaffected, and the STRATA signed-evidence reference remains the opaque value and
    still verifies."""
    import workbench_scenarios as wsc
    import workbench_core as wc
    import case_routes as _cr  # noqa: F401 - register() is reached through create_app()
    flags = {"RANGER_CASE_UI": "1", "RANGER_B2_BINDING": "1"}
    saved = {k: os.environ.get(k) for k in flags}
    os.environ.update(flags)
    import app as appmod
    from models import db, Candidate, Case, AdminUser, Cohort
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    try:
        db.create_all()
        if not Cohort.query.filter_by(name="2026-A").first():
            db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
        ad = AdminUser(github_id="gid-admin", login="alice", role="reviewer")
        db.session.add(ad); db.session.commit()
        for e in cat.register_all(db, boards=(2,)):
            cat.approve(db, e, ad)
        db.session.commit()
        asn.set_cohort_portfolio(db, "2026-A", 2, COHORTS["2026-A"], admin=ad)
        cand = Candidate(handle="cref", name="cref", email="cref@e", cohort="2026-A",
                         github_id="g-cref", status="active", current_board=2, token="tok-cref")
        db.session.add(cand); db.session.commit()
        a = b2.resolve_assignment(db, Candidate.query.get(cand.id))
        expected_opaque = b2.schema.case_ref(a.slug, 2, a.seed)

        client = application.test_client()
        with client.session_transaction() as s:
            s["cand"] = cand.id
        # the REAL _ensure_case runs here (S5 binding path)
        r = client.get("/case")
        assert r.status_code == 200, r.data
        case = Case.query.filter_by(candidate_id=cand.id, board=2, plane="qualification").first()
        assert case is not None
        # (1) the opaque correlation is in case_ref, NOT scenario_ref
        assert case.case_ref == expected_opaque
        assert case.scenario_ref is None, "S5 must not store the opaque ref in the F5 scenario_ref"
        # (2) the opaque value is NOT an F5 workbench scenario key (never resolves as metadata)
        assert wsc.get(case.case_ref, case.scenario_version) is None
        # (3) F5 reads scenario_ref (None here) and reports an accurate 'not available' state rather
        #     than resolving the opaque correlation as if it were approved scenario metadata
        assert wc.case_meta(case) is None
        el = (wc.scenario_eligibility(case, None) if hasattr(wc, "scenario_eligibility")
              else wsc.eligibility(case.scenario_ref, case.scenario_version))
        assert el["ok"] is False and el["status"] == "no_scenario"
        # (4) a genuine F5 workbench case (real approved scenario_ref) is unaffected by the change
        ref0 = "strata-soc-triage" if wsc.get("strata-soc-triage", 1) else None
        if ref0:
            fcase = Case(candidate_id=cand.id, board=1, cohort="2026-A", plane="assessment",
                         workflow="assigned", index_name="idx-f5", seed="s", scenario_version=1,
                         rubric_version=1, attempt=1, status="assigned", scenario_ref=ref0)
            db.session.add(fcase); db.session.commit()
            assert wc.case_meta(fcase) is not None, "F5 approved-scenario resolution must still work"
            assert fcase.case_ref is None
        # (5) the signed-evidence reference is still the opaque value and verifies end-to-end
        cluster = FakeCluster(); b2.provision(cluster, a)
        payload = _correct_submission(a, cluster)
        _case2, sub = _submit_signed(db, Candidate.query.get(cand.id), a, cluster, payload)
        rec = _json.loads(sub.evidence_record)
        assert rec["scenario_ref"] == expected_opaque
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        ctx.pop()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
