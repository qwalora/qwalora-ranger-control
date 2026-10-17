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
    for e in cat.register_all(db):
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
    meta = {"candidate": assignment.slug, "board": 2, "cohort": assignment.cohort,
            "scenario_ref": b2.schema.case_ref(assignment.slug, 2, assignment.seed),
            "submitted_at": "2026-03-02T00:00:00Z"}
    record, sig = cc.preserve_and_sign(payload, reader, assignment.index_name, meta)
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
        # a test activation is refused when the process declares itself production
        os.environ["RANGER_ENV"] = "production"
        try:
            with pytest.raises(sq.QualificationNotActivated):
                sq.decide(db, case, sub, a, _reader(cluster), principal=admin,
                          mode="authorized", activation=_test_activation())
        finally:
            os.environ.pop("RANGER_ENV", None)
    finally:
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
def test_provision_idempotent_and_refuses_foreign_index():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "prov", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster()
        r1 = b2.provision(cluster, a); r2 = b2.provision(cluster, a)
        assert r1["action"] == "provisioned" and r2["action"] == "reused"
        # forge a DIFFERENT assignment's fingerprint into the same index -> provision must refuse
        import dataclasses
        foreign = dataclasses.replace(a, dataset_fingerprint="f" * 64)
        with pytest.raises(b2.Board2ProvisionError):
            b2.provision(cluster, foreign)
    finally:
        ctx.pop()


def test_provision_converges_after_interrupted_ingest():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "retry", "2026-A")
        a = b2.resolve_assignment(db, c); cluster = FakeCluster()
        # simulate an interrupted ingest: create the index + a few events, NO completion meta
        events, _t = b2.generate_world(a)
        cluster.create_index(a.index_name)
        cluster.bulk_index(a.index_name, b2._stamp_plane(events[:50]))
        assert b2.read_index_meta(cluster, a.index_name) is None   # incomplete
        # a normal provision converges to the full, complete world (idempotent upsert)
        r = b2.provision(cluster, a)
        assert r["action"] == "provisioned"
        meta = b2.read_index_meta(cluster, a.index_name)
        assert meta["status"] == "complete" and meta["fingerprint"] == a.dataset_fingerprint
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
# 10. Reviewer/evaluator concurrency - against REAL PostgreSQL (skips if none authorized).
# =============================================================================================
def test_concurrent_authorized_decision_is_idempotent_postgres():
    import _pgtest
    ok, reason = _pgtest.authorization_status()
    if not ok:
        pytest.skip(f"no authorized PG test server: {reason}")
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
            for e in cat.register_all(db):
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
                                  principal={"service": "test-evaluator", "trusted": True},
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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
