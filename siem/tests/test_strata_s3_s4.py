"""S3/S4 acceptance - cohort-aware scenario diversity, randomized assignment, verified grading,
and the S3/S4 integrity-closure corrections (seed protection, Board 2 bypass, truth projection,
fail-closed portfolios, real version pinning, real admin authorization, concurrency).

Two synthetic cohorts, multiple candidates each, exercised through the ACTUAL Ranger architecture
(strata_catalog governance, strata_assignment runtime, the real board generators/graders, and the
live /labs/dataset + /grade/submit candidate routes with the portfolio flag on). Tests drive real
generation and grading, not metadata-string comparisons.
"""
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("SECRET_KEY", "s3s4")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

import json as _json  # noqa: E402

import pytest  # noqa: E402

import strata_catalog as cat  # noqa: E402
import strata_assignment as asn  # noqa: E402
from siem import board_variants as bv  # noqa: E402
from siem import scenario_pipeline as sp  # noqa: E402
from siem import schema as ev_schema  # noqa: E402
from siem import case_contract  # noqa: E402
import _pgtest  # noqa: E402

DATASET_BOARDS = (1, 3, 4)
BAND_IX = {"intro": 0, "standard": 1, "advanced": 2}

# two cohorts with overlapping-but-different approved portfolios per board
PORTFOLIO = {
    "2026-A": {1: ["b1-credential-access", "b1-execution-persistence"],
               2: ["b2-identity-takeover", "b2-insider-exfil"],
               3: ["b3-execution-c2", "b3-credential-identity"],
               4: ["b4-phish-rdp-schtask", "b4-webshell-service"]},
    "2026-B": {1: ["b1-lateral-exfil", "b1-execution-persistence"],
               2: ["b2-stealth-lateral", "b2-insider-exfil"],
               3: ["b3-evasion-impact", "b3-credential-identity"],
               4: ["b4-vpn-registry", "b4-webshell-service"]},
}


# --- recursive leak walker (used by the no-leak assertions) -----------------------------------
def _all_tokens(obj):
    """Every key and scalar in a nested structure, as strings (recursive)."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            out.extend(_all_tokens(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_all_tokens(v))
    else:
        out.append(str(obj))
    return out


def _assert_no_leak(obj, seed, *, extra_forbidden=()):
    toks = _all_tokens(obj)
    blob = "\x1f".join(toks)
    forbidden_keys = ("_malicious", "_key", "_flags", "_seed", "_techniques", "_variant",
                      "scenario_seed", "truth") + tuple(extra_forbidden)
    for k in forbidden_keys:
        assert k not in toks, f"forbidden key {k!r} present in candidate-facing payload"
    assert seed not in blob, "the protected generator seed leaked into a candidate-facing payload"


def _app():
    import app as appmod
    from models import db, AdminUser, Cohort
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.create_all()
    for nm in ("2026-A", "2026-B"):
        if not Cohort.query.filter_by(name=nm).first():
            db.session.add(Cohort(name=nm, pathway="strata", status="active"))
    admin = AdminUser(github_id="gid-admin", login="alice", role="reviewer")
    db.session.add(admin); db.session.commit()
    for e in cat.register_all(db):
        cat.approve(db, e, admin)
    db.session.commit()
    # declare each cohort's board portfolio under real admin authorization
    for cohort, boards in PORTFOLIO.items():
        for board, variants in boards.items():
            asn.set_cohort_portfolio(db, cohort, board, variants, admin=admin)
    return application, db, ctx, admin


def _cand(db, handle, cohort, board):
    from models import Candidate
    c = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort=cohort,
                  github_id=f"g-{handle}", status="active", current_board=board, token=f"tok-{handle}")
    db.session.add(c); db.session.commit()
    return c


def _correct(board, scen):
    if board == 1:
        return cat.board1_correct(scen)
    if board == 4:
        return cat.board4_correct(scen)
    return cat.board3_ruleset(scen["_techniques"])


# ======================= 1,2,3,4: diversity, parity, competency ==============================
def test_cohort_portfolios_are_structurally_different_and_parity():
    application, db, ctx, _ = _app()
    try:
        for board in (1, 2, 3, 4):
            pa, pb = PORTFOLIO["2026-A"][board], PORTFOLIO["2026-B"][board]
            assert set(pa) != set(pb), f"board {board} cohort portfolios must differ"
            a_only = [v for v in pa if v not in pb]
            b_only = [v for v in pb if v not in pa]
            assert a_only and b_only
            div = sp.axis_divergence(bv.diversity_axes(board, a_only[0]),
                                     bv.diversity_axes(board, b_only[0]))
            assert div >= sp.MIN_DIVERGENT_AXES, f"board {board} variants differ on only {div} axes"
            comps = {tuple(sorted(bv.competencies(board, v))) for v in pa + pb}
            assert len(comps) == 1, f"board {board} variants must cover equivalent competencies"
            bands = [cat.simulate(board, v)["difficulty"]["band"] for v in set(pa + pb)]
            assert max(BAND_IX[b] for b in bands) - min(BAND_IX[b] for b in bands) <= 1, \
                f"board {board} difficulty parity exceeded: {bands}"
    finally:
        ctx.pop()


# ======================= 5,6,7,9,10,11,13,14: assignment + grading (dataset boards) ==========
def test_assignment_generation_and_grading_dataset_boards():
    application, db, ctx, _ = _app()
    try:
        for board in DATASET_BOARDS:
            vA, vB = PORTFOLIO["2026-A"][board]
            a1 = _cand(db, f"a1b{board}", "2026-A", board)
            a2 = _cand(db, f"a2b{board}", "2026-A", board)
            b1 = asn.assign(db, a1, board, portfolio=[vA])
            b2 = asn.assign(db, a2, board, portfolio=[vB])
            assert b1.id != b2.id and b1.seed != b2.seed and b1.variant_id != b2.variant_id
            sA = asn.generate(b1)
            sB = asn.generate(b2)
            assert asn.generate(b1) == sA                      # 7. exact replay
            view = asn.candidate_view(b1, sA)                  # 9. no evaluator truth (recursive)
            _assert_no_leak(view, b1.seed)
            cs, _ = asn.grade(b1, _correct(board, sA))         # 10. correct >= 95 per variant
            assert cs >= 95.0, f"board {board} variant {vA} correct scored {cs}"
            cs2, _ = asn.grade(b2, _correct(board, sB))
            assert cs2 >= 95.0, f"board {board} variant {vB} correct scored {cs2}"
            empty = {"alerts": []} if board in (1, 4) else {"rules": []}
            es, _ = asn.grade(b1, empty)                       # 11. empty cannot reach 95
            assert es < 95.0
            cross, _ = asn.grade(b2, _correct(board, sA))      # 6+14. cross-variant non-transfer
            assert cross < 95.0, f"board {board} cross-variant transfer scored {cross} (must be <95)"
            assert b1.content_hash and b1.spec_version >= 1 and b1.variant_id == vA   # 13. pinned
    finally:
        ctx.pop()


# ======================= 12: grading correct after scenario rotation =========================
def test_grading_correct_after_rotation():
    application, db, ctx, _ = _app()
    try:
        c = _cand(db, "rot", "2026-A", 1)
        port = PORTFOLIO["2026-A"][1]
        b_a1 = asn.assign(db, c, 1, attempt=1, portfolio=port)
        s1 = asn.generate(b_a1)
        asn.mark_completed(db, b_a1)
        b_a2 = asn.assign(db, c, 1, attempt=2, portfolio=port)
        assert b_a2.variant_id != b_a1.variant_id
        s2 = asn.generate(b_a2)
        cs2, _ = asn.grade(b_a2, _correct(1, s2))
        assert cs2 >= 95.0
        cross, _ = asn.grade(b_a2, _correct(1, s1))
        assert cross < 95.0
    finally:
        ctx.pop()


# ======================= 8: unauthorized / revoked scenarios rejected ========================
def test_unauthorized_and_revoked_rejected():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "u1", "2026-A", 1)
        try:
            asn.assign(db, c, 1, portfolio=["b1-does-not-exist"])
            assert False, "unknown variant must be rejected"
        except asn.AssignmentError:
            pass
        e = cat.eligible(db, 1)[0]
        e.status = "deprecated"; db.session.add(e); db.session.commit()
        remaining = {cat.entry_variant(x) for x in cat.eligible(db, 1)}
        assert cat.entry_variant(e) not in remaining
    finally:
        ctx.pop()


# ======================= real candidate route (section 6) ====================================
def test_real_candidate_route_dataset_and_grade():
    application, db, ctx, _ = _app()
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    try:
        client = application.test_client()
        c = _cand(db, "route1", "2026-A", 1)
        hdr = {"X-Candidate-Token": c.token}
        r = client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr)
        assert r.status_code == 200, r.data
        body = r.get_json()
        # candidate response carries an OPAQUE case ref, never the seed or the hidden variant/family
        assert body.get("case_ref") and "variant" not in body and "seed" not in body
        from models import ScenarioBinding
        binding = ScenarioBinding.query.filter_by(candidate_id=c.id, board=1).first()
        assert body["case_ref"] == ev_schema.case_ref(c.github_id, 1, binding.seed)
        assert binding.seed not in r.data.decode()
        _assert_no_leak(body, binding.seed)
        scen = asn.generate(binding)
        g = client.post("/grade/submit", json={"handle": c.handle,
                                               "submission": cat.board1_correct(scen)}, headers=hdr)
        assert g.status_code == 200, g.data
        gb = g.get_json()
        assert gb["passed"] is True and gb["score"] >= 95.0
        assert binding.seed not in g.data.decode()
        guess = {"alerts": [{"id": a["id"], "verdict": "true_positive", "severity": "critical"}
                            for a in scen["alerts"]]}
        g2 = client.post("/grade/submit", json={"handle": c.handle, "submission": guess}, headers=hdr)
        assert g2.get_json()["passed"] is False
    finally:
        os.environ.pop("RANGER_STRATA_PORTFOLIOS", None)
        ctx.pop()


# ======================= 15: Board 2 signed-citation cannot be bypassed ======================
def test_board2_citation_not_bypassable():
    application, db, ctx, _ = _app()
    try:
        c = _cand(db, "b2", "2026-A", 2)
        binding = asn.assign(db, c, 2, portfolio=PORTFOLIO["2026-A"][2])
        try:
            asn.grade(binding, {"anything": True})
            assert False, "board 2 must not be graded by the generic grader"
        except asn.AssignmentError:
            pass
        events, truth = asn.generate(binding, candidate_id=c.github_id)
        idx = "qual-" + binding.spec_id
        reader = case_contract.InMemoryReader(idx, events)
        muid = truth["incidents"][0]["event_uids"][0]
        payload = {"baseline_summary": "b", "overall_conclusion": "c",
                   "incidents": [{"label": "i", "disposition": "confirmed_incident", "severity": "high",
                                  "confidence": 70, "attack_techniques": ["T1078"],
                                  "primary_identity": "u", "affected_assets": ["h"],
                                  "analyst_conclusion": "x",
                                  "cited_evidence": [{"event_uid": muid, "index": idx,
                                                      "query": {"query": {"ids": {"values": [muid]}}},
                                                      "role": "primary"}]}]}
        v = case_contract.verify_evidence(payload, reader, idx, truth=truth)
        assert v["incidents"][0]["citations"][0]["reference_valid"] is True
        bad = _json.loads(_json.dumps(payload))
        bad["incidents"][0]["cited_evidence"][0]["index"] = "someone-else"
        vb = case_contract.verify_evidence(bad, reader, idx, truth=truth)
        assert vb["incidents"][0]["citations"][0]["reference_valid"] is False
    finally:
        ctx.pop()


# ============================================================================================
# S3/S4 INTEGRITY-CLOSURE regression tests (gaps 1-6)
# ============================================================================================

# ---- Gap 1: generator seed is never exposed (legacy AND portfolio routes), recursive ---------
def test_gap1_no_seed_in_legacy_or_portfolio_routes():
    application, db, ctx, _ = _app()
    try:
        client = application.test_client()
        # legacy path (flag OFF): the response and the normalized dataset carry no seed
        c_leg = _cand(db, "leg", "2026-A", 1)
        seed_leg = None
        os.environ.pop("RANGER_STRATA_PORTFOLIOS", None)
        r = client.post("/labs/dataset", json={"handle": c_leg.handle},
                        headers={"X-Candidate-Token": c_leg.token})
        assert r.status_code == 200, r.data
        body = r.get_json()
        from models import ScenarioAssignment
        a = ScenarioAssignment.query.filter_by(github_id=c_leg.github_id, board=1).first()
        seed_leg = a.seed
        assert body.get("case_ref") and "seed" not in body
        _assert_no_leak(body, seed_leg)
        # portfolio path (flag ON): opaque ref only, seed absent everywhere
        os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
        c_pf = _cand(db, "pf", "2026-A", 3)
        r2 = client.post("/labs/dataset", json={"handle": c_pf.handle},
                         headers={"X-Candidate-Token": c_pf.token})
        assert r2.status_code == 200, r2.data
        body2 = r2.get_json()
        from models import ScenarioBinding
        b = ScenarioBinding.query.filter_by(candidate_id=c_pf.id, board=3).first()
        assert b.seed not in r2.data.decode()
        _assert_no_leak(body2, b.seed)
    finally:
        os.environ.pop("RANGER_STRATA_PORTFOLIOS", None)
        ctx.pop()


def test_gap1_normalized_event_has_no_seed_and_opaque_ref():
    """The indexed/normalized telemetry carries an opaque ref, NOT the seed."""
    from siem import schema as s
    seed = "super-secret-seed-123456"
    doc = s.normalized("cand-x", 2, seed, "ds", "process", "exec", "h1", "m", "2026-01-01T00:00:00Z")
    assert "scenario_seed" not in _all_tokens(doc)
    assert seed not in "\x1f".join(_all_tokens(doc))
    assert doc["ranger"]["scenario_ref"] == s.case_ref("cand-x", 2, seed)
    assert s.validate(doc) == []     # the schema still validates with the ref field


# ---- Gap 2: Board 2 generic grading route cannot bypass signed citations ---------------------
def test_gap2_board2_generic_grade_route_cannot_bypass():
    application, db, ctx, _ = _app()
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    os.environ["CI_TOKEN"] = "ci-secret"
    try:
        client = application.test_client()
        c = _cand(db, "b2route", "2026-A", 2)
        hdr = {"X-Candidate-Token": c.token}
        # the generic grader refuses Board 2 (409) and records NO objective credit
        g = client.post("/grade/submit", json={"handle": c.handle, "submission": {"incidents": []}},
                        headers=hdr)
        assert g.status_code == 409, g.data
        from models import BoardResult
        br = BoardResult.query.filter_by(candidate_id=c.id, board=2).first()
        assert (br is None) or (not br.objective_passed and br.objective_score is None), \
            "a generic Board 2 submission must not record objective credit"
        # the CI objective callback also refuses Board 2
        gc = client.post("/grade", json={"handle": c.handle, "board": 2, "score": 100},
                         headers={"X-CI-Token": "ci-secret"})
        assert gc.status_code == 409, gc.data
        br2 = BoardResult.query.filter_by(candidate_id=c.id, board=2).first()
        assert (br2 is None) or (not br2.objective_passed), "CI callback must not clear Board 2"
    finally:
        os.environ.pop("RANGER_STRATA_PORTFOLIOS", None)
        os.environ.pop("CI_TOKEN", None)
        ctx.pop()


# ---- Gap 3: Board 2 candidate projection strips all server-only truth (recursive) ------------
def test_gap3_board2_candidate_view_allowlist_strips_truth():
    application, db, ctx, _ = _app()
    try:
        c = _cand(db, "proj", "2026-A", 2)
        binding = asn.assign(db, c, 2, portfolio=PORTFOLIO["2026-A"][2])
        scen = asn.generate(binding, candidate_id=c.github_id)
        events, truth = scen
        # the raw generated events must themselves be scrubbed, and the candidate_view even more so
        view = asn.candidate_view(binding, scen)
        _assert_no_leak(view, binding.seed, extra_forbidden=("candidate_id", "generator_version",
                                                             "scenario_ref"))
        # every projected event carries ONLY allowlisted keys (no ranger.*, no sibling labels)
        for ev in view["events"]:
            assert set(ev.keys()) <= {"_id", "_source"}
            assert "ranger" not in ev.get("_source", {})
        # a defensive check: even if an upstream event carried a _malicious label and a seed, the
        # projection drops them
        poisoned = [{"_id": "x", "_source": {"message": "m", "ranger": {"scenario_seed": binding.seed}},
                     "_malicious": True}]
        proj = ev_schema.project_candidate_events(poisoned)
        _assert_no_leak(proj, binding.seed, extra_forbidden=("candidate_id",))
        assert proj[0].get("_malicious") is None and "ranger" not in proj[0]["_source"]
    finally:
        ctx.pop()


# ---- Gap 4: cohort portfolio fails closed --------------------------------------------------
def test_gap4_cohort_portfolio_fails_closed():
    application, db, ctx, admin = _app()
    try:
        from models import CohortScenarioPlan, ScenarioBinding
        # (a) a cohort with NO portfolio for the board: required resolution raises, no pool expansion
        c = _cand(db, "fc", "2026-C", 1)     # 2026-C has no configured portfolio
        try:
            asn.resolve_portfolio(db, "2026-C", 1, required=True)
            assert False, "missing portfolio must fail closed"
        except asn.AssignmentError:
            pass
        # the route fails closed (409) and creates no binding, never the legacy generic path
        os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
        r = application.test_client().post("/labs/dataset", json={"handle": c.handle},
                                           headers={"X-Candidate-Token": c.token})
        assert r.status_code == 409, r.data
        assert ScenarioBinding.query.filter_by(candidate_id=c.id, board=1).count() == 0
        # (b) a malformed stored portfolio raises (never silently 'no portfolio')
        row = CohortScenarioPlan(cohort="2026-D", board=1, portfolio_json="{not valid json")
        db.session.add(row); db.session.commit()
        try:
            asn.cohort_portfolio(db, "2026-D", 1)
            assert False, "malformed portfolio must raise"
        except asn.AssignmentError:
            pass
        # (c) saving a portfolio does NOT clobber admin notes / coverage
        plan = CohortScenarioPlan.query.filter_by(cohort="2026-A", board=1).first()
        plan.notes = "operator note: cohort kickoff 2026-01"; db.session.add(plan); db.session.commit()
        asn.set_cohort_portfolio(db, "2026-A", 1, PORTFOLIO["2026-A"][1], admin=admin)
        plan2 = CohortScenarioPlan.query.filter_by(cohort="2026-A", board=1).first()
        assert plan2.notes == "operator note: cohort kickoff 2026-01", "admin notes were clobbered"
        assert asn.cohort_portfolio(db, "2026-A", 1) == PORTFOLIO["2026-A"][1]
        # (d) a portfolio naming a wrong-board / unapproved variant is rejected at set time
        try:
            asn.set_cohort_portfolio(db, "2026-A", 1, ["b3-execution-c2"], admin=admin)
            assert False, "cross-board variant must be rejected"
        except asn.AssignmentError:
            pass
    finally:
        os.environ.pop("RANGER_STRATA_PORTFOLIOS", None)
        ctx.pop()


# ---- Gap 5: real version pinning - replay before AND after a variant revision ----------------
def test_gap5_version_pin_replay_before_and_after_revision():
    application, db, ctx, _ = _app()
    try:
        from models import ScenarioBinding
        vA = "b1-credential-access"
        c = _cand(db, "pin", "2026-A", 1)
        binding = asn.assign(db, c, 1, portfolio=[vA])
        world_before = asn.generate(binding)
        pinned_hash = binding.content_hash
        # simulate a REVISION of the live variant (different technique pool => different world+hash)
        orig = bv.VARIANTS[1][vA]["gen_params"]
        bv.VARIANTS[1][vA]["gen_params"] = {**orig, "tp_techniques": list(bv._B1_EXEC)}
        try:
            live_hash = cat.content_hash(cat.build_spec(1, vA))
            assert live_hash != pinned_hash, "the revision must change the live content hash"
            # the EXISTING binding still reproduces its ORIGINAL world (pinned contract), not the new one
            assert asn.generate(binding) == world_before, "pinned binding must replay the original world"
            cs, _ = asn.grade(binding, cat.board1_correct(world_before))
            assert cs >= 95.0, "grading the pinned world with its own key must still pass"
            # a LEGACY binding (no pinned contract) with the stale hash must FAIL CLOSED after drift
            legacy = ScenarioBinding(candidate_id=c.id, github_id=c.github_id, board=1,
                                     cohort="2026-A", attempt=9, spec_id="strata-b1-" + vA,
                                     spec_version=1, content_hash=pinned_hash, variant_id=vA,
                                     seed=binding.seed, status="bound",
                                     gen_contract=None, gen_hash=None)
            try:
                asn.resolve(legacy)
                assert False, "a legacy binding whose live variant drifted must fail closed"
            except asn.AssignmentError:
                pass
        finally:
            bv.VARIANTS[1][vA]["gen_params"] = orig
        # a TAMPERED pinned contract fails its integrity check
        tampered = ScenarioBinding.query.get(binding.id)
        contract = _json.loads(tampered.gen_contract)
        contract["gen_params"]["id"] = "b1-swapped"      # alter without fixing gen_hash
        tampered.gen_contract = _json.dumps(contract)
        db.session.add(tampered); db.session.commit()
        try:
            asn.resolve(tampered)
            assert False, "a tampered pinned contract must fail closed"
        except asn.AssignmentError:
            pass
    finally:
        ctx.pop()


# ---- Gap 6: real admin authorization for approval and portfolio configuration ----------------
def test_gap6_admin_authorization_is_real():
    application, db, ctx, admin = _app()
    try:
        from models import ScenarioCatalogEntry, AdminUser
        e = ScenarioCatalogEntry.query.filter_by(status="catalog_eligible").first()
        e.status = "calibrated"; db.session.add(e); db.session.commit()
        # a bare string, a ghost (unpersisted) identity, and None are all rejected
        for bogus in ("admin-1", {"github_id": "ghost", "role": "reviewer"}, None):
            try:
                cat.approve(db, e, bogus)
                assert False, f"approval by {bogus!r} must be rejected"
            except cat.CatalogError:
                pass
        # an in-memory AdminUser that was never persisted cannot approve
        transient = AdminUser(github_id="never-saved", login="mallory", role="reviewer")
        try:
            cat.approve(db, e, transient)
            assert False, "an unpersisted AdminUser must not authorize approval"
        except cat.CatalogError:
            pass
        # a sponsor (read-only) cannot approve
        sponsor = AdminUser(github_id="gid-sponsor", login="sam", role="sponsor", org="acme")
        db.session.add(sponsor); db.session.commit()
        try:
            cat.approve(db, e, sponsor)
            assert False, "a sponsor must not approve"
        except cat.CatalogError:
            pass
        # a real persisted reviewer CAN approve
        cat.approve(db, e, admin); db.session.commit()
        assert e.status == "catalog_eligible" and e.approved_by
        # portfolio configuration is likewise gated on a real admin
        for bogus in ("x", None, sponsor, transient):
            try:
                asn.set_cohort_portfolio(db, "2026-A", 1, PORTFOLIO["2026-A"][1], admin=bogus)
                assert False, f"portfolio set by {bogus!r} must be rejected"
            except asn.AssignmentError:
                pass
    finally:
        ctx.pop()


# ======================= concurrency / exhaustion / rollback / unauthorized ==================
def test_concurrent_assignment_is_idempotent_sqlite():
    application, db, ctx, _ = _app()
    try:
        c = _cand(db, "cc", "2026-A", 1)
        results = []

        def go():
            with application.app_context():
                try:
                    b = asn.assign(db, c, 1, portfolio=PORTFOLIO["2026-A"][1])
                    results.append(b.id)
                except Exception as e:  # noqa
                    results.append("ERR:" + str(e)[:30])
                finally:
                    db.session.remove()
        ts = [threading.Thread(target=go) for _ in range(6)]
        [t.start() for t in ts]; [t.join() for t in ts]
        from models import ScenarioBinding
        n = ScenarioBinding.query.filter_by(candidate_id=c.id, board=1, attempt=1).count()
        ids = {r for r in results if isinstance(r, int)}
        assert n == 1 and len(ids) == 1, f"concurrent assign not idempotent: rows={n} ids={ids} res={results}"
    finally:
        ctx.pop()


def test_concurrent_assignment_idempotent_postgres():
    """Gap 6: prove the UNIQUE(candidate, board, attempt) idempotency against a REAL PostgreSQL
    server with independent connections (SQLite threading is not a substitute). Skips with an
    explicit reason when no authorized disposable PG test server is configured (fail-closed)."""
    ok, reason = _pgtest.authorization_status()
    if not ok:
        pytest.skip(f"no authorized PG test server: {reason}")
    import app as appmod
    from models import db, ensure_schema, AdminUser, Cohort, Candidate, ScenarioBinding
    with _pgtest.isolated_pg_database():
        # create_app() reads DATABASE_URL (now the disposable PG) and rebinds the global db engine.
        application = appmod.create_app()
        with application.app_context():
            assert db.engine.dialect.name == "postgresql", "expected the disposable PG engine"
            db.create_all()
            ensure_schema(db)
            if not Cohort.query.filter_by(name="2026-A").first():
                db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
            admin = AdminUser(github_id="gid-admin", login="alice", role="reviewer")
            db.session.add(admin); db.session.commit()
            for e in cat.register_all(db):
                cat.approve(db, e, admin)
            db.session.commit()
            asn.set_cohort_portfolio(db, "2026-A", 1, PORTFOLIO["2026-A"][1], admin=admin)
            c = Candidate(handle="pgc", name="pgc", email="pgc@e", cohort="2026-A",
                          github_id="g-pgc", status="active", current_board=1, token="tok-pgc")
            db.session.add(c); db.session.commit()
            cid = c.id
        results = []

        def go():
            with application.app_context():
                try:
                    cc = Candidate.query.get(cid)
                    b = asn.assign(db, cc, 1, portfolio=PORTFOLIO["2026-A"][1])
                    results.append(b.id)
                except Exception as e:  # noqa
                    results.append("ERR:" + str(e)[:60])
                finally:
                    db.session.remove()
        ts = [threading.Thread(target=go) for _ in range(8)]
        [t.start() for t in ts]; [t.join() for t in ts]
        with application.app_context():
            n = ScenarioBinding.query.filter_by(candidate_id=cid, board=1, attempt=1).count()
            db.session.remove()
            # dispose the PG engine so the disposable database can be dropped cleanly on exit
            db.engine.dispose()
        ids = {r for r in results if isinstance(r, int)}
        errs = [r for r in results if not isinstance(r, int)]
        # integrity errors from the losing racers are fine (they re-read the winner); what matters is
        # exactly one row and one surviving binding id.
        assert n == 1, f"PG concurrent assign created {n} bindings (must be 1): {results}"
        assert len(ids) == 1, f"PG assign returned distinct ids {ids}; errs={errs}"


def test_catalog_exhaustion_is_explicit_no_silent_generic():
    application, db, ctx, _ = _app()
    try:
        c = _cand(db, "ex", "2026-A", 1)
        port = PORTFOLIO["2026-A"][1]
        for at in (1, 2):
            b = asn.assign(db, c, 1, attempt=at, portfolio=port)
            asn.mark_completed(db, b)
        try:
            asn.assign(db, c, 1, attempt=3, portfolio=port)
            assert False, "exhausted pool must raise, not fall back"
        except asn.AssignmentExhausted:
            pass
    finally:
        ctx.pop()


def test_rollback_on_empty_pool_creates_no_binding():
    application, db, ctx, _ = _app()
    try:
        from models import ScenarioBinding
        c = _cand(db, "rb", "2026-A", 1)
        try:
            asn.assign(db, c, 1, portfolio=[])
            assert False
        except asn.AssignmentError:
            pass
        assert ScenarioBinding.query.filter_by(candidate_id=c.id, board=1).count() == 0
    finally:
        ctx.pop()


def test_unauthorized_catalog_change_rejected():
    application, db, ctx, admin = _app()
    try:
        from models import ScenarioCatalogEntry
        e = ScenarioCatalogEntry.query.filter_by(status="catalog_eligible").first()
        e.status = "calibrated"; db.session.add(e); db.session.commit()
        for bogus in ("admin-1", {"github_id": "ghost", "role": "reviewer"}, None):
            try:
                cat.approve(db, e, bogus)
                assert False, f"approval by {bogus!r} must be rejected"
            except cat.CatalogError:
                pass
        assert e.status == "calibrated"
    finally:
        ctx.pop()


# ============================================================================================
# FINAL INTEGRATION CLOSURE regression tests
# ============================================================================================

# ---- Issue 1: Board 2 progression gate is a documented blocking release dependency -----------
def test_issue1_board2_progression_gate_is_blocking_release_dependency():
    """Trace + prove: a Board 2 candidate cannot be cleared/advanced by any default path. The
    objective-award half is unreachable (release-gated); the subjective half alone never clears."""
    application, db, ctx, _ = _app()
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    os.environ["CI_TOKEN"] = "ci-secret"
    try:
        from models import BoardResult
        client = application.test_client()
        c = _cand(db, "b2prog", "2026-A", 2)
        hdr = {"X-Candidate-Token": c.token}
        # satisfy the SUBJECTIVE gate (report approved) so only the objective half is in question
        br = BoardResult(candidate_id=c.id, board=2, report_status="approved")
        db.session.add(br); db.session.commit()
        # no generic path can award the objective half
        assert client.post("/grade/submit", json={"handle": c.handle, "submission": {"incidents": []}},
                           headers=hdr).status_code == 409
        assert client.post("/grade", json={"handle": c.handle, "board": 2, "score": 100},
                           headers={"X-CI-Token": "ci-secret"}).status_code == 409
        # objective stays unearned -> board not cleared -> candidate not advanced past Board 2
        br2 = BoardResult.query.filter_by(candidate_id=c.id, board=2).first()
        assert not br2.objective_passed and br2.objective_score is None
        assert not br2.cleared
        c2 = _reload(db, c.id)
        assert c2.current_board == 2, "candidate must not advance to Board 3 without the live gate"
    finally:
        os.environ.pop("RANGER_STRATA_PORTFOLIOS", None)
        os.environ.pop("CI_TOKEN", None)
        ctx.pop()


def _reload(db, cid):
    from models import Candidate
    return Candidate.query.get(cid)


# ---- Issue 2: approval authority is bound to the authenticated session, not a GitHub id -------
def test_issue2_approval_requires_authenticated_session_not_github_id():
    application, db, ctx, admin = _app()
    try:
        from flask import session
        from models import ScenarioCatalogEntry
        e = ScenarioCatalogEntry.query.filter_by(status="catalog_eligible").first()
        e.status = "calibrated"; db.session.add(e); db.session.commit()
        real_gid = admin.github_id   # a KNOWN, persisted reviewer's GitHub id

        # Inside a request with NO admin session: supplying the known reviewer's id (dict), the id
        # (string), or even the persisted AdminUser object must NOT authorize approval.
        for imposter in ({"github_id": real_gid, "role": "reviewer"}, real_gid, admin):
            with application.test_request_context():
                try:
                    cat.approve(db, e, imposter)
                    assert False, f"unauthenticated approval via {imposter!r} must be rejected"
                except cat.CatalogError:
                    pass
            assert ScenarioCatalogEntry.query.get(e.id).status == "calibrated"

        # portfolio changes are gated the same way
        with application.test_request_context():
            try:
                asn.set_cohort_portfolio(db, "2026-A", 1, PORTFOLIO["2026-A"][1],
                                         admin={"github_id": real_gid, "role": "reviewer"})
                assert False, "unauthenticated portfolio change must be rejected"
            except asn.AssignmentError:
                pass

        # With an AUTHENTICATED admin session, approval proceeds.
        with application.test_request_context():
            session["admin"] = True
            session["admin_login"] = admin.login
            session["admin_gid"] = real_gid
            cat.approve(db, e, None)   # arg ignored; the session is the authority
            db.session.commit()
        assert ScenarioCatalogEntry.query.get(e.id).status == "catalog_eligible"
    finally:
        ctx.pop()


# ---- Release note (a): the scenario reference is keyed (not brute-forceable from a 64-bit seed) --
def test_release_note_a_scenario_ref_is_keyed():
    import importlib
    from siem import schema as s
    legacy_64bit_seed = os.urandom(8).hex()   # the token_hex(8) legacy shape
    saved = os.environ.get("RANGER_REF_KEY")
    try:
        os.environ["RANGER_REF_KEY"] = "key-one"
        importlib.reload(s)
        r1 = s.case_ref("cand", 2, legacy_64bit_seed)
        os.environ["RANGER_REF_KEY"] = "key-two"
        importlib.reload(s)
        r2 = s.case_ref("cand", 2, legacy_64bit_seed)
        # different key => different reference: the ref is keyed, so it cannot be reproduced (or
        # brute-forced back to the seed) without the server secret
        assert r1 and r2 and r1 != r2
        assert legacy_64bit_seed not in (r1 + r2)
    finally:
        if saved is None:
            os.environ.pop("RANGER_REF_KEY", None)
        else:
            os.environ["RANGER_REF_KEY"] = saved
        importlib.reload(s)


# ---- Release note (b): the generation-contract MAC is keyed (tamper-evident vs a DB-only writer) -
def test_release_note_b_gen_contract_mac_is_keyed_tamper_evident():
    import hashlib
    application, db, ctx, _ = _app()
    try:
        from models import ScenarioBinding
        c = _cand(db, "macb", "2026-A", 1)
        binding = asn.assign(db, c, 1, portfolio=["b1-credential-access"])
        # a privileged DB writer WITHOUT the server key alters the contract and recomputes a PLAIN
        # SHA-256 (the best a keyless attacker can do). The stored MAC is keyed, so this is detected.
        contract = _json.loads(binding.gen_contract)
        contract["gen_params"]["id"] = "b1-swapped-by-db-writer"
        forged = _json.dumps(contract, sort_keys=True, separators=(",", ":"))
        binding.gen_contract = forged
        binding.gen_hash = hashlib.sha256(forged.encode()).hexdigest()   # plain digest, no key
        db.session.add(binding); db.session.commit()
        try:
            asn.resolve(ScenarioBinding.query.get(binding.id))
            assert False, "a keyless forged contract+digest must fail the keyed MAC check"
        except asn.AssignmentError:
            pass
    finally:
        ctx.pop()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
