"""S3/S4 acceptance - cohort-aware scenario diversity, randomized assignment, verified grading.

Two synthetic cohorts, multiple candidates each, exercised through the ACTUAL Ranger architecture
(strata_catalog governance, strata_assignment runtime, the real board generators/graders, and the
live /labs/dataset + /grade/submit candidate routes with the portfolio flag on). Demonstrates the 15
required properties for boards 1-4 plus concurrency, catalog exhaustion, rollback and unauthorized
catalog changes. Tests drive real generation and grading, not metadata-string comparisons.
"""
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECRET_KEY", "s3s4")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

import json as _json  # noqa: E402
import strata_catalog as cat  # noqa: E402
import strata_assignment as asn  # noqa: E402
from siem import board_variants as bv  # noqa: E402
from siem import scenario_pipeline as sp  # noqa: E402
from siem import case_contract  # noqa: E402

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
    # declare each cohort's board portfolio (what makes two cohorts materially different)
    for cohort, boards in PORTFOLIO.items():
        for board, variants in boards.items():
            asn.set_cohort_portfolio(db, cohort, board, variants)
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
            # 1. different approved portfolios
            assert set(pa) != set(pb), f"board {board} cohort portfolios must differ"
            a_only = [v for v in pa if v not in pb]
            b_only = [v for v in pb if v not in pa]
            assert a_only and b_only
            # 2. the difference is STRUCTURAL (diversity axes differ by >= MIN), not cosmetic
            div = sp.axis_divergence(bv.diversity_axes(board, a_only[0]),
                                     bv.diversity_axes(board, b_only[0]))
            assert div >= sp.MIN_DIVERGENT_AXES, f"board {board} variants differ on only {div} axes"
            # 3. equivalent competencies across the board's variants
            comps = {tuple(sorted(bv.competencies(board, v))) for v in pa + pb}
            assert len(comps) == 1, f"board {board} variants must cover equivalent competencies"
            # 4. difficulty parity: calibrated bands within one adjacency step
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
            vA, vB = PORTFOLIO["2026-A"][board]        # two distinct approved variants
            a1 = _cand(db, f"a1b{board}", "2026-A", board)
            a2 = _cand(db, f"a2b{board}", "2026-A", board)
            # bind the two candidates to DIFFERENT variants (materially different cases)
            b1 = asn.assign(db, a1, board, portfolio=[vA])
            b2 = asn.assign(db, a2, board, portfolio=[vB])
            # 5. independently bound cases (distinct bindings, seeds and variants)
            assert b1.id != b2.id and b1.seed != b2.seed and b1.variant_id != b2.variant_id
            sA = asn.generate(b1)
            sB = asn.generate(b2)
            # 7. exact replay from the pinned (variant, seed) reproduces the world + truth
            assert asn.generate(b1) == sA
            # 9. candidate-facing view carries no evaluator truth
            view = _json.dumps(asn.candidate_view(b1, sA))
            assert not any(t in view for t in ('"_key"', '"truth"', '"_flags"', '"_seed"',
                                               '"_techniques"', '"_variant"'))
            # 10. the correct authorized submission grades at/above 95 for each variant
            cs, _ = asn.grade(b1, _correct(board, sA))
            assert cs >= 95.0, f"board {board} variant {vA} correct scored {cs}"
            cs2, _ = asn.grade(b2, _correct(board, sB))
            assert cs2 >= 95.0, f"board {board} variant {vB} correct scored {cs2}"
            # 11. empty cannot reach 95
            empty = {"alerts": []} if board in (1, 4) else {"rules": []}
            es, _ = asn.grade(b1, empty)
            assert es < 95.0
            # 6 + 14. a submission that clears one candidate's case does NOT clear another candidate's
            # materially DIFFERENT case (different variant). For detection (board 3) this is exactly
            # "a ruleset built to pass Cohort A must not auto-pass Cohort B".
            cross, _ = asn.grade(b2, _correct(board, sA))
            assert cross < 95.0, f"board {board} cross-variant transfer scored {cross} (must be <95)"
            # 13. the binding durably pins spec_version + content_hash for historical reproducibility
            assert b1.content_hash and b1.spec_version >= 1 and b1.variant_id == vA
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
        # rotate: a returning candidate gets a DIFFERENT variant (no-repeat), still correctly graded
        b_a2 = asn.assign(db, c, 1, attempt=2, portfolio=port)
        assert b_a2.variant_id != b_a1.variant_id
        s2 = asn.generate(b_a2)
        cs2, _ = asn.grade(b_a2, _correct(1, s2))
        assert cs2 >= 95.0
        # the first attempt's correct answers do not clear the rotated case
        cross, _ = asn.grade(b_a2, _correct(1, s1))
        assert cross < 95.0
    finally:
        ctx.pop()


# ======================= 8: unauthorized / revoked scenarios rejected ========================
def test_unauthorized_and_revoked_rejected():
    application, db, ctx, admin = _app()
    try:
        c = _cand(db, "u1", "2026-A", 1)
        # a portfolio naming an unapproved/unknown variant is rejected
        try:
            asn.assign(db, c, 1, portfolio=["b1-does-not-exist"])
            assert False, "unknown variant must be rejected"
        except asn.AssignmentError:
            pass
        # a revoked (deprecated) catalog entry is not eligible/selectable
        e = cat.eligible(db, 1)[0]
        e.status = "deprecated"; db.session.add(e); db.session.commit()
        remaining = {cat.entry_variant(x) for x in cat.eligible(db, 1)}
        assert cat.entry_variant(e) not in remaining
        # restore for other tests in the module run is unnecessary (fresh app per test)
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
        # /labs/dataset returns the bound variant's dataset with no truth
        r = client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr)
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body["variant"] in PORTFOLIO["2026-A"][1] and body["scenario_ref"].startswith("strata-b1-")
        assert "_key" not in r.data.decode() and "truth" not in body["dataset"]
        # reconstruct the correct submission from the server-side scenario and grade it via the route
        from models import ScenarioBinding
        binding = ScenarioBinding.query.filter_by(candidate_id=c.id, board=1).first()
        scen = asn.generate(binding)
        g = client.post("/grade/submit", json={"handle": c.handle,
                                               "submission": cat.board1_correct(scen)}, headers=hdr)
        assert g.status_code == 200, g.data
        gb = g.get_json()
        assert gb["passed"] is True and gb["score"] >= 95.0 and gb["scenario_ref"] == binding.spec_id
        # a guessed submission through the same route cannot pass
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
        # board 2 is NOT graded by the generic grader (it would bypass citation verification)
        try:
            asn.grade(binding, {"anything": True})
            assert False, "board 2 must not be graded by the generic grader"
        except asn.AssignmentError:
            pass
        # the bound enterprise world still verifies real citations against the candidate's own index
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
        # a foreign-index citation is NOT reference-valid (cannot be bypassed)
        bad = _json.loads(_json.dumps(payload))
        bad["incidents"][0]["cited_evidence"][0]["index"] = "someone-else"
        vb = case_contract.verify_evidence(bad, reader, idx, truth=truth)
        assert vb["incidents"][0]["citations"][0]["reference_valid"] is False
    finally:
        ctx.pop()


# ======================= concurrency / exhaustion / rollback / unauthorized ==================
def test_concurrent_assignment_is_idempotent():
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


def test_catalog_exhaustion_is_explicit_no_silent_generic():
    application, db, ctx, _ = _app()
    try:
        c = _cand(db, "ex", "2026-A", 1)
        port = PORTFOLIO["2026-A"][1]   # two variants
        for at in (1, 2):
            b = asn.assign(db, c, 1, attempt=at, portfolio=port)
            asn.mark_completed(db, b)
        # both variants consumed -> exhaustion is explicit, never a silent generic scenario
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
            asn.assign(db, c, 1, portfolio=[])   # empty portfolio -> no eligible -> raise
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
        # a fresh (unapproved) entry cannot be approved by a non-admin or bare string
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


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
