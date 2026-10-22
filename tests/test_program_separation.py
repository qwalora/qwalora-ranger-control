"""PARALLAX / STRATA program-separation tests.

Proves the two programs are independent: STRATA enrollment grants no PARALLAX access and vice versa,
dual-entitled users see both, research and training data/metrics never cross, ownership is enforced,
signed evidence survives the route migration, and the deprecated /parallax/strata/* URLs cannot be
used to bypass the boundary (and never redirect an unauthorized user into the other program).
"""
import app as A
from models import db, Candidate, ProgramMembership, Report
from parallax.research import store as rstore

RESEARCH_TRACE = "/parallax/research/traces"
RESEARCH_INV = "/parallax/research/investigations"
STRATA_WORKSPACE = "/me/workspace"
STRATA_WORKSPACE_JSON = "/me/workspace/data"


def _login(client, cid):
    with client.session_transaction() as sess:
        sess["cand"] = cid


def _dual_candidate():
    """A candidate entitled to BOTH programs (created once)."""
    with A.app.app_context():
        c = Candidate.query.filter_by(github_id="dual-researcher").first()
        if c is None:
            c = Candidate(handle="dual", name="Dual", email="dual@nonprod.invalid",
                          cohort="2026-A", github_id="dual-researcher", status="active", current_board=1)
            db.session.add(c); db.session.commit()
            for prog in ("parallax", "strata"):
                db.session.add(ProgramMembership(candidate_id=c.id, program=prog, status="active",
                                                 cohort="2026-A"))
            db.session.commit()
        return c.id


# --------------------------------------------------------------- 1. STRATA-only cannot access PARALLAX

def test_strata_only_user_denied_parallax_research(client, seeded):
    _login(client, seeded["s_id"])
    for url in (RESEARCH_TRACE, RESEARCH_INV):
        r = client.get(url)
        assert r.status_code in (302, 303)
        assert "PARALLAX Research" not in r.get_data(as_text=True)


# --------------------------------------------------------------- 2. PARALLAX-only cannot access STRATA

def test_parallax_only_user_denied_strata(client, seeded):
    _login(client, seeded["b_id"])                     # rb-researcher: parallax active, no strata
    r = client.get(STRATA_WORKSPACE)
    assert r.status_code in (302, 303)                 # entitlement denial -> own dashboard
    assert (r.headers.get("Location") or "").rstrip("/").endswith("/me")
    # the JSON data surface is a hard 403 (no redirect leak) when JSON is requested
    rj = client.get(STRATA_WORKSPACE_JSON, headers={"Accept": "application/json"})
    assert rj.status_code == 403


# --------------------------------------------------------------- 3. dual-entitled sees two programs

def test_dual_entitled_user_reaches_both_programs(client, seeded):
    did = _dual_candidate()
    _login(client, did)
    # PARALLAX side works
    assert client.get(RESEARCH_TRACE).status_code == 200
    # STRATA side is NOT an entitlement denial (200, or board routing to the mission page) - crucially
    # the Location is not the bare own-dashboard denial that a non-entitled user gets.
    r = client.get(STRATA_WORKSPACE)
    assert r.status_code == 200 or "/me/mission" in (r.headers.get("Location") or "")
    # both memberships are active
    with A.app.app_context():
        progs = {m.program for m in ProgramMembership.query.filter_by(candidate_id=did, status="active")}
    assert {"parallax", "strata"} <= progs


# --------------------------------------------------------------- 4. no research findings in STRATA scores

def test_research_run_creates_no_strata_report(client, seeded):
    with A.app.app_context():
        before = Report.query.count()
        camp = {"manifest": {"kind": "trial", "backend": {"is_real": False, "model_id": "stub"},
                             "n_records": 1},
                "metrics": {"kind": "trial", "record": {"outcome": "boundary_preserved",
                                                        "condition": "baseline_benign"}}}
        rstore.persist_run(db, researcher_id="rb-researcher", campaign=camp)
        after = Report.query.count()
    assert after == before                              # research persistence writes NO STRATA report


# --------------------------------------------------------------- 5. no training grades in PARALLAX metrics

def test_parallax_overview_contains_only_research_kinds(client, seeded):
    with A.app.app_context():
        items = rstore.overview_for(db, authenticated_researcher_id="rb-researcher")
    assert items                                        # the researcher has research runs
    assert all(i.get("kind") in ("trial", "investigation") for i in items)   # never STRATA training data


# --------------------------------------------------------------- 6. ownership enforced on new routes

def test_cross_owner_and_unknown_are_identical_404_on_new_route(client, seeded):
    _login(client, seeded["a_id"])                     # researcher A requests B's run id
    foreign = client.get(RESEARCH_TRACE + "/" + seeded["b_run"])
    nonexistent = client.get(RESEARCH_TRACE + "/run-does-not-exist")
    assert foreign.status_code == 404 and nonexistent.status_code == 404
    assert foreign.get_data(as_text=True) == nonexistent.get_data(as_text=True)


# --------------------------------------------------------------- 7. signed evidence survives migration

def test_signed_evidence_verifies_through_new_route(client, seeded):
    # the fixture researcher A has a signed trial + investigation; it must still verify and be reachable
    with A.app.app_context():
        runs = rstore.runs_for(db, authenticated_researcher_id=seeded["a_gid"])
        trial = next((r for r in runs if r.get("kind") == "trial"), runs[0])
        full = rstore.get_run(db, run_id=trial["run_id"], authenticated_researcher_id=seeded["a_gid"])
    assert full is not None and full.get("signature_verifies") is True   # signature intact post-migration
    _login(client, seeded["a_id"])
    assert client.get(RESEARCH_INV).status_code == 200


# --------------------------------------------------------------- 8. old URLs cannot bypass the boundary

def test_legacy_strata_urls_gate_and_redirect_correctly(client, seeded):
    # (a) non-PARALLAX user: gated away, NEVER redirected into the PARALLAX program
    _login(client, seeded["s_id"])
    for url in ("/parallax/strata/trace", "/parallax/strata/investigation"):
        r = client.get(url)
        assert r.status_code in (302, 303)
        assert not (r.headers.get("Location") or "").startswith("/parallax/research")
    # (b) authorized PARALLAX user: legacy URL redirects to the correctly named research route
    _login(client, seeded["b_id"])
    rt = client.get("/parallax/strata/trace")
    assert rt.status_code in (301, 302) and (rt.headers.get("Location") or "").startswith("/parallax/research/traces")
    ri = client.get("/parallax/strata/investigation")
    assert ri.status_code in (301, 302) and (ri.headers.get("Location") or "").startswith("/parallax/research/investigations")


def test_unauthenticated_legacy_url_goes_to_login_not_research(client):
    for url in ("/parallax/strata/trace", "/parallax/strata/investigation"):
        r = client.get(url)
        assert r.status_code in (302, 303)
        assert not (r.headers.get("Location") or "").startswith("/parallax/research")
