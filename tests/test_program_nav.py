"""Ranger navigation program-independence tests (authenticated UI, test client).

Renders the real candidate dashboard (/me -> candidate_me.html -> candnav) for each entitlement shape
and asserts the sidebar shows ONLY the entitled program's links: STRATA-only, PARALLAX-only,
dual-entitled (program switcher, each program's links on switch), and a genuinely unentitled user
(membership rows present but none active, so no legacy STRATA fallback).
"""
import app as A
from models import db, Candidate, ProgramMembership

STRATA_LINKS = ("SOC workspace", "Mission brief")
PARALLAX_LINKS = ("Research console", "Investigations")


def _login(client, cid):
    with client.session_transaction() as sess:
        sess["cand"] = cid


def _mk(github_id, memberships):
    """memberships: list of (program, status). Returns candidate id."""
    with A.app.app_context():
        c = Candidate.query.filter_by(github_id=github_id).first()
        if c is None:
            c = Candidate(handle=github_id[:8], name=github_id, email=github_id + "@nonprod.invalid",
                          cohort="2026-A", github_id=github_id, status="active", current_board=1)
            db.session.add(c); db.session.commit()
            for prog, status in memberships:
                db.session.add(ProgramMembership(candidate_id=c.id, program=prog, status=status,
                                                 cohort="2026-A"))
            db.session.commit()
        return c.id


def test_parallax_only_nav_shows_research_not_strata(client, seeded):
    _login(client, seeded["b_id"])                     # parallax active only
    body = client.get("/me").get_data(as_text=True)
    assert all(l in body for l in PARALLAX_LINKS)
    assert not any(l in body for l in STRATA_LINKS)
    assert "/parallax/research/investigations" in body


def test_strata_only_nav_shows_strata_not_research(client, seeded):
    _login(client, seeded["s_id"])                     # strata active only
    body = client.get("/me").get_data(as_text=True)
    assert any(l in body for l in STRATA_LINKS)
    assert not any(l in body for l in PARALLAX_LINKS)
    assert "/parallax/research/investigations" not in body


def test_dual_nav_has_switcher_and_each_program_links_on_switch(client, seeded):
    did = _mk("dual-nav", [("parallax", "active"), ("strata", "active")])
    _login(client, did)
    home = client.get("/me").get_data(as_text=True)
    assert 'role="tablist"' in home and "Your programs" in home      # dual program switcher present
    par = client.get("/me?program=parallax").get_data(as_text=True)
    assert all(l in par for l in PARALLAX_LINKS) and "SOC workspace" not in par
    strat = client.get("/me?program=strata").get_data(as_text=True)
    assert "SOC workspace" in strat or "Mission brief" in strat
    assert "Research console" not in strat


def test_unentitled_user_sees_no_program_links(client, seeded):
    # membership row present but NOT active -> no access, and no legacy STRATA zero-row fallback
    uid = _mk("unentitled-nav", [("parallax", "pending")])
    _login(client, uid)
    body = client.get("/me").get_data(as_text=True)
    assert not any(l in body for l in PARALLAX_LINKS)
    assert not any(l in body for l in STRATA_LINKS)
