"""Ranger Foundation Track (Cisco NetAcad) tests.

Proves: the dashboard renders the NetAcad foundation card with the real public enroll links and the
program-aligned 'maps to' mapping; the must-take gate counts attestations; the attest endpoint
toggles a course complete/incomplete and reports progress; and the track is program-specific
(STRATA = Junior Cybersecurity Analyst + Ethical Hacker, PARALLAX = security fundamentals).
"""
import app as A
import netacad_foundation as NAF
from models import db, Candidate, ProgramMembership, FoundationAttestation


def _mkcand(gid, program):
    with A.app.app_context():
        c = Candidate.query.filter_by(github_id=gid).first()
        if c is None:
            c = Candidate(handle=gid, name=gid + " Ranger", email=gid + "@nonprod.invalid",
                          cohort="2026-A", github_id=gid, status="active", current_board=1)
            db.session.add(c); db.session.commit()
            db.session.add(ProgramMembership(candidate_id=c.id, program=program,
                                             status="active", cohort="2026-A"))
            db.session.commit()
        return c.id


def _login(client, cid):
    with client.session_transaction() as s:
        s["cand"] = cid


def _csrf(client):
    """Seed the CSRF token the way a dashboard render does, then read it back for the POST header."""
    client.get("/me")
    with client.session_transaction() as s:
        return s.get("csrf") or ""


def test_dashboard_shows_compact_foundation_tile(client):
    _login(client, _mkcand("naf-tile", "strata"))
    html = client.get("/me").get_data(as_text=True)
    # the dashboard carries only a compact metric tile linking to the Foundation tab,
    # not the full course list (that moved off the metrics-focused dashboard)
    assert 'href="/me/foundation"' in html
    assert "Foundation" in html
    assert "self-enroll/m/course-1605348" not in html


def test_strata_foundation_card_renders_with_real_links(client):
    _login(client, _mkcand("naf-strata", "strata"))
    html = client.get("/me/foundation").get_data(as_text=True)
    assert "Must take" in html
    # verified public self-enroll deep link (instance-scoped) for the universal entry course
    assert "instance_id=07160b4f-b734-42fb-aaba-d7d43c27bcdc" in html
    # the Junior Cybersecurity Analyst path courses are present and aligned
    assert "Network Defense" in html and "Cyber Threat Management" in html and "Ethical Hacker" in html
    assert "Maps to:" in html


def test_parallax_foundation_is_security_fundamentals(client):
    _login(client, _mkcand("naf-parallax", "parallax"))
    html = client.get("/me/foundation").get_data(as_text=True)
    # PARALLAX foundation is the 2-course security-fundamentals set: intro + network defense
    # (Cisco retired the standalone Cybersecurity Essentials; Network Defense now carries it).
    assert "Introduction to Cybersecurity" in html and "Network Defense" in html
    assert "instance_id=2478667b-3096-436b-a0d9-63055e781c93" in html  # network-defense self-enroll
    # the 2-course fundamentals set, not the full STRATA ladder path
    assert "0/2" in html


def test_attest_endpoint_toggles_and_counts(client):
    cid = _mkcand("naf-attest", "strata")
    _login(client, cid)
    tok = _csrf(client)
    total = len(NAF.required_course_keys("strata"))
    # mark one complete
    r = client.post("/me/foundation/attest",
                    data={"program": "strata", "course": "intro-cyber", "done": "1"},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    j = r.get_json()
    assert j["done"] == 1 and j["total"] == total and j["complete"] is False
    with A.app.app_context():
        assert FoundationAttestation.query.filter_by(
            candidate_id=cid, program="strata", course_key="intro-cyber").count() == 1
    # un-mark it
    r = client.post("/me/foundation/attest",
                    data={"program": "strata", "course": "intro-cyber", "done": "0"},
                    headers={"X-CSRF-Token": tok})
    assert r.get_json()["done"] == 0
    with A.app.app_context():
        assert FoundationAttestation.query.filter_by(
            candidate_id=cid, program="strata", course_key="intro-cyber").count() == 0


def test_attest_rejects_unknown_course(client):
    _login(client, _mkcand("naf-bad", "strata"))
    tok = _csrf(client)
    r = client.post("/me/foundation/attest",
                    data={"program": "strata", "course": "not-a-course", "done": "1"},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 400


def test_full_completion_flips_gate(client):
    cid = _mkcand("naf-complete", "parallax")
    _login(client, cid)
    tok = _csrf(client)
    for k in NAF.required_course_keys("parallax"):
        r = client.post("/me/foundation/attest",
                        data={"program": "parallax", "course": k, "done": "1"},
                        headers={"X-CSRF-Token": tok})
    assert r.get_json()["complete"] is True
    html = client.get("/me/foundation").get_data(as_text=True)
    assert "Foundation complete" in html
