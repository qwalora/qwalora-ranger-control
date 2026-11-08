"""End-to-end student onboarding journey: a new ranger applies at /enroll and lands pending with no
access; an admin approves; the student arrives on an active board-1 dashboard with the foundation
gate, the Path-to-Certified roadmap, and the per-board submission contract. This is the exact path a
real student walks, so it must stay green before we onboard anyone."""
import app as A
from models import db, Candidate, ProgramMembership


def _csrf(client):
    with client.session_transaction() as sess:
        sess["csrf"] = "t"


def test_onboarding_enroll_to_active_dashboard(client):
    # 1. the student applies (application, not activation)
    _csrf(client)
    r = client.post("/enroll",
                    data={"handle": "newstudent", "name": "New Student",
                          "email": "new@example.invalid", "cohort": "2026-A",
                          "github_id": "gh-newstudent", "csrf": "t"},
                    headers={"X-CSRF-Token": "t"})
    assert r.status_code == 200, r.data
    with A.app.app_context():
        c = Candidate.query.filter_by(handle="newstudent").first()
        assert c is not None
        assert c.status == "pending" and int(c.current_board) == 1
        m = ProgramMembership.query.filter_by(candidate_id=c.id).first()
        assert m is not None and m.status in ("pending", "requested")  # entitlement applied, no access
        cid = c.id

    # 2. an admin approves -> active, STRATA board 1 opened
    with client.session_transaction() as sess:
        sess["admin"] = True
        sess["admin_gid"] = "reviewer-x"
        sess["csrf"] = "t"
    ra = client.post("/admin/candidates/%d/approve" % cid,
                     data={"csrf": "t"}, headers={"X-CSRF-Token": "t", "Accept": "application/json"})
    assert ra.status_code in (200, 302), ra.data
    with A.app.app_context():
        c = Candidate.query.filter_by(id=cid).first()
        assert c.status == "active"
        assert ProgramMembership.query.filter_by(
            candidate_id=c.id, program="strata", status="active").first() is not None

    # 3. the student signs in and sees an active, working board-1 dashboard
    with client.session_transaction() as sess:
        sess.clear()
        sess["cand"] = cid
    r = client.get("/me")
    assert r.status_code == 200, r.data
    html = r.get_data(as_text=True)
    assert "Welcome" in html
    assert "SOC Analyst" in html                           # board 1 role, on the roadmap
    assert "Path to Certified" in html                     # the roadmap is present
    assert "NetAcad foundation" in html                    # the start-here gate
    assert "How board 1 is scored and submitted" in html   # the per-board submission contract
