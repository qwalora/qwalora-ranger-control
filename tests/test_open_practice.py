"""Open-practice access tier tests.

The SOC practice board is self-serve for any signed-in candidate when
RANGER_OPEN_PRACTICE_WORKLOADS names it, while the qualification ladder stays gated.
Proves: the feature is OFF by default (a non-entitled candidate is still denied), when ON a
signed-in non-entitled candidate sees ONLY the open board (not the gated ones), an open-only
candidate cannot fetch a gated board's brief, sign-in is still required, and a fully entitled
candidate still sees every board.
"""
import app as A
from models import db, Candidate, ProgramMembership

DET = "parallax-detection-basic"   # the open SOC practice board
PID = "parallax-pi-basic"          # a gated board


def _mkcand(gid, status, parallax=False):
    with A.app.app_context():
        c = Candidate.query.filter_by(github_id=gid).first()
        if c is None:
            c = Candidate(handle=gid, name=gid, email=gid + "@nonprod.invalid",
                          cohort="2026-A", github_id=gid, status=status, current_board=1)
            db.session.add(c); db.session.commit()
            if parallax:
                db.session.add(ProgramMembership(candidate_id=c.id, program="parallax",
                                                 status="active", cohort="2026-A"))
                db.session.commit()
        return c.id


def _login(client, cid):
    with client.session_transaction() as s:
        s["cand"] = cid


def _gate_env(monkeypatch, opens=""):
    monkeypatch.setenv("RANGER_SUBMISSION", "1")
    monkeypatch.setenv("RANGER_GITHUB_ORG_TOKEN", "test-token")
    monkeypatch.setenv("RANGER_ENV", "dev")
    monkeypatch.setenv("RANGER_SUBMISSION_WORKLOADS", "%s,%s" % (DET, PID))
    monkeypatch.setenv("RANGER_SUBMISSION_WORKLOAD", PID)
    if opens:
        monkeypatch.setenv("RANGER_OPEN_PRACTICE_WORKLOADS", opens)
    else:
        monkeypatch.delenv("RANGER_OPEN_PRACTICE_WORKLOADS", raising=False)


def test_feature_off_non_entitled_still_denied(client, monkeypatch):
    _gate_env(monkeypatch, opens="")
    _login(client, _mkcand("op-off", status="pending", parallax=False))
    assert client.get("/submit/boards").status_code == 403


def test_open_practice_non_entitled_sees_only_open_board(client, monkeypatch):
    _gate_env(monkeypatch, opens=DET)
    _login(client, _mkcand("op-on", status="pending", parallax=False))
    r = client.get("/submit/boards")
    assert r.status_code == 200
    wls = {b["workload_id"] for b in r.get_json()["boards"]}
    assert wls == {DET}                                   # only the open board, not the gated one


def test_open_only_candidate_cannot_fetch_gated_brief(client, monkeypatch):
    _gate_env(monkeypatch, opens=DET)
    _login(client, _mkcand("op-on", status="pending", parallax=False))
    assert client.get("/submit/board?workload=" + DET).status_code == 200
    assert client.get("/submit/board?workload=" + PID).status_code == 403


def test_open_practice_requires_sign_in(monkeypatch):
    _gate_env(monkeypatch, opens=DET)
    anon = A.app.test_client()
    assert anon.get("/submit/boards").status_code == 401


def _mkcand_noaccess(gid):
    """Active candidate with no entitled program. A non-active membership row disables the legacy
    zero-row STRATA fallback, so _effective_programs is empty and no_access is true."""
    with A.app.app_context():
        c = Candidate.query.filter_by(github_id=gid).first()
        if c is None:
            c = Candidate(handle=gid, name=gid, email=gid + "@nonprod.invalid",
                          cohort="2026-A", github_id=gid, status="active", current_board=1)
            db.session.add(c); db.session.commit()
            db.session.add(ProgramMembership(candidate_id=c.id, program="parallax",
                                             status="revoked", cohort="2026-A"))
            db.session.commit()
        return c.id


def test_open_practice_surfaced_on_dashboard(client, monkeypatch):
    _gate_env(monkeypatch, opens=DET)
    _login(client, _mkcand_noaccess("op-dash"))
    html = client.get("/me").get_data(as_text=True)
    assert "Open practice" in html           # the self-serve front door card
    assert 'id="pxd1-card"' in html          # the shared submission UI is rendered


def test_open_practice_off_hides_dashboard_frontdoor(client, monkeypatch):
    _gate_env(monkeypatch, opens="")
    _login(client, _mkcand_noaccess("op-dash2"))
    html = client.get("/me").get_data(as_text=True)
    assert "No program access yet" in html
    assert "Open practice" not in html


def test_fully_entitled_sees_all_boards(client, monkeypatch):
    _gate_env(monkeypatch, opens=DET)
    _login(client, _mkcand("op-entitled", status="active", parallax=True))
    wls = {b["workload_id"] for b in client.get("/submit/boards").get_json()["boards"]}
    assert DET in wls and PID in wls                      # entitlement still grants everything
