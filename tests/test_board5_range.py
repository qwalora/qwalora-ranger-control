"""Board 5 (Phase 2 AD range) end to end on the non-governed Railway path: the workspace
serves the enumerable AD graph, the BloodHound dataset downloads, and clearing advances to
board 6 through objective + report with no live-range attestation (that is governed-only)."""
import json

import app as A
from models import db, Candidate, ProgramMembership, BoardResult, Badge


def _cand_board5(gid):
    c = Candidate.query.filter_by(github_id=gid).first()
    if c is None:
        c = Candidate(handle=gid, name=gid, email=gid + "@nonprod.invalid", cohort="2026-A",
                      github_id=gid, status="active", current_board=5)
        db.session.add(c); db.session.commit()
        db.session.add(ProgramMembership(candidate_id=c.id, program="strata", status="active",
                                         cohort="2026-A")); db.session.commit()
    return c


def test_workspace_serves_ad_graph(client):
    with A.app.app_context():
        cid = _cand_board5("b5-data").id
    with client.session_transaction() as sess:
        sess["cand"] = cid
    r = client.get("/me/workspace/data")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["env"] == "ad-range"
    ds = body["dataset"]
    assert ds["domain"]["name"] and ds["users"] and ds["aces"]
    assert "foothold" in ds and ds["foothold"]["sam"]
    # answer-free: the intended path and crackable flags are never served
    assert "intended_path" not in ds
    assert all("crackable" not in u for u in ds["users"])


def test_bloodhound_download(client):
    with A.app.app_context():
        cid = _cand_board5("b5-bh").id
    with client.session_transaction() as sess:
        sess["cand"] = cid
    r = client.get("/me/workspace/bloodhound.zip")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/zip")
    assert r.data[:2] == b"PK" and len(r.data) > 500


def test_board5_clears_and_advances(client, monkeypatch):
    monkeypatch.delenv("RANGER_STRATA_PORTFOLIOS", raising=False)  # governance off
    import ad_range as AR
    monkeypatch.setattr(AR, "grade", lambda seed, sub: (100.0, {"note": "ok"}))
    with A.app.app_context():
        c = _cand_board5("b5-clear")
        db.session.add(BoardResult(candidate_id=c.id, board=5, role="red-teamer",
                                   report_status="approved"))
        db.session.commit()
        cid = c.id
    with client.session_transaction() as sess:
        sess["cand"] = cid
        sess["csrf"] = "t"
    r = client.post("/me/workspace/submit",
                    data=json.dumps({"submission": {"path": [{"source": "a", "technique": "DCSync",
                                                              "target": "b"}]}}),
                    content_type="application/json", headers={"X-CSRF-Token": "t"})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["passed"] is True
    with A.app.app_context():
        c = db.session.get(Candidate, cid)
        assert c.current_board == 6, "board 5 did not clear/advance to the capstone"
        assert Badge.query.filter_by(candidate_id=cid, level="5").first() is not None  # Raider rank
