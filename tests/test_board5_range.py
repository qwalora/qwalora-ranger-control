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


def test_board6_forest_serves_and_clears_to_certified(client, monkeypatch):
    monkeypatch.delenv("RANGER_STRATA_PORTFOLIOS", raising=False)
    import ad_range as AR
    monkeypatch.setattr(AR, "grade_forest", lambda seed, sub: (100.0, {"note": "ok"}))
    with A.app.app_context():
        c = Candidate.query.filter_by(github_id="b6-clear").first()
        if c is None:
            c = Candidate(handle="b6-clear", name="b6", email="b6@nonprod.invalid", cohort="2026-A",
                          github_id="b6-clear", status="active", current_board=6)
            db.session.add(c); db.session.commit()
            db.session.add(ProgramMembership(candidate_id=c.id, program="strata", status="active",
                                             cohort="2026-A")); db.session.commit()
        db.session.add(BoardResult(candidate_id=c.id, board=6, role="capstone",
                                   report_status="approved"))
        db.session.commit()
        cid = c.id
    # the forest workspace serves a 3-domain graph
    with client.session_transaction() as sess:
        sess["cand"] = cid
    data = client.get("/me/workspace/data").get_json()
    assert data["env"] == "ad-range" and "domains" in data["dataset"]
    assert len(data["dataset"]["domains"]) == 3
    # clearing board 6 graduates the candidate (certified)
    with client.session_transaction() as sess:
        sess["cand"] = cid
        sess["csrf"] = "t"
    r = client.post("/me/workspace/submit",
                    data=json.dumps({"submission": {"path": [{"source": "a", "technique": "DCSync",
                                                              "target": "b"}]}}),
                    content_type="application/json", headers={"X-CSRF-Token": "t"})
    assert r.status_code == 200, r.data
    with A.app.app_context():
        assert Badge.query.filter_by(candidate_id=cid, level="certified").first() is not None, \
            "clearing board 6 did not mint the terminal certification"


def test_board5_live_range_requires_compromise(client, monkeypatch):
    """When the live range is enabled, the attack-path objective plus an approved report is NOT
    enough to clear board 5: a verified live compromise is required (fail-closed). A creditable
    compromise then drives promotion to board 6."""
    monkeypatch.delenv("RANGER_STRATA_PORTFOLIOS", raising=False)  # governance off
    import ad_range as AR
    import adrange_live as AL
    monkeypatch.setattr(AR, "grade", lambda seed, sub: (100.0, {"note": "ok"}))
    monkeypatch.setattr(AL, "enabled", lambda: True)
    monkeypatch.setattr(AL, "verify_attestation",
                        lambda rec, **k: (bool(rec), "ok" if rec else "no attestation"))
    with A.app.app_context():
        c = _cand_board5("b5-live")
        db.session.add(BoardResult(candidate_id=c.id, board=5, role="red-teamer",
                                   report_status="approved"))
        db.session.commit()
        cid = c.id
    with client.session_transaction() as sess:
        sess["cand"] = cid
        sess["csrf"] = "t"
    # the isolated-board dashboard renders (exercises _submit_guide's live-range branch)
    assert client.get("/me").status_code == 200
    # attack-path objective passes, but without a live compromise the board does NOT clear
    r = client.post("/me/workspace/submit",
                    data=json.dumps({"submission": {"path": [{"source": "a", "technique": "DCSync",
                                                              "target": "b"}]}}),
                    content_type="application/json", headers={"X-CSRF-Token": "t"})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["passed"] is True and body["promoted"] is False
    with A.app.app_context():
        assert Candidate.query.filter_by(id=cid).first().current_board == 5
    # a creditable, verified compromise then clears the board and advances to 6
    monkeypatch.setattr(AL, "validate_live",
                        lambda **k: {"ok": True, "reachable": True, "checks": {}, "reason": "ok"})
    monkeypatch.setattr(AL, "verify_trophy",
                        lambda c, n, **k: {"ok": True, "present": True, "reachable": True,
                                           "reason": "trophy present", "flag": "pwn-test"})
    monkeypatch.setattr(AL, "attest",
                        lambda c, n, **k: (True, {"mode": "real", "real": True, "handle": "x"}))
    r2 = client.post("/me/workspace/compromise",
                     data=json.dumps({}),
                     content_type="application/json", headers={"X-CSRF-Token": "t"})
    assert r2.status_code == 200, r2.data
    assert r2.get_json()["promoted"] is True
    with A.app.app_context():
        assert Candidate.query.filter_by(id=cid).first().current_board == 6
