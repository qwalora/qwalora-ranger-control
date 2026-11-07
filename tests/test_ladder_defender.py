"""Phase 1 ladder completability + the STRATA Defender intermediate credential.

Two properties the "weak ladder" fix must guarantee for a non-governed cohort:
  1. Board 2 (enterprise hunt) is clearable through the standard worksheet + report
     flow - it is no longer a dead-end wall that strands a candidate after board 1.
  2. Clearing the last defensive-core board (4) mints a real, signed, publicly
     verifiable STRATA Defender credential, so a candidate earns a standalone outcome
     before the Phase 2 (GOAD) capstone exists.

Grading is stubbed to isolate the promotion/credential logic (the graders themselves
are covered by test_grader_discrimination). Report approval is pre-set on the board.
"""
import json

import app as A
from models import db, Candidate, ProgramMembership, BoardResult, Badge
import program as P


def _cand(gid, board):
    c = Candidate.query.filter_by(github_id=gid).first()
    if c is None:
        c = Candidate(handle=gid, name=gid, email=gid + "@nonprod.invalid",
                      cohort="2026-A", github_id=gid, status="active", current_board=board)
        db.session.add(c); db.session.commit()
        db.session.add(ProgramMembership(candidate_id=c.id, program="strata",
                                         status="active", cohort="2026-A")); db.session.commit()
    return c


def _approved_board(cid, board, role):
    br = BoardResult(candidate_id=cid, board=board, role=role, report_status="approved")
    db.session.add(br); db.session.commit()


def _submit(client, cid):
    with client.session_transaction() as sess:
        sess["cand"] = cid
        sess["csrf"] = "t"
    return client.post("/me/workspace/submit", data=json.dumps({"submission": {"alerts": []}}),
                       content_type="application/json", headers={"X-CSRF-Token": "t"})


def test_milestone_model():
    assert P.milestone_for_board(4) == P.STRATA_DEFENDER
    assert P.milestone_for_board(1) is None and P.milestone_for_board(3) is None
    assert P.STRATA_DEFENDER["level"] == "defender"
    assert P.is_phase2(5) and P.is_phase2(6) and not P.is_phase2(4)


def test_board2_is_clearable_without_governance(client, monkeypatch):
    monkeypatch.delenv("RANGER_STRATA_PORTFOLIOS", raising=False)  # governance off
    import scenarios as S
    monkeypatch.setattr(S, "grade", lambda n, seed, sub: (100.0, []))
    with A.app.app_context():
        c = _cand("ladder-b2", 2)
        _approved_board(c.id, 2, "threat-hunter")
        cid = c.id
    r = _submit(client, cid)
    assert r.status_code == 200, r.data
    with A.app.app_context():
        c = db.session.get(Candidate, cid)
        assert c.current_board == 3, "board 2 did not clear/advance for a non-governed cohort"
        assert Badge.query.filter_by(candidate_id=cid, level="2").first() is not None  # Tracker rank


def test_board4_clear_mints_signed_strata_defender(client, monkeypatch):
    monkeypatch.delenv("RANGER_STRATA_PORTFOLIOS", raising=False)
    import scenarios as S
    monkeypatch.setattr(S, "grade", lambda n, seed, sub: (100.0, []))
    with A.app.app_context():
        c = _cand("ladder-b4", 4)
        _approved_board(c.id, 4, "incident-responder")
        cid = c.id
    r = _submit(client, cid)
    assert r.status_code == 200, r.data
    with A.app.app_context():
        d = Badge.query.filter_by(candidate_id=cid, level="defender").first()
        assert d is not None, "STRATA Defender credential was not minted on clearing board 4"
        assert d.name == "Qwalora STRATA Defender"
        assert d.cert_id, "intermediate credential has no public cert_id"
        assert d.signature, "intermediate credential is unsigned"
        c = db.session.get(Candidate, cid)
        assert c.current_board == 5, "did not advance to the Phase 2 capstone after the core"


def test_dashboard_surfaces_earned_credential(client):
    from models import Badge
    with A.app.app_context():
        c = _cand("look-surface", 5)
        db.session.add(Badge(candidate_id=c.id, level="defender", name="Qwalora STRATA Defender",
                             role="strata-defender", cert_id="QR-TEST-0007", signature="sig"))
        db.session.commit()
        cid = c.id
    with client.session_transaction() as sess:
        sess["cand"] = cid
    r = client.get("/me")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Your credentials" in body
    assert "Qwalora STRATA Defender" in body and "QR-TEST-0007" in body
    assert "Phase 1" in body and "Phase 2" in body


def test_defender_credential_is_idempotent(client, monkeypatch):
    monkeypatch.delenv("RANGER_STRATA_PORTFOLIOS", raising=False)
    import scenarios as S
    monkeypatch.setattr(S, "grade", lambda n, seed, sub: (100.0, []))
    with A.app.app_context():
        c = _cand("ladder-idem", 4)
        _approved_board(c.id, 4, "incident-responder")
        cid = c.id
    _submit(client, cid)
    _submit(client, cid)  # a second submit must not mint a second credential
    with A.app.app_context():
        assert Badge.query.filter_by(candidate_id=cid, level="defender").count() == 1
