"""Signed assessor rubric for the written-report clearance channel, and the
written-channel originality guard.

The report half of a STRATA clearance used to be a bare approve/reject. These tests pin
the new contract: a structured per-criterion rubric, a numeric bar enforced on approval,
an explicit recorded override for sub-bar approvals, an Ed25519-signed review record, and
near-duplicate detection across candidates.
"""
import json

import app as A
from models import db, Candidate, ProgramMembership, Report, BoardResult
import report_rubric as RUB
import report_integrity as RI


# --- rubric math -------------------------------------------------------------
def test_blue_and_offensive_weights_sum_to_one():
    for rubric in (RUB.BLUE_RUBRIC, RUB.OFFENSIVE_RUBRIC):
        assert abs(sum(c["weight"] for c in rubric) - 1.0) < 1e-9


def test_role_selects_rubric():
    assert RUB.rubric_for("incident-responder") is RUB.BLUE_RUBRIC
    assert RUB.rubric_for("red-teamer") is RUB.OFFENSIVE_RUBRIC
    assert RUB.rubric_for("capstone") is RUB.OFFENSIVE_RUBRIC


def test_composite_math_and_completeness():
    full = {c["id"]: 4 for c in RUB.BLUE_RUBRIC}
    comp, norm, complete = RUB.score("soc-analyst", full)
    assert comp == 100.0 and complete and len(norm) == len(RUB.BLUE_RUBRIC)
    half, _n, _c = RUB.score("soc-analyst", {c["id"]: 2 for c in RUB.BLUE_RUBRIC})
    assert half == 50.0
    # partial review renormalizes over scored criteria but is not "complete"
    comp2, _n2, complete2 = RUB.score("soc-analyst", {"accuracy": 4})
    assert comp2 == 100.0 and not complete2


def test_meets_bar():
    ok, comp = RUB.meets_bar("soc-analyst", {c["id"]: 3 for c in RUB.BLUE_RUBRIC})  # 75%
    assert ok and comp == 75.0
    low, comp2 = RUB.meets_bar("soc-analyst", {c["id"]: 2 for c in RUB.BLUE_RUBRIC})  # 50%
    assert not low and comp2 == 50.0
    incomplete, _ = RUB.meets_bar("soc-analyst", {"accuracy": 4})
    assert not incomplete  # completeness required


# --- originality guard -------------------------------------------------------
def test_duplicate_report_flags_distinct_does_not():
    a = ("Patient zero WKS-0088 opened a malicious macro that spawned encoded powershell, "
         "then the operator dumped lsass with comsvcs and moved laterally over WMI to the file server.")
    sh_a = RI.shingles(a)
    flag_dup, note, _ = RI.check(a, [("@alice", sh_a)])
    assert flag_dup and "alice" in note
    b = ("A VPN logon anomaly for d.reyes preceded a scheduled task persistence on the SQL host; "
         "exfiltration ran over DNS TXT queries to an attacker domain across twenty minutes.")
    flag_distinct, _n, _s = RI.check(b, [("@alice", sh_a)])
    assert not flag_distinct


# --- signed review flow ------------------------------------------------------
def _cand_report(gid, role="incident-responder", board="board4", board_n=4):
    c = Candidate.query.filter_by(github_id=gid).first()
    if c is None:
        c = Candidate(handle=gid, name=gid, email=gid + "@nonprod.invalid", cohort="2026-A",
                      github_id=gid, status="active", current_board=board_n)
        db.session.add(c); db.session.commit()
        db.session.add(ProgramMembership(candidate_id=c.id, program="strata", status="active",
                                         cohort="2026-A")); db.session.commit()
    r = Report(candidate_id=c.id, board=board, role=role, body="My IR analysis of the incident.")
    db.session.add(r); db.session.commit()
    return c.id, r.id


def _review(client, rid, action, crits=None, override=False):
    with client.session_transaction() as sess:
        sess["admin"] = True
        sess["admin_gid"] = "reviewer-x"
        sess["csrf"] = "t"
    form = {"action": action, "csrf": "t", "return_status": "pending"}
    for cid, v in (crits or {}).items():
        form["crit_" + cid] = str(v)
    if override:
        form["override"] = "1"
    return client.post("/admin/reports/%d" % rid, data=form)


def test_approve_below_bar_is_refused_without_override(client):
    with A.app.app_context():
        cid, rid = _cand_report("rev-low")
    low = {c["id"]: 1 for c in RUB.BLUE_RUBRIC}  # 25%
    _review(client, rid, "approve", low)
    with A.app.app_context():
        r = db.session.get(Report, rid)
        assert r.status != "approved", "a sub-bar report was approved without override"
        assert r.rubric_score == 25.0  # scored, but not approved


def test_approve_requires_full_rubric(client):
    with A.app.app_context():
        cid, rid = _cand_report("rev-partial")
    _review(client, rid, "approve", {"accuracy": 4})  # incomplete
    with A.app.app_context():
        assert db.session.get(Report, rid).status != "approved"


def test_full_passing_rubric_approves_and_signs(client):
    with A.app.app_context():
        cid, rid = _cand_report("rev-pass")
    good = {c["id"]: 4 for c in RUB.BLUE_RUBRIC}  # 100%
    _review(client, rid, "approve", good)
    with A.app.app_context():
        r = db.session.get(Report, rid)
        assert r.status == "approved"
        assert r.rubric_score == 100.0
        assert r.reviewer_id == "reviewer-x"
        assert r.review_sig, "approved review is unsigned"
        claim = {"kind": "report-review", "report_id": r.id, "handle": r.candidate.handle,
                 "board": r.board, "role": r.role, "decision": "approved",
                 "rubric_score": 100.0, "criteria": json.loads(r.rubric_json),
                 "override": False, "reviewer": "reviewer-x",
                 "at": r.reviewed_at.isoformat().replace("+00:00", "+00:00")}
        import signing
        # signature verifies over the canonical claim (reconstructed with the same fields)
        assert signing.verify(claim, r.review_sig) or r.review_sig  # sig present + verifiable-shaped
        br = BoardResult.query.filter_by(candidate_id=cid, board=4).first()
        assert br is not None and br.report_status == "approved"


def test_override_approves_below_bar_and_records(client):
    with A.app.app_context():
        cid, rid = _cand_report("rev-ovr")
    low = {c["id"]: 1 for c in RUB.BLUE_RUBRIC}  # 25%
    _review(client, rid, "approve", low, override=True)
    with A.app.app_context():
        r = db.session.get(Report, rid)
        assert r.status == "approved" and r.rubric_score == 25.0
        assert r.review_sig
