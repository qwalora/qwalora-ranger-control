"""Signed SOC-Analyst (Practice) badge tests.

Passing the detection board (PX-DE1) mints a signed, idempotent SOC-Analyst badge and the dashboard
surfaces it. The grader HTTP result path is exercised with the assessment math and registry approval
stubbed, so the test targets the badge-minting hook itself, not the (separately tested) scoring.
"""
import json

import app as A
from models import db, Candidate, ProgramMembership, ParallaxSubmission, Badge

DET = "parallax-detection-basic"


def _env(monkeypatch):
    monkeypatch.setenv("RANGER_SUBMISSION", "1")
    monkeypatch.setenv("RANGER_ENV", "dev")
    monkeypatch.setenv("RANGER_GRADER_TOKEN", "grader-test-token")


def _stub_grade(monkeypatch, passed):
    import parallax.registry as PR
    import parallax.detection_assessment as DEA
    monkeypatch.setattr(PR, "active_spec_approval", lambda *a, **k: {"record": {"approver_id": "admin"}})
    monkeypatch.setattr(PR, "authorized_admins", lambda *a, **k: {"admin"})
    monkeypatch.setattr(DEA, "run_assessment", lambda **k: {
        "assessment_passed": passed,
        "candidate_feedback": {"final_score": 92.0 if passed else 20.0},
        "signed": {"record": {"record_hash": "abc123"}},
    })


def _mkcand_sub(gid):
    with A.app.app_context():
        c = Candidate.query.filter_by(github_id=gid).first()
        if c is None:
            c = Candidate(handle=gid, name=gid, email=gid + "@nonprod.invalid",
                          cohort="2026-A", github_id=gid, status="active", current_board=1)
            db.session.add(c); db.session.commit()
            db.session.add(ProgramMembership(candidate_id=c.id, program="parallax",
                                             status="active", cohort="2026-A")); db.session.commit()
        n = ParallaxSubmission.query.filter_by(candidate_id=c.id).count()
        sub = ParallaxSubmission(candidate_id=c.id, cohort="2026-A", workload_id=DET,
                                 repo=gid + "-repo", attempt=n + 1, status="grading",
                                 commit_sha="deadbeef", content_digest="0" * 64,
                                 manifest="{}", manifest_sig="sig")
        db.session.add(sub); db.session.commit()
        return c.id, sub.id


def _post_result(client, sid):
    return client.post("/submit/internal/result",
                       data=json.dumps({"submission_id": sid, "board": "PX-DE1",
                                        "measurement": {"metrics": {"findings_available": True}},
                                        "code_sha256": "c0ffee", "grader_version": "test"}),
                       content_type="application/json",
                       headers={"X-Grader-Token": "grader-test-token",
                                "X-CI-Token": "grader-test-token"})


def test_detection_pass_mints_signed_soc_badge(client, monkeypatch):
    _env(monkeypatch)
    _stub_grade(monkeypatch, passed=True)
    cid, sid = _mkcand_sub("soc-pass")
    assert _post_result(client, sid).status_code == 200
    with A.app.app_context():
        b = Badge.query.filter_by(candidate_id=cid, level="soc-practice").first()
        assert b is not None
        assert b.name == "SOC Analyst (Practice)" and b.role == "soc-analyst"
        assert b.signature                                   # signed credential


def test_detection_fail_mints_no_badge(client, monkeypatch):
    _env(monkeypatch)
    _stub_grade(monkeypatch, passed=False)
    cid, sid = _mkcand_sub("soc-fail")
    assert _post_result(client, sid).status_code == 200
    with A.app.app_context():
        assert Badge.query.filter_by(candidate_id=cid, level="soc-practice").first() is None


def test_soc_badge_is_idempotent(client, monkeypatch):
    _env(monkeypatch)
    _stub_grade(monkeypatch, passed=True)
    cid, sid1 = _mkcand_sub("soc-twice")
    _post_result(client, sid1)
    _, sid2 = _mkcand_sub("soc-twice")      # a second passing attempt
    _post_result(client, sid2)
    with A.app.app_context():
        assert Badge.query.filter_by(candidate_id=cid, level="soc-practice").count() == 1


def test_soc_badge_surfaced_on_dashboard(client, monkeypatch):
    _env(monkeypatch)
    _stub_grade(monkeypatch, passed=True)
    cid, sid = _mkcand_sub("soc-dash")
    _post_result(client, sid)
    with client.session_transaction() as s:
        s["cand"] = cid
    html = client.get("/me").get_data(as_text=True)
    assert "SOC Analyst (Practice)" in html
    assert "cryptographically signed" in html
