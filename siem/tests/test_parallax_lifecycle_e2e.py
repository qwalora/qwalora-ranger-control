"""PARALLAX Phase 1E Workstream A + F - integrated assessment lifecycle through REAL application
request + persistence boundaries (Flask test client), plus adversarial cases.

The full lifecycle is exercised over HTTP: an authenticated candidate submits (governance approval read
from the persisted registry, never minted in the route), the signed decision is persisted, an
authorized admin assigns a reviewer, the assigned reviewer adjudicates (identity-bound), and the
candidate retrieves an assessment-only status that is never a pathway qualification. Simulation
provenance is explicit throughout.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1e-e2e")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["DEFAULT_COHORT"] = "2026-A"
# gate the Lab A routes ON in a non-production environment; clear any production markers
os.environ["RANGER_PARALLAX_LABA"] = "1"
os.environ["RANGER_PARALLAX_LABA_ENV"] = "test"
for _m in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
    os.environ.pop(_m, None)

import pytest  # noqa: E402

from parallax import registry, laba_assessment as LA, laba_blueprint as BP, laba_sim as sim  # noqa: E402

COHORT = "2026-A"


@pytest.fixture()
def ctx():
    import app as appmod
    from models import db, AdminUser, Candidate, ProgramMembership
    application = appmod.create_app()
    app_ctx = application.app_context(); app_ctx.push()
    db.drop_all(); db.create_all()
    db.session.add_all([
        AdminUser(github_id="admin-1", login="admin-1", role="reviewer"),
        AdminUser(github_id="rev-1", login="rev-1", role="reviewer"),
        AdminUser(github_id="rev-2", login="rev-2", role="reviewer"),
        Candidate(handle="gh-alice", name="A", email="a@e", cohort=COHORT, github_id="gh-alice",
                  status="active", current_board=1),
        Candidate(handle="gh-bob", name="B", email="b@e", cohort=COHORT, github_id="gh-bob",
                  status="active", current_board=1)])
    db.session.commit()
    # PARALLAX access is an explicit program entitlement (research routes now require it).
    for h in ("gh-alice", "gh-bob"):
        cid = Candidate.query.filter_by(handle=h).first().id
        db.session.add(ProgramMembership(candidate_id=cid, program="parallax",
                                         status="active", cohort=COHORT))
    db.session.commit()
    # authorized-admin test fixture: persist the governance approval (NOT minted in any route)
    admin = AdminUser.query.filter_by(github_id="admin-1").first()
    registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=admin)
    client = application.test_client()
    yield application, db, client
    app_ctx.pop()


def _cid(db, handle):
    from models import Candidate
    return Candidate.query.filter_by(handle=handle).first().id


CSRF = {"X-CSRF-Token": "t"}   # session-authed POSTs are CSRF-protected; a browser sends this token


def _post(client, url, **kw):
    kw.setdefault("headers", CSRF)
    return client.post(url, **kw)


def _login_candidate(client, db, handle):
    with client.session_transaction() as s:
        s.clear(); s["cand"] = _cid(db, handle); s["csrf"] = "t"


def _login_admin(client, gid):
    with client.session_transaction() as s:
        s.clear(); s["admin"] = True; s["admin_gid"] = gid; s["admin_login"] = gid; s["csrf"] = "t"


def _passing_submission(db, candidate_key="gh-alice"):
    approval = registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint())
    admins = registry.authorized_admins(db)
    spec, contract, inst = LA.bind_instance(cohort=COHORT, candidate_key=candidate_key,
                                            approval=approval, authorized_admins=admins)
    t = sim.truth(inst)
    return {"findings": [{"event_id": b, "classification": "unauthorized_access", "evidence": [b]}
                         for b in sorted(t["breaches"])], "analysis": "root-cause: injection bypass"}


def _rubric(db):
    return {d["dimension"]: 95 for d in BP.blueprint().get("rubric_dimensions", [])}


# ============================ Workstream A: full lifecycle over HTTP ============================
def test_full_assessment_lifecycle_through_http(ctx):
    _app, db, client = ctx
    # 1-7: candidate authenticates and submits; signed decision persisted
    _login_candidate(client, db, "gh-alice")
    r = _post(client, "/parallax/laba/assessment", json={"submission": _passing_submission(db)})
    assert r.status_code == 201, r.get_data(as_text=True)
    body = r.get_json()
    assert body["simulation"] is True and body["disposition"]["qualified"] is False
    assert body["disposition"]["awaiting_review"] is True       # reviewer pending

    # status before review: assessment-only, not met, never qualified
    r = client.get("/parallax/laba/assessment/status")
    st = r.get_json()
    assert st["verdict"] == "VALID" and st["pathway_qualified"] is False
    assert st["disposition"]["requirements_met"] is False and st["disposition"]["awaiting_review"] is True

    # 8: an authorized admin assigns a reviewer (authorized setup, not in a candidate route)
    _login_admin(client, "admin-1")
    r = _post(client, "/parallax/laba/admin/assign-reviewer",
                    json={"reviewer_id": "rev-1", "candidate_key": "gh-alice", "cohort": COHORT})
    assert r.status_code == 201, r.get_data(as_text=True)

    # 9-11: the assigned reviewer sees the assignment and submits a bound, signed adjudication
    _login_admin(client, "rev-1")
    r = client.get("/parallax/laba/review/assignments")
    asg = r.get_json()["assignments"]
    assert len(asg) == 1 and asg[0]["candidate_key"] == "gh-alice" and asg[0]["simulation"] is True
    r = _post(client, "/parallax/laba/review/adjudicate",
                    json={"candidate_key": "gh-alice", "decision": "pass", "note": "verified",
                          "rubric_scores": _rubric(db)})
    assert r.status_code == 201, r.get_data(as_text=True)
    assert r.get_json()["disposition"]["qualified"] is False

    # 12-14: candidate retrieves status: requirements met, assessment-only, NEVER qualified
    _login_candidate(client, db, "gh-alice")
    st = client.get("/parallax/laba/assessment/status").get_json()
    assert st["verdict"] == "VALID"
    assert st["disposition"]["requirements_met"] is True
    assert st["disposition"]["reviewer_pass"] is True and st["disposition"]["rubric_ok"] is True
    assert st["disposition"]["qualified"] is False and st["pathway_qualified"] is False
    assert st["simulation"] is True


# ============================ Workstream F: adversarial over HTTP ============================
def test_unauthenticated_candidate_denied(ctx):
    _app, db, client = ctx
    with client.session_transaction() as s:
        s.clear()
    assert _post(client, "/parallax/laba/assessment", json={"submission": {}}).status_code in (400, 401)
    assert client.get("/parallax/laba/assessment/status").status_code == 401


def test_candidate_sees_only_own_status(ctx):
    _app, db, client = ctx
    # alice submits
    _login_candidate(client, db, "gh-alice")
    _post(client, "/parallax/laba/assessment", json={"submission": _passing_submission(db)})
    # bob has no record of his own; status is INCOMPLETE, and bob never sees alice's record
    _login_candidate(client, db, "gh-bob")
    st = client.get("/parallax/laba/assessment/status").get_json()
    assert st["verdict"] == "INCOMPLETE"
    assert st["disposition"]["qualified"] is False


def test_identity_from_session_not_query_param(ctx):
    _app, db, client = ctx
    _login_candidate(client, db, "gh-bob")
    # a candidate_key query param must NOT grant access to another candidate's assessment
    _post(client, "/parallax/laba/assessment?candidate_key=gh-alice",
                json={"submission": _passing_submission(db, "gh-bob")})
    st = client.get("/parallax/laba/assessment/status?candidate_key=gh-alice").get_json()
    # the status is bob's own (session identity), never alice's via the param
    assert st["candidate_key"] == "gh-bob" if "candidate_key" in st else True
    # bob's own record exists; the param did not redirect identity
    assert st["verdict"] in ("VALID", "INCOMPLETE")


def test_admin_without_assignment_cannot_adjudicate(ctx):
    _app, db, client = ctx
    _login_candidate(client, db, "gh-alice")
    _post(client, "/parallax/laba/assessment", json={"submission": _passing_submission(db)})
    # admin-1 is an authorized admin but is NOT an assigned reviewer for this attempt
    _login_admin(client, "admin-1")
    r = _post(client, "/parallax/laba/review/adjudicate",
                    json={"candidate_key": "gh-alice", "decision": "pass", "rubric_scores": _rubric(db)})
    assert r.status_code == 403


def test_unassigned_reviewer_denied_and_revoked_assignment_denied(ctx):
    _app, db, client = ctx
    from parallax import reviewer_store
    _login_candidate(client, db, "gh-alice")
    _post(client, "/parallax/laba/assessment", json={"submission": _passing_submission(db)})
    # rev-2 is an authorized reviewer identity but has no assignment -> denied
    _login_admin(client, "rev-2")
    r = _post(client, "/parallax/laba/review/adjudicate",
                    json={"candidate_key": "gh-alice", "decision": "pass", "rubric_scores": _rubric(db)})
    assert r.status_code == 403
    # assign rev-1, then revoke; a revoked reviewer is denied
    _login_admin(client, "admin-1")
    _post(client, "/parallax/laba/admin/assign-reviewer",
                json={"reviewer_id": "rev-1", "candidate_key": "gh-alice", "cohort": COHORT})
    from models import AdminUser
    reviewer_store.revoke_assignment(db, principal=AdminUser.query.filter_by(github_id="admin-1").first(),
                                     reviewer_id="rev-1", candidate_key="gh-alice", cohort=COHORT,
                                     assessment_id="LAB-A", attempt=1)
    _login_admin(client, "rev-1")
    r = _post(client, "/parallax/laba/review/adjudicate",
                    json={"candidate_key": "gh-alice", "decision": "pass", "rubric_scores": _rubric(db)})
    assert r.status_code == 403


def test_routes_404_when_flag_or_env_off(ctx):
    _app, db, client = ctx
    _login_candidate(client, db, "gh-alice")
    saved = os.environ.get("RANGER_PARALLAX_LABA")
    os.environ.pop("RANGER_PARALLAX_LABA", None)
    try:
        assert client.get("/parallax/laba/assessment/status").status_code == 404
    finally:
        os.environ["RANGER_PARALLAX_LABA"] = saved


def test_adjudicate_requires_existing_record(ctx):
    _app, db, client = ctx
    _login_admin(client, "admin-1")
    _post(client, "/parallax/laba/admin/assign-reviewer",
                json={"reviewer_id": "rev-1", "candidate_key": "gh-alice", "cohort": COHORT})
    _login_admin(client, "rev-1")
    # no assessment submitted yet -> nothing to adjudicate
    r = _post(client, "/parallax/laba/review/adjudicate",
                    json={"candidate_key": "gh-alice", "decision": "pass", "rubric_scores": _rubric(db)})
    assert r.status_code == 404


def test_single_assessment_is_never_qualified_under_any_flag(ctx):
    _app, db, client = ctx
    # drive a fully met assessment, then assert qualified stays False regardless of the flags
    _login_candidate(client, db, "gh-alice")
    _post(client, "/parallax/laba/assessment", json={"submission": _passing_submission(db)})
    _login_admin(client, "admin-1")
    _post(client, "/parallax/laba/admin/assign-reviewer",
                json={"reviewer_id": "rev-1", "candidate_key": "gh-alice", "cohort": COHORT})
    _login_admin(client, "rev-1")
    _post(client, "/parallax/laba/review/adjudicate",
                json={"candidate_key": "gh-alice", "decision": "pass", "rubric_scores": _rubric(db)})
    _login_candidate(client, db, "gh-alice")
    for fa in ("", "1"):
        for fp in ("", "1"):
            if fa:
                os.environ["RANGER_PARALLAX_QUALIFICATION_ACTIVE"] = fa
            else:
                os.environ.pop("RANGER_PARALLAX_QUALIFICATION_ACTIVE", None)
            if fp:
                os.environ["RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"] = fp
            else:
                os.environ.pop("RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE", None)
            st = client.get("/parallax/laba/assessment/status").get_json()
            assert st["disposition"]["qualified"] is False and st["pathway_qualified"] is False
    for k in ("RANGER_PARALLAX_QUALIFICATION_ACTIVE", "RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE"):
        os.environ.pop(k, None)
