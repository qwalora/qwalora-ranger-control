"""PARALLAX Lab A dev-route security (finding 4): multiply-gated, authenticated, no auto-approval."""
import base64
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "parallax-routes-test")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

import app as appmod  # noqa: E402
from parallax import governance, laba_blueprint as BP  # noqa: E402

_ENVVARS = ("RANGER_PARALLAX_LABA", "RANGER_PARALLAX_LABA_ENV", "RANGER_ENV", "RANGER_PARALLAX_ADMINS",
            "RANGER_PARALLAX_LABA_APPROVAL_B64")


@pytest.fixture()
def client():
    # Snapshot the exact prior values and RESTORE them in teardown, so this suite never clobbers a
    # process-wide var another suite relies on (e.g. STRATA Board 2 sets RANGER_ENV=test at import).
    saved = {k: os.environ.get(k) for k in _ENVVARS}
    # start from a clean slate only for the PARALLAX flags this suite drives; leave RANGER_ENV alone
    for k in ("RANGER_PARALLAX_LABA", "RANGER_PARALLAX_LABA_ENV", "RANGER_PARALLAX_ADMINS",
              "RANGER_PARALLAX_LABA_APPROVAL_B64"):
        os.environ.pop(k, None)
    app = appmod.create_app()
    c = app.test_client()
    yield c
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _valid_approval_b64():
    approval = governance.approve_spec(BP.LABA_SPEC, BP.blueprint(), approver_id="admin-1",
                                       authorized_admins={"admin-1"})
    return base64.b64encode(json.dumps(approval).encode()).decode()


def _enable_nonprod():
    os.environ["RANGER_PARALLAX_LABA"] = "1"
    os.environ["RANGER_PARALLAX_LABA_ENV"] = "development"


def test_404_when_flag_off(client):
    assert client.get("/parallax/laba/brief").status_code == 404


def test_404_without_nonproduction_assertion(client):
    os.environ["RANGER_PARALLAX_LABA"] = "1"   # flag on but no env assertion
    assert client.get("/parallax/laba/brief").status_code == 404


def test_404_when_production_marker_present(client):
    _enable_nonprod()
    os.environ["RANGER_ENV"] = "production"
    assert client.get("/parallax/laba/brief").status_code == 404


def test_401_without_authenticated_candidate_session(client):
    _enable_nonprod()
    os.environ["RANGER_PARALLAX_ADMINS"] = "admin-1"
    os.environ["RANGER_PARALLAX_LABA_APPROVAL_B64"] = _valid_approval_b64()
    # a handle query param must NOT authenticate
    assert client.get("/parallax/laba/brief?handle=gh-alice").status_code == 401


def test_409_without_valid_signed_approval(client):
    _enable_nonprod()
    os.environ["RANGER_PARALLAX_ADMINS"] = "admin-1"   # names alone do not authorize
    with client.session_transaction() as s:
        s["cand"] = "gh-alice"
    assert client.get("/parallax/laba/brief").status_code == 409


def test_409_on_approval_from_unauthorized_approver(client):
    _enable_nonprod()
    os.environ["RANGER_PARALLAX_ADMINS"] = "admin-1"
    bad = governance.approve_spec(BP.LABA_SPEC, BP.blueprint(), approver_id="admin-1",
                                  authorized_admins={"admin-1"})
    bad["record"]["approver_id"] = "intruder"
    os.environ["RANGER_PARALLAX_LABA_APPROVAL_B64"] = base64.b64encode(json.dumps(bad).encode()).decode()
    with client.session_transaction() as s:
        s["cand"] = "gh-alice"
    assert client.get("/parallax/laba/brief").status_code == 409


def test_200_with_all_gates_satisfied(client):
    _enable_nonprod()
    os.environ["RANGER_PARALLAX_ADMINS"] = "admin-1"
    os.environ["RANGER_PARALLAX_LABA_APPROVAL_B64"] = _valid_approval_b64()
    with client.session_transaction() as s:
        s["cand"] = "gh-alice"
    r = client.get("/parallax/laba/brief?cohort=2026-A")
    assert r.status_code == 200
    body = r.get_json()
    assert body["brief"]["simulated"] is True
    # the brief never leaks sealed truth labels
    assert all("classification" not in e for e in body["brief"]["case"]["events"])
