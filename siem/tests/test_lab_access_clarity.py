"""Candidate lab-access clarity (acceptance checks D/E and G#4-8).

Every authorized assignment must make the environment and launch unambiguous, and must never
misrepresent an environment as ready when it is not. Specifically:
  - Board 1 (Sentinel) is PORTAL-HOSTED: the dashboard offers the SOC workspace launch, states
    no external SIEM/OpenSearch/VPN is required, and shows NO "Start lab" (GOAD) control.
  - Board 2 (Tracker) is a live OpenSearch SOC that is NOT candidate-accessible by default: the
    dashboard labels it "Not available yet", offers NO launch and NO OpenSearch button, and the
    next-action never tells the candidate to "Start your lab".
  - The Board-1 SOC launch reaches the real authorized workspace route.
These guard the two live-acceptance failures: obsolete/ambiguous environment guidance and a
false OpenSearch promise.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "lab-access-test")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
# ensure Board-2 SOC gateway / case UI are NOT configured, so Board 2 is honestly unavailable
for _k in ("RANGER_CASE_UI", "RANGER_JWT_PRIVATE_B64", "OPENSEARCH_ADMIN_PASSWORD"):
    os.environ.pop(_k, None)

import pytest  # noqa: E402


@pytest.fixture()
def ctx():
    import importlib
    import app as appmod
    importlib.reload(appmod)
    from models import db, Candidate, Cohort, ProgramMembership
    application = appmod.create_app()
    appctx = application.app_context()
    appctx.push()
    db.drop_all()
    db.create_all()
    db.session.add(Cohort(name="2026-A", sequence=1, status="active", pathway="strata"))
    db.session.commit()

    def mk(handle, board):
        c = Candidate(handle=handle, name=handle, email=handle + "@e", cohort="2026-A",
                      github_id=handle, status="active", current_board=board, token="tok-" + handle)
        db.session.add(c)
        db.session.commit()
        db.session.add(ProgramMembership(candidate_id=c.id, program="strata",
                                         status="active", cohort="2026-A"))
        db.session.commit()
        return c

    p = {"b1": mk("lac_b1", 1), "b2": mk("lac_b2", 2)}
    yield application, p
    appctx.pop()


def _dash(application, cid):
    cl = application.test_client()
    with cl.session_transaction() as s:
        s.clear()
        s["cand"] = cid
        s["csrf"] = "t"
    r = cl.get("/me")
    assert r.status_code == 200
    return cl, r.data.decode()


def test_board1_portal_hosted_launch_and_no_startlab(ctx):
    application, p = ctx
    cl, html = _dash(application, p["b1"].id)
    # portal-hosted environment is named and the SOC workspace launch is present
    assert "Portal-hosted SOC workspace" in html
    assert 'href="/me/workspace"' in html, "Board 1 must offer the SOC workspace launch"
    # the clarity statement that no external SIEM/OpenSearch is required
    assert "No external SIEM, OpenSearch" in html
    # NO GOAD 'Start lab' control on a portal-hosted board
    assert "Start lab" not in html, "Board 1 must not show a Start lab (range) control"
    # the Board-1 SOC launch reaches a real authorized workspace
    r = cl.get("/me/workspace")
    assert r.status_code == 200, "Board-1 SOC workspace route must be reachable by the candidate"


def test_board2_opensearch_not_falsely_promised(ctx):
    application, p = ctx
    cl, html = _dash(application, p["b2"].id)
    # the environment is named as OpenSearch-via-gateway but labeled not available
    assert "Private OpenSearch SOC (Ranger gateway)" in html
    assert "Not available yet" in html, "Board 2 OpenSearch must be labeled unavailable"
    # no launch / Start-lab control is offered while unavailable
    assert "Start lab" not in html
    assert 'action="/me/start"' not in html
    # the next-action must NOT tell the candidate to start a lab for board 2
    assert "Start your lab for board 2" not in html
    # the honest unavailable message is shown
    assert "not yet available in this environment" in html


def test_board2_workspace_launch_not_shown(ctx):
    # the SOC workspace launch is Board-1 only; Board 2 must not present it
    application, p = ctx
    _cl, html = _dash(application, p["b2"].id)
    assert 'href="/me/workspace"' not in html
