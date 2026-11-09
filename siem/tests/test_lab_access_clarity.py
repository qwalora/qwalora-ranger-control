"""Candidate lab-access clarity (acceptance checks D/E and G#4-8).

Every authorized assignment must make the environment and launch unambiguous, and must never
misrepresent an environment as ready when it is not. Boards 1 and 2 (ungoverned) are the same
gateway-backed SOC console (OpenSearch). Specifically:
  - When the SOC gateway is configured, the SOC console offers a real launch and never a GOAD
    "Start lab" control; the hunt workspace route is reachable.
  - When the gateway is NOT configured, the console is honestly labeled "Not available yet" /
    "console not configured", offers NO launch, and the next-action never tells the candidate to
    "Start your lab".
These guard the live-acceptance failures: obsolete/ambiguous environment guidance and a false
OpenSearch-readiness promise.
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


def test_board1_soc_console_launch_when_configured_and_no_startlab(ctx):
    # Board 1 is the gateway-backed SOC console (OpenSearch). With the SOC gateway configured it
    # offers a real launch and never a GOAD 'Start lab' control; the hunt workspace is reachable.
    application, p = ctx
    saved = {k: os.environ.get(k) for k in ("RANGER_JWT_PRIVATE_B64", "OPENSEARCH_ADMIN_PASSWORD")}
    os.environ["RANGER_JWT_PRIVATE_B64"] = "x"
    os.environ["OPENSEARCH_ADMIN_PASSWORD"] = "x"
    try:
        cl, html = _dash(application, p["b1"].id)
        assert "SOC console (OpenSearch)" in html, "Board 1 environment must be named the SOC console"
        assert "Open the SOC console" in html, "configured Board 1 must offer the SOC console launch"
        assert "Start lab" not in html, "Board 1 must not show a Start lab (GOAD) control"
        r = cl.get("/me/workspace")
        assert r.status_code == 200, "Board-1 hunt workspace route must be reachable by the candidate"
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def test_board1_soc_console_not_falsely_promised_when_unconfigured(ctx):
    # With the SOC gateway NOT configured (fixture default) the console is honestly labeled
    # unavailable and offers no launch - never a false 'ready' promise, and never a GOAD 'Start lab'.
    application, p = ctx
    _cl, html = _dash(application, p["b1"].id)
    assert "SOC console (OpenSearch)" in html
    assert "Not available yet" in html and "console not configured" in html
    assert "Open the SOC console" not in html, "must not offer a launch while unavailable"
    assert "Start lab" not in html
    assert 'action="/me/start"' not in html
    assert "Start your lab for board" not in html


def test_board2_soc_console_not_falsely_promised(ctx):
    # Board 2 (ungoverned) is the same gateway-backed SOC console; with no gateway it is honestly
    # unavailable, offers no launch and no Start-lab, and never tells the candidate to start a lab.
    application, p = ctx
    _cl, html = _dash(application, p["b2"].id)
    assert "SOC console (OpenSearch)" in html
    assert "Not available yet" in html and "console not configured" in html
    assert "Open the SOC console" not in html
    assert "Start lab" not in html
    assert 'action="/me/start"' not in html
    assert "Start your lab for board 2" not in html
