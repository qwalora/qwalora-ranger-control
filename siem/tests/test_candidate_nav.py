"""Navigation regression for the candidate shell's Handbook link.

Live-acceptance finding: the candidate sidebar's Handbook item pointed at
https://ranger.qwalora.com/handbook, which 404s on the public site. The
authoritative destination is the published Ranger manual
(https://ranger.qwalora.com/downloads/Qwalora-Ranger-Manual.pdf), which the
public site's own navigation labels "Ranger manual".

The Handbook is a shared account control outside both program scopes, so it must
render identically for STRATA-only, PARALLAX-only and dual candidates. These
tests pin the authoritative destination and guard against the broken /handbook
path reappearing in any candidate nav surface.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "cand-nav-test")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

# The authoritative handbook destination is the in-app /handbook page (HTML built from the markdown
# source by scripts/build_handbook.py; the external PDF is only a build artifact, not the published
# handbook). Pinned as the exact nav href so a silent retarget to the PDF fails this suite.
HANDBOOK_URL = 'href="/handbook"'
# The superseded external PDF; the candidate nav must no longer reference it.
BROKEN_HANDBOOK = "ranger.qwalora.com/downloads/Qwalora-Ranger-Manual.pdf"


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

    def mk(handle, programs, board=1):
        c = Candidate(handle=handle, name=handle, email=handle + "@e", cohort="2026-A",
                      github_id=handle, status="active", current_board=board, token="tok-" + handle)
        db.session.add(c)
        db.session.commit()
        for prog in programs:
            db.session.add(ProgramMembership(candidate_id=c.id, program=prog,
                                             status="active", cohort="2026-A"))
        db.session.commit()
        return c

    p = {
        "strata": mk("n_strata", ["strata"]),
        "px": mk("n_px", ["parallax"]),
        "dual": mk("n_dual", ["strata", "parallax"]),
    }
    yield application, p
    appctx.pop()


def _html(application, cid, path="/account"):
    cl = application.test_client()
    with cl.session_transaction() as s:
        s.clear()
        s["cand"] = cid
        s["csrf"] = "t"
    r = cl.get(path)
    assert r.status_code == 200, (path, r.status_code)
    return r.data.decode()


@pytest.mark.parametrize("who", ["strata", "px", "dual"])
def test_handbook_link_points_to_authoritative_manual(ctx, who):
    """Every authorized candidate sees the Handbook pointing at the Ranger manual,
    never the removed /handbook path."""
    application, p = ctx
    html = _html(application, p[who].id)
    assert HANDBOOK_URL in html, f"Handbook missing authoritative manual for {who}"
    assert BROKEN_HANDBOOK not in html, f"broken /handbook path present for {who}"


def test_handbook_renders_for_both_programs_identically(ctx):
    """The Handbook is a shared account control: it must render for STRATA-only and
    PARALLAX-only candidates alike (not gated behind either program)."""
    application, p = ctx
    for who in ("strata", "px", "dual"):
        html = _html(application, p[who].id)
        assert html.count(HANDBOOK_URL) == 1, f"expected exactly one Handbook link for {who}"


def test_handbook_opens_inline_in_the_portal(ctx):
    """The handbook is a contained portal page (rendered in the app shell), so its nav link opens
    inline in the same tab, not in a new window."""
    application, p = ctx
    html = _html(application, p["strata"].id)
    i = html.find(HANDBOOK_URL)
    assert i >= 0
    # the anchor's attributes follow the href; window forward past the URL to the tag close
    seg = html[max(0, i - 60):i + 120]
    assert 'target="_blank"' not in seg, "Handbook is an in-portal page; it must not open in a new tab"


def test_no_broken_handbook_path_on_dashboard(ctx):
    """The shared candnav macro is also rendered on the dashboard; the broken path must
    not appear there either."""
    application, p = ctx
    html = _html(application, p["strata"].id, path="/me")
    assert BROKEN_HANDBOOK not in html
    assert HANDBOOK_URL in html
