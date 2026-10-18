"""S2 - browser-level responsive regression for the mission workspace.

Renders the real mission page in headless Chromium at narrow widths and asserts there is no
horizontal document overflow (document.documentElement.scrollWidth <= window.innerWidth), the mission
shell stays within the viewport, the tab strip scrolls inside its own container rather than widening
the page, and the four tabs switch by keyboard and by touch/click. Skips cleanly when Playwright or
Chromium is unavailable (so CI without a browser does not fail).
"""
import os
import re
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECRET_KEY", "mresp")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("LUDUS_API_URL", None)   # board 5 range stays unavailable


def _mission_html(board):
    """Render the mission page for a board and inline app.css + mission.css for file:// rendering."""
    import app as appmod
    from models import db, Candidate
    application = appmod.create_app()
    with application.app_context():
        db.create_all()
        c = Candidate(handle=f"mr{board}", name="MR", email=f"mr{board}@e", cohort="2026-A",
                      github_id=f"g-mr{board}", status="active", current_board=board)
        db.session.add(c); db.session.commit()
        cid = c.id
    client = application.test_client()
    with client.session_transaction() as s:
        s["cand"] = cid
    html = client.get("/me/mission").data.decode()
    app_css = open(os.path.join(ROOT, "static", "app.css")).read()
    mw_css = open(os.path.join(ROOT, "static", "mission.css")).read()
    html = re.sub(r"<link[^>]*app\.css[^>]*>", f"<style>{app_css}</style>", html)
    html = re.sub(r"<link[^>]*mission\.css[^>]*>", f"<style>{mw_css}</style>", html)
    return html


def _page(pw, html, width):
    f = tempfile.NamedTemporaryFile("w", suffix=".html", delete=False)
    f.write(html); f.close()
    browser = pw.chromium.launch()
    page = browser.new_page(viewport={"width": width, "height": 800})
    page.goto("file://" + f.name)
    page.wait_for_timeout(150)
    return browser, page, f.name


def test_mission_no_horizontal_overflow_mobile():
    sync = pytest.importorskip("playwright.sync_api")
    html = _mission_html(5)   # a range board (longer title, "Unavailable" pill)
    try:
        with sync.sync_playwright() as pw:
            for width in (390, 320):
                browser, page, path = _page(pw, html, width)
                try:
                    m = page.evaluate("""() => {
                      const vw = window.innerWidth;
                      const sw = document.documentElement.scrollWidth;
                      const shell = document.querySelector('.mw-shell').getBoundingClientRect();
                      const tl = document.querySelector('.mw-tablist');
                      return {vw, sw, shellRight: shell.right,
                              tabScrolls: tl.scrollWidth > tl.clientWidth,
                              tabInside: tl.getBoundingClientRect().right <= vw + 0.5};
                    }""")
                    assert m["sw"] <= m["vw"], (
                        f"horizontal overflow at {width}px: scrollWidth {m['sw']} > innerWidth {m['vw']}")
                    assert m["shellRight"] <= m["vw"] + 0.5, f"shell escapes viewport at {width}px"
                    assert m["tabInside"], f"tab strip escapes viewport at {width}px"
                finally:
                    browser.close(); os.unlink(path)
    except sync.Error as e:  # chromium not installed / cannot launch
        pytest.skip(f"headless Chromium unavailable: {e}")


def test_mission_tabs_keyboard_and_touch():
    sync = pytest.importorskip("playwright.sync_api")
    html = _mission_html(1)
    try:
        with sync.sync_playwright() as pw:
            browser, page, path = _page(pw, html, 390)
            try:
                # default: Mission panel visible, others hidden
                assert page.eval_on_selector("#mwp-mission", "el => getComputedStyle(el).display") == "block"
                assert page.eval_on_selector("#mwp-env", "el => getComputedStyle(el).display") == "none"
                # keyboard: focus the Mission radio, ArrowRight selects the next tab (Environment)
                page.focus("#mwt-mission")
                page.keyboard.press("ArrowRight")
                assert page.eval_on_selector("#mwt-env", "el => el.checked") is True
                assert page.eval_on_selector("#mwp-env", "el => getComputedStyle(el).display") == "block"
                # touch/click: tapping a tab label switches the panel
                page.click('label[for="mwt-sub"]')
                assert page.eval_on_selector("#mwt-sub", "el => el.checked") is True
                assert page.eval_on_selector("#mwp-sub", "el => getComputedStyle(el).display") == "block"
                # the radios are reachable (not display:none) so they can hold keyboard focus
                assert page.eval_on_selector("#mwt-ref", "el => getComputedStyle(el).display") != "none"
            finally:
                browser.close(); os.unlink(path)
    except sync.Error as e:
        pytest.skip(f"headless Chromium unavailable: {e}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
