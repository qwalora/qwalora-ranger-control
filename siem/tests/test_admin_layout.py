"""Admin layout regressions for the width/nav fixes (static assertions; no app needed).

Operations was capped at a narrow 900px column; the compact rail rendered as a stray column on
Ranges/Cohort/reports. These assert the corrected, responsive rules stay in place.
"""
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read(*parts):
    return io.open(os.path.join(ROOT, *parts), encoding="utf-8").read()


def test_compact_rail_hidden_on_shell():
    css = _read("static", "app.css")
    # the redundant rail is hidden so it never renders as a stray column
    assert ".app .rail{display:none}" in css


def test_operations_uses_available_width_responsively():
    html = _read("templates", "admin_ops.html")
    # wider readable max + responsive two-column grid that collapses on narrow viewports
    assert "max-width:1240px" in html
    assert "grid-template-columns:1fr 1fr" in html
    assert "@media(max-width:860px)" in html
    # the old narrow cap is gone
    assert "max-width:900px" not in html


def test_research_review_is_responsive():
    css = _read("static", "app.css")
    html = _read("templates", "admin_research_review.html")
    nav = _read("templates", "_adminnav.html")
    assert ".rr-wrap{" in css and "grid-template-columns:minmax(320px,1.1fr) minmax(360px,1.4fr)" in css
    assert "@media(max-width:900px){.rr-wrap{grid-template-columns:1fr}" in css
    assert "Investigation queue" in html and "Investigation detail" in html
    assert "/admin/research-review" in nav and "Research review" in nav


def test_evidence_console_is_responsive():
    html = _read("templates", "admin_evidence.html")
    css = _read("static", "app.css")
    assert "ev-wrap" in html and "ev-grid" in html
    assert ".ev-grid{" in css and "grid-template-columns:1fr 1fr" in css
    assert "@media(max-width:860px){.ev-grid{grid-template-columns:1fr}" in css
    # the global login card cap is untouched (scoped fix only)
    assert ".card{width:100%;max-width:460px;" in css
