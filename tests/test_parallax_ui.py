"""Authorization, isolation, and rendering tests for the PARALLAX researcher-facing surfaces.

Covers the negative cases the mandate requires: unauthenticated access, cross-program entitlement,
cross-owner evidence access, reviewer-only functions, and feature-flag/prod gating; plus positive
rendering of the command center, evidence center, and identity surface, and the owner-scoped export.
"""
import os

from conftest import login


# ---------------- positive rendering (authorized researcher) ----------------

def test_command_center_renders_live_activity(client, seeded):
    login(client, seeded["a_id"])
    r = client.get("/me?program=parallax")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "Research activity" in html
    assert "Evidence &amp; publications" in html
    assert "assessment-only" in html  # honest labeling preserved


def test_evidence_center_renders_owner_records(client, seeded):
    login(client, seeded["a_id"])
    r = client.get("/parallax/research/evidence")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "Your signed research evidence" in html
    assert "Evidence records" in html
    assert "Export signed record" in html
    assert "simulated" in html  # provenance shown honestly (stub backend)


def test_identity_surface_shows_github_and_entitlements(client, seeded):
    login(client, seeded["a_id"])
    r = client.get("/account")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "GitHub authenticated" in html and "Program access" in html


def test_owner_can_export_own_signed_record(client, seeded):
    login(client, seeded["b_id"])
    r = client.get("/parallax/research/evidence/%s.json" % seeded["b_run"])
    assert r.status_code == 200
    assert "attachment" in r.headers.get("Content-Disposition", "")
    assert r.is_json or r.mimetype == "application/json"


# ---------------- cross-owner isolation ----------------

def test_cross_owner_export_is_404(client, seeded):
    # researcher A must not be able to export researcher B's signed record
    login(client, seeded["a_id"])
    r = client.get("/parallax/research/evidence/%s.json" % seeded["b_run"])
    assert r.status_code == 404  # never reveals another researcher's run exists


# ---------------- cross-program entitlement ----------------

def test_strata_only_denied_evidence_page(client, seeded):
    login(client, seeded["s_id"])
    r = client.get("/parallax/research/evidence")
    # entitlement is not met: must NOT render the evidence center; redirect away, no leak
    assert r.status_code in (301, 302)
    assert "/me" in r.headers.get("Location", "") or "login" in r.headers.get("Location", "")


def test_strata_only_denied_evidence_export(client, seeded):
    login(client, seeded["s_id"])
    r = client.get("/parallax/research/evidence/%s.json" % seeded["b_run"])
    assert r.status_code in (401, 403, 404)  # no active PARALLAX membership => denied


def test_strata_only_denied_history_json(client, seeded):
    login(client, seeded["s_id"])
    r = client.get("/parallax/research/history")
    assert r.status_code in (401, 403)


# ---------------- unauthenticated ----------------

def test_unauthenticated_evidence_redirects(client, seeded):
    r = client.get("/parallax/research/evidence")
    assert r.status_code in (301, 302)  # routed to GitHub login / dashboard


def test_unauthenticated_export_denied(client, seeded):
    r = client.get("/parallax/research/evidence/%s.json" % seeded["b_run"])
    assert r.status_code in (401, 403, 404)


# ---------------- reviewer-only function stays reviewer-only ----------------

def test_researcher_cannot_adjudicate(client, seeded):
    # a plain researcher (not in REVIEWER_GITHUB_IDS) must be refused the reviewer action. Send a
    # valid CSRF token (extracted from a rendered page) so the request passes CSRF and actually
    # exercises the reviewer-authorization gate rather than being rejected earlier.
    import json as _json
    import re
    login(client, seeded["a_id"])
    page = client.get("/parallax/workspace").get_data(as_text=True)
    m = re.search(r"var CSRF\s*=\s*(\"[^\"]*\")", page)
    tok = _json.loads(m.group(1)) if m else ""
    r = client.post("/parallax/research/adjudicate",
                    json={"investigation_id": "x", "decision": "met"},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 403  # reviewer-only; a researcher is refused even with a valid CSRF token


# ---------------- feature-flag / prod gating ----------------

def test_flag_off_is_404(client, seeded, monkeypatch):
    login(client, seeded["a_id"])
    monkeypatch.setenv("RANGER_PARALLAX_LABA", "")
    assert client.get("/parallax/research/evidence").status_code == 404


def test_prod_marker_is_404(client, seeded, monkeypatch):
    login(client, seeded["a_id"])
    monkeypatch.setenv("RANGER_ENV", "production")
    assert client.get("/parallax/research/evidence").status_code == 404


# ---------------- store overview_for: owner-scoped, excludes reviewer rows ----------------

def test_overview_for_is_owner_scoped_and_excludes_adjudications(seeded):
    import app as A
    from parallax.research import store as rstore
    with A.app.app_context():
        a = rstore.overview_for(db_=None) if False else rstore.overview_for(
            __import__("models").db, authenticated_researcher_id=seeded["a_gid"])
        # A owns a trial + an investigation; no adjudication rows surface to the researcher
        kinds = {i["kind"] for i in a}
        assert "adjudication" not in kinds
        assert "investigation" in kinds and "trial" in kinds
        # none of B's runs appear in A's overview
        ids = {i["run_id"] for i in a}
        assert seeded["b_run"] not in ids
        # every record reports a signature-verify boolean
        assert all("signature_verifies" in i for i in a)


from models import db  # noqa: E402  (used by the overview test under app context)
