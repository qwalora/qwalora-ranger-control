"""Release-aligned documentation validation (section C; acceptance G#1-3,10).

The doc release check must PASS on the current repo (docs reference real routes, per-board
environment facts hold, the handbook link is authoritative, internal links resolve) and must
CATCH drift (negative controls), so documentation cannot silently fall behind the code.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

os.environ.setdefault("SECRET_KEY", "doc-release-test")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
for _k in ("RANGER_CASE_UI", "RANGER_JWT_PRIVATE_B64", "OPENSEARCH_ADMIN_PASSWORD"):
    os.environ.pop(_k, None)

import doc_release_check as drc  # noqa: E402


def test_doc_release_check_passes_on_current_repo():
    result = drc.run_check()
    assert result["ok"] is True, f"doc release check failed: {result['failures']}"
    md = result["metadata"]
    # release metadata is present and identifies app + doc state (acceptance #10)
    assert md["app_git_commit"] and md["checked_at"]
    assert md["required_routes_verified"] == len(drc.REQUIRED_ROUTES)
    assert md["boards_env_verified"] == len(drc.EXPECTED_ENV_KIND)
    assert md["handbook_url"] == drc.HANDBOOK_URL


def test_catches_missing_route(monkeypatch):
    # negative control: a documented route that no longer exists is detected (stale-doc guard)
    monkeypatch.setattr(drc, "REQUIRED_ROUTES", drc.REQUIRED_ROUTES + ["/me/this-route-was-removed"])
    result = drc.run_check()
    assert result["ok"] is False
    assert any("route-missing" in f for f in result["failures"])


def test_catches_env_drift(monkeypatch):
    # negative control: a board documented with the wrong environment kind is detected
    drifted = dict(drc.EXPECTED_ENV_KIND)
    drifted[1] = "siem"   # claim Board 1 is OpenSearch when it is really a portal dataset
    monkeypatch.setattr(drc, "EXPECTED_ENV_KIND", drifted)
    result = drc.run_check()
    assert result["ok"] is False
    assert any("env-drift" in f and "board 1" in f for f in result["failures"])
