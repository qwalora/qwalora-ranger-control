"""Test harness for the PARALLAX researcher-facing UI (feature/parallax-research-platform-ui).

Boots the real app on a throwaway SQLite DB with the PARALLAX feature flags on in a nonprod env,
then seeds three principals: a PARALLAX researcher with signed runs (A), a second PARALLAX
researcher (B, for cross-owner isolation), and a STRATA-only candidate (S, for cross-program
isolation). No network, no real model (stub provenance), no Railway.
"""
import os
import tempfile

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///" + tempfile.mkdtemp() + "/ui_test.db")
os.environ.setdefault("SECRET_KEY", "test-ui-fixed-secret-000000000000")
os.environ.setdefault("RANGER_ENV", "dev")
os.environ.setdefault("RANGER_PARALLAX_LABA", "1")
os.environ.setdefault("RANGER_PARALLAX_LABA_ENV", "dev")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import app as A  # noqa: E402
from models import db, Candidate, ProgramMembership  # noqa: E402


def _persist_stub_trial(researcher_id, outcome="boundary_preserved"):
    from parallax.research import store as rstore
    camp = {"manifest": {"kind": "trial",
                         "backend": {"is_real": False, "model_id": "stub", "runtime": "n/a", "backend": "stub"},
                         "n_records": 1},
            "metrics": {"kind": "trial", "record": {"outcome": outcome, "condition": "baseline_benign",
                                                    "evaluation": {"canary": False}}}}
    return rstore.persist_run(db, researcher_id=researcher_id, campaign=camp)


@pytest.fixture(scope="session")
def seeded():
    with A.app.app_context():
        import scripts.px_review_fixture as fx
        fx.ensure_fixture(db)  # researcher A (fixture): parallax + signed trial + investigation
        a = Candidate.query.filter_by(github_id="nonprod-fixture:parallax-review-selftest").first()

        b = Candidate.query.filter_by(github_id="rb-researcher").first()
        if b is None:
            b = Candidate(handle="rb", name="Researcher B", email="rb@nonprod.invalid",
                          cohort="2026-A", github_id="rb-researcher", status="active", current_board=1)
            db.session.add(b); db.session.commit()
            db.session.add(ProgramMembership(candidate_id=b.id, program="parallax", status="active",
                                             cohort="2026-A")); db.session.commit()
            _persist_stub_trial("rb-researcher")

        s = Candidate.query.filter_by(github_id="sc-strata").first()
        if s is None:
            s = Candidate(handle="sc", name="Strata Only", email="sc@nonprod.invalid",
                          cohort="2026-A", github_id="sc-strata", status="active", current_board=1)
            db.session.add(s); db.session.commit()
            db.session.add(ProgramMembership(candidate_id=s.id, program="strata", status="active",
                                             cohort="2026-A")); db.session.commit()

        from parallax.research import store as rstore
        b_runs = rstore.runs_for(db, authenticated_researcher_id="rb-researcher")
        return {"a_id": a.id, "a_gid": a.github_id, "b_id": b.id, "b_gid": "rb-researcher",
                "s_id": s.id, "b_run": b_runs[0]["run_id"]}


@pytest.fixture()
def client():
    return A.app.test_client()


def login(client, cid):
    with client.session_transaction() as sess:
        sess["cand"] = cid
