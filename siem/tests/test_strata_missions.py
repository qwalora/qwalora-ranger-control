"""S2 - STRATA mission package integrity and integration tests.

Verifies that every board's candidate mission package is complete, candidate-safe, versioned and
approved, cohort/scenario-reference-ready, and that environment availability is computed from real
signals (never implied by the documentation existing). Also exercises the candidate-facing route so
the mission is discoverable for an authorized candidate and never leaks protected material.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECRET_KEY", "missions")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("LUDUS_API_URL", None)   # broker stays mock -> boards 5/6 range unavailable

import strata_missions as sm  # noqa: E402
import program as P           # noqa: E402

BOARDS = (1, 2, 3, 4, 5, 6)
TEXT_SECTIONS = ("business_context", "assigned_role", "authorized_scope", "environment",
                 "evidence", "submission", "evaluation", "support")
LIST_SECTIONS = ("objectives", "deliverables")

# material that must NEVER appear in a candidate-facing mission package: exploitation tooling,
# step-by-step solutions, query strings that would locate a hidden incident, hidden-truth field
# names, or expected answers. (Submission VOCABULARY the candidate must use, such as the verdict
# values true_positive/false_positive or the disposition confirmed_incident, is legitimately
# candidate-facing and is not listed here.)
FORBIDDEN = ("mimikatz", "secretsdump", "getuserspn", "rubeus", "crackmapexec", "evil-winrm",
             "psexec.py", "hashcat", "impacket", "step 1", "step-by-step", "copy and paste",
             "copy-and-paste", "winlog.event_data", "event_uid:", "the answer is",
             "patient_zero =", '"_key"', '"_flags"', '"_seed"', '"truth"', "the flag is qr")


def test_every_board_has_complete_approved_package():
    for b in BOARDS:
        pkg = sm.get(b)
        assert pkg is not None, f"board {b} has no approved mission package"
        assert pkg["approved"] is True and pkg["version"] >= 1
        for s in TEXT_SECTIONS:
            assert isinstance(pkg.get(s), str) and len(pkg[s]) > 80, \
                f"board {b} section {s!r} is missing or too thin"
        for s in LIST_SECTIONS:
            assert isinstance(pkg.get(s), list) and len(pkg[s]) >= 1, \
                f"board {b} section {s!r} is missing"
        assert pkg["title"] and pkg["role_title"] and pkg["org"]
        # the 95 bar is quoted from program, not redefined
        assert pkg["pass_bar"] == P.PASS_BAR == 95.0


def test_packages_are_candidate_safe():
    import json
    for b in BOARDS:
        pkg = sm.get(b)
        blob = json.dumps(pkg).lower()
        hits = [t for t in FORBIDDEN if t in blob]
        assert not hits, f"board {b} mission package leaks forbidden material: {hits}"


def test_versioned_and_approval_is_explicit():
    for b in BOARDS:
        assert sm.is_approved(b, 1) is True
        assert sm.is_approved(b, 99) is False          # unknown version is not approved
        assert sm.latest_version(b) == 1
    # an unapproved draft is never returned by get() nor listed as available
    sm.MISSIONS.setdefault(1, {})[2] = {"approved": False, "title": "draft v2",
                                        "environment_kind": sm.ENV_DATASET}
    try:
        assert sm.is_approved(1, 2) is False
        assert 2 not in sm.available_versions(1)
        assert sm.get(1, 2) is None                    # explicitly requesting a draft returns None
        assert sm.latest_version(1) == 1               # latest approved is still v1
    finally:
        sm.MISSIONS[1].pop(2, None)


def test_environment_availability_from_real_signals():
    # dataset boards (1,3,4) and the SIEM board (2) are available to an authorized candidate
    for b in (1, 2, 3, 4):
        assert sm.environment_availability(b)["available"] is True
    # range boards (5,6) are UNAVAILABLE while the broker is mock, even though the docs exist
    for b in (5, 6):
        av = sm.environment_availability(b)
        assert av["available"] is False and av["state"] == "range_unavailable"
        assert "not yet available" in av["message"].lower()


def test_availability_independent_of_documentation_existence():
    # the package exists and is approved for board 5, yet the environment is not available:
    # documentation existing must never imply the environment is available.
    assert sm.get(5) is not None
    assert sm.environment_availability(5)["available"] is False

    # and when the broker IS live, the same package flips to available with no doc change.
    class _LiveBroker:
        @staticmethod
        def is_live():
            return True
    assert sm.environment_availability(5, broker_mod=_LiveBroker)["available"] is True


def test_cohort_and_scenario_reference_ready():
    for b in BOARDS:
        pkg = sm.get(b)
        # reference fields exist so a future cohort can bind a different approved scenario without
        # changing this template (scenario_ref/version may be None at the board-level base package).
        assert "scenario_ref" in pkg and "scenario_version" in pkg
        assert isinstance(pkg.get("required_evidence_types"), list) and pkg["required_evidence_types"]
        assert pkg["environment_kind"] in (sm.ENV_DATASET, sm.ENV_SIEM, sm.ENV_RANGE)
    # the business context does not hard-code a single incident identifier across boards
    # (the specific incident is bound per cohort via the scenario, not baked into the mission text).
    assert "ALRT-" not in sm.get(1)["business_context"]


def test_mission_index_covers_all_boards():
    idx = sm.mission_index()
    assert [r["board"] for r in idx] == list(BOARDS)
    for r in idx:
        assert r["title"] and r["environment_kind"]


def test_candidate_route_shows_own_board_and_never_leaks():
    import app as appmod
    from models import db, Candidate
    application = appmod.create_app()
    with application.app_context():
        db.create_all()
        c = Candidate(handle="mcand", name="M", email="m@e", cohort="2026-A", github_id="g-m",
                      status="active", current_board=1)
        db.session.add(c); db.session.commit()
        cid = c.id
    client = application.test_client()
    with client.session_transaction() as s:
        s["cand"] = cid
    # dashboard surfaces the mission link
    me = client.get("/me")
    assert me.status_code == 200 and b"/me/mission" in me.data
    # board 1 (dataset) mission renders and shows the environment ready, no truth
    m1 = client.get("/me/mission")
    assert m1.status_code == 200 and b"Environment ready" in m1.data
    assert b"_key" not in m1.data and b"_flags" not in m1.data
    # move to board 5 (range): mission renders but the environment shows not-yet-available
    with application.app_context():
        from models import Candidate as C
        cc = C.query.get(cid); cc.current_board = 5; db.session.commit()
    m5 = client.get("/me/mission")
    assert m5.status_code == 200
    assert b"not yet available" in m5.data, "board 5 must not imply a live range exists"
    # an unauthenticated / non-active user cannot read a mission
    anon = application.test_client()
    assert anon.get("/me/mission").status_code in (302, 401)


# --- presentation regression (the refined mission workspace) --------------------------------
def _render(board):
    import app as appmod
    from models import db, Candidate
    application = appmod.create_app()
    with application.app_context():
        db.create_all()
        c = Candidate(handle=f"pres{board}", name="P", email=f"p{board}@e", cohort="2026-A",
                      github_id=f"g-p{board}", status="active", current_board=board)
        db.session.add(c); db.session.commit()
        cid = c.id
    client = application.test_client()
    with client.session_transaction() as s:
        s["cand"] = cid
    return client.get("/me/mission")


def test_presentation_workspace_overview_and_tabs():
    r = _render(1)
    assert r.status_code == 200
    html = r.data.decode()
    # the mission view uses its own responsive stylesheet (not the narrow global card)
    assert "mission.css" in html
    assert 'class="mw-shell"' in html and 'class="card"' not in html
    # always-visible overview: role, environment, version, objective standard
    for marker in ("Professional role", "Environment", "Mission version", "Objective standard",
                   "v1 · approved", "95.0%"):
        assert marker in html, f"overview missing {marker!r}"
    # four accessible tabs and four panels; Mission is the default-checked tab
    assert 'id="mwt-mission" checked' in html
    for t in ("mwt-mission", "mwt-env", "mwt-sub", "mwt-ref"):
        assert f'id="{t}"' in html
    for p in ("mwp-mission", "mwp-env", "mwp-sub", "mwp-ref"):
        assert f'id="{p}"' in html
    for label in (">Mission<", ">Environment<", ">Submission<", ">References<"):
        assert label in html, f"tab label missing {label!r}"


def test_presentation_preserves_all_sections_and_substance():
    # every substantive paragraph of all ten sections must still be present verbatim (not shortened).
    r = _render(1)
    html = r.data.decode()
    import html as _h
    pkg = sm.get(1)
    for key in ("business_context", "assigned_role", "authorized_scope", "environment",
                "evidence", "submission", "evaluation", "support"):
        assert _h.escape(pkg[key]) in html or pkg[key] in html, f"section {key} text was dropped"
    for item in pkg["objectives"] + pkg["deliverables"]:
        assert _h.escape(item) in html or item in html, f"list item dropped: {item[:40]}"
    # references are present and compact (rendered in the references panel)
    for ref in pkg["references"]:
        assert _h.escape(ref["title"]) in html or ref["title"] in html


def test_presentation_environment_truthful_for_range_boards():
    for board in (5, 6):
        html = _render(board).data.decode()
        # overview status reads "Unavailable" (not "Pending") and the env tab says not yet available
        assert "Unavailable" in html and "Pending" not in html
        assert "not yet available" in html.lower(), f"board {board} must show range unavailable"
    # a dataset board shows ready, no false pending
    html1 = _render(1).data.decode()
    assert "Ready" in html1 and "not yet available" not in html1.lower()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
