"""STRATA S6 §18 - the Board 6 (Vanguard) capstone rubric: a DISTINCT, VERSIONED scoring rubric
with mandatory end-to-end milestones and an OSCP-style critical-failure gate, so a candidate cannot
pass the capstone by accumulating points on easier objectives while skipping a defining milestone.
Board 5 (Raider) keeps its flat points-weighted sum - the two boards are graded differently. Offline."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

import scenarios as sc  # noqa: E402


def _world(seed="cap-seed"):
    return sc.generate_board6(seed)


def test_rubric_is_versioned_and_distinct_from_board5():
    w = _world()
    assert w["rubric"]["version"] == sc.CAPSTONE_RUBRIC_VERSION
    assert w["rubric"]["kind"] == "capstone"
    assert set(w["rubric"]["mandatory_objectives"]) == set(sc._B6_MANDATORY)
    # board 5 has NO capstone rubric and its scorer emits no rubric metadata
    w5 = sc.generate_board5("b5-seed")
    assert "rubric" not in w5
    _, fb5 = sc.score_board5(w5, {"flags": dict(w5["_flags"])})
    assert "rubric_version" not in fb5[0] and "mandatory_missing" not in fb5[0]


def test_full_capstone_passes():
    w = _world()
    score, fb = sc.score_board6(w, {"flags": dict(w["_flags"])})
    assert score == 100.0 and fb[0]["capstone_complete"] is True
    assert fb[0]["mandatory_missing"] == [] and fb[0]["rubric_version"] == sc.CAPSTONE_RUBRIC_VERSION


def test_mandatory_gate_caps_a_high_point_submission():
    # Capture EVERYTHING except the (low-point, mandatory) crown-jewel exfil. Points clear the bar,
    # but the capstone is incomplete, so the rubric caps the effective score below 95 and names it.
    w = _world()
    flags = dict(w["_flags"])
    no_crown = {k: v for k, v in flags.items() if k != "crown"}
    raw_points = sum(o["points"] for o in w["objectives"] if o["id"] != "crown")
    assert raw_points >= 95, "the test only means something if the non-crown points clear the bar"
    score, fb = sc.score_board6(w, {"flags": no_crown})
    assert score < 95.0, "a missing mandatory milestone must fail the capstone regardless of points"
    assert fb[0]["capstone_complete"] is False
    assert fb[0]["mandatory_missing"] == ["crown"]
    assert "critical_failure" in fb[0]


def test_each_mandatory_objective_is_individually_required():
    w = _world()
    flags = dict(w["_flags"])
    for oid in sc._B6_MANDATORY:
        sub = {k: v for k, v in flags.items() if k != oid}
        score, fb = sc.score_board6(w, {"flags": sub})
        assert score < 95.0, f"skipping mandatory {oid} must not pass"
        assert oid in fb[0]["mandatory_missing"]


def test_public_brief_exposes_rubric_without_leaking_flags():
    w = _world()
    pub = sc.public_board6(w)
    assert pub["rubric"]["version"] == sc.CAPSTONE_RUBRIC_VERSION
    assert "mandatory_objectives" in pub["rubric"]
    blob = json.dumps(pub)
    assert "_flags" not in blob and "QR6" not in blob


def test_generated_world_is_reproducible_with_rubric():
    assert sc.generate_board6("same") == sc.generate_board6("same")
