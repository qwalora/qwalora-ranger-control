"""S1 - STRATA board assessment regression tests (boards 1, 3, 4, 5, 6).

Before S1 these five boards had generators and graders in scenarios.py but NO test exercised them.
This module verifies, for each board, the properties that make an assessment trustworthy:

  * deterministic reproduction of the world from the assigned seed,
  * candidate-visible content never carries the hidden truth / answer key,
  * a correct solution (built from the hidden key server-side) grades at or above the 95 bar,
  * an empty submission cannot pass,
  * incorrect / unsupported claims are penalized,
  * trivial guessing and answer padding cannot reach the bar,
  * repeated attempts preserve the assignment rules (a different seed is a different world; flags
    are per-seed and non-transferable),
  * candidate data stays isolated (one candidate's key never grades another's),
  * the board-specific competency is actually measured.

Board 2 is already covered by test_enterprise*, test_case_contract, test_calibration, etc.; it is
only regression-pinned here for the shared dispatch. The 95 standard (program.PASS_BAR) is read, not
modified. Boards 5/6 are graded on seed-derived flags only; this module also asserts the fail-closed
posture when the Ludus broker is in mock mode (no live range).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

import scenarios as sc            # noqa: E402
import program as P               # noqa: E402
import broker                     # noqa: E402

BAR = P.PASS_BAR                  # 95.0, read-only


# ============================ helpers =======================================
def _no_truth(public, forbidden_keys=("_key", "truth", "_flags", "_seed", "verdict", "iocs",
                                      "technique", "incident", "patient_zero", "persistence")):
    """Assert no answer-bearing key appears anywhere in the candidate-visible structure.
    `technique`/`verdict` are allowed only where they are legitimately candidate-facing (board 3
    threats are labeled intel; board 5/6 objective techniques are public), handled by the caller."""
    import json
    blob = json.dumps(public)
    return [k for k in forbidden_keys if ('"%s"' % k) in blob]


# ============================ Board 1: SOC triage (Sentinel) =================
def _b1_correct(scenario):
    alerts = []
    for a in scenario["alerts"]:
        k = a["_key"]
        row = {"id": a["id"], "verdict": k["verdict"], "severity": k["severity"]}
        if k["verdict"] == "true_positive":
            row["attack_technique"] = k["technique"]
            row["iocs"] = list(k["iocs"])
        alerts.append(row)
    return {"alerts": alerts}


def test_board1_deterministic_and_truth_safe():
    s1 = sc.generate_board1("seed-b1-x")
    s2 = sc.generate_board1("seed-b1-x")
    assert s1 == s2, "board 1 must reproduce identically from the same seed"
    pub = sc.public_board1(s1)
    # the public view must not carry the per-alert key
    assert "_key" not in str(pub), "board 1 public view leaks the answer key"
    for a in pub["alerts"]:
        assert set(a.keys()) == {"id", "timestamp", "host", "signal", "raw"}
    # a different seed is a different world (assignment rule for repeat attempts)
    assert sc.generate_board1("seed-b1-y") != s1


def test_board1_correct_passes_empty_fails():
    s = sc.generate_board1("seed-b1-score")
    score, per = sc.score_board1(s, _b1_correct(s))
    assert score >= BAR, f"a fully correct triage must pass the bar, got {score}"
    empty, _ = sc.score_board1(s, {"alerts": []})
    assert empty < BAR, f"an empty triage must not pass, got {empty}"
    # feedback exposes only correctness flags, never the correct values
    assert all(set(p) <= {"id", "verdict_correct", "severity_correct", "technique_correct"}
               for p in per)


def test_board1_penalizes_wrong_and_resists_guessing():
    s = sc.generate_board1("seed-b1-guess")
    # invert every verdict -> should score far below the bar
    inv = {"alerts": [{"id": a["id"],
                       "verdict": ("false_positive" if a["_key"]["verdict"] == "true_positive"
                                   else "true_positive")} for a in s["alerts"]]}
    inv_score, _ = sc.score_board1(s, inv)
    assert inv_score < BAR
    # trivial guessing: mark EVERYTHING true_positive, high severity, one technique. The FP alerts
    # and the wrong techniques/severities must keep it below the bar.
    allo = {"alerts": [{"id": a["id"], "verdict": "true_positive", "severity": "critical",
                        "attack_technique": "T1078", "iocs": ["x"]} for a in s["alerts"]]}
    guess_score, _ = sc.score_board1(s, allo)
    assert guess_score < BAR, f"blanket-true_positive guessing must not pass, got {guess_score}"


def test_board1_measures_components_and_isolation():
    s = sc.generate_board1("seed-b1-comp")
    # correct verdicts but WRONG technique/severity/iocs on the true positives must score strictly
    # lower than a fully correct submission -> technique/severity/IOC are really measured.
    partial = {"alerts": []}
    for a in s["alerts"]:
        k = a["_key"]
        row = {"id": a["id"], "verdict": k["verdict"], "severity": "low"}
        if k["verdict"] == "true_positive":
            row["attack_technique"] = "T9999"; row["iocs"] = ["nonsense"]
        partial["alerts"].append(row)
    full_score, _ = sc.score_board1(s, _b1_correct(s))
    part_score, _ = sc.score_board1(s, partial)
    assert part_score < full_score, "severity/technique/IOC must affect the score"
    # isolation: another candidate's key (different seed) does not grade this candidate's world
    other = sc.generate_board1("seed-b1-other")
    cross, _ = sc.score_board1(s, _b1_correct(other))
    assert cross < full_score, "a different candidate's answers must not grade this world well"


# ============================ Board 3: detection engineering (Warden) =======
def _b3_ruleset():
    """A detection ruleset keyed on each technique's INVARIANT tradecraft (image + command tokens),
    not on sample-specific strings, so it generalizes to the holdout and avoids the benign
    near-misses. This is what a competent detection engineer would author from the labeled intel."""
    return [
        {"name": "enc_powershell_from_office", "technique": "T1059.001",
         "detection": {"sel": {"image": "powershell.exe", "command|contains": "-enc"},
                       "condition": "sel"}},
        {"name": "certutil_download", "technique": "T1105",
         "detection": {"sel": {"image": "certutil.exe", "command|contains": "-urlcache"},
                       "condition": "sel"}},
        {"name": "domain_account_discovery", "technique": "T1087.002",
         "detection": {"sel": {"image": "net.exe",
                               "command|contains|all": ["group", "/domain"]}, "condition": "sel"}},
        {"name": "lsass_comsvcs_minidump", "technique": "T1003.001",
         "detection": {"sel": {"image": "rundll32.exe",
                               "command|contains|all": ["comsvcs.dll", "minidump"]},
                       "condition": "sel"}},
        {"name": "wmi_remote_exec", "technique": "T1047",
         "detection": {"sel": {"image": "wmic.exe",
                               "command|contains|all": ["/node:", "process call create"]},
                       "condition": "sel"}},
        {"name": "schtasks_persistence", "technique": "T1053.005",
         "detection": {"sel": {"image": "schtasks.exe", "command|contains": "/create"},
                       "condition": "sel"}},
        {"name": "web_c2_beacon", "technique": "T1071.001",
         "detection": {"sel": {"event_type": "network", "command|contains": "beacon"},
                       "condition": "sel"}},
        {"name": "dns_exfil", "technique": "T1048.003",
         "detection": {"sel": {"event_type": "dns", "command|contains": "txt"},
                       "condition": "sel"}},
    ]


def test_board3_deterministic_and_truth_safe():
    s1 = sc.generate_board3("seed-b3-x")
    s2 = sc.generate_board3("seed-b3-x")
    assert s1 == s2
    pub = sc.public_board3(s1)
    # the shown malicious samples are labeled INTEL by design; what must never ship is the holdout
    # (the graded corpus) and the internal seed used to derive it.
    assert "_seed" not in pub, "board 3 public view must not expose the holdout seed"
    assert "holdout" not in str(pub).lower(), "board 3 public view must not expose the holdout"
    assert sc.generate_board3("seed-b3-y") != s1


def test_board3_real_rule_eval_passes_empty_fails():
    s = sc.generate_board3("seed-b3-score")
    score, fb = sc.score_board3(s, {"rules": _b3_ruleset()})
    assert score >= BAR, f"a correct generalizing ruleset must pass, got {score} ({fb[0]})"
    # held-out evaluation really ran: feedback reports covered techniques + validation FPs
    assert "techniques_covered" in fb[0] and "validation_false_positives" in fb[0]
    empty, _ = sc.score_board3(s, {"rules": []})
    assert empty < BAR, "no rules cannot pass"


def test_board3_resists_match_everything_and_penalizes_fps():
    s = sc.generate_board3("seed-b3-fp")
    # a rule that matches everything (command contains the empty string) catches all benign too;
    # precision collapses, so F1 and the score must stay below the bar.
    allrule = [{"name": "match_all", "detection": {"sel": {"command|contains": ""},
                                                   "condition": "sel"}}]
    score, fb = sc.score_board3(s, {"rules": allrule})
    assert score < BAR, f"a match-everything rule must not pass, got {score}"
    assert fb[0]["validation_false_positives"] > 0, "benign events must be counted as FPs"
    # a single-technique rule cannot pass: macro-recall across the 8 techniques caps it.
    one = [{"name": "only_ps", "detection": {"sel": {"image": "powershell.exe",
            "command|contains": "-enc"}, "condition": "sel"}}]
    one_score, _ = sc.score_board3(s, {"rules": one})
    assert one_score < BAR, "covering one of eight techniques must not pass (macro-recall)"


def test_board3_discriminates_and_isolation():
    s = sc.generate_board3("seed-b3-disc")
    rs = {"rules": _b3_ruleset()}
    score, fb = sc.score_board3(s, rs)
    # legitimate-vs-malicious discrimination: high recall AND high precision on the holdout
    assert fb[0]["precision"] >= 0.9 and fb[0]["macro_recall"] >= 0.9
    # the same good ruleset generalizes to a DIFFERENT candidate's holdout (invariant tradecraft),
    # but each candidate is graded on their own seed's holdout (no shared answer key).
    s_other = sc.generate_board3("seed-b3-disc-other")
    assert s_other != s


# ============================ Board 4: IR / forensics (Reclaimer) ===========
def _b4_correct(scenario):
    t = scenario["truth"]
    return {"patient_zero": t["patient_zero"], "initial_access": t["initial_access"],
            "affected_hosts": list(t["affected_hosts"]),
            "affected_accounts": list(t["affected_accounts"]),
            "timeline": list(t["timeline"]), "persistence": list(t["persistence"])}


def test_board4_deterministic_and_truth_safe():
    s1 = sc.generate_board4("seed-b4-x")
    s2 = sc.generate_board4("seed-b4-x")
    assert s1 == s2
    pub = sc.public_board4(s1)
    assert "truth" not in pub and "_key" not in str(pub), \
        "board 4 public view must not expose the incident truth or per-event key"
    for a in pub["alerts"]:
        assert set(a.keys()) == {"id", "timestamp", "host", "user", "event_type", "detail"}
    assert sc.generate_board4("seed-b4-y") != s1


def test_board4_correct_passes_empty_fails():
    s = sc.generate_board4("seed-b4-score")
    score, fb = sc.score_board4(s, _b4_correct(s))
    assert score >= BAR, f"a correct IR report must pass, got {score} ({fb[0]})"
    empty, _ = sc.score_board4(s, {})
    assert empty < BAR, "an empty IR report must not pass"


def test_board4_penalizes_wrong_sequence_and_scope():
    s = sc.generate_board4("seed-b4-order")
    good = _b4_correct(s)
    # reversed timeline: membership is identical but order is wrong -> strictly lower score.
    rev = dict(good); rev["timeline"] = list(reversed(good["timeline"]))
    good_score, _ = sc.score_board4(s, good)
    rev_score, _ = sc.score_board4(s, rev)
    assert rev_score < good_score, "an out-of-order timeline must be penalized"
    # wrong patient zero + wrong scope -> strictly lower.
    wrong = dict(good); wrong["patient_zero"] = "NOT-A-HOST"; wrong["affected_hosts"] = ["NOT-A-HOST"]
    wrong_score, _ = sc.score_board4(s, wrong)
    assert wrong_score < good_score, "wrong patient zero / scope must be penalized"


def test_board4_measures_persistence_and_isolation():
    s = sc.generate_board4("seed-b4-persist")
    good = _b4_correct(s)
    nopersist = dict(good); nopersist["persistence"] = []
    full, _ = sc.score_board4(s, good)
    nop, _ = sc.score_board4(s, nopersist)
    assert nop < full, "missing the persistence mechanism must lower the score"
    # isolation: another incident's truth does not grade this one well.
    other = sc.generate_board4("seed-b4-persist-other")
    cross, _ = sc.score_board4(s, _b4_correct(other))
    assert cross < full, "a different candidate's IR answers must not grade this incident well"


# ============================ Boards 5/6: GOAD flag capture =================
def test_board5_flag_derivation_and_scoring():
    s = sc.generate_board5("seed-b5-x")
    assert s == sc.generate_board5("seed-b5-x"), "board 5 brief reproduces from the seed"
    pub = sc.public_board5(s)
    assert "_flags" not in pub and "_flags" not in str(pub), "flags must never ship to the candidate"
    # a correct capture (the seed-derived flags) scores 100; empty/guessed scores 0.
    full, fb = sc.score_board5(s, {"flags": dict(s["_flags"])})
    assert full >= BAR and full == 100.0
    empty, _ = sc.score_board5(s, {"flags": {}})
    assert empty == 0.0, "no captured flags cannot pass"
    guess = {"flags": {oid: "QR5{deadbeefdeadbeef}" for oid in s["_flags"]}}
    gscore, _ = sc.score_board5(s, guess)
    assert gscore == 0.0, "guessed flags must not score"


def test_board5_cryptographic_nontransfer_and_padding():
    # per-candidate derivation: different seeds yield different flags for the same objective.
    fa = sc.flags_for_board(5, "cand-A")
    fb = sc.flags_for_board(5, "cand-B")
    assert set(fa) == set(fb) and all(fa[o] != fb[o] for o in fa), "flags must be per-candidate"
    # cross-candidate non-transferability: candidate A submitting their own flags into B's world = 0.
    sB = sc.generate_board5("cand-B")
    cross, _ = sc.score_board5(sB, {"flags": fa})
    assert cross == 0.0, "another candidate's flags must not score"
    # answer padding: submit every objective's flag but also junk extras -> only real captures count,
    # and partial captures earn only their points (never the bar by padding).
    partial = dict(sB["_flags"]); first = sorted(partial)[0]
    padded = {k: v for k, v in partial.items()}
    padded.pop(first)                                  # drop one real capture
    padded["bogus_objective"] = "QR5{0000000000000000}"
    pscore, pfb = sc.score_board5(sB, {"flags": padded})
    assert pscore < BAR, "padding with extras cannot reach the bar without all real captures"
    assert pscore == round(100.0 * (sum(o["points"] for o in sB["objectives"] if o["id"] != first)
                                    / sum(o["points"] for o in sB["objectives"])), 1)


def test_board5_fail_closed_when_ludus_mock():
    # With no LUDUS_API_URL the broker is in mock mode: no live range exists, so a candidate cannot
    # capture real flags, and the mock WireGuard profile is explicitly marked as not-live. The grader
    # requires the exact seed-derived flag, so the mock posture cannot yield a pass.
    saved = os.environ.pop("LUDUS_API_URL", None)
    try:
        assert broker.is_live() is False, "broker must be mock without LUDUS_API_URL"
        assert broker.mode() == "mock" and "mock" in broker.broker_status().lower()
    finally:
        if saved is not None:
            os.environ["LUDUS_API_URL"] = saved


def test_board6_distinct_derivation_and_separation_from_board5():
    s6 = sc.generate_board6("seed-b6-x")
    assert s6 == sc.generate_board6("seed-b6-x")
    pub = sc.public_board6(s6)
    assert "_flags" not in pub and "_flags" not in str(pub)
    # capstone objectives differ from board 5's set (different competency), and scoring works.
    assert [o["id"] for o in s6["objectives"]] != [o["id"] for o in sc.generate_board5("seed-b6-x")["objectives"]]
    full, _ = sc.score_board6(s6, {"flags": dict(s6["_flags"])})
    assert full == 100.0
    # separation from board 5: the SAME objective id + same seed yields a DIFFERENT flag across
    # boards, so a board-5 capture can never satisfy a board-6 objective.
    f5 = sc.flags_for_board(5, "same-seed")
    f6 = sc.flags_for_board(6, "same-seed")
    shared = set(f5) & set(f6)
    assert shared == {"foothold"}  # only the shared objective id
    assert all(f5[o] != f6[o] for o in shared), "flags must not transfer across boards"
    assert f6[next(iter(f6))].startswith("QR6{"), "board 6 flags carry the board-6 tag"


# ============================ shared dispatch regression ====================
def test_dispatch_and_kinds_preserved():
    assert sorted(sc._GENERATORS) == [1, 2, 3, 4, 5, 6]
    assert sc.kind(1) == "triage" and sc.kind(3) == "detection" and sc.kind(4) == "ir"
    assert sc.kind(5) == "flags" and sc.kind(6) == "flags"
    # the 95 bar is unchanged.
    assert P.PASS_BAR == 95.0


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
