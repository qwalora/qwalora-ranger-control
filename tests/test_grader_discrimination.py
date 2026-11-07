"""Grader discrimination invariant.

A qualification is only credible if its graders separate genuine work from
no-work and from answer-leak scrapers. This test runs, per live board, an
EMPTY submission, a NO-ANALYSIS submission that reads only the public view
(never the evidence/logs), and a REFERENCE submission derived from the hidden
key, and asserts: empty and no-analysis fall below the pass bar across seeds,
while the reference clears it. It is a standing guard against a future change
re-introducing a leak (e.g. a public field that reveals the verdict/technique).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scenarios as S  # noqa: E402

PASS_BAR = 95.0
SEEDS = ["disc-%04d" % i for i in range(16)]


# --- Board 1: SOC triage -----------------------------------------------------
_SIG_TP = {
    "Administrative share access": "T1021.002",
    "Process credential-memory access": "T1003.001",
    "Remote WMI execution": "T1047",
    "Scheduled task created": "T1053.005",
    "Suspicious script execution": "T1059.001",
    "Authentication anomaly": "T1078",
}


def _b1_scraper(pub):
    """Reads only the fired-rule name; never the raw log. The strongest attack
    that does no analysis."""
    out = []
    for a in pub["alerts"]:
        sig = a["signal"]
        if sig in _SIG_TP:
            out.append({"id": a["id"], "verdict": "true_positive",
                        "severity": "high", "attack_technique": _SIG_TP[sig]})
        else:
            out.append({"id": a["id"], "verdict": "false_positive", "severity": "low"})
    return {"alerts": out}


def _b1_reference(scn):
    return {"alerts": [{"id": a["id"], **{k: a["_key"][k] for k in
            ("verdict", "severity", "iocs")}, "attack_technique": a["_key"]["technique"]}
            for a in scn["alerts"]]}


# --- Board 3: detection engineering ------------------------------------------
_B3_SIG = {
    "T1059.001": ("command|contains", "-enc"),
    "T1105": ("command|contains", "-urlcache"),
    "T1087.002": ("command|contains|all", ["group", "/domain"]),
    "T1003.001": ("command|contains", "comsvcs.dll"),
    "T1047": ("command|contains", "process call create"),
    "T1053.005": ("command|contains|all", ["/create", "SYSTEM"]),
    "T1071.001": ("command|contains", "beacon"),
    "T1048.003": ("command|contains", "TXT queries"),
    "T1003.002": ("command|contains", "HKLM\\SAM"),
    "T1136.001": ("command|contains|all", ["user", "/add"]),
    "T1562.001": ("command|contains", "DisableRealtimeMonitoring"),
    "T1490": ("command|contains", "delete shadows"),
    "T1552.001": ("command|contains", "password"),
    "T1569.002": ("command|contains", "binPath"),
}


def _b3_reference(scn):
    rules = []
    for t in scn.get("_techniques", list(S._B3_TECHNIQUES)):
        sig = _B3_SIG.get(t)
        if sig:
            field, needle = sig
            rules.append({"name": "r_%s" % t,
                          "detection": {"sel": {field: needle}, "condition": "sel"}})
    return {"rules": rules}


def _b3_broad(scn):
    # one over-broad rule: poor precision and recall
    return {"rules": [{"name": "broad",
                       "detection": {"sel": {"command|contains": "exe"}, "condition": "sel"}}]}


# --- Board 4: incident response ----------------------------------------------
def _b4_reference(scn):
    t = scn["truth"]
    return {k: t[k] for k in ("patient_zero", "initial_access", "affected_hosts",
                              "affected_accounts", "timeline", "persistence")}


def _b4_scraper(pub):
    # name every host/account and dump every id as the timeline: no scoping skill
    hosts = sorted({a["host"] for a in pub["alerts"]})
    accts = sorted({a["user"] for a in pub["alerts"]})
    ids = [a["id"] for a in pub["alerts"]]
    return {"patient_zero": hosts[0] if hosts else "", "initial_access": "T1566.001",
            "affected_hosts": hosts, "affected_accounts": accts,
            "timeline": ids, "persistence": ids}


def _scores(board, builder, from_public):
    out = []
    gen, pub, _ = S._GENERATORS[board]
    for seed in SEEDS:
        scn = gen(seed)
        sub = builder(pub(scn)) if from_public else builder(scn)
        score, _ = S.grade(board, seed, sub)
        out.append(score)
    return out


@pytest.mark.parametrize("board,empty", [
    (1, {"alerts": []}), (3, {"rules": []}), (4, {}),
])
def test_empty_submission_fails(board, empty):
    assert max(_scores(board, lambda _s: empty, from_public=False)) < PASS_BAR


def test_board1_no_analysis_scraper_fails():
    s = _scores(1, _b1_scraper, from_public=True)
    assert max(s) < PASS_BAR, "a no-log-analysis scraper cleared the bar: signal leak"
    assert sum(s) / len(s) < 75.0, "no-analysis mean too high: board-1 skill under test is thin"


def test_board1_reference_passes():
    assert min(_scores(1, _b1_reference, from_public=False)) >= 99.0


def test_board3_broad_rule_fails_and_reference_passes():
    assert max(_scores(3, _b3_broad, from_public=False)) < PASS_BAR
    assert min(_scores(3, _b3_reference, from_public=False)) >= PASS_BAR


def test_board4_scraper_fails_and_reference_passes():
    assert max(_scores(4, _b4_scraper, from_public=True)) < PASS_BAR
    assert min(_scores(4, _b4_reference, from_public=False)) >= PASS_BAR


def test_board1_fired_rule_never_reveals_verdict():
    """No public rule-name may map to only true positives: a suspicious category
    must always contain benign look-alikes, or verdict/technique leak for free."""
    import collections
    by_sig = collections.defaultdict(set)
    for i in range(300):
        for a in S.generate_board1("leak-%04d" % i)["alerts"]:
            by_sig[a["signal"]].add(a["_key"]["verdict"])
    tp_only = [s for s, v in by_sig.items() if v == {"true_positive"}]
    assert not tp_only, "rule name(s) map only to true positives (answer leak): %s" % tp_only
