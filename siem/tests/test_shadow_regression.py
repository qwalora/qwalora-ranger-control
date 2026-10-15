"""M3 security + regression invariants: the shadow grader is ADDITIVE and changes
nothing about qualification. Asserts the protected pieces are intact — PASS_BAR,
the live score_board2 path, BoardResult's objective fields, the Ed25519 signing,
and the rule that hidden truth never reaches a candidate-visible artifact."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


def run():
    # ---- PASS_BAR unchanged -------------------------------------------------
    import program as prog
    check("program.PASS_BAR is still 95.0", prog.PASS_BAR == 95.0)

    # ---- the live board-2 grader is untouched and still authoritative -------
    import scenarios
    check("scenarios.score_board2 still exists and is callable", callable(scenarios.score_board2))
    # v1 hunting scoring: marking everything benign scores 0 (unchanged spirit)
    scen = scenarios.generate_board2("regress-seed")
    zero, _ = scenarios.score_board2(scen, {"alerts": []})
    check("score_board2: empty submission scores 0 (unchanged)", zero == 0.0)
    # a perfect v1 submission still scores 100 under the live grader
    perfect = {"alerts": [{"id": a["id"], "verdict": a["_key"]["verdict"],
                           "severity": a["_key"]["severity"],
                           "attack_technique": a["_key"]["technique"],
                           "iocs": a["_key"]["iocs"]} for a in scen["alerts"]]}
    full, _ = scenarios.score_board2(scen, perfect)
    check("score_board2: perfect v1 submission still scores 100", full == 100.0)

    # ---- BoardResult objective fields are present and unmodified by shadow ---
    import models
    cols = models.BoardResult.__table__.columns.keys()
    check("BoardResult still carries objective_score/objective_passed/objective_sig",
          {"objective_score", "objective_passed", "objective_sig"} <= set(cols))
    # the shadow grader writes NONE of these; it only knows CaseSubmission.shadow_*
    import inspect
    from siem import enterprise_grader as g
    gsrc = inspect.getsource(g)
    check("shadow grader never references BoardResult or objective_*",
          "BoardResult" not in gsrc and "objective_" not in gsrc)
    scols = models.CaseSubmission.__table__.columns.keys()
    check("shadow results land only in CaseSubmission.shadow_* (separate from qualification)",
          {"shadow_score", "shadow_breakdown", "review_flags"} <= set(scols))

    # ---- Ed25519 signing intact --------------------------------------------
    import signing
    payload = {"a": 1, "b": [2, 3]}
    sig = signing.sign(payload)
    check("signing round-trips", signing.verify(payload, sig))
    check("signing detects tampering", not signing.verify({"a": 2, "b": [2, 3]}, sig))

    # ---- hidden truth never reaches a candidate-visible artifact -----------
    from siem import case_contract as cc
    from siem import enterprise
    INDEX = "ranger-pilot-cand-a-b2"
    events, truth = enterprise.generate("cand-a", 2, "regress", "B")
    reader = cc.InMemoryReader(INDEX, events)
    # indexed events carry no truth label
    check("indexed events carry no _malicious/truth label",
          all("_malicious" not in e and "verdict" not in e.get("_source", {}) for e in events))
    # candidate-facing brief discloses no structure
    brief = cc.candidate_brief("valyria-financial", "2026-03-01", "2026-03-14")
    low = brief.lower()
    check("candidate brief discloses no incident count / missed-detection / answer",
          "incident" in low and not any(w in low for w in
              ["three ", "3 incidents", "missed detection", "detection failure", "answer key"]))
    # candidate-safe verification exposes no truth
    sub = {"baseline_summary": "b", "overall_conclusion": "o",
           "incidents": [{"label": "x", "disposition": "confirmed_incident", "severity": "high",
                          "confidence": 60, "attack_techniques": ["T1078"], "primary_identity": "u",
                          "affected_assets": ["h"], "analyst_conclusion": "c",
                          "cited_evidence": [{"event_uid": truth["incidents"][0]["event_uids"][0],
                                              "index": INDEX,
                                              "query": {"query": {"ids": {"values": [truth["incidents"][0]["event_uids"][0]]}}},
                                              "role": "primary"}]}]}
    cv = cc.candidate_verification(sub, reader, INDEX)
    import json
    blob = json.dumps(cv)
    check("candidate-safe verification leaks no truth key",
          cv["truth_consulted"] is False and "malicious_activity" not in blob
          and "claim_support" not in blob and "claim_consistent" not in blob)

    print(f"\n{P} passed, {F} failed")
    return F == 0


def test_shadow_regression():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
