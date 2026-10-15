"""M3 tests for the enterprise SHADOW grader (score_board2_enterprise): component
behaviour, anchors, human-review triggers, preserved v2 weights, the
applicable-only renormalization, and the shadow-only invariant (never imports or
mutates qualification state)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from siem import case_contract as cc
from siem import enterprise
from siem import enterprise_grader as g

INDEX = "ranger-pilot-cand-a-b2"

P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


def _world(seed):
    events, truth = enterprise.generate("cand-a", 2, seed, "B")
    reader = cc.InMemoryReader(INDEX, events)
    return events, truth, reader


def _host(src):
    h = (src or {}).get("host")
    return h.get("name") if isinstance(h, dict) else None


def _perfect(truth, reader):
    incs = []
    for t in truth["incidents"]:
        uids = sorted(t["event_uids"], key=lambda u: reader.get_source(INDEX, u)["@timestamp"])
        incs.append({
            "label": t["family"], "disposition": "confirmed_incident", "severity": "high",
            "confidence": 95, "attack_techniques": list(t["techniques"]),
            "primary_identity": t["primary_identity"],
            "affected_assets": sorted({_host(reader.get_source(INDEX, u)) for u in uids if _host(reader.get_source(INDEX, u))}),
            "timeline": [{"event_uid": u, "ts": reader.get_source(INDEX, u)["@timestamp"]} for u in uids],
            "cited_evidence": [{"event_uid": u, "index": INDEX,
                                "query": {"query": {"ids": {"values": [u]}}},
                                "role": "primary" if i == 0 else "corroborating"}
                               for i, u in enumerate(uids)],
            "detection_assessment": {"detector_should_have_fired": True, "gap": "x", "proposed_detection": "y"},
            "response_recommendations": ["contain"],
            "analyst_conclusion": "confirmed",
        })
    return {"baseline_summary": "b", "overall_conclusion": "all found",
            "stated_limitations": "window", "incidents": incs}


def run():
    # ---- preserved v2 weights ----------------------------------------------
    check("weights sum to 100", sum(g.WEIGHTS.values()) == 100)
    check("weights match approved rubric v2",
          g.WEIGHTS == {"incident_identification": 30, "evidence_quality": 20,
                        "attribution": 15, "detection_gap": 15,
                        "timeline_correlation": 10, "judgment": 10})
    check("grader reports rubric_version 2 and version 1",
          g.RUBRIC_VERSION == 2 and g.ENTERPRISE_GRADER_VERSION == 1)
    check("pass bar reference is 95.0 and comes from program.py", g.PASS_BAR == 95.0)

    events, truth, reader = _world("grader-01")
    res = g.score_board2_enterprise(truth, _perfect(truth, reader), reader, INDEX)

    # ---- shadow invariants --------------------------------------------------
    check("result marked shadow", res["shadow"] is True)
    check("perfect submission scores >= 95 (passes shadow bar)", res["score"] >= 95.0)
    check("every component present with weight+anchor+applicable",
          set(res["components"]) == set(g.WEIGHTS)
          and all({"score", "weight", "anchor", "applicable", "points"} <= set(c)
                  for c in res["components"].values()))
    check("perfect submission: all applicable components anchor full",
          all(c["anchor"] == "full" for c in res["components"].values() if c["applicable"]))

    # ---- applicable-only renormalization -----------------------------------
    df_present = any(t.get("verdict") == g._DETECTION_FAILURE_VERDICT for t in truth["incidents"])
    comp = res["components"]["detection_gap"]
    check("detection_gap applicability tracks presence of a detection-failure scenario",
          comp["applicable"] == df_present)
    # denominator = sum of applicable weights only
    den = sum(c["weight"] for c in res["components"].values() if c["applicable"])
    num = sum(c["points"] for c in res["components"].values() if c["applicable"])
    check("normalized == applicable points / applicable weights",
          abs(res["normalized"] - (num / den)) < 1e-3)

    # ---- missing incident collapses identification + fires trigger ----------
    half = _perfect(truth, reader)
    if len(half["incidents"]) >= 2:
        half["incidents"] = half["incidents"][:-1]
    r2 = g.score_board2_enterprise(truth, half, reader, INDEX)
    check("missing a real incident cannot reach the bar",
          r2["score"] < 95.0 and r2["components"]["incident_identification"]["score"] < 1.0)

    # ---- false incident fires FALSE_INCIDENT_CLAIMED ------------------------
    ben = next(e["_id"] for e in events if e["_id"] not in cc._truth_member_uids(truth))
    fp = _perfect(truth, reader)
    fp["incidents"].append({"label": "fl", "disposition": "confirmed_incident", "severity": "high",
                            "confidence": 95, "attack_techniques": ["T1078"],
                            "primary_identity": "x", "affected_assets": ["h"],
                            "analyst_conclusion": "c",
                            "cited_evidence": [{"event_uid": ben, "index": INDEX,
                                                "query": {"query": {"ids": {"values": [ben]}}},
                                                "role": "primary"}]})
    r3 = g.score_board2_enterprise(truth, fp, reader, INDEX)
    check("false incident -> FALSE_INCIDENT_CLAIMED + precision drop",
          g.TRIG_FALSE_INCIDENT in r3["review_flags"]
          and bool(r3["matching"]["false_incidents"]))

    # ---- near-bar trigger band ---------------------------------------------
    check("near-bar trigger only fires in [90,97)",
          (g.TRIG_NEAR_BAR in res["review_flags"]) == (90.0 <= res["score"] < 97.0))

    # ---- grader never imports qualification write-path ----------------------
    import inspect
    src = inspect.getsource(g)
    check("grader does not reference BoardResult / objective_ / clearance",
          "BoardResult" not in src and "objective_" not in src and "clearance" not in src)
    check("grader reads program.PASS_BAR but never writes back to program",
          "_program.PASS_BAR" in src
          and "_program.PASS_BAR =" not in src and "program.PASS_BAR =" not in src)

    print(f"\n{P} passed, {F} failed")
    return F == 0


def test_enterprise_grader():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
