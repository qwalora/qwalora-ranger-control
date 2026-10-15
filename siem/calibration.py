"""Board 2 enterprise shadow-grader calibration suite.

Constructs nine deterministic submission archetypes from the protected truth of a
given seed, grades each with the SHADOW evaluator (enterprise_grader), and records
the expected band, the actual score, the raised review flags, whether the grader
agrees with the expectation, and a short reason. It also carries the anti-gaming
probes that assert a candidate cannot reach the 95% bar by guessing or padding
evidence.

This module BUILDS submissions from the truth server-side purely to exercise the
grader — it is the grader's test oracle, never anything a candidate sees. Nothing
here is wired to qualification.

Archetypes (per the M3 brief):
  1 fully_correct
  2 technically_correct_alternative
  3 partially_correct
  4 missed_incidents
  5 false_positive
  6 unsupported_fabricated_evidence
  7 correct_evidence_incorrect_conclusion
  8 correct_conclusion_insufficient_evidence
  9 strong_analysis_weak_response
Anti-gaming probes:
  g1 guessing_shotgun
  g2 evidence_padding
"""
from __future__ import annotations

from . import case_contract as cc
from . import enterprise
from . import enterprise_grader as g

# Score bands used to express expectations. PASS is the only band that reaches the
# 95% qualification bar; everything else must stay below it.
PASS = "pass(>=95)"
NEAR = "near(80..95)"
PARTIAL = "partial(40..80)"
LOW = "low(<40)"


def _band(score):
    if score >= 95:
        return PASS
    if score >= 80:
        return NEAR
    if score >= 40:
        return PARTIAL
    return LOW


def _host(src):
    h = (src or {}).get("host")
    return h.get("name") if isinstance(h, dict) else None


def _ts(src):
    return (src or {}).get("@timestamp")


class _World:
    """Everything the builders need for one seed: the truth, a reader over the
    candidate index, the member uid set, and helpers to pull member sources."""
    def __init__(self, seed, profile="B", candidate_id="cal-cand", board=2):
        self.index = f"ranger-pilot-{candidate_id}-b2"
        self.events, self.truth = enterprise.generate(candidate_id, board, seed, profile)
        self.reader = cc.InMemoryReader(self.index, self.events)
        self.members = cc._truth_member_uids(self.truth)
        self.benign = [e["_id"] for e in self.events if e["_id"] not in self.members]

    def src(self, uid):
        return self.reader.get_source(self.index, uid)

    def chain_in_order(self, tinc):
        return sorted(tinc["event_uids"], key=lambda u: str(_ts(self.src(u))))

    def cite(self, uid, role):
        return {"event_uid": uid, "index": self.index,
                "query": {"query": {"ids": {"values": [uid]}}}, "role": role}


# --- incident builders -------------------------------------------------------
def _full_incident(w: _World, tinc, confidence=90, with_response=True,
                   with_detection=True):
    uids = w.chain_in_order(tinc)
    assets = sorted({_host(w.src(u)) for u in uids if _host(w.src(u))})
    inc = {
        "label": tinc["family"], "disposition": "confirmed_incident",
        "severity": "high", "confidence": confidence,
        "attack_techniques": list(tinc["techniques"]),
        "primary_identity": tinc["primary_identity"],
        "affected_assets": assets,
        "timeline": [{"event_uid": u, "ts": _ts(w.src(u))} for u in uids],
        "cited_evidence": [w.cite(u, "primary" if i == 0 else "corroborating")
                           for i, u in enumerate(uids)],
        "analyst_conclusion": f"{tinc['family']} confirmed; chain reconstructed.",
    }
    if with_detection:
        inc["detection_assessment"] = {
            "detector_should_have_fired": True,
            "gap": "no rule covers this channel/technique",
            "proposed_detection": "author a rule keyed on the invariant tradecraft",
        }
    if with_response:
        inc["response_recommendations"] = ["isolate host", "revoke identity", "rotate creds"]
    return inc


def _base(incidents, limitations="Scoped to the assessment window.",
          conclusion="See incidents."):
    return {"baseline_summary": "Baseline established for valyria-financial.",
            "overall_conclusion": conclusion, "stated_limitations": limitations,
            "incidents": incidents}


# --- the nine archetypes -----------------------------------------------------
def build_archetypes(w: _World):
    T = w.truth["incidents"]
    out = {}

    # 1 fully correct: every incident, correct everything.
    out["fully_correct"] = (
        _base([_full_incident(w, t, confidence=95) for t in T]),
        PASS, "all incidents, correct disposition/attribution/evidence/timeline/detection")

    # 2 technically-correct alternative: correct incidents, but cites a valid
    # alternative subset of the chain (not the whole chain) and a superset-compatible
    # technique list; confidence well-calibrated. Should stay high, not cratered.
    alt = []
    for t in T:
        inc = _full_incident(w, t, confidence=80)
        uids = w.chain_in_order(t)
        keep = uids[:max(2, len(uids) - 1)]  # a defensible subset of the chain
        inc["cited_evidence"] = [w.cite(u, "primary" if i == 0 else "corroborating")
                                 for i, u in enumerate(keep)]
        inc["attack_techniques"] = list(t["techniques"]) + ["T1059"]  # extra plausible technique
        out_assets = sorted({_host(w.src(u)) for u in keep if _host(w.src(u))})
        inc["affected_assets"] = out_assets
        alt.append(inc)
    out["technically_correct_alternative"] = (
        _base(alt), NEAR, "correct incidents via a defensible subset of evidence + extra plausible technique")

    # 3 partially correct: find all but one incident.
    if len(T) >= 2:
        part = [_full_incident(w, t, confidence=85) for t in T[:-1]]
    else:
        # single-incident seed: cite only half the chain of the one incident
        inc = _full_incident(w, T[0], confidence=70)
        uids = w.chain_in_order(T[0])
        inc["cited_evidence"] = [w.cite(uids[0], "primary")]
        inc["timeline"] = inc["timeline"][:1]
        part = [inc]
    out["partially_correct"] = (
        _base(part), None, "misses at least one real incident; proportional, below bar")

    # 4 missed incidents: concludes no incidents (everything benign).
    out["missed_incidents"] = (
        _base([{"label": "all-clear", "disposition": "no_incident", "severity": "low",
                "confidence": 60,
                "cited_evidence": [w.cite(w.benign[0], "primary")]}],
              conclusion="No incidents found."),
        LOW, "marks the environment clean; misses every real incident")

    # 5 false positive: confidently flags benign clusters as incidents.
    fps = []
    for i in range(min(3, len(w.benign))):
        fps.append({
            "label": f"false-lead-{i}", "disposition": "confirmed_incident",
            "severity": "high", "confidence": 90, "attack_techniques": ["T1078"],
            "primary_identity": "someone", "affected_assets": ["ws-corp-01"],
            "analyst_conclusion": "looks malicious",
            "timeline": [{"event_uid": w.benign[i], "ts": _ts(w.src(w.benign[i]))}],
            "cited_evidence": [w.cite(w.benign[i], "primary")],
        })
    out["false_positive"] = (
        _base(fps, conclusion="Several incidents (all benign in truth)."),
        None, "confident incidents built on benign events; precision collapses")

    # 6 unsupported / fabricated evidence: real-looking conclusion, citations that
    # do not exist or do not reproduce.
    t0 = T[0]
    fab = _full_incident(w, t0, confidence=85)
    fab["cited_evidence"] = [
        {"event_uid": "FABRICATED0000000000", "index": w.index,
         "query": {"query": {"ids": {"values": ["FABRICATED0000000000"]}}}, "role": "primary"},
        {"event_uid": t0["event_uids"][0], "index": w.index,
         "query": {"query": {"term": {"host.name": "no-such-host"}}}, "role": "corroborating"},
    ]
    out["unsupported_fabricated_evidence"] = (
        _base([fab]), None, "fabricated uid + non-reproducing query; evidence quality fails")

    # 7 correct evidence, incorrect conclusion: cites the real malicious chain but
    # calls it benign (no_incident).
    t1 = T[0]
    uids = w.chain_in_order(t1)
    wrong = {"label": "misjudged", "disposition": "no_incident", "severity": "low",
             "confidence": 85,
             "cited_evidence": [w.cite(u, "primary" if i == 0 else "corroborating")
                                for i, u in enumerate(uids)],
             "analyst_conclusion": "benign automation"}
    out["correct_evidence_incorrect_conclusion"] = (
        _base([wrong], conclusion="No incident; activity is benign."),
        None, "cites the true malicious chain but dispositions it benign; review flags fire")

    # 8 correct conclusion, insufficient evidence: right incident & disposition,
    # but only one thin citation and no timeline/attribution depth.
    thin = []
    for t in T:
        uids = w.chain_in_order(t)
        thin.append({
            "label": t["family"], "disposition": "confirmed_incident", "severity": "high",
            "confidence": 65, "attack_techniques": [t["techniques"][0]],
            "primary_identity": t["primary_identity"], "affected_assets": [],
            "cited_evidence": [w.cite(uids[0], "primary")],
            "analyst_conclusion": "incident", "timeline": [{"event_uid": uids[0], "ts": _ts(w.src(uids[0]))}],
        })
    out["correct_conclusion_insufficient_evidence"] = (
        _base(thin), None, "right incidents but under-evidenced; sufficiency drags the composite below bar")

    # 9 strong analysis, weak response: full identification/evidence/attribution/
    # timeline, but no response recommendations, no detection proposal, no limitations.
    strong = [_full_incident(w, t, confidence=90, with_response=False, with_detection=False)
              for t in T]
    out["strong_analysis_weak_response"] = (
        _base(strong, limitations=""), None,
        "excellent analysis, missing response + detection + limitations; capped below bar")

    return out


def build_anti_gaming(w: _World):
    T = w.truth["incidents"]
    out = {}

    # g1 guessing shotgun: many confident incidents each on a random benign event.
    shots = []
    for i in range(min(8, len(w.benign))):
        shots.append({
            "label": f"guess-{i}", "disposition": "confirmed_incident", "severity": "high",
            "confidence": 95, "attack_techniques": ["T1078"], "primary_identity": "x",
            "affected_assets": ["h"], "analyst_conclusion": "maybe",
            "cited_evidence": [w.cite(w.benign[i], "primary")],
            "timeline": [{"event_uid": w.benign[i], "ts": _ts(w.src(w.benign[i]))}],
        })
    out["guessing_shotgun"] = (_base(shots), "guessing many incidents on benign events")

    # g2 evidence padding: one real incident, correct, but padded with many benign
    # citations as supporting evidence to inflate volume.
    t0 = T[0]
    uids = w.chain_in_order(t0)
    inc = _full_incident(w, t0, confidence=85)
    pad = [w.cite(w.benign[i], "primary") for i in range(min(12, len(w.benign)))]
    inc["cited_evidence"] = inc["cited_evidence"] + pad
    out["evidence_padding"] = (_base([inc]), "one real incident padded with benign citations")

    return out


# --- runner ------------------------------------------------------------------
def run(seed="cal-seed-01", profile="B"):
    """Grade every archetype + anti-gaming probe for one seed. Returns a dict with
    rows and the pass_bar for reference."""
    w = _World(seed, profile)
    rows = []
    for name, (sub, expected_band, reason) in build_archetypes(w).items():
        res = g.score_board2_enterprise(w.truth, sub, w.reader, w.index)
        actual = res["score"]
        band = _band(actual)
        passes = actual >= g.PASS_BAR
        agree = (expected_band is None) or (band == expected_band) or (
            # allow NEAR expectation to be met by PASS and vice-versa within tolerance
            expected_band == NEAR and band in (NEAR, PASS))
        rows.append({
            "archetype": name, "expected_band": expected_band or "below_bar",
            "actual_score": actual, "actual_band": band, "passes_bar": passes,
            "review_flags": res["review_flags"],
            "components": {k: v["score"] for k, v in res["components"].items()},
            "agree": bool(agree), "reason": reason,
            "matching": res["matching"],
        })
    anti = []
    for name, (sub, reason) in build_anti_gaming(w).items():
        res = g.score_board2_enterprise(w.truth, sub, w.reader, w.index)
        anti.append({
            "probe": name, "actual_score": res["score"], "passes_bar": res["score"] >= g.PASS_BAR,
            "review_flags": res["review_flags"], "reason": reason,
        })
    return {"seed": seed, "profile": profile, "pass_bar": g.PASS_BAR,
            "truth_families": [i["family"] for i in w.truth["incidents"]],
            "rows": rows, "anti_gaming": anti}


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2, default=str))
