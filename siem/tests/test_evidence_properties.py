"""M3 tests: the three NON-INTERCHANGEABLE evidence properties (reference validity,
claim support, malicious-activity determination) and the hardened evidence
preservation (embedded snapshots, self-consistency offline, unavailable-index
handling, no hidden truth in the record). Uses real enterprise.generate data and
an in-memory reader."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from siem import case_contract as cc
from siem import enterprise

INDEX = "ranger-pilot-cand-a-b2"

P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


def _world(seed="props-01"):
    events, truth = enterprise.generate("cand-a", 2, seed, "B")
    reader = cc.InMemoryReader(INDEX, events)
    members = cc._truth_member_uids(truth)
    mal = truth["incidents"][0]["event_uids"][0]
    ben = next(e["_id"] for e in events if e["_id"] not in members)
    return events, truth, reader, mal, ben


def _one(disposition, uid, role):
    inc = {"label": "x", "disposition": disposition, "severity": "high", "confidence": 60,
           "attack_techniques": ["T1078"], "cited_evidence": [
               {"event_uid": uid, "index": INDEX,
                "query": {"query": {"ids": {"values": [uid]}}}, "role": role}]}
    if disposition == "confirmed_incident":
        inc.update(primary_identity="u", affected_assets=["h"], analyst_conclusion="c")
    return {"baseline_summary": "b", "overall_conclusion": "o", "incidents": [inc]}


def _cite(v):
    return v["incidents"][0]["citations"][0]


def run():
    events, truth, reader, mal, ben = _world()

    # ---- the three properties are distinct ---------------------------------
    # malicious event, cited as PRIMARY for a confirmed incident:
    v = _cite(cc.verify_evidence(_one("confirmed_incident", mal, "primary"), reader, INDEX, truth=truth))
    check("malicious primary: reference_valid A, malicious C=True, claim_support B=supported",
          v["reference_valid"] is True and v["malicious_activity"] is True
          and v["claim_support"] == "supported")

    # benign event, legitimately cited as a BASELINE under a confirmed incident:
    # reference-valid, NOT malicious, and claim-supported (membership is not required
    # for a baseline). Membership alone does not drive the credit.
    v = _cite(cc.verify_evidence(_one("confirmed_incident", ben, "baseline"), reader, INDEX, truth=truth))
    check("benign baseline: valid A, malicious C=False, claim_support B=supported (legit comparison)",
          v["reference_valid"] and v["malicious_activity"] is False and v["claim_support"] == "supported")

    # benign as EXCLUSION likewise credited
    v = _cite(cc.verify_evidence(_one("confirmed_incident", ben, "exclusion"), reader, INDEX, truth=truth))
    check("benign exclusion: claim_support B=supported", v["claim_support"] == "supported")

    # the KEY non-interchangeability: a REAL malicious event mis-filed as a benign
    # baseline is MISCLASSIFIED (C=True but B=unsupported) and flagged — membership
    # did not earn credit.
    v = _cite(cc.verify_evidence(_one("confirmed_incident", mal, "baseline"), reader, INDEX, truth=truth))
    check("malicious mis-filed as baseline: C=True but B=misclassified + flag (membership != credit)",
          v["malicious_activity"] is True and v["claim_support"] == "misclassified"
          and v.get("review_flag") == cc.FLAG_MALICIOUS_AS_REFERENCE)

    # benign as PRIMARY proof of a confirmed incident: valid ref, but unsupported + flag
    v = _cite(cc.verify_evidence(_one("confirmed_incident", ben, "primary"), reader, INDEX, truth=truth))
    check("benign primary for confirmed: B=unsupported + primary-inconsistent flag",
          v["reference_valid"] and v["claim_support"] == "unsupported"
          and v.get("review_flag") == cc.FLAG_PRIMARY_INCONSISTENT)

    # corroborating role: member strengthens (supported), benign is partial (not zero)
    vm = _cite(cc.verify_evidence(_one("confirmed_incident", mal, "corroborating"), reader, INDEX, truth=truth))
    vb = _cite(cc.verify_evidence(_one("confirmed_incident", ben, "corroborating"), reader, INDEX, truth=truth))
    check("corroborating: member supported(1.0), benign partial(>0, not zeroed)",
          vm["claim_support"] == "supported" and vm["relevance"] == 1.0
          and vb["claim_support"] == "partial" and 0 < vb["relevance"] < 1.0)

    # no_incident citing a malicious member in a supporting role: missed detection flag
    v = _cite(cc.verify_evidence(_one("no_incident", mal, "corroborating"), reader, INDEX, truth=truth))
    check("no_incident cites malicious member: misclassified + benign-disposition flag",
          v["claim_support"] == "misclassified"
          and v.get("review_flag") == cc.FLAG_BENIGN_DISP_CITES_MALICIOUS)

    # reference INVALIDITY is independent of the other two: a fabricated uid is not
    # reference-valid and carries no malicious/claim determination the grader trusts.
    v = _cite(cc.verify_evidence(_one("confirmed_incident", "FABRICATED0000000000", "primary"),
                                 reader, INDEX, truth=truth))
    check("fabricated uid: reference_valid A=False, exists False",
          v["reference_valid"] is False and v["exists"] is False)

    # ---- candidate-safe mode reveals NONE of properties B or C -------------
    cv = _cite(cc.candidate_verification(_one("confirmed_incident", mal, "primary"), reader, INDEX))
    check("candidate-safe exposes property A only (no B/C keys)",
          cv["reference_valid"] and "malicious_activity" not in cv
          and "claim_support" not in cv and "claim_consistent" not in cv)

    # ---- preservation hardening --------------------------------------------
    good = _one("confirmed_incident", mal, "primary")
    # add a second real citation so the record has >1 entry
    good["incidents"][0]["cited_evidence"].append(
        {"event_uid": truth["incidents"][0]["event_uids"][1], "index": INDEX,
         "query": {"query": {"ids": {"values": [truth["incidents"][0]["event_uids"][1]]}}},
         "role": "corroborating"})
    meta = {"candidate": "cand-a", "board": 2, "cohort": "pilot", "seed": "props-01",
            "case_id": 1, "submitted_at": "2026-03-20T00:00:00Z"}
    rec, sig = cc.preserve_and_sign(good, reader, INDEX, meta)
    check("record signs + verifies (integrity/origin)", cc.verify_evidence_record(rec, sig))
    check("record carries provenance: index, role, query, sha256, snapshot per citation",
          all(c.get("index") == INDEX and c.get("role") and isinstance(c.get("query"), dict)
              and c.get("sha256") and "source_snapshot" in c for c in rec["cited"]))

    # self-consistent offline (no cluster needed)
    sc = cc.verify_record_self_consistent(rec)
    check("record self-verifies offline from embedded snapshots", sc["ok"] and not sc["mismatches"])

    # tamper a snapshot -> self-consistency breaks AND signature breaks
    tam = {**rec, "cited": [dict(c) for c in rec["cited"]]}
    tam["cited"][0]["source_snapshot"] = {"tampered": True}
    check("tampered snapshot fails self-consistency", not cc.verify_record_self_consistent(tam)["ok"])
    check("tampered snapshot fails signature", not cc.verify_evidence_record(tam, sig))

    # unavailable index: a reader that returns nothing -> verified offline, still ok
    class _Empty:
        def get_source(self, *a, **k): return None
        def query_matches(self, *a, **k): return False
    ri = cc.reverify_integrity(rec, _Empty())
    check("unavailable index -> index_unavailable + verified_offline + ok",
          ri["index_unavailable"] and ri["verified_offline"] and ri["ok"] and not ri["missing"])

    # live index intact -> ok, not offline
    ri2 = cc.reverify_integrity(rec, reader)
    check("live index intact -> ok, not offline", ri2["ok"] and not ri2["index_unavailable"])

    # ---- NO hidden truth ever lands in the preserved record ----------------
    import json as _json
    blob = _json.dumps(rec)
    check("record has no truth/verdict/_malicious field",
          "_malicious" not in blob and '"verdict"' not in blob and '"techniques"' not in blob
          and all("_malicious" not in (c.get("source_snapshot") or {}) for c in rec["cited"]))

    print(f"\n{P} passed, {F} failed")
    return F == 0


def test_evidence_properties():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
