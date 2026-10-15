"""Milestone 1 tests for the Board 2 case contract: submission validation, the
server-side evidence verification procedure, evidence preservation + signing +
tamper detection, and the lifecycle state machine. Uses real enterprise.generate
data and an in-memory reader (no live cluster)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from siem import case_contract as cc
from siem import enterprise

INDEX = "ranger-pilot-cand-a-b2"


def _dataset():
    events, truth = enterprise.generate("cand-a", 2, "case-contract-test", "A")
    reader = cc.InMemoryReader(INDEX, events)
    member = set()
    for inc in truth["incidents"]:
        member.update(inc["event_uids"])
    mal_uid = truth["incidents"][0]["event_uids"][0]
    ben_uid = next(e["_id"] for e in events if e["_id"] not in member)
    return events, truth, reader, mal_uid, ben_uid


def _good_submission(mal_uid):
    return {
        "baseline_summary": "Established baseline for valyria-financial.",
        "overall_conclusion": "One confirmed privileged-identity incident.",
        "stated_limitations": "Limited to the assessment window.",
        "incidents": [{
            "label": "priv-id-compromise",
            "disposition": "confirmed_incident",
            "severity": "high",
            "confidence": 70,
            "attack_techniques": ["T1078", "T1059.001"],
            "primary_identity": "someone",
            "affected_assets": ["host-1"],
            "timeline": [{"event_uid": mal_uid, "ts": "2026-03-01T00:00:00Z", "note": "logon"}],
            "cited_evidence": [{
                "event_uid": mal_uid, "index": INDEX,
                "query": {"query": {"ids": {"values": [mal_uid]}}},
                "supports_claim": "anomalous privileged logon",
            }],
            "detection_assessment": {"detector_should_have_fired": True, "gap": "x", "proposed_detection": "y"},
            "response_recommendations": ["contain"],
            "analyst_conclusion": "Privileged identity compromised.",
        }],
    }


P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name)
    P += ok; F += (not ok)


def run():
    events, truth, reader, mal_uid, ben_uid = _dataset()

    # --- validation ---------------------------------------------------------
    good = _good_submission(mal_uid)
    check("valid submission passes validation", cc.validate_submission(good)["ok"])

    missing = _good_submission(mal_uid); missing["baseline_summary"] = ""
    r = cc.validate_submission(missing)
    check("missing baseline -> MISSING_MANDATORY_FIELD",
          not r["ok"] and any(e["code"] == "MISSING_MANDATORY_FIELD" for e in r["errors"]))

    badtech = _good_submission(mal_uid); badtech["incidents"][0]["attack_techniques"] = ["T1078", "nope"]
    r = cc.validate_submission(badtech)
    check("bad technique id -> BAD_TECHNIQUE_ID",
          any(e["code"] == "BAD_TECHNIQUE_ID" for e in r["errors"]))

    noev = _good_submission(mal_uid); noev["incidents"][0]["cited_evidence"] = []
    r = cc.validate_submission(noev)
    check("confirmed incident w/o evidence -> EMPTY_EVIDENCE_FOR_CONFIRMED",
          any(e["code"] == "EMPTY_EVIDENCE_FOR_CONFIRMED" for e in r["errors"]))

    badconf = _good_submission(mal_uid); badconf["incidents"][0]["confidence"] = 250
    r = cc.validate_submission(badconf)
    check("confidence out of range -> CONFIDENCE_OUT_OF_RANGE",
          any(e["code"] == "CONFIDENCE_OUT_OF_RANGE" for e in r["errors"]))

    # --- evidence verification ---------------------------------------------
    v = cc.verify_evidence(good, reader, INDEX, truth=truth)
    cite0 = v["incidents"][0]["citations"][0]
    check("malicious citation: exists+reproduces+member+credit",
          cite0["exists"] and cite0["reproduces"] and cite0["incident_member"] and cite0["credit_eligible"])

    # benign event cited for an incident: exists + reproduces but NOT a member -> no credit
    ben = _good_submission(ben_uid)
    vb = cc.verify_evidence(ben, reader, INDEX, truth=truth)
    cb = vb["incidents"][0]["citations"][0]
    check("benign citation: exists+reproduces but not member -> NOT credit-eligible",
          cb["exists"] and cb["reproduces"] and cb["incident_member"] is False and not cb["credit_eligible"])

    # fabricated uid -> not found
    fab = _good_submission("FABRICATEDUID000000")
    vf = cc.verify_evidence(fab, reader, INDEX, truth=truth)
    cf = vf["incidents"][0]["citations"][0]
    check("fabricated uid -> EVIDENCE_UID_NOT_FOUND, no credit",
          (not cf["exists"]) and ("EVIDENCE_UID_NOT_FOUND" in cf["errors"]) and not cf["credit_eligible"])

    # out-of-scope index
    oos = _good_submission(mal_uid)
    oos["incidents"][0]["cited_evidence"][0]["index"] = "ranger-pilot-cand-b-b2"
    vo = cc.verify_evidence(oos, reader, INDEX, truth=truth)
    co = vo["incidents"][0]["citations"][0]
    check("out-of-scope index -> EVIDENCE_OUT_OF_SCOPE, no credit",
          ("EVIDENCE_OUT_OF_SCOPE" in co["errors"]) and not co["credit_eligible"])

    # query that does not reproduce (term on a wrong value)
    nr = _good_submission(mal_uid)
    nr["incidents"][0]["cited_evidence"][0]["query"] = {"query": {"term": {"host.name": "no-such-host-xyz"}}}
    vn = cc.verify_evidence(nr, reader, INDEX, truth=truth)
    cn = vn["incidents"][0]["citations"][0]
    check("non-reproducing query -> QUERY_DOES_NOT_REPRODUCE, no credit",
          cn["exists"] and (not cn["reproduces"]) and ("QUERY_DOES_NOT_REPRODUCE" in cn["errors"])
          and not cn["credit_eligible"])

    # truth not supplied -> incident_member is None, credit not gated on membership
    vns = cc.verify_evidence(good, reader, INDEX, truth=None)
    cns = vns["incidents"][0]["citations"][0]
    check("no truth -> member None, credit on exists+reproduces only",
          cns["incident_member"] is None and cns["credit_eligible"])

    # --- preservation + signing + tamper ------------------------------------
    meta = {"candidate": "cand-a", "board": 2, "cohort": "pilot", "seed": "case-contract-test",
            "case_id": 1, "submitted_at": "2026-03-20T00:00:00Z"}
    record, sig = cc.preserve_and_sign(good, reader, INDEX, meta)
    check("evidence record signs + verifies", cc.verify_evidence_record(record, sig))
    tampered = dict(record); tampered["cited"] = list(record["cited"]) + [{"event_uid": "x", "sha256": "0"}]
    check("tampered record fails verification", not cc.verify_evidence_record(tampered, sig))
    check("integrity re-verify ok against live index", cc.reverify_integrity(record, reader)["ok"])

    # --- lifecycle ----------------------------------------------------------
    check("lifecycle: assigned->authorized ok", cc.can_transition("assigned", "authorized"))
    check("lifecycle: submitted->evaluated ok", cc.can_transition("submitted", "evaluated"))
    check("lifecycle: assigned->closed rejected", not cc.can_transition("assigned", "closed"))
    check("lifecycle: closed is terminal", not cc.CASE_TRANSITIONS["closed"])

    print(f"\n{P} passed, {F} failed")
    return F == 0


def test_case_contract():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
