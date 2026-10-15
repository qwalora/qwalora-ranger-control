"""M4.3.1 regression tests: the deterministic, pathway-aware scenario foundation -
capability inventory, versioned/typed ScenarioSpec, compile+validate+simulate+
calibrate+diversity+promote pipeline, spec-driven generation, and the preserved
production invariants. Fully offline (no AI, no cluster, no network)."""
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pathways
from siem import capability_inventory as capinv
from siem import scenario_spec as ss
from siem import scenario_pipeline as sp
from siem import enterprise

P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


def _spec(spec_id="soc-001", families=None, objective="steal customer PII",
          services=("core-banking",), gaps=("dns-exfil",), decoys=("quarter-close export",),
          difficulty="standard", seed="pkg-seed-1"):
    return {
        "spec_id": spec_id, "spec_version": 1, "pathway": "strata",
        "specialization": None, "curriculum_version": "strata-v1",
        "environment_type": "soc-opensearch", "spec_type": "soc-investigation",
        "board_compat": [2], "difficulty_profile": difficulty,
        "enterprise_version": "valyria-1", "required_capabilities": [],
        "evidence_kinds": ["event_reference"], "provenance": {"author": "human"},
        "payload": {
            "candidate_visible": {"business_context": "Valyria operations under review."},
            "admin": {
                "families": list(families or ["privileged-identity-compromise",
                                              "data-exfiltration", "detection-failure"]),
                "profile": "B", "package_seed": seed,
                "affected": {"systems": ["dc01", "db-core"], "identities": [],
                             "services": list(services)},
                "adversary": {"objective": objective, "bounded_behavior": "no destructive ops"},
                "incident_progression": [{"id": "s1", "depends_on": []},
                                         {"id": "s2", "depends_on": ["s1"]}],
                "benign_decoys": [{"pattern": d} for d in decoys],
                "response_requirements": ["revoke_token", "block_domain"],
                "detection_gaps": list(gaps),
            },
            "evaluator_only": {"protected_truth_ref": "enterprise.generate(seed)"},
        },
    }


def run():
    # ---- pathway identity (stable ids, legacy normalization, display-only branding) --
    check("stable pathway ids are strata/parallax (no marketing names in logic)",
          pathways.PATHWAYS == ("strata", "parallax") and pathways.DEFAULT_PATHWAY == "strata")
    check("legacy ids normalize non-destructively (cyber-ops->strata, cyber-ai->parallax)",
          pathways.normalize_pathway("cyber-ops") == "strata"
          and pathways.normalize_pathway("cyber-ai") == "parallax"
          and pathways.normalize_pathway("STRATA") == "strata"
          and pathways.normalize_pathway(None) == "strata")
    check("is_valid_pathway accepts canonical + legacy, rejects unknown/marketing",
          pathways.is_valid_pathway("strata") and pathways.is_valid_pathway("parallax")
          and pathways.is_valid_pathway("cyber-ops")
          and not pathways.is_valid_pathway("RANGER STRATA")
          and not pathways.is_valid_pathway("mars"))
    check("branding is display-only, present for both, and separate from ids",
          pathways.branding("strata")["name"] == "RANGER STRATA"
          and pathways.branding("parallax")["name"] == "RANGER PARALLAX"
          and pathways.branding("cyber-ai")["name"] == "RANGER PARALLAX")

    # ---- capability inventory ----------------------------------------------
    inv = capinv.build_inventory()
    check("inventory builds, pathway strata, env soc-opensearch",
          inv["pathway"] == "strata" and inv["environment_type"] == "soc-opensearch")
    check("inventory is grounded in real datasets (observed, not invented)",
          "network.dns" in inv["telemetry"]["observed_datasets"]
          and "windows.security" in inv["telemetry"]["observed_datasets"])
    check("validate_refs accepts supported, rejects unsupported",
          capinv.validate_refs(["family:data-exfiltration", "host:db-trading",
                                 "field:winlog.event_id"]) == []
          and capinv.validate_refs(["host:mars", "dataset:okta.audit", "family:nope"])
              == ["host:mars", "dataset:okta.audit", "family:nope"])
    check("future-lab capability is unavailable (not referenceable)",
          "lab:ludus-goad" not in capinv.capability_ids(inv)
          and inv["future_lab"]["ludus_goad_ranges"]["availability"] == capinv.UNAVAILABLE)
    try:
        capinv.build_inventory("media-forensics")
        media_raises = False
    except NotImplementedError:
        media_raises = True
    check("unimplemented environment type raises (no silent fake support)", media_raises)

    # ---- ScenarioSpec schema + layers --------------------------------------
    good = _spec()
    check("valid spec passes schema", ss.validate_schema(good)["ok"])

    legacy = copy.deepcopy(good); legacy["pathway"] = "cyber-ops"
    check("legacy pathway 'cyber-ops' still validates (back-compat)",
          ss.validate_schema(legacy)["ok"])

    badpw = copy.deepcopy(good); badpw["pathway"] = "RANGER STRATA"
    check("marketing/unknown pathway -> INVALID_PATHWAY",
          any(e["code"] == "INVALID_PATHWAY" for e in ss.validate_schema(badpw)["errors"]))

    missing = copy.deepcopy(good); missing["pathway"] = ""
    check("missing pathway -> MISSING_MANDATORY_FIELD",
          any(e["code"] == "MISSING_MANDATORY_FIELD" for e in ss.validate_schema(missing)["errors"]))

    unknown = copy.deepcopy(good); unknown["rogue_field"] = 1
    check("unknown envelope key -> UNKNOWN_FIELD",
          any(e["code"] == "UNKNOWN_FIELD" for e in ss.validate_schema(unknown)["errors"]))

    privileged = copy.deepcopy(good); privileged["payload"]["admin"]["command"] = "rm -rf /"
    r = ss.validate_schema(privileged)
    check("privileged/executable key rejected (no command injection via fields)",
          not r["ok"] and any(e["code"] == "PRIVILEGED_FIELD" for e in r["errors"]))

    badtype = copy.deepcopy(good); badtype["spec_type"] = "deepfake-forensics"
    check("unregistered spec_type -> UNSUPPORTED_SPEC_TYPE",
          any(e["code"] == "UNSUPPORTED_SPEC_TYPE" for e in ss.validate_schema(badtype)["errors"]))

    futurekind = copy.deepcopy(good); futurekind["evidence_kinds"] = ["media_asset"]
    check("declared-but-unimplemented evidence kind -> EVIDENCE_KIND_NOT_IMPLEMENTED",
          any(e["code"] == "EVIDENCE_KIND_NOT_IMPLEMENTED" for e in ss.validate_schema(futurekind)["errors"]))

    cv = ss.candidate_view(good)
    check("candidate_view excludes evaluator_only (no truth leak)",
          "evaluator_only" not in str(cv) and "protected_truth_ref" not in str(cv))
    av = ss.admin_view(good)
    check("admin_view excludes evaluator_only too",
          "protected_truth_ref" not in str(av))

    h1 = ss.content_hash(good)
    edited = copy.deepcopy(good); edited["payload"]["admin"]["profile"] = "C"
    check("content hash is stable and changes on edit (immutability anchor)",
          h1 == ss.content_hash(copy.deepcopy(good)) and h1 != ss.content_hash(edited))

    # ---- capability + causal validation ------------------------------------
    unsup = copy.deepcopy(good); unsup["payload"]["admin"]["affected"]["systems"] = ["mars-01"]
    rv = ss.validate_schema(unsup)
    check("unsupported host -> UNSUPPORTED_CAPABILITY",
          any(e["code"] == "UNSUPPORTED_CAPABILITY" for e in rv["errors"]))

    broken = copy.deepcopy(good)
    broken["payload"]["admin"]["incident_progression"] = [{"id": "s2", "depends_on": ["s1"]}]
    rc = sp.validate(broken)
    check("broken causal dependency -> BROKEN_CAUSALITY",
          any(e["code"] == "BROKEN_CAUSALITY" for e in rc["errors"]))

    # ---- simulate (executable test) ----------------------------------------
    sim = sp.simulate(good)
    check("simulate: all checks pass (telemetry/detection/truth/evidence/reproducible)",
          sim["ok"] and all(c["ok"] for c in sim["checks"].values()))
    check("simulate reproducibility: regeneration identical", sim["checks"]["reproducible"]["ok"])

    # ---- calibrate ---------------------------------------------------------
    cal = sp.calibrate(good, sim)
    check("calibrate yields a vector + band from the simulated world",
          "kill_chain_depth" in cal["vector"] and cal["band"] in sp.DIFFICULTY_BANDS)

    # ---- diversity: superficial variation is NOT material ------------------
    a = _spec(spec_id="pkg-A", seed="seed-A")
    b_superficial = _spec(spec_id="pkg-B", seed="seed-B")  # only id+seed differ
    c_material = _spec(spec_id="pkg-C", seed="seed-C", objective="tamper trading positions",
                       families=["compromised-service-identity", "endpoint-lateral-movement"],
                       services=["trading-platform"], gaps=["svc-wrong-host"])
    check("superficial variation (only ids/seeds) is NOT materially diverse",
          not sp.is_materially_diverse(b_superficial, [a])["material"])
    check("different objective/families/gaps IS materially diverse",
          sp.is_materially_diverse(c_material, [a])["material"])

    # ---- promote gating ----------------------------------------------------
    gspec = _spec(spec_id="promote-1")
    gsim = sp.simulate(gspec)
    gcal = sp.calibrate(gspec, gsim)
    gspec["difficulty_profile"] = gcal["band"]
    gcal = sp.calibrate(gspec, gsim)
    no_appr = sp.promote(gspec, gsim, gcal, approver="", prior_specs=[])
    check("promote without approver -> blocked (NO_APPROVER)",
          not no_appr["ok"] and any(e["code"] == "NO_APPROVER" for e in no_appr["errors"]))
    dup = sp.promote(gspec, gsim, gcal, approver="admin-1", prior_specs=[copy.deepcopy(gspec)])
    check("promote duplicate axes -> blocked (NOT_MATERIALLY_DIVERSE)",
          not dup["ok"] and any(e["code"] == "NOT_MATERIALLY_DIVERSE" for e in dup["errors"]))
    mism = copy.deepcopy(gspec); mism["difficulty_profile"] = "intro"
    rmis = sp.promote(mism, sp.simulate(mism), sp.calibrate(mism, sp.simulate(mism)),
                      approver="admin-1", prior_specs=[])
    check("promote difficulty mismatch -> blocked (DIFFICULTY_MISMATCH)",
          not rmis["ok"] and any(e["code"] == "DIFFICULTY_MISMATCH" for e in rmis["errors"]))
    ok = sp.promote(gspec, gsim, gcal, approver="admin-1", prior_specs=[])
    check("promote all-pass -> catalog_eligible + content hash + approver",
          ok["ok"] and ok["state"] == "catalog_eligible" and ok["content_hash"]
          and ok["approved_by"] == "admin-1")

    # ---- spec-driven generation (enterprise.generate families=) ------------
    ev1, t1 = enterprise.generate("k", 2, "s", "B", families=["data-exfiltration",
                                                              "privileged-identity-compromise"])
    ev2, t2 = enterprise.generate("k", 2, "s", "B", families=["data-exfiltration",
                                                              "privileged-identity-compromise"])
    check("families= honored + deterministic",
          [i["family"] for i in t1["incidents"]][:2] == ["data-exfiltration", "privileged-identity-compromise"]
          and [e["_id"] for e in ev1] == [e["_id"] for e in ev2])
    try:
        enterprise.generate("k", 2, "s", "B", families=["nope"]); raised = False
    except ValueError:
        raised = True
    check("unknown family -> ValueError", raised)
    evd, _ = enterprise.generate("k", 2, "s", "A")  # default path unchanged
    check("default (no families) generation still works", len(evd) > 0)

    # ---- preserved production invariants ------------------------------------
    import program
    check("program.PASS_BAR unchanged (95.0)", program.PASS_BAR == 95.0)
    import scenarios
    scen = scenarios.generate_board2("inv-regress")
    zero, _ = scenarios.score_board2(scen, {"alerts": []})
    check("score_board2 unchanged: empty submission scores 0", zero == 0.0)
    import signing
    sg = signing.sign({"a": 1})
    check("Ed25519 signing round-trips", signing.verify({"a": 1}, sg) and not signing.verify({"a": 2}, sg))
    import models
    cols = models.ScenarioCatalogEntry.__table__.columns.keys()
    check("ScenarioCatalogEntry model present + pathway-aware + immutable version",
          {"spec_id", "spec_version", "pathway", "content_hash", "status"} <= set(cols))
    ccols = models.Cohort.__table__.columns.keys()
    check("Cohort is pathway-aware (default strata, backward compatible)",
          "pathway" in ccols and "curriculum_version" in ccols
          and models.Cohort.PATHWAYS == ("strata", "parallax")
          and models.Cohort.pathway.default.arg == "strata")
    bcols = models.BoardResult.__table__.columns.keys()
    check("BoardResult objective fields untouched",
          {"objective_score", "objective_passed", "objective_sig"} <= set(bcols))

    print(f"\n{P} passed, {F} failed")
    return F == 0


def test_scenario_catalog():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
