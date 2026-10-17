"""M4.3.1 - the Ranger Capability Inventory.

A versioned, machine-readable statement of what Ranger can ACTUALLY produce and
verify, derived programmatically from the real implementation modules so it cannot
drift from the code. It is the authority an AI- or human-authored ScenarioSpec is
validated against (siem/scenario_pipeline.py): a spec may reference only capabilities
listed here, and a referenced capability that does not exist is a hard validation
failure. Nothing here is invented - every entry cites its source symbol, and the
telemetry datasets/fields are observed from a real generated world, not declared by
hand.

Deterministic and offline: building the inventory generates one small in-memory
Profile-A world (no cluster, no AI, no network) to observe the datasets and winlog
fields the generator truly emits.
"""
from __future__ import annotations

import hashlib

from . import SCHEMA_VERSION, GENERATOR_VERSION
from . import enterprise, detection, schema, case_contract

CAPABILITY_INVENTORY_VERSION = 1
FOUNDATION_VERSION = "valyria-1"   # the persistent Valyria enterprise foundation id

# Ranger is an extensible platform with two PATHWAYS (stable internal ids; see the
# root `pathways` module for the single source of truth and the display-only branding):
#   strata   - RANGER STRATA: the existing 26-week six-board SOC/adversarial program.
#   parallax - RANGER PARALLAX: the digital-forensics & AI-security pathway (deepfake
#              forensics, synthetic-identity fraud, LLM/agent security, adversarial AI
#              assessment). PARALLAX does NOT inherit the six-board sequence; its
#              curriculum is designed and approved separately.
# A capability inventory is PER environment type, not SOC-only: the SOC/OpenSearch
# inventory is one builder; PARALLAX environment types (e.g. media-forensics) register
# their own builder here without changing the catalog, cohort, or evidence-verification
# contracts. Today only the SOC environment is implemented.
from pathways import PATHWAY_STRATA, PATHWAY_PARALLAX  # stable ids, not marketing names
ENVIRONMENT_SOC_OPENSEARCH = "soc-opensearch"
ENVIRONMENT_GOAD_RANGE = "goad-range"   # S6: isolated GOAD AD red-team ranges (boards 5/6)
# S4: the seed-dataset environment behind STRATA boards 1/3/4 (triage, detection, IR). These are
# graded in-process against a seeded dataset rather than a live cluster, so their inventory is the
# dataset generator's own capability surface, not the OpenSearch topology.
ENVIRONMENT_SOC_DATASET = "soc-dataset"
# Declared, not implemented (future PARALLAX environment types):
ENVIRONMENT_MEDIA_FORENSICS = "media-forensics"   # deepfake audio/video forensics
ENVIRONMENT_LLM_REDTEAM = "llm-redteam"           # LLM/agent security, prompt injection
KNOWN_ENVIRONMENT_TYPES = (ENVIRONMENT_SOC_OPENSEARCH, ENVIRONMENT_MEDIA_FORENSICS,
                           ENVIRONMENT_LLM_REDTEAM)

# Availability states a capability can be in.
AVAILABLE = "available"
LIMITED = "limited"            # works with a documented constraint
UNAVAILABLE = "unavailable"    # declared for the future, not usable now


def _schema_leaf_fields() -> list[str]:
    props = schema.INDEX_MAPPING["mappings"]["properties"]

    def leaves(d, prefix=""):
        out = []
        for k, v in d.items():
            if isinstance(v, dict) and "properties" in v:
                out += leaves(v["properties"], prefix + k + ".")
            else:
                out.append(prefix + k)
        return out

    return sorted(leaves(props))


def _observed_datasets_and_fields():
    """Observe the datasets and winlog.event_data fields the generator REALLY emits,
    by generating one small deterministic world (Profile A). Grounds the inventory in
    actual output rather than a hand-maintained list."""
    events, _truth = enterprise.generate("capinv", 2, "capability-inventory", "A")
    datasets, actions, winlog_fields = set(), set(), set()
    for e in events:
        src = e["_source"]
        ev = src.get("event", {})
        if ev.get("dataset"):
            datasets.add(ev["dataset"])
        if ev.get("action"):
            actions.add(ev["action"])
        wl = src.get("winlog", {}) or {}
        ed = wl.get("event_data", {}) or {}
        for k in ed:
            winlog_fields.add("winlog.event_data." + k)
    return sorted(datasets), sorted(actions), sorted(winlog_fields)


def _topology_hash(obj) -> str:
    import json
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:16]


def build_inventory(environment_type: str = ENVIRONMENT_SOC_OPENSEARCH) -> dict:
    """Assemble the capability inventory for an environment type. Pure + deterministic.

    Only the SOC/OpenSearch environment is implemented today; other environment types
    (future AI-track specializations) raise so nothing silently claims support it does
    not have."""
    if environment_type == ENVIRONMENT_SOC_DATASET:
        return _build_soc_dataset_inventory()
    if environment_type == ENVIRONMENT_GOAD_RANGE:
        return _build_goad_inventory()
    if environment_type != ENVIRONMENT_SOC_OPENSEARCH:
        raise NotImplementedError(
            f"environment_type {environment_type!r} is declared but not implemented; "
            f"only {ENVIRONMENT_SOC_OPENSEARCH!r} and {ENVIRONMENT_SOC_DATASET!r} "
            f"have a capability inventory today")
    return _build_soc_opensearch_inventory()


def _build_soc_dataset_inventory() -> dict:
    """Minimal inventory for the seed-dataset boards (1/3/4). The board-typed payload validators
    (soc-triage / detection-engineering / ir-forensics) validate structural fields directly and do
    not resolve capability refs against this inventory, so it records only the environment id."""
    return {"environment_type": ENVIRONMENT_SOC_DATASET, "id": "strata-dataset-1",
            "capabilities": {}, "families": [], "hosts": [], "identities": []}


def _build_goad_inventory() -> dict:
    """Deterministic capability inventory for the isolated GOAD ranges (boards 5/6). It records the
    domains, DCs, member servers and the service / AS-REP identities the GOAD blueprint seeds, so a
    board-5/6 spec's referenced accounts and hosts can be checked for feasibility, and so the range
    attestation can later compare an expected VM inventory. No secrets or flags are recorded here."""
    return {
        "environment_type": ENVIRONMENT_GOAD_RANGE, "id": "strata-goad-1",
        "domains": ["sevenkingdoms.local", "north.sevenkingdoms.local", "essos.local"],
        "dcs": ["kingslanding", "winterfell", "braavos"],
        "servers": ["castelblack", "meereen"],
        "hosts": ["kingslanding", "winterfell", "braavos", "castelblack", "meereen"],
        "identities": {
            "service_accounts": ["sql_svc", "http_svc", "backup_svc", "web_svc"],
            "asrep_users": ["brandon.stark", "missandei", "jon.snow", "samwell.tarly"],
        },
        "capabilities": {}, "families": [],
    }


def _build_soc_opensearch_inventory() -> dict:
    datasets, actions, winlog_ed_fields = _observed_datasets_and_fields()

    identities = {
        "people": sorted({p["user"] for p in enterprise.PEOPLE}),
        "service_accounts": sorted({s["user"] for s in enterprise.SERVICE_ACCOUNTS}),
        "admins": sorted({a["user"] for a in enterprise.ADMINS}),
    }
    assets = {
        "hosts": {h: seg for h, seg in enterprise.HOSTS.items()},
        "segments": list(enterprise.SEGMENTS),
        "business_apps": list(enterprise.BUSINESS_APPS),
        "departments": list(enterprise.DEPARTMENTS),
    }

    foundation = {
        "id": FOUNDATION_VERSION,
        "org": enterprise.ORG,
        "identities": identities,
        "assets": assets,
        "external_benign": list(enterprise.EXTERNAL_BENIGN),
        "external_suspicious": list(enterprise.EXTERNAL_SUS),
        "source": "siem/enterprise.py",
    }

    telemetry = {
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "ecs_fields": _schema_leaf_fields(),           # candidate-queryable fields (schema.INDEX_MAPPING)
        "observed_datasets": datasets,                 # datasets the generator actually emits
        "observed_actions": actions,
        "operational_keyword_fields": winlog_ed_fields + [
            # the op-plane keyword fields M4.2 proved necessary for Sigma endswith/wildcard
            "winlog.event_data.Image", "winlog.event_data.ParentImage",
            "winlog.event_data.CommandLine", "winlog.event_data.TargetUserName",
            "winlog.event_data.MemberName", "winlog.event_data.SubjectUserName",
        ],
        "source": "siem/schema.py",
    }

    scenario_families = {
        fam: {"id": f"family:{fam}", "source": "siem/enterprise.py:SCENARIO_FAMILIES",
              "availability": AVAILABLE}
        for fam in enterprise.SCENARIO_FAMILIES
    }

    detection_caps = {
        "offline_rules": {
            "id": "detect:detection.py",
            "rules": [r.get("id") for r in detection.RULES if isinstance(r, dict) and r.get("id")],
            "correlation": detection.CORRELATION,
            "source": "siem/detection.py",
            "availability": AVAILABLE,
            "validation_method": "run_rules + correlate over a generated world",
        },
        "security_analytics_prepackaged_windows": {
            "id": "detect:sa-windows-prepackaged",
            "source": "OpenSearch Security Analytics (validated M4.2)",
            "availability": AVAILABLE,
            "validation_method": "native detector finding on a synthetic event (M4.2)",
        },
        "security_analytics_custom_rule": {
            "id": "detect:sa-custom-rule",
            "source": "OpenSearch Security Analytics",
            "availability": LIMITED,
            "constraint": "custom rule create returns 500 SearchPhaseExecutionException on the current build; use pre-packaged rules",
        },
    }

    evidence = {
        "citation_roles": list(case_contract.ROLES),
        "dispositions": list(case_contract.DISPOSITIONS),
        "severities": list(case_contract.SEVERITIES),
        "verification_properties": ["reference_validity", "claim_support", "malicious_activity_determination"],
        "preservation": "Ed25519-signed evidence record with embedded source snapshots",
        "source": "siem/case_contract.py",
        "availability": AVAILABLE,
    }

    # A bounded, declarative response-action allowlist (no executable semantics; these
    # are the decisions a candidate documents, grounded in scenario response fields).
    response_actions = {
        "allowlist": ["contain_host", "isolate_host", "revoke_token", "rotate_credentials",
                      "disable_account", "restore_dataset", "block_domain", "add_detection_rule",
                      "escalate", "no_action_justified"],
        "source": "declarative; documented analyst decisions only",
        "availability": AVAILABLE,
    }

    truth = {
        "id": "truth:enterprise.generate",
        "model": "incidents[]{family,event_uids,techniques,verdict,actor_ip,primary_identity}",
        "source": "siem/enterprise.py:generate (returned to backend only; never indexed)",
        "availability": AVAILABLE,
        "validation_method": "recompute from seed server-side; verify_evidence against the index",
    }

    future_lab = {
        "ludus_goad_ranges": {
            "id": "lab:ludus-goad",
            "source": "RangeRequest / EnvironmentProvisioner contract (M4.3 doc)",
            "availability": UNAVAILABLE,
            "note": "boards 5-6; declared only, not provisioned or executable now",
        },
    }

    profiles = {k: {"benign": v["benign"], "incidents": v["incidents"], "days": v["days"],
                    "desc": v["desc"]} for k, v in enterprise.PROFILES.items()}

    inventory = {
        "capability_inventory_version": CAPABILITY_INVENTORY_VERSION,
        "pathway": PATHWAY_STRATA,
        "environment_type": ENVIRONMENT_SOC_OPENSEARCH,
        "foundation": foundation,
        "telemetry": telemetry,
        "scenario_families": scenario_families,
        "profiles": profiles,
        "detection": detection_caps,
        "evidence": evidence,
        "response_actions": response_actions,
        "truth": truth,
        "future_lab": future_lab,
    }
    inventory["topology_hash"] = _topology_hash({"foundation": foundation,
                                                 "families": list(scenario_families)})
    return inventory


def capability_ids(inv: dict | None = None) -> set:
    """The flat set of reference-able capability ids a ScenarioSpec may cite:
    families, hosts, identities, business apps, segments, datasets, ecs fields,
    detection rule ids, citation roles, dispositions, response actions."""
    inv = inv or build_inventory()
    ids: set = set()
    for fam in inv["scenario_families"]:
        ids.add(f"family:{fam}")
    f = inv["foundation"]
    for h in f["assets"]["hosts"]:
        ids.add(f"host:{h}")
    for seg in f["assets"]["segments"]:
        ids.add(f"segment:{seg}")
    for app in f["assets"]["business_apps"]:
        ids.add(f"app:{app}")
    for group in ("people", "service_accounts", "admins"):
        for u in f["identities"][group]:
            ids.add(f"identity:{u}")
    for ds in inv["telemetry"]["observed_datasets"]:
        ids.add(f"dataset:{ds}")
    for fld in inv["telemetry"]["ecs_fields"] + inv["telemetry"]["operational_keyword_fields"]:
        ids.add(f"field:{fld}")
    for rid in inv["detection"]["offline_rules"]["rules"]:
        ids.add(f"rule:{rid}")
    ids.add("detect:sa-windows-prepackaged")
    for role in inv["evidence"]["citation_roles"]:
        ids.add(f"role:{role}")
    for disp in inv["evidence"]["dispositions"]:
        ids.add(f"disposition:{disp}")
    for act in inv["response_actions"]["allowlist"]:
        ids.add(f"response:{act}")
    return ids


def validate_refs(refs, inv: dict | None = None) -> list[str]:
    """Return the subset of `refs` that are NOT present in the inventory (unsupported).
    An empty list means every reference is supported. Future-lab (unavailable)
    capabilities are intentionally NOT in the referenceable set, so citing one fails."""
    ids = capability_ids(inv)
    return [r for r in refs if r not in ids]
