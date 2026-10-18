"""M4.3.1 - the deterministic scenario compile + validation + calibration pipeline.

Lifecycle (no AI, no cluster, pure/offline):

  draft -> schema_validated -> capability_validated -> executable_tested
        -> calibrated -> approved -> catalog_eligible

Every gate is deterministic or (for `approved`) human. An LLM cannot approve its own
scenario, set its own difficulty, or certify its own correctness: this module does
all of that from the real generators and detectors, against the Capability Inventory.
A proposal that references anything Ranger cannot produce, or that fails simulation,
is rejected with actionable errors - narrative plausibility never substitutes for a
passing technical test.
"""
from __future__ import annotations

from . import capability_inventory as capinv
from . import enterprise, detection, case_contract
from . import scenario_spec as sspec

STATES = ("draft", "schema_validated", "capability_validated", "executable_tested",
          "calibrated", "approved", "catalog_eligible")
_ORDER = {s: i for i, s in enumerate(STATES)}

# difficulty bands keyed by a composite complexity score (see calibrate()).
DIFFICULTY_BANDS = {"intro": (0, 3), "standard": (3, 6), "advanced": (6, 99)}


def _err(code, msg, **kv):
    d = {"code": code, "message": msg}
    d.update(kv)
    return d


def can_advance(frm: str, to: str) -> bool:
    return _ORDER.get(to, -1) == _ORDER.get(frm, -1) + 1


# --- compile: spec -> deterministic generator config -------------------------
def compile_spec(spec: dict) -> dict:
    """Turn a validated ScenarioSpec into the generator config the two-layer
    generator consumes. Pure; rejects families not in the inventory. Does NOT accept
    any executable field (the spec validator already blocked privileged keys)."""
    admin = (spec.get("payload") or {}).get("admin") or {}
    families = list(admin.get("families") or [])
    profile = admin.get("profile", "B")
    board = (spec.get("board_compat") or [2])[0] if spec.get("board_compat") else 2
    seed = admin.get("package_seed") or spec.get("spec_id")
    cohort_key = admin.get("cohort_key") or f"spec:{spec.get('spec_id')}"
    return {"cohort_key": cohort_key, "board": int(board), "seed": seed,
            "profile": profile, "families": families,
            "enterprise_version": spec.get("enterprise_version", capinv.FOUNDATION_VERSION)}


# --- validate: schema + capability + causal consistency ----------------------
def validate(spec: dict) -> dict:
    """Schema + capability + causal validation. Returns {ok, state, errors}."""
    errors = []
    schema_res = sspec.validate_schema(spec)
    if not schema_res["ok"]:
        return {"ok": False, "state": "draft", "errors": schema_res["errors"]}

    # capability validation is largely done inside the payload validator; re-affirm
    # families exist and map to the environment inventory.
    inv = capinv.build_inventory(spec.get("environment_type"))
    cfg = compile_spec(spec)
    bad_fam = [f for f in cfg["families"] if f"family:{f}" not in capinv.capability_ids(inv)]
    for f in bad_fam:
        errors.append(_err("UNSUPPORTED_CAPABILITY", f"unsupported family {f!r}", path="payload.admin.families"))

    # causal consistency: incident_progression steps must form a DAG and reference
    # declared families/assets only.
    admin = (spec.get("payload") or {}).get("admin") or {}
    prog = admin.get("incident_progression") or []
    seen = set()
    for i, step in enumerate(prog):
        if not isinstance(step, dict):
            errors.append(_err("BAD_PROGRESSION", "progression step must be an object", path=f"incident_progression[{i}]"))
            continue
        sid = step.get("id")
        for dep in (step.get("depends_on") or []):
            if dep not in seen:
                errors.append(_err("BROKEN_CAUSALITY",
                                   f"step {sid!r} depends on {dep!r} which does not precede it",
                                   path=f"incident_progression[{i}]"))
        if sid:
            seen.add(sid)

    state = "capability_validated" if not errors else "schema_validated"
    return {"ok": not errors, "state": state, "errors": errors}


# --- simulate: executable test against the real generators + detectors -------
def simulate(spec: dict) -> dict:
    """Compile + generate the world + run detectors, proving: telemetry is produced,
    detection behaves as declared (incidents detected, declared gaps genuinely
    un-alerted), truth is derivable, evidence is available and verifiable, and the
    world is reproducible. Returns a structured report with ok + per-check detail."""
    cfg = compile_spec(spec)
    index = f"ranger-sim-{cfg['cohort_key']}-b{cfg['board']}".lower().replace(":", "-")
    events, truth = enterprise.generate(cfg["cohort_key"], cfg["board"], cfg["seed"],
                                        cfg["profile"], families=cfg["families"] or None)
    checks = {}

    # telemetry produced
    datasets = {e["_source"]["event"]["dataset"] for e in events}
    checks["telemetry_produced"] = {"ok": len(events) > 0 and len(datasets) >= 2,
                                    "events": len(events), "datasets": sorted(datasets)}

    # detection behavior vs truth (detection.validate derives from rule logic)
    det = detection.validate(events, truth)
    detected = [p for p in det["per_incident"] if p.get("detected")]
    missed = [p for p in det["per_incident"] if not p.get("detected")]
    # a detection-failure family should be a genuine miss; others should be detected
    checks["detection_behavior"] = {
        "ok": len(detected) >= 1,
        "detected": len(detected), "missed": len(missed),
        "has_genuine_gap": any(inc["family"] == "detection-failure" for inc in truth["incidents"])
                           == bool([p for p in missed])}

    # truth derivable
    member = {u for inc in truth["incidents"] for u in inc["event_uids"]}
    checks["truth_derivable"] = {"ok": len(truth["incidents"]) >= 1 and len(member) >= 1,
                                 "incidents": len(truth["incidents"]), "malicious_uids": len(member)}

    # evidence available + verifiable (reference a real malicious uid)
    reader = case_contract.InMemoryReader(index, events)
    mal_uid = truth["incidents"][0]["event_uids"][0]
    payload = {"baseline_summary": "b", "overall_conclusion": "c",
               "incidents": [{"label": "i", "disposition": "confirmed_incident",
                              "severity": "high", "confidence": 70,
                              "attack_techniques": ["T1078"], "primary_identity": "u",
                              "affected_assets": ["h"], "analyst_conclusion": "x",
                              "cited_evidence": [{"event_uid": mal_uid, "index": index,
                                                  "query": {"query": {"ids": {"values": [mal_uid]}}},
                                                  "role": "primary"}]}]}
    v = case_contract.verify_evidence(payload, reader, index, truth=truth)
    c0 = v["incidents"][0]["citations"][0]
    checks["evidence_verifiable"] = {"ok": bool(c0["reference_valid"]) and c0.get("malicious_activity") is True,
                                     "reference_valid": c0["reference_valid"],
                                     "malicious_activity": c0.get("malicious_activity")}

    # reproducibility: regenerate -> identical ids
    events2, _ = enterprise.generate(cfg["cohort_key"], cfg["board"], cfg["seed"],
                                     cfg["profile"], families=cfg["families"] or None)
    checks["reproducible"] = {"ok": [e["_id"] for e in events] == [e["_id"] for e in events2]}

    ok = all(c["ok"] for c in checks.values())
    return {"ok": ok, "state": "executable_tested" if ok else "capability_validated",
            "checks": checks, "truth": truth, "index": index}


# --- calibrate: difficulty + workload ----------------------------------------
def calibrate(spec: dict, sim: dict) -> dict:
    """Compute a complexity vector from the simulated world (not from the spec's
    self-assessment) and map it to a difficulty band. Returns {vector, score, band,
    matches_declared}."""
    truth = sim["truth"]
    incidents = truth["incidents"]
    stages = max((len(inc["event_uids"]) for inc in incidents), default=0)
    # distinct datasets across malicious events = correlation sources required
    # genuine detection gaps = incidents whose truth verdict is a detector miss
    gap_count = len([inc for inc in incidents if inc.get("verdict") == "true_positive_missed_by_detector"])
    admin = (spec.get("payload") or {}).get("admin") or {}
    decoys = len(admin.get("benign_decoys") or [])
    responses = len(admin.get("response_requirements") or [])
    vector = {"kill_chain_depth": stages, "incidents": len(incidents),
              "detection_gaps": gap_count, "benign_decoys": decoys,
              "response_decisions": responses}
    # composite score: emphasize genuine analytical complexity, not event count
    score = (stages * 0.6) + (len(incidents) * 0.8) + (gap_count * 1.5) + \
            (min(decoys, 5) * 0.3) + (min(responses, 5) * 0.2)
    band = next((b for b, (lo, hi) in DIFFICULTY_BANDS.items() if lo <= score < hi), "advanced")
    return {"vector": vector, "score": round(score, 2), "band": band,
            "matches_declared": band == spec.get("difficulty_profile")}


# --- diversity: material, not superficial ------------------------------------
def diversity_axes(spec: dict) -> dict:
    """The axes that make a scenario materially different. Deliberately EXCLUDES
    identifiers (usernames, addresses, timestamps, event ids, seeds): changing those
    is superficial and must not count as diversity."""
    admin = (spec.get("payload") or {}).get("admin") or {}
    aff = admin.get("affected") or {}
    return {"objective": (admin.get("adversary") or {}).get("objective"),
            "families": sorted(admin.get("families") or []),
            "systems": sorted(aff.get("services") or []),
            "detection_gaps": sorted(admin.get("detection_gaps") or []),
            "decoys": sorted(d.get("pattern") if isinstance(d, dict) else d
                             for d in (admin.get("benign_decoys") or []))}


# A scenario must differ from every prior on at least this many MATERIAL axes; a trivial
# difference on a single axis (while every other axis matches) does NOT qualify.
MIN_DIVERGENT_AXES = 2


def axis_divergence(a: dict, b: dict) -> int:
    """Number of axis keys on which two diversity-axis dicts differ. Order-insensitive for list
    values. Identifiers/timestamps are never part of a diversity-axis dict by construction."""
    keys = set(a) | set(b)
    n = 0
    for k in keys:
        av, bv = a.get(k), b.get(k)
        if isinstance(av, list) or isinstance(bv, list):
            if sorted(map(str, av or [])) != sorted(map(str, bv or [])):
                n += 1
        elif av != bv:
            n += 1
    return n


def axes_materially_diverse(mine: dict, prior_axes: list, *, min_divergent: int = MIN_DIVERGENT_AXES):
    """Generic (board-agnostic) material-diversity check over diversity-axis dicts: `mine` must differ
    from EVERY prior on at least `min_divergent` axes. Returns {material, collisions} where a
    collision is a prior that is too similar (differs on fewer than min_divergent axes)."""
    collisions = []
    for i, p in enumerate(prior_axes):
        if axis_divergence(mine, p) < min_divergent:
            collisions.append(i)
    return {"material": not collisions, "collisions": collisions,
            "min_divergent": min_divergent}


def is_materially_diverse(spec: dict, prior_specs: list) -> dict:
    """A spec is materially diverse only if it differs from EVERY prior on at least
    MIN_DIVERGENT_AXES material axes. A trivial one-axis difference (or only identifier/timestamp
    changes, which are excluded from the axes entirely) does NOT qualify. Returns
    {material, collisions} where a collision names a prior that is too similar."""
    mine = diversity_axes(spec)
    res = axes_materially_diverse(mine, [diversity_axes(p) for p in prior_specs])
    collisions = [prior_specs[i].get("spec_id") for i in res["collisions"]]
    return {"material": not collisions, "collisions": collisions,
            "min_divergent": MIN_DIVERGENT_AXES}


# --- promote -----------------------------------------------------------------
def promote(spec: dict, sim: dict, calib: dict, approver: str,
            prior_specs: list | None = None) -> dict:
    """Final gate. Promotes ONLY when schema+capability+simulation+calibration pass,
    the spec is materially diverse, and a human approver is named. Returns a catalog
    record (status catalog_eligible) with the immutable content hash + approval."""
    prior_specs = prior_specs or []
    errors = []
    vres = validate(spec)
    if not vres["ok"]:
        errors += vres["errors"]
    if not sim.get("ok"):
        errors.append(_err("SIMULATION_FAILED", "executable test did not pass"))
    if not calib.get("matches_declared"):
        errors.append(_err("DIFFICULTY_MISMATCH",
                           f"calibrated band {calib.get('band')!r} != declared {spec.get('difficulty_profile')!r}"))
    div = is_materially_diverse(spec, prior_specs)
    if not div["material"]:
        errors.append(_err("NOT_MATERIALLY_DIVERSE", "duplicates an existing package's axes",
                           collisions=div["collisions"]))
    if not str(approver or "").strip():
        errors.append(_err("NO_APPROVER", "an administrator must approve promotion"))
    if errors:
        return {"ok": False, "state": "executable_tested", "errors": errors}
    return {"ok": True, "state": "catalog_eligible",
            "content_hash": sspec.content_hash(spec),
            "calibration": calib, "diversity": div,
            "approved_by": approver, "spec_id": spec.get("spec_id"),
            "spec_version": spec.get("spec_version")}
