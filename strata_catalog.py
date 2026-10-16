"""S3/S4 - STRATA scenario catalog + governance.

Turns an approved structural VARIANT (siem/board_variants) into a validated, calibrated, immutable
catalog entry (models.ScenarioCatalogEntry) through the existing governance pipeline:

  build spec -> schema-validate -> executable-simulate -> calibrate -> material-diversity -> approve

Board 2 reuses siem/scenario_pipeline (soc-investigation spec over siem/enterprise.generate). Boards
1/3/4 use board-typed specs (soc-triage / detection-engineering / ir-forensics) and a board-aware
simulation that actually GENERATES the world and GRADES a reference-correct submission, proving the
scenario is generable, truth-derivable, gradeable, reproducible and leak-free - not merely that
metadata validates.

Approval is REAL: approve() requires an authenticated models.AdminUser with an authorizing role and
records that identity. A bare approver string is never accepted. Synthetic tests may build and
simulate entries, but an entry only becomes catalog_eligible when a real AdminUser approves it.
Protected truth is never stored in a catalog entry; it is recomputed from (variant, seed).
"""
from __future__ import annotations

import json

import scenarios as sc
from siem import board_variants as bv
from siem import scenario_spec as sspec
from siem import scenario_pipeline as sp
from siem import enterprise, detection, case_contract

PATHWAY = "strata"
SPEC_TYPE = {1: "soc-triage", 2: "soc-investigation", 3: "detection-engineering", 4: "ir-forensics"}
ENVIRONMENT = {1: "soc-dataset", 2: "soc-opensearch", 3: "soc-dataset", 4: "soc-dataset"}
CALIBRATION_SEED = "calib-seed-v1"   # fixed seed for deterministic calibration/simulation


class CatalogError(RuntimeError):
    pass


# ============================ spec construction ============================================
def spec_id_for(board, variant_id):
    return f"strata-b{board}-{variant_id}"


def build_spec(board, variant_id):
    """A declarative ScenarioSpec for a variant. Board 2 is a soc-investigation payload (families);
    boards 1/3/4 are board-typed payloads carrying the structural content. evaluator_only references
    truth by GENERATION; no answers are embedded."""
    v = bv.get(board, variant_id)
    if not v:
        raise CatalogError(f"unknown variant {board}/{variant_id}")
    gp = v["gen_params"]
    admin = {"variant_id": variant_id, "difficulty": v["difficulty"],
             "competencies": v["competencies"]}
    if board == 2:
        admin["families"] = list(gp["families"])
        admin["profile"] = gp.get("profile", "B")
        admin["affected"] = {"services": []}
    elif board == 1:
        admin["technique_pool"] = sorted(t[0] for t in gp["tp_techniques"])
    elif board == 3:
        admin["technique_set"] = list(gp["techniques"])
    elif board == 4:
        admin["kill_chain"] = v["diversity"]["chain"]
        admin["initial_access"] = v["diversity"]["initial_access"]
        admin["persistence"] = v["diversity"]["persistence"]
    spec = {
        "spec_id": spec_id_for(board, variant_id), "spec_version": sspec.SCENARIO_SPEC_VERSION,
        "pathway": PATHWAY, "environment_type": ENVIRONMENT[board], "spec_type": SPEC_TYPE[board],
        "board_compat": [board], "difficulty_profile": v["difficulty"],
        "evidence_kinds": [sspec.EVIDENCE_KIND_EVENT_REFERENCE],
        "payload": {
            "candidate_visible": {"business_context": v["business_context"], "title": v["title"]},
            "admin": admin,
            "evaluator_only": {"protected_truth_ref": {"generator": "variant",
                                                       "board": board, "variant_id": variant_id}},
        },
    }
    return spec


def content_hash(spec):
    return sspec.content_hash(spec)


# ============================ reference submissions (also used by tests) ===================
def board1_correct(scenario):
    out = []
    for a in scenario["alerts"]:
        k = a["_key"]
        row = {"id": a["id"], "verdict": k["verdict"], "severity": k["severity"]}
        if k["verdict"] == "true_positive":
            row["attack_technique"] = k["technique"]; row["iocs"] = list(k["iocs"])
        out.append(row)
    return {"alerts": out}


def board4_correct(scenario):
    t = scenario["truth"]
    return {k: (list(t[k]) if isinstance(t[k], list) else t[k])
            for k in ("patient_zero", "initial_access", "affected_hosts",
                      "affected_accounts", "timeline", "persistence")}


# technique -> detection rule (invariant tradecraft) covering the whole expanded catalog
_B3_RULES = {
    "T1059.001": {"image": "powershell.exe", "command|contains": "-enc"},
    "T1105": {"image": "certutil.exe", "command|contains": "-urlcache"},
    "T1087.002": {"image": "net.exe", "command|contains|all": ["group", "/domain"]},
    "T1003.001": {"image": "rundll32.exe", "command|contains|all": ["comsvcs.dll", "minidump"]},
    "T1047": {"image": "wmic.exe", "command|contains|all": ["/node:", "process call create"]},
    "T1053.005": {"image": "schtasks.exe", "command|contains": "/create"},
    "T1071.001": {"event_type": "network", "command|contains": "beacon"},
    "T1048.003": {"event_type": "dns", "command|contains": "txt"},
    "T1003.002": {"image": "reg.exe", "command|contains|all": ["save", "hklm\\sam"]},
    "T1136.001": {"image": "net.exe", "command|contains|all": ["user", "/add"]},
    "T1562.001": {"image": "powershell.exe", "command|contains": "set-mppreference"},
    "T1490": {"image": "vssadmin.exe", "command|contains": "delete shadows"},
    "T1552.001": {"image": "findstr.exe", "command|contains": "password"},
    "T1569.002": {"image": "sc.exe", "command|contains|all": ["create", "binpath"]},
}


def board3_ruleset(techniques):
    """A correct, generalizing detection ruleset for exactly the given technique set."""
    rules = []
    for t in techniques:
        sel = _B3_RULES.get(t)
        if sel:
            rules.append({"name": "r_" + t.replace(".", "_"), "technique": t,
                          "detection": {"sel": dict(sel), "condition": "sel"}})
    return {"rules": rules}


# ============================ board-aware simulation + calibration =========================
def simulate(board, variant_id, seed=CALIBRATION_SEED):
    """Generate the variant's world and prove it behaves: telemetry produced, candidate view carries
    no truth, a reference-correct submission grades at/above the 95 bar, an empty/trivial one does
    not, and the world is reproducible. Returns {ok, checks, difficulty}."""
    gp = bv.gen_params(board, variant_id)
    checks = {}
    if board == 2:
        # Simulation validates generability/truth/evidence/reproducibility, which hold at any volume,
        # so it runs at the light functional profile for speed; candidates still get the variant's
        # full profile at assignment time.
        sim_profile = "A"
        ev, truth = enterprise.generate("sim", 2, seed, sim_profile, families=gp["families"])
        ev2, _ = enterprise.generate("sim", 2, seed, sim_profile, families=gp["families"])
        det = detection.validate(ev, truth)
        idx = f"sim-b2-{variant_id}"
        reader = case_contract.InMemoryReader(idx, ev)
        muid = truth["incidents"][0]["event_uids"][0]
        payload = {"baseline_summary": "b", "overall_conclusion": "c",
                   "incidents": [{"label": "i", "disposition": "confirmed_incident", "severity": "high",
                                  "confidence": 70, "attack_techniques": ["T1078"], "primary_identity": "u",
                                  "affected_assets": ["h"], "analyst_conclusion": "x",
                                  "cited_evidence": [{"event_uid": muid, "index": idx,
                                                      "query": {"query": {"ids": {"values": [muid]}}},
                                                      "role": "primary"}]}]}
        vres = case_contract.verify_evidence(payload, reader, idx, truth=truth)
        c0 = vres["incidents"][0]["citations"][0]
        checks["telemetry_produced"] = {"ok": len(ev) > 100}
        checks["truth_derivable"] = {"ok": len(truth["incidents"]) >= 1}
        checks["detection_behaves"] = {"ok": len([p for p in det["per_incident"] if p.get("detected")]) >= 1}
        checks["evidence_verifiable"] = {"ok": bool(c0["reference_valid"]) and c0.get("malicious_activity") is True}
        checks["reproducible"] = {"ok": [e["_id"] for e in ev] == [e["_id"] for e in ev2]}
        difficulty = _calibrate_board2(gp["families"], gp.get("profile", "B"))
    else:
        scen = _gen(board, seed, gp)
        scen2 = _gen(board, seed, gp)
        pub = _public(board, scen)
        blob = json.dumps(pub)
        no_truth = not any(t in blob for t in ('"_key"', '"truth"', '"_flags"', '"_seed"',
                                               '"_techniques"', '"_variant"'))
        correct = _correct(board, scen)
        cs, _ = _score(board, scen, correct)
        es, _ = _score(board, scen, _empty(board))
        checks["telemetry_produced"] = {"ok": bool(_public_items(board, pub))}
        checks["candidate_view_no_truth"] = {"ok": no_truth}
        checks["gradeable_correct_passes"] = {"ok": cs >= 95.0, "score": cs}
        checks["empty_fails"] = {"ok": es < 95.0, "score": es}
        checks["reproducible"] = {"ok": _repro_equal(board, scen, scen2)}
        difficulty = _calibrate_other(board, scen, gp)
    ok = all(c["ok"] for c in checks.values())
    return {"ok": ok, "checks": checks, "difficulty": difficulty}


def _gen(board, seed, gp):
    return {1: sc.generate_board1, 3: sc.generate_board3, 4: sc.generate_board4}[board](seed, gp)


def _public(board, scen):
    return {1: sc.public_board1, 3: sc.public_board3, 4: sc.public_board4}[board](scen)


def _public_items(board, pub):
    return pub.get("alerts") or pub.get("threats") or []


def _correct(board, scen):
    if board == 1:
        return board1_correct(scen)
    if board == 4:
        return board4_correct(scen)
    if board == 3:
        return board3_ruleset(scen["_techniques"])
    return {}


def _empty(board):
    return {"alerts": []} if board in (1, 4) else {"rules": []}


def _score(board, scen, sub):
    return {1: sc.score_board1, 3: sc.score_board3, 4: sc.score_board4}[board](scen, sub)


def _repro_equal(board, a, b):
    if board == 3:
        return a["_techniques"] == b["_techniques"] and a["threats"] == b["threats"]
    return a == b


# Static per-family analytical profile (stages, techniques, is_detection_gap), derived from
# siem.enterprise._scenario. Used to calibrate board-2 difficulty from the chosen family portfolio
# at the intended workload profile WITHOUT generating full enterprise telemetry.
_FAMILY_PROFILE = {
    "privileged-identity-compromise": (4, 4, False),
    "data-exfiltration": (7, 4, False),
    "compromised-service-identity": (3, 3, False),
    "endpoint-lateral-movement": (5, 4, False),
    "detection-failure": (2, 2, True),
}


def _calibrate_board2(families, profile):
    chosen = list(families)[:enterprise.PROFILES[profile]["incidents"]]
    profs = [_FAMILY_PROFILE[f] for f in chosen if f in _FAMILY_PROFILE]
    stages = max((p[0] for p in profs), default=0)
    techs = sum(p[1] for p in profs)
    gaps = sum(1 for p in profs if p[2])
    score = stages * 0.6 + len(chosen) * 0.8 + gaps * 1.5 + min(techs, 12) * 0.2
    return {"vector": {"kill_chain_depth": stages, "incidents": len(chosen),
                       "detection_gaps": gaps, "techniques": techs, "profile": profile},
            "score": round(score, 2), "band": _band(score)}


def _calibrate_other(board, scen, gp):
    if board == 1:
        tp = len(gp["tp_techniques"]); mal = len([a for a in scen["alerts"] if a["_key"]["verdict"] == "true_positive"])
        score = tp * 0.9 + mal * 0.2
        vec = {"technique_pool": tp, "malicious_alerts": mal}
    elif board == 3:
        techs = len(scen["_techniques"]); score = techs * 1.1
        vec = {"techniques_to_detect": techs}
    else:  # board 4
        tl = len(scen["truth"]["timeline"]); hosts = len(scen["truth"]["affected_hosts"])
        accts = len(scen["truth"]["affected_accounts"])
        score = tl * 0.7 + hosts * 0.8 + accts * 0.5
        vec = {"timeline_length": tl, "affected_hosts": hosts, "affected_accounts": accts}
    return {"vector": vec, "score": round(score, 2), "band": _band(score)}


def _band(score):
    return "intro" if score < 4 else "standard" if score < 7 else "advanced"


# ============================ material diversity ===========================================
def _axes(board, variant_id):
    return bv.diversity_axes(board, variant_id)


def materially_diverse(board, variant_id, prior_variant_ids):
    mine = _axes(board, variant_id)
    priors = [_axes(board, v) for v in prior_variant_ids]
    return sp.axes_materially_diverse(mine, priors)


# ============================ persistence (catalog) ========================================
def register(db, board, variant_id):
    """Build, validate, simulate, calibrate and persist a catalog entry at status 'calibrated'
    (review-only; NOT yet eligible). Rejects a variant whose structure duplicates an existing
    approved entry's axes. Returns the ScenarioCatalogEntry (uncommitted-safe; caller commits)."""
    from models import ScenarioCatalogEntry
    spec = build_spec(board, variant_id)
    schema = sspec.validate_schema(spec)
    if not schema["ok"]:
        raise CatalogError(f"schema invalid for {variant_id}: {schema['errors'][:2]}")
    sim = simulate(board, variant_id)
    if not sim["ok"]:
        raise CatalogError(f"simulation failed for {variant_id}: "
                           f"{[k for k, c in sim['checks'].items() if not c['ok']]}")
    ch = content_hash(spec)
    sid = spec["spec_id"]
    existing = ScenarioCatalogEntry.query.filter_by(spec_id=sid, spec_version=spec["spec_version"]).first()
    if existing:
        return existing
    entry = ScenarioCatalogEntry(
        spec_id=sid, spec_version=spec["spec_version"], pathway=PATHWAY,
        environment_type=ENVIRONMENT[board], spec_type=SPEC_TYPE[board],
        board_compat=json.dumps([board]), difficulty=sim["difficulty"]["band"],
        status="calibrated", content_hash=ch, spec_json=json.dumps(spec),
        calibration=json.dumps(sim["difficulty"]), diversity=json.dumps(_axes(board, variant_id)))
    db.session.add(entry)
    db.session.flush()
    return entry


def _is_authorized_admin(admin):
    """A real approver is a models.AdminUser row with an authorizing role, OR a dict carrying a
    verified admin identity {github_id, role}. A bare string is NEVER accepted."""
    from models import AdminUser
    if isinstance(admin, AdminUser):
        return admin.role in ("reviewer", "sponsor") and bool(admin.github_id), \
            (admin.login or admin.github_id)
    if isinstance(admin, dict) and admin.get("github_id") and admin.get("role") in ("reviewer", "sponsor"):
        # must correspond to a persisted AdminUser (no invented reviewer identity)
        row = AdminUser.query.filter_by(github_id=admin["github_id"]).first()
        if row and row.role in ("reviewer", "sponsor"):
            return True, (row.login or row.github_id)
    return False, None


def approve(db, entry, admin):
    """Promote a calibrated entry to catalog_eligible using a REAL authenticated administrator.
    A bare approver string, an invented reviewer, or a non-admin is rejected (the entry stays
    review-only). Re-checks material diversity against the board's already-eligible entries."""
    import datetime as _dt
    from models import ScenarioCatalogEntry
    ok, who = _is_authorized_admin(admin)
    if not ok:
        raise CatalogError("approval requires an authenticated authorized administrator "
                           "(AdminUser); a bare approver string is not accepted")
    if entry.status not in ("calibrated", "catalog_eligible"):
        raise CatalogError(f"entry is not in a reviewable state ({entry.status})")
    board = json.loads(entry.board_compat)[0]
    my_variant = json.loads(entry.spec_json)["payload"]["admin"]["variant_id"]
    prior = [e for e in ScenarioCatalogEntry.query.filter_by(
        pathway=PATHWAY, status="catalog_eligible").all() if json.loads(e.board_compat)[0] == board]
    prior_variants = [json.loads(e.spec_json)["payload"]["admin"]["variant_id"] for e in prior]
    div = materially_diverse(board, my_variant, prior_variants)
    if not div["material"]:
        raise CatalogError(f"not materially diverse from approved entries (collisions {div['collisions']})")
    entry.status = "catalog_eligible"
    entry.approved_by = who
    entry.approved_at = _dt.datetime.now(_dt.timezone.utc)
    db.session.add(entry)
    db.session.flush()
    return entry


def eligible(db, board, pathway=PATHWAY):
    """Approved, selectable catalog entries for a board (status catalog_eligible)."""
    from models import ScenarioCatalogEntry
    rows = ScenarioCatalogEntry.query.filter_by(pathway=pathway, status="catalog_eligible").all()
    return [e for e in rows if json.loads(e.board_compat)[0] == int(board)]


def entry_variant(entry):
    return json.loads(entry.spec_json)["payload"]["admin"]["variant_id"]


def entry_family(entry):
    """The incident family axis used for reuse-cooldown (board 2 uses the objective; others use the
    attack theme / detection domain / initial access)."""
    d = json.loads(entry.diversity or "{}")
    return d.get("objective") or d.get("attack_theme") or d.get("detection_domain") \
        or d.get("initial_access")


def register_all(db, boards=bv.PORTFOLIO_BOARDS):
    """Register (review-only) every variant for the given boards. Does NOT approve."""
    out = []
    for b in boards:
        for vid in bv.variants_for(b):
            out.append(register(db, b, vid))
    return out
