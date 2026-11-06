"""PX-D1 submission contract: the files a candidate submits, the checklist they pick from, and the
automatic validation applied at submit time (portal) and again at grade time (grader, fail closed).

Candidate repo layout (read as DATA, never executed):
  parallax_submission.json  -> {"board":"PX-D1","defense":{...},"addresses":[...],"writeup_path":"writeup.md"}
  writeup.md                -> the written threat model + approach + tradeoffs

Shared by:
  * submission_gateway.submit_now  -> automatic submit-time gating (422 with the unmet checklist items)
  * grader/worker                  -> reads the same normalized defense + writeup for scoring
"""
from __future__ import annotations

import io
import json
import tarfile
from typing import Any, Dict, List, Optional

from .research import defense as D

SUBMISSION_FILE = "parallax_submission.json"
DEFAULT_WRITEUP = "writeup.md"
MIN_WRITEUP_CHARS = 400
MAX_WRITEUP_BYTES = 200_000

# The board's required deliverables. The candidate selects which they are submitting; a graded
# submission must select and satisfy every required item. (Optional items can be added later.)
CHECKLIST = [
    {"id": "defense_config", "required": True,
     "label": "Declarative defense (parallax_submission.json)",
     "describes": "hardened system/developer instructions and input/output guards"},
    {"id": "writeup", "required": True,
     "label": "Written analysis (writeup.md)",
     "describes": "threat model, approach, and the task-completion vs resistance tradeoffs"},
    {"id": "addresses_attacks", "required": True,
     "label": "Declared attack families addressed",
     "describes": "the injection families your defense is designed to resist"},
]
REQUIRED_IDS = [c["id"] for c in CHECKLIST if c["required"]]


def checklist() -> List[Dict[str, Any]]:
    return [dict(c) for c in CHECKLIST]


def _basename(name: str) -> str:
    return name.rsplit("/", 1)[-1]


def read_submission(snapshot_bytes: bytes) -> Dict[str, Any]:
    """Read parallax_submission.json + the writeup from the repo tarball (GitHub .tar.gz, one top-level
    dir). Returns {spec, spec_error, writeup, files}. Never executes anything; reads members in-memory."""
    out: Dict[str, Any] = {"spec": None, "spec_error": None, "writeup": None, "files": []}
    try:
        tf = tarfile.open(fileobj=io.BytesIO(snapshot_bytes), mode="r:*")
    except Exception as e:  # noqa: BLE001
        out["spec_error"] = "unreadable snapshot: %s" % type(e).__name__
        return out
    spec_member = None
    members = {}
    with tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            rel = m.name.split("/", 1)[1] if "/" in m.name else m.name  # strip the top-level dir
            out["files"].append(rel)
            members[rel] = m
            if _basename(m.name) == SUBMISSION_FILE and (spec_member is None or rel == SUBMISSION_FILE):
                spec_member = m
        if spec_member is not None:
            try:
                raw = tf.extractfile(spec_member).read()
                out["spec"] = json.loads(raw.decode("utf-8"))
                if not isinstance(out["spec"], dict):
                    out["spec"], out["spec_error"] = None, "%s must be a JSON object" % SUBMISSION_FILE
            except Exception as e:  # noqa: BLE001
                out["spec_error"] = "%s is not valid JSON: %s" % (SUBMISSION_FILE, type(e).__name__)
        # writeup (path from the spec, default writeup.md)
        wp = DEFAULT_WRITEUP
        if isinstance(out["spec"], dict) and isinstance(out["spec"].get("writeup_path"), str):
            wp = out["spec"]["writeup_path"].lstrip("/")
        wm = members.get(wp) or next((members[k] for k in members if _basename(k) == _basename(wp)), None)
        if wm is not None and wm.size <= MAX_WRITEUP_BYTES:
            try:
                out["writeup"] = tf.extractfile(wm).read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                out["writeup"] = None
    return out


def normalize(spec: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    spec = spec if isinstance(spec, dict) else {}
    addresses = [a for a in (spec.get("addresses") or []) if isinstance(a, str) and a][:16]
    return {"defense": D.normalize_defense(spec.get("defense")),
            "addresses": addresses,
            "writeup_path": spec.get("writeup_path") if isinstance(spec.get("writeup_path"), str)
            else DEFAULT_WRITEUP}


def validate(snapshot_bytes: bytes, selected: Optional[List[str]] = None) -> Dict[str, Any]:
    """Automatic validation. Returns {ok, unmet:[{id,reason}], defense, addresses, checklist_selected,
    writeup_present, writeup_chars}. `selected` is the candidate's checklist pick; when omitted, all
    required items are assumed selected (the submit UI sends the explicit selection)."""
    sub = read_submission(snapshot_bytes)
    spec = sub["spec"]
    norm = normalize(spec)
    writeup = sub["writeup"] or ""
    selected = selected if selected is not None else list(REQUIRED_IDS)
    selected = [s for s in selected if s in REQUIRED_IDS]
    unmet: List[Dict[str, str]] = []

    # every required checklist item must be selected
    for rid in REQUIRED_IDS:
        if rid not in selected:
            unmet.append({"id": rid, "reason": "not selected on the submission checklist"})

    # defense_config
    if spec is None:
        unmet.append({"id": "defense_config",
                      "reason": sub["spec_error"] or "%s is missing" % SUBMISSION_FILE})
    else:
        errs = D.validate_defense(spec.get("defense"))
        if errs:
            unmet.append({"id": "defense_config", "reason": "invalid defense: %s" % "; ".join(errs[:4])})
        elif not D.is_active(spec.get("defense")):
            unmet.append({"id": "defense_config",
                          "reason": "defense is empty (add a system prompt or input/output guards)"})

    # writeup
    if len(writeup.strip()) < MIN_WRITEUP_CHARS:
        unmet.append({"id": "writeup",
                      "reason": "writeup must be at least %d characters (threat model + tradeoffs)"
                      % MIN_WRITEUP_CHARS})

    # addresses_attacks
    if not norm["addresses"]:
        unmet.append({"id": "addresses_attacks",
                      "reason": "declare at least one attack family your defense addresses"})

    # de-dup unmet by (id, reason)
    seen, deduped = set(), []
    for u in unmet:
        key = (u["id"], u["reason"])
        if key not in seen:
            seen.add(key); deduped.append(u)
    return {"ok": not deduped, "unmet": deduped, "defense": norm["defense"],
            "defense_hash": D.defense_hash(norm["defense"]), "addresses": norm["addresses"],
            "checklist_selected": selected, "writeup_present": bool(sub["writeup"]),
            "writeup_chars": len(writeup.strip())}
