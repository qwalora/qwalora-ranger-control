"""PX-CAP (Capstone) submission contract. Candidate repo layout (read as DATA, executed only in the
sandbox): authz.py, detect.py, gates.py, architecture.py (one per component board) + writeup.md.
Every component file is required and static-checked against its board's interface at submit time.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from . import pid_submission as PS
from . import pid_sandbox as SB

MIN_WRITEUP_CHARS = PS.MIN_WRITEUP_CHARS

# component -> (file, interface, checklist id)
COMPONENTS = [
    ("authz", "authz.py", ("handle",), "authz_code"),
    ("detect", "detect.py", ("detect",), "detect_code"),
    ("gates", "gates.py", ("scan_secrets", "allow_merge", "allow_release"), "gates_code"),
    ("architecture", "architecture.py", ("review",), "architecture_code"),
]
CODE_CHECKLIST = (
    [{"id": cid, "required": True, "label": "%s (%s)" % (name.capitalize(), f),
      "describes": "sandboxed %s component for the capstone" % name}
     for (name, f, _iface, cid) in COMPONENTS]
    + [{"id": "writeup", "required": True, "label": "Written analysis (writeup.md)",
        "describes": "how your four components work and the competencies they demonstrate"}]
)
CODE_REQUIRED_IDS = [c["id"] for c in CODE_CHECKLIST if c["required"]]


def code_checklist() -> List[Dict[str, Any]]:
    return [dict(c) for c in CODE_CHECKLIST]


def read_code_map(snapshot_bytes: bytes) -> Dict[str, str]:
    """Read the four component files from the snapshot into {component: code}. Used by the grader."""
    return {name: (PS.read_file(snapshot_bytes, f) or "") for (name, f, _iface, _cid) in COMPONENTS}


def combined_sha(code_map: Dict[str, str]) -> str:
    """Stable combined hash binding all four components in a fixed order."""
    parts = [hashlib.sha256((code_map.get(name) or "").encode("utf-8")).hexdigest()
             for (name, _f, _iface, _cid) in COMPONENTS]
    return hashlib.sha256(":".join(parts).encode("ascii")).hexdigest()


def validate_code(snapshot_bytes: bytes, selected: Optional[List[str]] = None) -> Dict[str, Any]:
    sub = PS.read_submission(snapshot_bytes)
    writeup = sub.get("writeup") or ""
    code_map = read_code_map(snapshot_bytes)
    selected = selected if selected is not None else list(CODE_REQUIRED_IDS)
    selected = [s for s in selected if s in CODE_REQUIRED_IDS]
    unmet: List[Dict[str, str]] = []
    for rid in CODE_REQUIRED_IDS:
        if rid not in selected:
            unmet.append({"id": rid, "reason": "not selected on the submission checklist"})
    for (name, f, iface, cid) in COMPONENTS:
        code = code_map.get(name) or ""
        if not code.strip():
            unmet.append({"id": cid, "reason": "%s is missing or empty" % f})
            continue
        errs = SB.static_check(code, interface=iface)
        if errs:
            unmet.append({"id": cid, "reason": "unsafe/invalid %s: %s" % (f, "; ".join(errs[:3]))})
    if len(writeup.strip()) < MIN_WRITEUP_CHARS:
        unmet.append({"id": "writeup", "reason": "writeup must be at least %d characters" % MIN_WRITEUP_CHARS})
    seen, dd = set(), []
    for u in unmet:
        k = (u["id"], u["reason"])
        if k not in seen:
            seen.add(k); dd.append(u)
    return {"ok": not dd, "unmet": dd, "code_sha256": combined_sha(code_map),
            "checklist_selected": selected, "writeup_chars": len(writeup.strip()),
            "code_present": all((code_map.get(n) or "").strip() for (n, _f, _i, _c) in COMPONENTS)}
