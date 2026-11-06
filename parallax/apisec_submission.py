"""PX-A1 (Board 3) submission contract: the files a candidate submits and the automatic validation
applied at submit time (portal) and again at grade time (grader, fail-closed).

Candidate repo layout (read as DATA, executed only in the sandbox):
  authz.py    -> defines handle(req) -> {"status": int, "body"?: str}  (the object-level authz fix)
  writeup.md  -> the written threat model + approach + tradeoffs
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import pid_submission as PS   # reuse the tarball reader (read_file) and writeup limits
from . import pid_sandbox as SB
from .apisec_harness import INTERFACE, HANDLER_FILE

MIN_WRITEUP_CHARS = PS.MIN_WRITEUP_CHARS
DEFAULT_CODE_FILE = HANDLER_FILE

CODE_CHECKLIST = [
    {"id": "authz_code", "required": True, "label": "Authorization handler (authz.py)",
     "describes": "a sandboxed handle(req) that enforces object-level authorization"},
    {"id": "writeup", "required": True, "label": "Written analysis (writeup.md)",
     "describes": "the authorization threat model, your fix, and tradeoffs"},
]
CODE_REQUIRED_IDS = [c["id"] for c in CODE_CHECKLIST if c["required"]]


def code_checklist() -> List[Dict[str, Any]]:
    return [dict(c) for c in CODE_CHECKLIST]


def validate_code(snapshot_bytes: bytes, selected: Optional[List[str]] = None) -> Dict[str, Any]:
    """Automatic submit-time validation for PX-A1. Static-checks the candidate handler in the sandbox
    allowlist (handler interface) BEFORE anything runs; fail-closed with the reasons."""
    import hashlib
    sub = PS.read_submission(snapshot_bytes)
    spec = sub.get("spec")
    writeup = sub.get("writeup") or ""
    code_path = (spec or {}).get("code_path") if isinstance(spec, dict) else None
    code = PS.read_file(snapshot_bytes, code_path or DEFAULT_CODE_FILE) or ""
    selected = selected if selected is not None else list(CODE_REQUIRED_IDS)
    selected = [s for s in selected if s in CODE_REQUIRED_IDS]
    unmet: List[Dict[str, str]] = []
    for rid in CODE_REQUIRED_IDS:
        if rid not in selected:
            unmet.append({"id": rid, "reason": "not selected on the submission checklist"})
    if not code.strip():
        unmet.append({"id": "authz_code", "reason": "%s is missing or empty" % DEFAULT_CODE_FILE})
    else:
        errs = SB.static_check(code, interface=INTERFACE)
        if errs:
            unmet.append({"id": "authz_code", "reason": "unsafe/invalid code: %s" % "; ".join(errs[:4])})
    if len(writeup.strip()) < MIN_WRITEUP_CHARS:
        unmet.append({"id": "writeup", "reason": "writeup must be at least %d characters" % MIN_WRITEUP_CHARS})
    seen, dd = set(), []
    for u in unmet:
        k = (u["id"], u["reason"])
        if k not in seen:
            seen.add(k); dd.append(u)
    code_sha = hashlib.sha256(code.encode("utf-8")).hexdigest() if code else None
    return {"ok": not dd, "unmet": dd, "code_sha256": code_sha,
            "checklist_selected": selected, "writeup_chars": len(writeup.strip()),
            "code_present": bool(code.strip())}
