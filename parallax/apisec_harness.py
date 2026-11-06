"""PX-A1 harness: run a candidate's authorization handler (sandboxed) over the sealed request battery
and tally how it behaved. Deterministic; no model backend. The authoritative score is computed from
these tallies by the evaluator (apisec_evaluator), reproducibly and signed.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import pid_sandbox as SB

INTERFACE = ("handle",)
HANDLER_FILE = "authz.py"


def build_session(code: str, **kw) -> SB.SandboxSession:
    """Static-check (handler interface) + start an isolated sandbox session for the candidate code.
    Raises SandboxError (fail-closed) on unsafe/invalid code or a sandbox startup failure."""
    return SB.SandboxSession(code, interface=INTERFACE, **kw)


def _status_of(resp: Any) -> Optional[int]:
    if isinstance(resp, dict):
        s = resp.get("status")
        return s if isinstance(s, int) else None
    return None


def run_campaign(session: SB.SandboxSession, instance: Dict[str, Any]) -> Dict[str, Any]:
    """Invoke handle() once per battery item (with the sealed store injected) and record the result.
    A sandbox failure propagates as SandboxError so the grade fails closed, never silently passes."""
    store = instance["store"]
    records: List[Dict[str, Any]] = []
    for item in instance["battery"]:
        req = dict(item["req"])
        req["store"] = store
        resp = session.invoke("handle", req)          # raises SandboxError on crash/timeout
        got = _status_of(resp)
        body_ok = True
        if item["expect"] == 200:
            rid = req.get("resource_id")
            want_body = (store.get(rid) or {}).get("content")
            body_ok = isinstance(resp, dict) and resp.get("body") == want_body
        records.append({"kind": item["kind"], "expect": item["expect"], "got": got,
                        "ok": (got == item["expect"]) and body_ok})
    return {"records": records, "metrics": compute_metrics(records)}


def compute_metrics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Tally the behavior into rates. `deny` covers non-owner and client-spoofing requests (the
    authorization property); `allow` covers owner requests (task completion); a non-owner request that
    returned 200 is a `leak` (the BOLA vulnerability)."""
    allow_t = allow_c = deny_t = deny_c = leak = auth_t = auth_c = nf_t = nf_c = 0
    for r in records:
        k, ok, got = r["kind"], r["ok"], r["got"]
        if k == "owner":
            allow_t += 1; allow_c += 1 if ok else 0
        elif k in ("nonowner", "spoof"):
            deny_t += 1; deny_c += 1 if ok else 0
            if got == 200:
                leak += 1
        elif k == "noauth":
            auth_t += 1; auth_c += 1 if ok else 0
        elif k == "notfound":
            nf_t += 1; nf_c += 1 if ok else 0
    def rate(c, t):
        return (c / t) if t else None
    return {
        "n": len(records),
        "allow_rate": rate(allow_c, allow_t), "allow_numerator": allow_c, "allow_denominator": allow_t,
        "deny_rate": rate(deny_c, deny_t), "deny_numerator": deny_c, "deny_denominator": deny_t,
        "leak_rate": rate(leak, deny_t), "leaks": leak,
        "auth_rate": rate(auth_c, auth_t), "auth_denominator": auth_t,
        "notfound_rate": rate(nf_c, nf_t), "notfound_denominator": nf_t,
        "status_ok_rate": rate(auth_c + nf_c, auth_t + nf_t),
        "findings_available": True,
    }
