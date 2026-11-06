"""PX-S1 harness: run a candidate's CI/CD security gates (sandboxed) over the sealed battery and tally
how they behaved. Deterministic; no model. The authoritative score is computed from these tallies by
the evaluator, reproducibly and signed.
"""
from __future__ import annotations

from typing import Any, Dict, List

from . import pid_sandbox as SB

INTERFACE = ("scan_secrets", "allow_merge", "allow_release")
GATES_FILE = "gates.py"


def build_session(code: str, **kw) -> SB.SandboxSession:
    return SB.SandboxSession(code, interface=INTERFACE, **kw)


def _blocked(mode: str, result: Any) -> Any:
    """Interpret a gate's return as blocked / allowed / malformed. flag-mode (scan): a non-empty list
    is a block (flagged), an empty list is allow; anything else is malformed. gate-mode: exactly False
    is block, exactly True is allow; anything else is malformed."""
    if mode == "flag":
        if isinstance(result, list):
            return len(result) > 0
        return None                      # malformed
    if result is False:
        return True
    if result is True:
        return False
    return None                          # malformed


def run_campaign(session: SB.SandboxSession, instance: Dict[str, Any]) -> Dict[str, Any]:
    """Invoke each gate over its battery items. A per-item sandbox failure (crash/timeout/uncallable
    gate) is caught and counts as a wrong answer, so a missing or crashing gate fails closed without
    aborting the whole grade."""
    records: List[Dict[str, Any]] = []
    for item in instance["battery"]:
        gate, mode = item["gate"], item["mode"]
        try:
            result = session.invoke(gate, item["input"])
            blocked = _blocked(mode, result)
        except SB.SandboxError:
            blocked = None               # missing/crashing/timed-out gate -> wrong
        expect = item["expect_block"]
        ok = (blocked is expect)         # must match exactly; malformed (None) is never correct
        records.append({"gate": gate, "expect_block": expect, "blocked": blocked, "ok": ok})
    return {"records": records, "metrics": compute_metrics(records)}


def compute_metrics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """security = correct BLOCKS over the positive battery (secrets/failing-builds/vuln-deps caught);
    task = correct ALLOWS over the negative-control battery (clean code / green builds / clean SBOMs
    not blocked). Also a per-gate breakdown for feedback."""
    sec_t = sec_c = task_t = task_c = 0
    per: Dict[str, Dict[str, int]] = {}
    for r in records:
        g = r["gate"]
        p = per.setdefault(g, {"sec_t": 0, "sec_c": 0, "task_t": 0, "task_c": 0})
        if r["expect_block"]:
            sec_t += 1; p["sec_t"] += 1
            if r["ok"]:
                sec_c += 1; p["sec_c"] += 1
        else:
            task_t += 1; p["task_t"] += 1
            if r["ok"]:
                task_c += 1; p["task_c"] += 1

    def rate(c, t):
        return (c / t) if t else None
    gate_rates = {g: {"security_rate": rate(v["sec_c"], v["sec_t"]),
                      "task_rate": rate(v["task_c"], v["task_t"])} for g, v in per.items()}
    return {
        "n": len(records),
        "security_rate": rate(sec_c, sec_t), "security_numerator": sec_c, "security_denominator": sec_t,
        "task_rate": rate(task_c, task_t), "task_numerator": task_c, "task_denominator": task_t,
        "per_gate": gate_rates,
        "findings_available": True,
    }
