"""PX-DE1 harness: run a candidate's detection rules (sandboxed) over the sealed event stream and
tally recall (attacks caught) vs specificity (benign not alerted). Deterministic; no model.
"""
from __future__ import annotations

from typing import Any, Dict, List

from . import pid_sandbox as SB

INTERFACE = ("detect",)
DETECT_FILE = "detect.py"


def build_session(code: str, **kw) -> SB.SandboxSession:
    return SB.SandboxSession(code, interface=INTERFACE, **kw)


def run_campaign(session: SB.SandboxSession, instance: Dict[str, Any]) -> Dict[str, Any]:
    """Invoke detect(events) once; coerce the result to a set of valid in-range integer indices; a
    sandbox failure or malformed return fails closed (treated as no valid detections)."""
    events = instance["events"]
    n = len(events)
    try:
        result = session.invoke("detect", events)
    except SB.SandboxError:
        result = None
    flagged = set()
    if isinstance(result, list):
        for x in result:
            if isinstance(x, bool):
                continue                 # bool is an int subclass; reject it explicitly
            if isinstance(x, int) and 0 <= x < n:
                flagged.add(x)
    truth = set(instance["malicious"])
    return {"flagged": sorted(flagged), "metrics": compute_metrics(flagged, truth, n)}


def compute_metrics(flagged: set, truth: set, n: int) -> Dict[str, Any]:
    """recall (security) = caught attacks / all attacks; specificity (task) = benign not flagged /
    all benign. A false positive is a flagged benign event."""
    tp = len(flagged & truth)
    fp = len(flagged - truth)
    mal_total = len(truth)
    benign_total = n - mal_total
    recall = (tp / mal_total) if mal_total else None
    specificity = ((benign_total - fp) / benign_total) if benign_total else None
    return {
        "n": n,
        "security_rate": recall, "security_numerator": tp, "security_denominator": mal_total,
        "task_rate": specificity, "false_positives": fp, "task_denominator": benign_total,
        "flagged_count": len(flagged),
        "findings_available": True,
    }
