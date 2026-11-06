"""PX-AR1 harness: run a candidate's architecture review (sandboxed) over the sealed flawed+sound
design pair and tally recall (violations found in the flawed design) vs specificity (no false findings
on the sound design). Deterministic; no model.
"""
from __future__ import annotations

from typing import Any, Dict, List

from . import pid_sandbox as SB
from .architecture_content import CODES

INTERFACE = ("review",)
REVIEW_FILE = "architecture.py"
_CODESET = set(CODES)


def build_session(code: str, **kw) -> SB.SandboxSession:
    return SB.SandboxSession(code, interface=INTERFACE, **kw)


def _codes(result: Any) -> set:
    if isinstance(result, list):
        return {c for c in result if isinstance(c, str) and c in _CODESET}
    return set()


def run_campaign(session: SB.SandboxSession, instance: Dict[str, Any]) -> Dict[str, Any]:
    """Invoke review() on the flawed and sound designs; a sandbox failure fails closed (no findings)."""
    try:
        on_flawed = _codes(session.invoke("review", instance["flawed"]))
    except SB.SandboxError:
        on_flawed = set()
    try:
        on_sound = _codes(session.invoke("review", instance["sound"]))
    except SB.SandboxError:
        on_sound = set()
    expected = set(instance["violations"])
    return {"found": sorted(on_flawed & expected), "false_findings": sorted(on_sound),
            "metrics": compute_metrics(on_flawed, on_sound, expected)}


def compute_metrics(on_flawed: set, on_sound: set, expected: set) -> Dict[str, Any]:
    """security (recall) = expected violations found in the flawed design / all expected;
    task (specificity) = control classes correctly NOT flagged on the sound design / all classes."""
    n_classes = len(_CODESET)
    recall = (len(on_flawed & expected) / len(expected)) if expected else None
    false_on_sound = len(on_sound & _CODESET)
    specificity = (n_classes - false_on_sound) / n_classes
    return {
        "n": n_classes,
        "security_rate": recall, "security_numerator": len(on_flawed & expected),
        "security_denominator": len(expected),
        "task_rate": specificity, "false_findings": false_on_sound, "task_denominator": n_classes,
        "findings_available": True,
    }
