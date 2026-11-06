"""PX-CAP (Capstone) harness: run each component file through its own board's sandboxed measurement
against that component's sealed fixture, then compute per-component composite / critical / pass using
each board's own scoring and floors. Deterministic; no model. The capstone passes IFF every component
passes its board's bar and none critical-fails.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from . import pid_sandbox as SB
from . import apisec_evaluator as _AUTHZ_EV, apisec_blueprint as _AUTHZ_BP
from . import detection_evaluator as _DET_EV, detection_blueprint as _DET_BP
from . import devsecops_evaluator as _GATE_EV, devsecops_blueprint as _GATE_BP
from . import architecture_evaluator as _ARCH_EV, architecture_blueprint as _ARCH_BP


def _authz_critical(m):
    leak, allow = m.get("leak_rate"), m.get("allow_rate")
    return (leak is not None and leak >= _AUTHZ_BP.LEAK_CEILING) or \
           (allow is not None and allow < _AUTHZ_BP.ALLOW_FLOOR)


def _sec_task_critical(bp):
    def fn(m):
        s, t = m.get("security_rate"), m.get("task_rate")
        return (s is not None and s < bp.SECURITY_FLOOR) or (t is not None and t < bp.TASK_FLOOR)
    return fn


# component -> {interface, measure(code, fixture, defense_hash=...)->{metrics}, composite(m), critical(m), bar}
COMPONENTS = {
    "authz": {"interface": ("handle",), "measure": _AUTHZ_EV.measure_authz,
              "composite": _AUTHZ_EV.composite_score, "critical": _authz_critical,
              "bar": _AUTHZ_BP.OBJECTIVE_PASS},
    "detect": {"interface": ("detect",), "measure": _DET_EV.measure_detection,
               "composite": _DET_EV.composite_score, "critical": _sec_task_critical(_DET_BP),
               "bar": _DET_BP.OBJECTIVE_PASS},
    "gates": {"interface": ("scan_secrets", "allow_merge", "allow_release"), "measure": _GATE_EV.measure_gates,
              "composite": _GATE_EV.composite_score, "critical": _sec_task_critical(_GATE_BP),
              "bar": _GATE_BP.OBJECTIVE_PASS},
    "architecture": {"interface": ("review",), "measure": _ARCH_EV.measure_review,
                     "composite": _ARCH_EV.composite_score, "critical": _sec_task_critical(_ARCH_BP),
                     "bar": _ARCH_BP.OBJECTIVE_PASS},
}
ORDER = ["authz", "detect", "gates", "architecture"]


def run_components(code_map: Dict[str, Optional[str]], instance: Dict[str, Any]) -> Dict[str, Any]:
    """Grade every component. A missing/unsafe/crashing component is a critical fail for that
    component (fail-closed), never a silent pass. Returns {components, metrics}."""
    comps: Dict[str, Any] = {}
    for name in ORDER:
        spec = COMPONENTS[name]
        code = (code_map or {}).get(name) or ""
        if not code.strip():
            comps[name] = {"ok": False, "critical": True, "reason": "missing", "composite": None}
            continue
        errs = SB.static_check(code, interface=spec["interface"])
        if errs:
            comps[name] = {"ok": False, "critical": True, "reason": "unsafe_code",
                           "composite": None, "errors": errs[:3]}
            continue
        try:
            m = spec["measure"](code, instance[name], defense_hash="capstone")["metrics"]
        except Exception as e:  # noqa: BLE001 - sandbox failure fails this component closed
            comps[name] = {"ok": False, "critical": True, "reason": "sandbox:%s" % str(e)[:60],
                           "composite": None}
            continue
        composite = spec["composite"](m)
        critical = bool(spec["critical"](m))
        ok = (not critical) and composite is not None and composite >= spec["bar"]
        comps[name] = {"ok": ok, "critical": critical, "composite": composite,
                       "security_rate": m.get("security_rate"), "task_rate": m.get("task_rate"),
                       "leak_rate": m.get("leak_rate"), "allow_rate": m.get("allow_rate"),
                       "bar": spec["bar"]}
    return {"components": comps, "metrics": compute_metrics(comps)}


def compute_metrics(comps: Dict[str, Any]) -> Dict[str, Any]:
    total = len(ORDER)
    passed = [n for n in ORDER if comps.get(n, {}).get("ok")]
    composites = [comps[n]["composite"] for n in ORDER if comps.get(n, {}).get("composite") is not None]
    any_critical = any(comps.get(n, {}).get("critical") for n in ORDER)
    mean_c = round(sum(composites) / len(composites), 1) if len(composites) == total else None
    return {
        "total_components": total, "passed_components": len(passed),
        "passed_names": passed, "failed_names": [n for n in ORDER if not comps.get(n, {}).get("ok")],
        "all_passed": len(passed) == total, "any_critical": any_critical,
        "mean_composite": mean_c, "findings_available": True,
    }
