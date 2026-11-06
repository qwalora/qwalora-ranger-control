"""PX-CAP (Capstone) content: a sealed per-instance fixture for EACH component board, derived from the
same candidate/cohort seed so the whole capstone is one blind, reproducible instance. The capstone
composes four competencies: authorization (PX-A1), detection (PX-DE1), secure-release gates (PX-S1),
and architecture review (PX-AR1). The candidate must pass ALL of them.
"""
from __future__ import annotations

from typing import Any, Dict

from . import apisec_content as _AUTHZ
from . import detection_content as _DETECT
from . import devsecops_content as _GATES
from . import architecture_content as _ARCH

CAPSTONE_CORPUS_VERSION = "capstone-v1"

# component -> (candidate file, derived seed salt)
COMPONENT_FILES = {"authz": "authz.py", "detect": "detect.py",
                   "gates": "gates.py", "architecture": "architecture.py"}


def generate_instance(seed: int) -> Dict[str, Any]:
    """One blind capstone instance: a distinct sealed fixture per component, all derived from `seed`."""
    return {
        "version": CAPSTONE_CORPUS_VERSION,
        "authz": _AUTHZ.generate_instance(seed ^ 0x00A1, n_notes=10),
        "detect": _DETECT.generate_instance(seed ^ 0x00DE),
        "gates": _GATES.generate_instance(seed ^ 0x0051),
        "architecture": _ARCH.generate_instance(seed ^ 0x00A5),
    }
