"""PX-AR1 (Board 5) secure-architecture-review content: a sealed per-instance pair of system-design
specs - one that violates every control class, one that is sound. The candidate submits
`architecture.py` exposing `review(architecture) -> list[str]` returning the violation codes present.

Control classes (fixed policy, documented so grading is deterministic):
  * EXPOSED_DATASTORE   : a datastore reachable from the public internet
  * UNENCRYPTED_PII      : a datastore that holds PII and is not encrypted at rest
  * PLAINTEXT_PII_LINK   : a network link that carries PII and is not encrypted in transit
  * NO_AUTH_PUBLIC       : a public-facing service with auth == "none"
  * SPOF_CRITICAL        : a critical service with neither multi-AZ nor backups (single point of failure)

The flawed design violates all five; the sound design violates none. Recall over the flawed design is
the security property; not flagging the sound design is the task (specificity) property.
"""
from __future__ import annotations

import random
from typing import Any, Dict, List

ARCHITECTURE_CORPUS_VERSION = "architecture-review-v1"

CODES = ["EXPOSED_DATASTORE", "UNENCRYPTED_PII", "PLAINTEXT_PII_LINK", "NO_AUTH_PUBLIC", "SPOF_CRITICAL"]
_SVC = ["api", "web", "worker", "admin", "billing", "auth", "reports"]
_DB = ["orders", "users", "events", "ledger", "sessions"]


def _sound(rng: random.Random) -> Dict[str, Any]:
    s1, s2 = rng.sample(_SVC, 2)
    d1 = rng.choice(_DB)
    return {
        "services": [
            {"name": s1, "exposure": "public", "auth": "token", "tls": True},
            {"name": s2, "exposure": "internal", "auth": "mtls", "tls": True},
        ],
        "datastores": [{"name": d1, "contains_pii": True, "encrypted": True, "public": False}],
        "links": [{"from": s1, "to": d1, "encrypted": True, "carries_pii": True}],
        "redundancy": {s1: {"multi_az": True, "backups": True},
                       s2: {"multi_az": True, "backups": True}},
        "critical_services": [s1],
    }


def _flawed(rng: random.Random) -> Dict[str, Any]:
    pub = rng.choice(_SVC)
    crit = rng.choice([s for s in _SVC if s != pub])
    d1 = rng.choice(_DB)
    return {
        "services": [
            {"name": pub, "exposure": "public", "auth": "none", "tls": True},          # NO_AUTH_PUBLIC
            {"name": crit, "exposure": "internal", "auth": "token", "tls": True},
        ],
        "datastores": [
            {"name": d1, "contains_pii": True, "encrypted": False, "public": True},     # EXPOSED + UNENCRYPTED_PII
        ],
        "links": [{"from": pub, "to": d1, "encrypted": False, "carries_pii": True}],     # PLAINTEXT_PII_LINK
        "redundancy": {pub: {"multi_az": True, "backups": True},
                       crit: {"multi_az": False, "backups": False}},                     # SPOF (crit is critical)
        "critical_services": [crit],
    }


def generate_instance(seed: int) -> Dict[str, Any]:
    """Deterministic per-instance flawed+sound design pair + the expected violation set (all CODES)."""
    rng = random.Random(seed)
    return {"version": ARCHITECTURE_CORPUS_VERSION,
            "flawed": _flawed(rng), "sound": _sound(rng), "violations": list(CODES)}


# Naive baseline (negative control): finds nothing. MUST score 0 / critical miss.
NAIVE_BASELINE = (
    "def review(architecture):\n"
    "    # TODO: return the list of violation codes present in the design.\n"
    "    return []\n"
)
