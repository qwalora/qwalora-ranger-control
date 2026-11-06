"""PX-S1 (Board 4) DevSecOps secure-release-gate content: sealed per-instance batteries for three CI/CD
security gates the candidate implements in `gates.py`:

  * scan_secrets(text) -> list     : flag planted secrets in a diff/text (must flag; must not
                                         false-positive on clean code)   [mode: flag]
  * allow_merge(ci) -> bool           : block a merge when the build is not green  [mode: gate]
  * allow_release(sbom) -> bool       : block a release when a dependency is high/critical severity
                                         or carries a disallowed license  [mode: gate]

Each gate is graded over a POSITIVE battery (the secure action is to BLOCK/flag) and a NEGATIVE-CONTROL
battery (the secure action is to ALLOW/stay silent). The negative controls are the manual's
"prove it allows the legitimate case" discipline and the anti-gaming floor: a gate that blocks
everything fails its allow cases, and a gate that allows everything fails its block cases.

The exact policies are fixed and documented (so grading is deterministic):
  - merge is allowed IFF tests failed == 0 AND lint_errors == 0.
  - release is allowed IFF no dependency has severity in {high, critical} AND no dependency license is
    in the disallowed set {GPL-3.0, AGPL-3.0}.
  - a secret is any of: an AWS access key id (AKIA + 16 upper/digits), a GitHub token (ghp_ + 36),
    a PEM private-key header, or an assignment of a password/secret/token/api_key to a quoted literal.
"""
from __future__ import annotations

import random
from typing import Any, Dict, List

DEVSECOPS_CORPUS_VERSION = "devsecops-gate-v1"

DISALLOWED_LICENSES = ["GPL-3.0", "AGPL-3.0"]
BLOCKING_SEVERITIES = ["high", "critical"]

_BENIGN_CODE = [
    "def add(a, b):\n    return a + b\n",
    "const timeout = 30  # seconds\nexport default timeout\n",
    "# config: retries=3, backoff=exponential\nMAX_RETRIES = 3\n",
    "SELECT id, name FROM users WHERE active = true;\n",
    "logger.info('request handled in %d ms', elapsed)\n",
    "resource \"aws_s3_bucket\" \"logs\" {\n  bucket = \"app-logs\"\n}\n",
]
_PKGS = ["left-pad", "lodash", "requests", "flask", "jackson-databind", "log4j-core", "openssl",
         "express", "django", "spring-core"]
_OK_LICENSES = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]


def _secret(rng: random.Random) -> str:
    kind = rng.randrange(4)
    if kind == 0:
        return "AKIA" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
    if kind == 1:
        return "ghp_" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(36))
    if kind == 2:
        return "-----BEGIN PRIVATE KEY-----\nMIIBVz%03d...\n-----END PRIVATE KEY-----" % rng.randrange(1000)
    key = rng.choice(["password", "api_key", "secret", "token"])
    return "%s = \"%s%04x\"" % (key, rng.choice(["hunter", "s3cr3t", "swordfish"]), rng.randrange(0x10000))


def generate_instance(seed: int) -> Dict[str, Any]:
    """Deterministic per-instance battery. Each item: {gate, mode, input, expect_block}. Pure function
    of the integer seed, so two candidates/cohorts get different (but equivalently hard) batteries."""
    rng = random.Random(seed)
    battery: List[Dict[str, Any]] = []

    # --- secret-scan gate (mode: flag) ---
    for _ in range(4):
        sec = _secret(rng)
        code = rng.choice(_BENIGN_CODE)
        text = code + "\n" + sec + "\n" + rng.choice(_BENIGN_CODE)
        battery.append({"gate": "scan_secrets", "mode": "flag",
                        "input": text, "expect_block": True})
    for _ in range(4):
        text = "\n".join(rng.sample(_BENIGN_CODE, 3))
        battery.append({"gate": "scan_secrets", "mode": "flag",
                        "input": text, "expect_block": False})

    # --- CI merge gate (mode: gate) ---
    for _ in range(3):
        ci = {"tests": {"passed": rng.randrange(10, 100), "failed": rng.randrange(1, 5)},
              "lint_errors": rng.randrange(0, 4), "coverage": round(rng.uniform(0.6, 0.95), 2)}
        battery.append({"gate": "allow_merge", "mode": "gate", "input": ci, "expect_block": True})
    for _ in range(1):   # lint-only failure also blocks
        ci = {"tests": {"passed": rng.randrange(20, 100), "failed": 0},
              "lint_errors": rng.randrange(1, 5), "coverage": 0.9}
        battery.append({"gate": "allow_merge", "mode": "gate", "input": ci, "expect_block": True})
    for _ in range(4):
        ci = {"tests": {"passed": rng.randrange(20, 120), "failed": 0},
              "lint_errors": 0, "coverage": round(rng.uniform(0.7, 0.99), 2)}
        battery.append({"gate": "allow_merge", "mode": "gate", "input": ci, "expect_block": False})

    # --- dependency/SBOM release gate (mode: gate) ---
    def dep(sev, lic=None):
        return {"name": rng.choice(_PKGS), "version": "%d.%d.%d" % (rng.randrange(5), rng.randrange(20),
                rng.randrange(20)), "severity": sev, "license": lic or rng.choice(_OK_LICENSES)}

    for _ in range(3):
        sbom = [dep(rng.choice(["none", "low", "medium"])) for _ in range(rng.randrange(2, 5))]
        sbom.append(dep(rng.choice(BLOCKING_SEVERITIES)))   # one blocking vuln
        rng.shuffle(sbom)
        battery.append({"gate": "allow_release", "mode": "gate", "input": sbom, "expect_block": True})
    for _ in range(1):   # disallowed license also blocks
        sbom = [dep("low") for _ in range(2)]
        sbom.append(dep("none", lic=rng.choice(DISALLOWED_LICENSES)))
        rng.shuffle(sbom)
        battery.append({"gate": "allow_release", "mode": "gate", "input": sbom, "expect_block": True})
    for _ in range(4):
        sbom = [dep(rng.choice(["none", "low", "medium"])) for _ in range(rng.randrange(2, 6))]
        battery.append({"gate": "allow_release", "mode": "gate", "input": sbom, "expect_block": False})

    rng.shuffle(battery)
    return {"version": DEVSECOPS_CORPUS_VERSION, "battery": battery}


# Permissive baseline (the negative control): every gate waves everything through. It MUST score 0 /
# critical bypass, which is how we prove the board discriminates a real set of gates from a no-op.
PERMISSIVE_BASELINE = (
    "def scan_secrets(text):\n"
    "    # TODO: detect secrets in the diff/text; return a list of findings.\n"
    "    return []\n\n"
    "def allow_merge(ci):\n"
    "    # TODO: block unless the build is green (ci['tests']['failed'] and ci['lint_errors']).\n"
    "    return True\n\n"
    "def allow_release(sbom):\n"
    "    # TODO: block on high/critical severity or a disallowed license in the SBOM list.\n"
    "    return True\n"
)
