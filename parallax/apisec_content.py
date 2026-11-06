"""PX-A1 (Board 3) API-security content: a sealed per-instance notes store and the request battery
that probes a candidate's object-level authorization handler.

The candidate submits `authz.py` exposing `handle(req) -> {"status": int, "body"?: str}` where
`req = {"token_valid": bool, "subject": str, "resource_id": str, "store": {id: {owner, content}},
        ...decoys}`. Correct behavior (the BOLA fix):

  - no/invalid token            -> 401
  - resource_id not in store    -> 404
  - store[resource_id].owner != subject  -> 403   (the authorization check)
  - otherwise                   -> 200 with the record's content

The store and ownership differ per instance (keyed seed), so a handler cannot hard-code: only a
generically correct ownership check passes. The battery includes a client-spoofing probe (a non-owner
request carrying decoy `owner`/`is_owner`/`is_admin` fields) that a correct handler must ignore.
"""
from __future__ import annotations

import random
from typing import Any, Dict, List

APISEC_CORPUS_VERSION = "apisec-notes-v1"

SUBJECTS = ["alice", "bob", "carol", "dave", "erin", "frank"]
_WORDS = ["ledger", "roadmap", "payroll", "incident", "contract", "keys", "design", "budget",
          "roster", "backup", "audit", "secrets"]


def _store(rng: random.Random, n_notes: int) -> Dict[str, Dict[str, str]]:
    store: Dict[str, Dict[str, str]] = {}
    for i in range(n_notes):
        nid = "n-%04x" % rng.randrange(0x10000)
        if nid in store:
            continue
        owner = rng.choice(SUBJECTS)
        store[nid] = {"owner": owner,
                      "content": "%s-%s-%04x" % (owner, rng.choice(_WORDS), rng.randrange(0x10000))}
    return store


def generate_instance(seed: int, *, n_notes: int = 10) -> Dict[str, Any]:
    """Deterministic per-instance store + request battery. Each battery item carries the request the
    handler receives and the ground-truth `expect` status the harness scores against. Pure function of
    the integer seed (portal-computed per cohort/candidate/attempt), so it is reproducible."""
    rng = random.Random(seed)
    store = _store(rng, n_notes)
    ids = list(store.keys())
    battery: List[Dict[str, Any]] = []

    def req(kind, **kw):
        r = {"token_valid": True, "subject": None, "resource_id": None}
        r.update(kw)
        battery.append({"kind": kind, "req": r, "expect": None})
        return battery[-1]

    for nid in ids:
        owner = store[nid]["owner"]
        others = [s for s in SUBJECTS if s != owner]
        # owner positive -> 200 (task completion)
        item = req("owner", subject=owner, resource_id=nid); item["expect"] = 200
        # non-owner -> 403 (the authorization property)
        no = rng.choice(others)
        item = req("nonowner", subject=no, resource_id=nid); item["expect"] = 403
        # client-spoofing non-owner probe: decoy fields a correct handler must ignore -> still 403
        no2 = rng.choice(others)
        item = req("spoof", subject=no2, resource_id=nid, owner=no2, is_owner=True, is_admin=True)
        item["expect"] = 403
    # missing / invalid token -> 401
    for _ in range(max(2, n_notes // 4)):
        nid = rng.choice(ids)
        item = req("noauth", subject=rng.choice(SUBJECTS), resource_id=nid, token_valid=False)
        item["expect"] = 401
    # not found -> 404
    for _ in range(max(2, n_notes // 4)):
        item = req("notfound", subject=rng.choice(SUBJECTS), resource_id="n-zz%02x" % rng.randrange(256))
        if item["req"]["resource_id"] in store:
            item["req"]["resource_id"] = "missing-xyz"
        item["expect"] = 404

    rng.shuffle(battery)
    return {"version": APISEC_CORPUS_VERSION, "store": store, "battery": battery}


# The known-vulnerable baseline (BOLA): returns the record for any valid token WITHOUT an owner check.
# Used by the grader's/evaluator's negative control and by tests: it MUST score 0 / critical-fail, which
# is how we prove the board's measurement actually discriminates a real fix from the vulnerable code.
VULNERABLE_BASELINE = (
    "def handle(req):\n"
    "    if not req.get('token_valid'):\n"
    "        return {'status': 401}\n"
    "    store = req.get('store') or {}\n"
    "    rid = req.get('resource_id')\n"
    "    if rid not in store:\n"
    "        return {'status': 404}\n"
    "    return {'status': 200, 'body': store[rid].get('content')}\n"
)
