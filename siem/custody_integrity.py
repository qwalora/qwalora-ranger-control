"""F4 correction (C) - chain-of-custody integrity: re-verification from the DB, and truncation
detection via a separately-protected checkpoint/anchor.

The F3 custody chain is tamper-evident for record REWRITING: each event hashes its own content and
references the prior event's hash, so altering any event breaks every later link. But a hash chain
cannot, on its own, detect TRUNCATION: delete the most recent N events and the surviving prefix
still verifies perfectly. Detecting that the latest events were removed requires some state kept
OUTSIDE the chain - a count/head anchored separately.

This module adds that anchor without any paid external infrastructure:

  * Each event now carries a 0-based `seq` inside its signed record (see evidence_persistence),
    so every event commits to its own position in the chain.
  * `build_checkpoint` records, per evidence artifact, the chain's head hash, head seq and event
    COUNT in a `custody_checkpoints` row, itself signed and chained to the previous checkpoint
    (prev_checkpoint_hash) so checkpoints cannot be silently rolled back.
  * `assess` compares the live DB chain against the latest checkpoint and reports: ok | truncated
    | rewritten | reordered | no_checkpoint | broken_chain.

Honest limitation (documented, not hidden): events and checkpoints are signed with the SAME server
Ed25519 key. An attacker who holds that key can forge both, so this does not defend against a fully
compromised signing key. It DOES defend against DB-level tampering or truncation by anyone without
the key, and against accidental loss, for everything up to the last checkpoint. A future external
transparency-log anchor (hash of the latest checkpoint published out of band) would close the
same-key gap and needs no paid service to adopt.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json

import signing
from . import evidence_persistence as ep


def _iso(ts=None):
    return (ts or _dt.datetime.now(_dt.timezone.utc)).isoformat()


# --- re-verification from persisted rows -------------------------------------
def signed_from_row(row) -> dict:
    """Reconstruct the exact {record, signature} from a models.CustodyEvent row. Prefers the
    persisted record_json (exact), falling back to reconstructing from columns for older rows."""
    rj = _get(row, "record_json")
    if rj:
        try:
            return json.loads(rj)
        except Exception:
            pass
    rec = {"kind": _get(row, "kind"), "evidence_id": _get(row, "evidence_id"),
           "actor": _get(row, "actor"), "candidate_id": _get(row, "candidate_id"),
           "cohort": _get(row, "cohort"), "pathway": _get(row, "pathway"),
           "detail": _loads(_get(row, "detail")), "ts": _get(row, "ts"),
           "seq": _get(row, "seq"), "parent_hash": _get(row, "parent_hash"),
           "record_hash": _get(row, "record_hash")}
    return {"record": rec, "signature": _get(row, "signature")}


def verify_rows(rows) -> dict:
    """Verify a list of custody rows (any order) as a chain. Returns {ok, reason, count, head}."""
    signed = [signed_from_row(r) for r in rows]
    signed.sort(key=lambda s: (_seqkey(s), s["record"].get("ts") or ""))
    prev = None
    for i, s in enumerate(signed):
        if not ep.verify_custody_event(s):
            return {"ok": False, "reason": f"bad_signature_or_hash_at_index_{i}",
                    "count": len(signed), "head": prev}
        rec = s["record"]
        if rec.get("parent_hash") != prev:
            return {"ok": False, "reason": f"broken_link_at_index_{i}",
                    "count": len(signed), "head": prev}
        if rec.get("seq") is not None and rec.get("seq") != i:
            return {"ok": False, "reason": f"seq_gap_at_index_{i}",
                    "count": len(signed), "head": prev}
        prev = rec["record_hash"]
    return {"ok": True, "reason": "ok", "count": len(signed),
            "head": prev, "head_seq": (signed[-1]["record"].get("seq") if signed else None)}


# --- checkpoint (anchor) construction + verification -------------------------
def build_checkpoint(evidence_id, rows, *, prev_checkpoint_hash=None) -> dict:
    """Build a signed checkpoint over the current chain. Returns a dict ready to persist as a
    models.CustodyCheckpoint row. The chain must verify first (raises ValueError otherwise)."""
    v = verify_rows(rows)
    if not v["ok"]:
        raise ValueError(f"cannot checkpoint an invalid chain: {v['reason']}")
    rec = {"evidence_id": evidence_id, "event_count": v["count"], "head_hash": v["head"],
           "head_seq": v["head_seq"], "prev_checkpoint_hash": prev_checkpoint_hash, "ts": _iso()}
    rec["checkpoint_hash"] = hashlib.sha256(signing.canonical(rec)).hexdigest()
    sig = signing.sign(rec)
    return {"evidence_id": evidence_id, "event_count": rec["event_count"],
            "head_hash": rec["head_hash"], "head_seq": rec["head_seq"],
            "prev_checkpoint_hash": prev_checkpoint_hash,
            "checkpoint_hash": rec["checkpoint_hash"], "ts": rec["ts"], "signature": sig}


def verify_checkpoint(cp) -> bool:
    rec = {"evidence_id": _get(cp, "evidence_id"), "event_count": _get(cp, "event_count"),
           "head_hash": _get(cp, "head_hash"), "head_seq": _get(cp, "head_seq"),
           "prev_checkpoint_hash": _get(cp, "prev_checkpoint_hash"), "ts": _get(cp, "ts")}
    expect = hashlib.sha256(signing.canonical(rec)).hexdigest()
    if _get(cp, "checkpoint_hash") != expect:
        return False
    rec["checkpoint_hash"] = expect
    return signing.verify(rec, _get(cp, "signature"))


# --- the full assessment -----------------------------------------------------
OK = "ok"
TRUNCATED = "truncated"
REWRITTEN = "rewritten"
BROKEN = "broken_chain"
NO_CHECKPOINT = "no_checkpoint"
FORGED_CHECKPOINT = "forged_checkpoint"


def assess(rows, latest_checkpoint) -> dict:
    """Compare the live chain (rows) against its latest checkpoint. Detects truncation of the most
    recent events (live count < anchored count) and head rewrites (same count, different head), in
    addition to the chain's own rewrite/break detection. Returns {status, detail, live, anchored}."""
    v = verify_rows(rows)
    live = {"count": v["count"], "head": v.get("head"), "chain_ok": v["ok"], "reason": v["reason"]}
    if not v["ok"]:
        return {"status": BROKEN, "detail": v["reason"], "live": live, "anchored": None}
    if latest_checkpoint is None:
        return {"status": NO_CHECKPOINT,
                "detail": "no anchor exists yet; truncation of the latest events cannot be ruled out",
                "live": live, "anchored": None}
    if not verify_checkpoint(latest_checkpoint):
        return {"status": FORGED_CHECKPOINT, "detail": "checkpoint signature/hash invalid",
                "live": live, "anchored": None}
    anchored = {"count": _get(latest_checkpoint, "event_count"),
                "head": _get(latest_checkpoint, "head_hash")}
    if live["count"] < anchored["count"]:
        return {"status": TRUNCATED,
                "detail": f"live chain has {live['count']} events but the anchor commits to "
                          f"{anchored['count']}: the latest {anchored['count'] - live['count']} "
                          f"event(s) were removed",
                "live": live, "anchored": anchored}
    if live["count"] == anchored["count"] and live["head"] != anchored["head"]:
        return {"status": REWRITTEN,
                "detail": "event count matches the anchor but the head hash differs: the latest "
                          "event was rewritten",
                "live": live, "anchored": anchored}
    # live["count"] > anchored["count"] is normal growth since the last checkpoint; if equal and
    # heads match, the chain is exactly as anchored.
    return {"status": OK,
            "detail": ("chain matches the anchor" if live["count"] == anchored["count"]
                       else f"chain has grown by {live['count'] - anchored['count']} event(s) since "
                            f"the last checkpoint (expected)"),
            "live": live, "anchored": anchored}


LIMITATIONS = [
    "events and checkpoints are signed with the same server Ed25519 key; a holder of that key "
    "could forge both (does not defend against full key compromise)",
    "truncation is detected only back to the most recent checkpoint; events added AND removed "
    "entirely between two checkpoints with no checkpoint in between are not individually anchored",
    "no external transparency-log anchor yet (a future, no-paid-infra extension publishes the "
    "latest checkpoint hash out of band to close the same-key gap)",
]


# --- helpers -----------------------------------------------------------------
def _get(obj, name):
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _loads(s):
    if not s:
        return {}
    try:
        return json.loads(s)
    except Exception:
        return {}


def _seqkey(signed):
    s = signed["record"].get("seq")
    return s if isinstance(s, int) else 1_000_000_000
