"""PARALLAX Phase 1C Workstream C - audit-chain integrity: full re-verification plus truncation
detection via a separately-protected checkpoint anchor.

The Phase 1B audit chain (parallax.auditlog) is tamper-evident for record REWRITING, REORDERING, and
MIDDLE deletion: each event hashes its own content, commits to its own `seq`, and references the prior
event's hash, so altering, reordering, or removing any interior event breaks a later link. But a hash
chain cannot, on its own, detect TRUNCATION of its TAIL: drop the most recent N events and the
surviving prefix still verifies. Detecting that the latest events were removed requires state kept
OUTSIDE the chain - an event COUNT and head anchored separately.

This module adds that anchor, mirroring the STRATA custody-chain design in siem.custody_integrity, and
provides a non-destructive, admin-facing integrity report that exposes only ids/hashes/counts (never
secrets or assessment evidence).

Honest limitation (documented, not hidden): events and checkpoints are signed with the SAME server
Ed25519 key, so a holder of that key could forge both. This defends against DB-level truncation or
tampering by anyone WITHOUT the signing key, and against accidental loss, up to the last checkpoint. A
future external transparency-log anchor (publishing the latest checkpoint hash out of band) would close
the same-key gap and needs no paid infrastructure.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
from typing import Any, Dict, List, Optional

import signing
from . import auditlog, registry

_STREAM = auditlog._STREAM

OK = "ok"
TRUNCATED = "truncated"
REWRITTEN = "rewritten"
BROKEN = "broken_chain"
NO_CHECKPOINT = "no_checkpoint"
FORGED_CHECKPOINT = "forged_checkpoint"
ANCHOR_INDEPENDENCE = "not_independent_same_store_same_key"

LIMITATIONS = [
    "events and checkpoints are signed with the same server Ed25519 key; a holder of that key could "
    "forge both (does not defend against full key compromise)",
    "truncation is detected only back to the most recent checkpoint; the window between two "
    "checkpoints is anchored only by its endpoints",
    "the checkpoint lives in the same database as the events, so it is not an independent anchor; "
    "an external transparency-log hash (no paid infra) is a future extension",
]


def _iso():
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# --- full chain re-verification from persisted rows ----------------------------------------------
def verify_events(db, stream: str = _STREAM) -> Dict[str, Any]:
    """Re-verify the whole chain from the DB. Returns {ok, reason, count, head, head_seq}. Detects bad
    signatures (kid-aware), broken predecessor links, and seq gaps/duplicates/reordering."""
    from models import ParallaxAuditEvent
    rows = (ParallaxAuditEvent.query.filter_by(stream=stream)
            .order_by(ParallaxAuditEvent.seq.asc()).all())
    prev = None
    for i, r in enumerate(rows):
        try:
            record = json.loads(r.detail_json)
        except Exception:  # noqa: BLE001
            return {"ok": False, "reason": "unreadable_record_at_%d" % i, "count": i, "head": prev}
        if record.get("seq") != i or r.seq != i:
            return {"ok": False, "reason": "seq_gap_or_dup_at_%d" % i, "count": i, "head": prev}
        if record.get("parent_hash") != prev:
            return {"ok": False, "reason": "broken_link_at_%d" % i, "count": i, "head": prev}
        if hashlib.sha256(signing.canonical(record)).hexdigest() != r.record_hash:
            return {"ok": False, "reason": "record_hash_mismatch_at_%d" % i, "count": i, "head": prev}
        if not signing.verify(record, r.signature, kid=r.signing_kid):
            return {"ok": False, "reason": "bad_signature_at_%d" % i, "count": i, "head": prev}
        prev = r.record_hash
    return {"ok": True, "reason": "ok", "count": len(rows), "head": prev,
            "head_seq": (rows[-1].seq if rows else None)}


# --- checkpoint construction + verification ------------------------------------------------------
def _checkpoint_record(stream, count, head, head_seq, prev_cp_hash):
    rec = {"stream": stream, "event_count": count, "head_hash": head, "head_seq": head_seq,
           "prev_checkpoint_hash": prev_cp_hash, "ts": _iso()}
    rec["checkpoint_hash"] = hashlib.sha256(signing.canonical(
        {k: rec[k] for k in rec if k != "checkpoint_hash"})).hexdigest()
    return rec


def verify_checkpoint(cp) -> bool:
    """True if a checkpoint row's hash and signature are intact (kid-aware)."""
    rec = {"stream": cp.stream, "event_count": cp.event_count, "head_hash": cp.head_hash,
           "head_seq": cp.head_seq, "prev_checkpoint_hash": cp.prev_checkpoint_hash, "ts": cp.ts}
    expect = hashlib.sha256(signing.canonical(rec)).hexdigest()
    if cp.checkpoint_hash != expect:
        return False
    rec["checkpoint_hash"] = expect
    return signing.verify(rec, cp.signature, kid=cp.signing_kid)


def latest_checkpoint(db, stream: str = _STREAM):
    from models import ParallaxAuditCheckpoint
    return (ParallaxAuditCheckpoint.query.filter_by(stream=stream)
            .order_by(ParallaxAuditCheckpoint.id.desc()).first())


def write_checkpoint(db, *, principal, stream: str = _STREAM):
    """Authorized admins only. Anchor the current chain head/count in a signed, checkpoint-chained row.
    Refuses to checkpoint a chain that does not currently verify. Does NOT append an audit event (that
    would immediately make the checkpoint stale)."""
    from models import ParallaxAuditCheckpoint
    registry._authorize(db, principal)
    v = verify_events(db, stream)
    if not v["ok"]:
        raise ValueError("cannot checkpoint an invalid chain: %s" % v["reason"])
    prev = latest_checkpoint(db, stream)
    prev_hash = prev.checkpoint_hash if prev else None
    rec = _checkpoint_record(stream, v["count"], v["head"], v.get("head_seq"), prev_hash)
    row = ParallaxAuditCheckpoint(
        stream=stream, event_count=rec["event_count"], head_hash=rec["head_hash"],
        head_seq=rec["head_seq"], prev_checkpoint_hash=prev_hash,
        checkpoint_hash=rec["checkpoint_hash"], ts=rec["ts"],
        signature=signing.sign(rec), signing_kid=signing.active_kid())
    db.session.add(row)
    registry._commit_recover(db, lambda: None)
    return row


# --- full assessment + admin report --------------------------------------------------------------
def assess(db, stream: str = _STREAM) -> Dict[str, Any]:
    """Compare the live chain against its latest checkpoint. Statuses: ok | truncated | rewritten |
    broken_chain | no_checkpoint | forged_checkpoint. Always carries anchor_independence so a
    same-store checkpoint is never mistaken for an independent anchor."""
    v = verify_events(db, stream)
    live = {"count": v["count"], "head": v.get("head"), "chain_ok": v["ok"], "reason": v["reason"]}
    cp = latest_checkpoint(db, stream)
    out = {"anchor_independence": ANCHOR_INDEPENDENCE, "live": live, "anchored": None}
    if not v["ok"]:
        out.update({"status": BROKEN, "detail": v["reason"]})
        return out
    if cp is None:
        out.update({"status": NO_CHECKPOINT,
                    "detail": "no anchor exists yet; tail truncation cannot be ruled out"})
        return out
    if not verify_checkpoint(cp):
        out.update({"status": FORGED_CHECKPOINT, "detail": "checkpoint signature/hash invalid"})
        return out
    anchored = {"count": cp.event_count, "head": cp.head_hash, "head_seq": cp.head_seq}
    out["anchored"] = anchored
    if live["count"] < anchored["count"]:
        out.update({"status": TRUNCATED,
                    "detail": "live chain has %d events but the anchor commits to %d: the latest "
                              "%d event(s) were removed"
                              % (live["count"], anchored["count"], anchored["count"] - live["count"])})
    elif live["count"] == anchored["count"] and live["head"] != anchored["head"]:
        out.update({"status": REWRITTEN,
                    "detail": "event count matches the anchor but the head hash differs"})
    else:
        out.update({"status": OK,
                    "detail": ("chain matches the anchor" if live["count"] == anchored["count"]
                               else "chain has grown by %d event(s) since the last checkpoint"
                                    % (live["count"] - anchored["count"]))})
    return out


def integrity_report(db, stream: str = _STREAM) -> Dict[str, Any]:
    """Non-destructive, admin-safe integrity report. Exposes only ids/hashes/counts/status - never
    event payloads, secrets, or assessment evidence. Suitable to expose to an administrator."""
    a = assess(db, stream)
    cp = latest_checkpoint(db, stream)
    return {
        "stream": stream,
        "status": a["status"],
        "detail": a["detail"],
        "chain_ok": a["live"]["chain_ok"],
        "event_count": a["live"]["count"],
        "head_hash": a["live"]["head"],
        "checkpoint": (None if cp is None else {
            "event_count": cp.event_count, "head_hash": cp.head_hash, "head_seq": cp.head_seq,
            "checkpoint_hash": cp.checkpoint_hash, "ts": cp.ts, "signing_kid": cp.signing_kid,
            "verifies": verify_checkpoint(cp)}),
        "anchor_independence": a["anchor_independence"],
        "limitations": LIMITATIONS,
    }


# --- threat model + external-anchor interface (Phase 1D Workstream C) -----------------------------
# What the SAME-STORE, SAME-KEY checkpoint demonstrably mitigates, and what it does not. Keyed by the
# adversary's capability; each value is (mitigated: bool, how).
THREAT_MODEL = {
    "accidental_corruption":
        (True, "chain hash + per-event signature + seq ordering detect accidental edits/loss"),
    "unauthorized_db_modification_without_signing_key":
        (True, "any edit/insert/reorder breaks a signature or the hash chain (attacker lacks the key)"),
    "tail_truncation_without_signing_key":
        (True, "the signed checkpoint anchors event COUNT + head; a shorter live chain is TRUNCATED"),
    "truncation_plus_checkpoint_deletion_without_key":
        (True, "detected ONLY if an external anchor (export_anchor) was emitted; otherwise degrades to "
               "NO_CHECKPOINT, which is itself an anomaly but not positive proof"),
    "compromised_signing_key_without_db_write":
        (True, "the key alone cannot insert/alter rows; DB-side chain + unique(seq) still constrain"),
    "simultaneous_db_and_signing_key_compromise":
        (False, "NOT mitigated by a same-store same-key checkpoint: the attacker can forge events AND "
                "a matching checkpoint. Requires an INDEPENDENT external anchor outside the signing "
                "authority's control (OPEN - see export_anchor and the Phase 1D report architecture)"),
}


def anchor_record(cp) -> Dict[str, Any]:
    """The minimal, independently-verifiable record a verifier needs from a checkpoint: stream, count,
    head hash, checkpoint hash, ts, kid. Contains no secrets or event payloads."""
    return {"stream": cp.stream, "event_count": cp.event_count, "head_hash": cp.head_hash,
            "head_seq": cp.head_seq, "checkpoint_hash": cp.checkpoint_hash, "ts": cp.ts,
            "signing_kid": cp.signing_kid}


def export_anchor(db, *, sink, stream: str = _STREAM):
    """Emit the latest checkpoint's anchor_record to an EXTERNAL sink (a callable receiving the dict).

    This is the INTERFACE for independent anchoring. Its security value depends entirely on where the
    sink writes: an anchor stored OUTSIDE the signing authority's control (append-only object storage
    with immutability, a transparency log, or a separately-managed authority) is what would detect the
    simultaneous DB+key compromise that the in-DB checkpoint cannot. A sink that writes back to the
    same database or same host provides NO additional independence. No external/paid service is
    activated here; selecting and provisioning an independent sink is an OPEN founder decision
    (architecture + validation plan in the Phase 1D report)."""
    cp = latest_checkpoint(db, stream)
    if cp is None:
        raise ValueError("no checkpoint to anchor")
    rec = anchor_record(cp)
    sink(rec)
    return rec


def verify_against_external_anchor(db, anchor: Dict[str, Any], stream: str = _STREAM) -> Dict[str, Any]:
    """Compare the live chain to an anchor held EXTERNALLY (previously emitted by export_anchor). This
    is the detection path for truncation/rewrite even if every in-DB checkpoint was also deleted or
    forged. Returns {status, detail} with status ok | truncated | rewritten | broken_chain."""
    v = verify_events(db, stream)
    if not v["ok"]:
        return {"status": BROKEN, "detail": v["reason"]}
    live_count, live_head = v["count"], v.get("head")
    a_count, a_head = anchor.get("event_count"), anchor.get("head_hash")
    if live_count < a_count:
        return {"status": TRUNCATED,
                "detail": "external anchor commits to %d events; live chain has %d" % (a_count, live_count)}
    if live_count == a_count and live_head != a_head:
        return {"status": REWRITTEN, "detail": "external anchor head differs from live head at equal count"}
    return {"status": OK, "detail": "live chain is consistent with the external anchor"}
