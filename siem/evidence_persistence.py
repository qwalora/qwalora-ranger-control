"""F3 - secure evidence acquisition, provenance, retrieval, integrity, and retention.

Ties the ArtifactStore (bytes) to the typed EvidenceArtifact envelope (metadata), the Case/
candidate ownership model, Ed25519 signing, and an append-only signed chain of custody. It does
NOT create a second case or qualification system - it persists evidence for the existing one.

Trust posture: the server independently computes the SHA-256, sniffs the file signature, enforces
size + format, and never trusts a candidate-supplied filename, MIME type, hash, or provenance
assertion. Uploaded content is never executed, decompressed, or rendered. Until a malware-scan
policy is approved, artifacts are marked `unscanned` and are not promoted to `validated`.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json

import signing
import pathways
from . import artifact_store as store_mod
from . import evidence_types as et


class AcquisitionError(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _now():
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(ts=None):
    return (ts or _now()).isoformat()


# --- signed, append-only chain of custody ------------------------------------
def custody_event(kind, *, evidence_id, actor, candidate_id=None, cohort=None, pathway=None,
                  detail=None, parent_hash=None):
    """Build an immutable, signed custody event. Returns {record, signature}. The record hashes
    its own content; the next event references it via parent_hash, forming a tamper-evident chain."""
    rec = {"kind": kind, "evidence_id": evidence_id, "actor": actor,
           "candidate_id": candidate_id, "cohort": cohort,
           "pathway": pathways.normalize_pathway(pathway) if pathway else None,
           "detail": detail or {}, "ts": _iso(), "parent_hash": parent_hash}
    rec["record_hash"] = hashlib.sha256(signing.canonical(rec)).hexdigest()
    return {"record": rec, "signature": signing.sign(rec)}


def verify_custody_event(signed) -> bool:
    rec = signed.get("record", {})
    expect = hashlib.sha256(
        signing.canonical({k: rec.get(k) for k in rec if k != "record_hash"})).hexdigest()
    return rec.get("record_hash") == expect and signing.verify(rec, signed.get("signature"))


def verify_custody_chain(events) -> bool:
    """Verify a list of custody events (oldest first): each signature valid and each parent_hash
    links to the prior event's record_hash."""
    prev = None
    for e in events:
        if not verify_custody_event(e):
            return False
        if e["record"].get("parent_hash") != prev:
            return False
        prev = e["record"]["record_hash"]
    return True


# --- secure acquisition ------------------------------------------------------
def acquire(store, fileobj, *, evidence_type, case_id, candidate_id, cohort, pathway,
            source_identity, actor="ranger-server", declared_media_type=None,
            max_bytes=None, retention_class="default"):
    """Stream an upload into the store with server-side hashing/sniffing/validation, build the
    typed EvidenceArtifact envelope (unscanned -> needs_review), and emit the first custody
    event. Returns {artifact, put, custody}. Raises AcquisitionError on anything unsafe.

    The declared_media_type is advisory only; the authoritative type is sniffed from bytes."""
    spec = et.EVIDENCE_TYPES.get(evidence_type)
    if spec is None:
        raise AcquisitionError("UNSUPPORTED_EVIDENCE_TYPE", f"unknown type {evidence_type!r}")
    if not spec["blob"]:
        raise AcquisitionError("NOT_A_BLOB_TYPE", f"{evidence_type} is not stored as an object")
    cap = max_bytes or spec["max_bytes"] or store_mod._DEFAULT_MAX
    allowed = spec["media"]
    try:
        put = store.put_stream(fileobj, max_bytes=cap, allowed_media_types=allowed)
    except store_mod.StorageError as e:
        # malformed/truncated/oversized/unsupported -> safe, explicit failure; nothing persisted
        raise AcquisitionError(e.code, e.message)

    blob = et.blob_ref("blob/" + put.sha256, put.sha256, put.media_type, put.size,
                       provenance={"acquired": _iso(), "source_identity": source_identity})
    art = et.new_artifact(evidence_type=evidence_type, case_id=case_id, candidate_id=candidate_id,
                          cohort=cohort, pathway=pathway, source_identity=source_identity,
                          content_hash=put.sha256, blob=blob, validation_state="needs_review")
    art["object_key"] = put.key
    art["scan_state"] = put.scan_state          # unscanned until an approved scan policy runs
    art["retention_class"] = retention_class
    art["acquisition_ts"] = _iso()
    cev = custody_event("acquire", evidence_id=art["evidence_id"], actor=actor,
                        candidate_id=candidate_id, cohort=cohort, pathway=pathway,
                        detail={"object_key": put.key, "sha256": put.sha256, "size": put.size,
                                "media_type": put.media_type, "declared_media_type": declared_media_type,
                                "scan_state": put.scan_state})
    return {"artifact": art, "put": put.as_dict(), "custody": cev}


# --- secure retrieval (server-side authorization) ----------------------------
def retrieve(store, artifact, *, requester, actor="ranger-server", verify_integrity=True):
    """Authorize (ownership/cohort/pathway/retention/revocation via evidence_types), optionally
    re-verify stored bytes against the preserved hash, and return the bytes. Never exposes the
    object path or storage credentials to the caller. Returns {ok, bytes?, reason, custody}."""
    allowed, why = et.authorize_access(artifact, requester=requester)
    if not allowed:
        return {"ok": False, "reason": why, "bytes": None, "custody": None}
    key = artifact.get("object_key")
    if not key or not store.exists(key):
        return {"ok": False, "reason": "missing", "bytes": None, "custody": None}
    if verify_integrity and not store.verify(key, artifact.get("content_hash")):
        # corrupted / tampered at rest -> deny + quarantine custody event
        qev = custody_event("quarantine", evidence_id=artifact["evidence_id"], actor=actor,
                            candidate_id=artifact.get("candidate_id"), cohort=artifact.get("cohort"),
                            pathway=artifact.get("pathway"),
                            detail={"reason": "integrity_mismatch", "object_key": key})
        return {"ok": False, "reason": "corrupted", "bytes": None, "custody": qev}
    data = store.get_bytes(key)
    aev = custody_event("access", evidence_id=artifact["evidence_id"], actor=actor,
                        candidate_id=requester.get("candidate_id"), cohort=artifact.get("cohort"),
                        pathway=artifact.get("pathway"), detail={"role": requester.get("role")})
    return {"ok": True, "reason": "ok", "bytes": data, "custody": aev}


def issue_access_grant(store, artifact, *, requester, operation="get", ttl_seconds=300):
    """Authorize, THEN return a short-lived scoped access grant (presigned descriptor) if the
    backend supports it. Issued only after authorization; scoped to the one object + operation."""
    allowed, why = et.authorize_access(artifact, requester=requester)
    if not allowed:
        return {"ok": False, "reason": why, "grant": None}
    key = artifact.get("object_key")
    grant = store.presign(key, operation=operation, ttl_seconds=ttl_seconds)
    return {"ok": True, "reason": "ok", "grant": grant}


# --- derived artifacts (no overwrite of the source) --------------------------
def persist_derived(store, parent_artifact, derived_bytes, *, evidence_type, transform,
                    tool_version, actor="forensic-tool", max_bytes=None):
    """Store a derived artifact's bytes as a NEW object and envelope that references the parent.
    The parent (source) is never overwritten. Emits a signed `derive` custody event recording the
    transformation type + tool version + derived hash. Returns {artifact, put, custody}."""
    spec = et.EVIDENCE_TYPES.get(evidence_type)
    cap = max_bytes or (spec and spec["max_bytes"]) or store_mod._DEFAULT_MAX
    import io
    put = store.put_stream(io.BytesIO(derived_bytes), max_bytes=cap,
                           allowed_media_types=(spec["media"] if spec else None))
    blob = et.blob_ref("blob/" + put.sha256, put.sha256, put.media_type, put.size,
                       provenance={"derived_from": parent_artifact["evidence_id"],
                                   "transform": transform, "tool_version": tool_version})
    art = et.derive(parent_artifact, evidence_type=evidence_type, blob=blob,
                    content_hash=put.sha256, source_identity=actor,
                    provenance={"transform": transform, "tool_version": tool_version})
    art["object_key"] = put.key
    art["scan_state"] = put.scan_state
    art["transform"] = transform
    art["tool_version"] = tool_version
    cev = custody_event("derive", evidence_id=art["evidence_id"], actor=actor,
                        candidate_id=parent_artifact.get("candidate_id"),
                        cohort=parent_artifact.get("cohort"), pathway=parent_artifact.get("pathway"),
                        detail={"parent": parent_artifact["evidence_id"], "transform": transform,
                                "tool_version": tool_version, "derived_hash": put.sha256})
    return {"artifact": art, "put": put.as_dict(), "custody": cev}


# --- integrity re-verification + retention -----------------------------------
def reverify(store, artifact):
    """Independently re-verify stored bytes against the preserved content_hash. Returns a status:
    ok | missing | corrupted | revoked | expired. Signed-metadata checks are the caller's (the
    artifact row carries a signature verified via evidence_types.verify_artifact)."""
    if artifact.get("validation_state") == "revoked" or artifact.get("revoked"):
        return "revoked"
    ret = artifact.get("retention_until")
    if ret:
        try:
            if _dt.datetime.fromisoformat(ret) < _now():
                return "expired"
        except Exception:
            return "expired"
    key = artifact.get("object_key")
    if not key or not store.exists(key):
        return "missing"
    return "ok" if store.verify(key, artifact.get("content_hash")) else "corrupted"


# Retention classes that must never be auto-deleted while in use.
PROTECTED_RETENTION = {"active_assessment", "signed_qualification"}


def can_delete(artifact, *, reason, now=None) -> tuple:
    """Return (allowed, why). Evidence tied to an active assessment or a signed qualification is
    NEVER auto-deletable; deletion needs an explicit authorized reason and a non-protected class
    (or an expired retention window). A case being submitted or a cohort retired is NOT a reason."""
    if not reason:
        return (False, "no_authorized_reason")
    if artifact.get("retention_class") in PROTECTED_RETENTION:
        # only deletable once retention has explicitly expired
        ret = artifact.get("retention_until")
        if not ret:
            return (False, "protected_no_expiry")
        try:
            if _dt.datetime.fromisoformat(ret) >= (now or _now()):
                return (False, "retention_active")
        except Exception:
            return (False, "bad_retention")
    return (True, "ok")


def delete_evidence(store, artifact, *, reason, now=None):
    """Guarded deletion: enforces can_delete, then removes the object and emits a signed custody
    event. Does NOT delete on case submission or cohort retirement."""
    ok, why = can_delete(artifact, reason=reason, now=now)
    if not ok:
        return {"ok": False, "reason": why, "custody": None}
    store.delete(artifact["object_key"], authorized_reason=reason)
    cev = custody_event("retain", evidence_id=artifact["evidence_id"], actor="ranger-server",
                        candidate_id=artifact.get("candidate_id"), cohort=artifact.get("cohort"),
                        pathway=artifact.get("pathway"),
                        detail={"action": "deleted", "reason": reason})
    return {"ok": True, "reason": "deleted", "custody": cev}


def custody_row(signed_event):
    """Project a signed custody event into kwargs for the models.CustodyEvent row."""
    r = signed_event["record"]
    return {"evidence_id": r["evidence_id"], "kind": r["kind"], "actor": r.get("actor"),
            "candidate_id": r.get("candidate_id"), "cohort": r.get("cohort"),
            "pathway": r.get("pathway"), "detail": json.dumps(r.get("detail") or {}),
            "record_hash": r["record_hash"], "parent_hash": r.get("parent_hash"),
            "signature": signed_event["signature"]}
