"""Durable, signed persistence for research runs, integrated with PARALLAX's existing signing + audit
architecture (no alternative governance mechanism). A run record = {manifest, metrics}; it is signed,
hashed, audited, idempotent on run_id, and access-controlled (a researcher reads only their own runs).
Research runs confer NO qualification.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

import signing
from .. import auditlog, registry


class ResearchStoreError(Exception):
    pass


def _canon(obj: Any) -> str:
    return signing.canonical(obj).decode("utf-8")


def persist_run(db, *, researcher_id: str, campaign: Dict[str, Any]) -> Dict[str, Any]:
    """Persist a signed research run. `campaign` is the output of harness.run_campaign plus a computed
    `metrics` dict. Idempotent on run_id; appends a signed audit event atomically. Returns the row."""
    from models import ParallaxResearchRun
    if not researcher_id:
        raise ResearchStoreError("a researcher identity is required")
    manifest = campaign.get("manifest") or {}
    metrics = campaign.get("metrics") or {}
    run_id = "run-" + uuid.uuid4().hex[:12]
    record = {"run_id": run_id, "researcher_id": researcher_id, "manifest": manifest,
              "metrics": metrics, "backend_provenance": manifest.get("backend", {}).get("is_real")
              and "infrastructure_backed" or "simulated"}
    import hashlib
    record_hash = hashlib.sha256(signing.canonical(record)).hexdigest()
    provenance = record["backend_provenance"]

    row = ParallaxResearchRun(
        run_id=run_id, researcher_id=researcher_id, backend_provenance=provenance,
        model_id=(manifest.get("backend") or {}).get("model_id"),
        record_count=int(manifest.get("n_records") or 0),
        run_record=_canon(record), record_hash=record_hash,
        signature=signing.sign(record), signing_kid=signing.active_kid())
    db.session.add(row)
    auditlog.append(db, action="research_run_persisted", actor_id=researcher_id,
                    subject_kind="research_run", subject_ref=run_id,
                    detail={"provenance": provenance, "n_records": row.record_count,
                            "model_id": row.model_id})
    registry._commit_recover(db, lambda: None)
    return row


def get_run(db, *, run_id: str, authenticated_researcher_id: str) -> Optional[Dict[str, Any]]:
    """Return the signed run for its OWNER only (access control), with signature-verify status."""
    from models import ParallaxResearchRun
    row = ParallaxResearchRun.query.filter_by(run_id=run_id).first()
    if row is None:
        return None
    if row.researcher_id != authenticated_researcher_id:
        raise ResearchStoreError("a researcher may only read their own runs")
    record = json.loads(row.run_record)
    verifies = signing.verify(record, row.signature, kid=row.signing_kid)
    return {"run_id": row.run_id, "researcher_id": row.researcher_id,
            "backend_provenance": row.backend_provenance, "model_id": row.model_id,
            "record_count": row.record_count, "record": record,
            "signature_verifies": verifies, "record_hash": row.record_hash,
            "is_empirical_finding": (row.backend_provenance == "infrastructure_backed" and verifies)}


def admin_verify_run(db, *, run_id: str) -> Dict[str, Any]:
    """ADMINISTRATIVE, STRICTLY READ-ONLY evidence-integrity verification of ONE research run.

    Unlike get_run (which is candidate-facing and owner-scoped), this is NOT owner-scoped: access is
    governed entirely by the ADMIN authorization enforced at the route (never a candidate/researcher
    web session), so it does not bypass the researcher-ownership rule that protects candidates. It
    performs NO writes, runs NO model, creates NO trial, and never mutates the stored record. It
    returns ONLY sanitized results: booleans, non-sensitive evaluation metadata, and a short public
    key fingerprint. It never returns the signature, any key, credentials, or the full research
    payload (only the observed-response LENGTH, not its text).

    Checks: record existence, canonical SHA-256 hash match, Ed25519 signature validity via the
    trusted-key registry, signing-key trust state, trial-identity binding (signed run_id == queried
    id), model provenance (manifest vs record), researcher/provenance consistency, evaluation
    integrity, and an in-memory tampering negative control (a deep copy with one signed field altered
    must fail verification; the copy is never persisted)."""
    from models import ParallaxResearchRun
    row = ParallaxResearchRun.query.filter_by(run_id=run_id).first()
    if row is None:
        return {"run_id": run_id, "exists": False}
    rec = json.loads(row.run_record)
    canon = signing.canonical(rec)
    hash_match = (hashlib.sha256(canon).hexdigest() == row.record_hash)
    sig_valid = bool(signing.verify(rec, row.signature, kid=row.signing_kid))
    kid_state = signing.key_state(row.signing_kid) if row.signing_kid else None
    kid_trusted = kid_state in ("active", "verify_only", "retired")
    key_fingerprint16 = None
    try:
        pub_b64 = signing.public_key_b64(row.signing_kid) if row.signing_kid else None
        if pub_b64:
            key_fingerprint16 = hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()[:16]
    except Exception:  # noqa: BLE001 - never surface key material; just omit the fingerprint
        key_fingerprint16 = None
    manifest = rec.get("manifest", {}) or {}
    backend = manifest.get("backend", {}) or {}
    metrics = rec.get("metrics", {}) or {}
    trec = metrics.get("record", {}) if isinstance(metrics, dict) else {}
    trec = trec or {}
    ev = trec.get("evaluation", {}) or {}
    model_manifest = backend.get("model_id")
    model_record = (trec.get("model") or {}).get("id")
    # in-memory tampering negative control (never written back to the database)
    tam = copy.deepcopy(rec)
    try:
        tam["metrics"]["record"]["observed_behavior"] = str(trec.get("observed_behavior")) + " [TAMPER]"
    except Exception:  # noqa: BLE001
        tam["_tamper"] = True
    tamper_fails = (signing.verify(tam, row.signature, kid=row.signing_kid) is False)
    signed_run_id_matches = (rec.get("run_id") == run_id)
    all_checks_pass = bool(hash_match and sig_valid and kid_trusted and signed_run_id_matches
                           and tamper_fails
                           and rec.get("backend_provenance") == row.backend_provenance
                           and rec.get("researcher_id") == row.researcher_id)
    return {
        "run_id": run_id, "exists": True,
        "signed_run_id_matches": signed_run_id_matches,
        "hash_match": hash_match,
        "signature_valid": sig_valid,
        "kid_present": bool(row.signing_kid),
        "kid_state": kid_state,
        "kid_trusted": kid_trusted,
        "key_fingerprint16": key_fingerprint16,
        "researcher_matches_column": rec.get("researcher_id") == row.researcher_id,
        "backend_provenance": row.backend_provenance,
        "provenance_in_record_matches": rec.get("backend_provenance") == row.backend_provenance,
        "is_empirical": (row.backend_provenance == "infrastructure_backed" and sig_valid),
        "model_id": model_manifest or model_record,
        "model_manifest_matches_record": (model_manifest == model_record),
        "condition": trec.get("condition"),
        "outcome": trec.get("outcome"),
        "canary_emitted": ev.get("canary"),
        "task_ok": ev.get("task_ok"),
        "observed_len": len(str(trec.get("observed_behavior") or "")),
        "record_count": row.record_count,
        "tamper_negative_control_fails": tamper_fails,
        "all_checks_pass": all_checks_pass,
    }


def runs_for(db, *, authenticated_researcher_id: str) -> List[Dict[str, Any]]:
    from models import ParallaxResearchRun
    rows = (ParallaxResearchRun.query.filter_by(researcher_id=authenticated_researcher_id)
            .order_by(ParallaxResearchRun.created_at.desc()).all())
    return [{"run_id": r.run_id, "backend_provenance": r.backend_provenance, "model_id": r.model_id,
             "record_count": r.record_count,
             "is_empirical_finding": r.backend_provenance == "infrastructure_backed"} for r in rows]
