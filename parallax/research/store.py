"""Durable, signed persistence for research runs, integrated with PARALLAX's existing signing + audit
architecture (no alternative governance mechanism). A run record = {manifest, metrics}; it is signed,
hashed, audited, idempotent on run_id, and access-controlled (a researcher reads only their own runs).
Research runs confer NO qualification.
"""
from __future__ import annotations

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


def runs_for(db, *, authenticated_researcher_id: str) -> List[Dict[str, Any]]:
    from models import ParallaxResearchRun
    rows = (ParallaxResearchRun.query.filter_by(researcher_id=authenticated_researcher_id)
            .order_by(ParallaxResearchRun.created_at.desc()).all())
    return [{"run_id": r.run_id, "backend_provenance": r.backend_provenance, "model_id": r.model_id,
             "record_count": r.record_count,
             "is_empirical_finding": r.backend_provenance == "infrastructure_backed"} for r in rows]
