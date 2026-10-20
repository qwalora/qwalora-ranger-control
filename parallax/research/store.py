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


def overview_for(db, *, authenticated_researcher_id: str) -> List[Dict[str, Any]]:
    """Owner-scoped, READ-ONLY researcher summary of their OWN signed runs, for the researcher
    command center and evidence center. For each trial/investigation (adjudications, which are
    reviewer-authored, are excluded) it returns kind, provenance, signature-verify, and - for an
    investigation - the researcher's OWN review status + authorized feedback (exactly the fields
    review_status_for already exposes to the owner). It reuses the same owner scope as runs_for and
    the same sanitization as review_status_for/_evidence_summary: it never returns another
    researcher's rows, never a signature/key/raw payload, and no reviewer-only data beyond the
    authorized feedback already visible to the owner. Newest first."""
    from models import ParallaxResearchRun
    rows = (ParallaxResearchRun.query.filter_by(researcher_id=authenticated_researcher_id)
            .order_by(ParallaxResearchRun.created_at.desc()).all())
    out: List[Dict[str, Any]] = []
    for r in rows:
        rec = _rec_of(r)
        kind = _kind_of(rec) or "run"
        if kind == "adjudication":
            continue  # reviewer-authored; not part of the researcher's own evidence view
        verifies = bool(signing.verify(rec, r.signature, kid=r.signing_kid))
        item = {
            "run_id": r.run_id, "kind": kind, "parent_run": _parent_of(rec),
            "backend_provenance": r.backend_provenance,
            "signature_verifies": verifies,
            "is_empirical_finding": (r.backend_provenance == "infrastructure_backed" and verifies),
            "record_count": r.record_count, "model_id": r.model_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        if kind == "trial":
            tr = (rec.get("metrics") or {}).get("record") or {}
            item["outcome"] = tr.get("outcome")
            item["condition"] = tr.get("condition")
            item["canary_emitted"] = (tr.get("evaluation") or {}).get("canary")
        elif kind == "investigation":
            decisions = _decisions_for(db, r.run_id)
            latest = decisions[-1] if decisions else None
            item["review_status"] = "reviewed" if decisions else "pending_review"
            item["decision"] = latest["decision"] if latest else None
            item["feedback"] = latest["comment"] if latest else None
            item["reviewed_at"] = latest["at"] if latest else None
        out.append(item)
    return out


# =============================================================================================
# PARALLAX research reviewer workflow (adjudication integrity, review queue, candidate visibility)
# All functions here are read-only EXCEPT adjudicate_investigation, which persists ONE signed
# adjudication after full integrity checks. None run a model; none touch historical trial evidence.
# =============================================================================================

INVESTIGATION_DECISIONS = ("met", "not_met", "inconclusive")


def _err(msg: str, http: int) -> "ResearchStoreError":
    e = ResearchStoreError(msg)
    e.http = http  # type: ignore[attr-defined]
    return e


def _rec_of(row) -> Dict[str, Any]:
    try:
        return json.loads(row.run_record)
    except Exception:  # noqa: BLE001
        return {}


def _kind_of(rec: Dict[str, Any]) -> Optional[str]:
    return ((rec.get("manifest") or {}).get("kind")) or ((rec.get("metrics") or {}).get("kind"))


def _parent_of(rec: Dict[str, Any]) -> Optional[str]:
    return ((rec.get("manifest") or {}).get("parent_run")
            or (rec.get("metrics") or {}).get("parent_run"))


def _decisions_for(db, investigation_id: str) -> List[Dict[str, Any]]:
    """All adjudications targeting this investigation, oldest first, with signature-verify status.
    Sanitized (no signatures/keys)."""
    from models import ParallaxResearchRun
    rows = (ParallaxResearchRun.query
            .filter(ParallaxResearchRun.run_record.contains('"kind":"adjudication"'))
            .filter(ParallaxResearchRun.run_record.contains(investigation_id)).all())
    out = []
    for r in rows:
        rec = _rec_of(r)
        m = rec.get("metrics") or {}
        if m.get("kind") == "adjudication" and m.get("target") == investigation_id:
            out.append({"adjudication_id": r.run_id, "decision": m.get("decision"),
                        "reviewer_id": m.get("reviewer_id"), "comment": m.get("comment"),
                        "at": r.created_at.isoformat() if r.created_at else None,
                        "signature_verifies": bool(signing.verify(rec, r.signature, kid=r.signing_kid))})
    out.sort(key=lambda d: d["at"] or "")
    return out


def _evidence_summary(db, parent_id: str, inv_researcher_id: str) -> Dict[str, Any]:
    """Sanitized summary + verification of the investigation's linked evidence (never raw signatures
    or keys). observed_behavior is the reviewable model output and is included for authorized reviewers,
    bounded in length."""
    from models import ParallaxResearchRun
    prow = ParallaxResearchRun.query.filter_by(run_id=parent_id).first()
    if prow is None:
        return {"evidence_run_id": parent_id, "exists": False, "signature_verifies": False,
                "owner_matches": False}
    prec = _rec_of(prow)
    ptr = (prec.get("metrics") or {}).get("record", {}) or {}
    ev_verifies = bool(signing.verify(prec, prow.signature, kid=prow.signing_kid))
    obs = ptr.get("observed_behavior")
    return {
        "evidence_run_id": parent_id, "exists": True,
        "backend_provenance": prow.backend_provenance,
        "is_empirical": (prow.backend_provenance == "infrastructure_backed" and ev_verifies),
        "model_id": ((prec.get("manifest") or {}).get("backend") or {}).get("model_id")
                    or (ptr.get("model") or {}).get("id"),
        "condition": ptr.get("condition"), "outcome": ptr.get("outcome"),
        "canary_emitted": (ptr.get("evaluation") or {}).get("canary"),
        "observed_behavior": (obs[:2000] if isinstance(obs, str) else obs),
        "protocol_version": ptr.get("protocol_version") or prec.get("protocol_version"),
        "corpus_version": ptr.get("corpus_version"),
        "signature_verifies": ev_verifies,
        "owner_matches": (prow.researcher_id == inv_researcher_id),
    }


def list_investigations_for_review(db, *, status: str = "all", q: str = "",
                                   limit: int = 200) -> List[Dict[str, Any]]:
    """Reviewer/admin READ-ONLY queue of research investigations. `status` in {all,pending,reviewed}.
    `q` filters on investigation id / researcher / evidence id / analysis (case-insensitive). Returns
    a sanitized list (no signatures/keys/full raw records)."""
    from models import ParallaxResearchRun
    rows = (ParallaxResearchRun.query
            .filter(ParallaxResearchRun.run_record.contains('"kind":"investigation"'))
            .order_by(ParallaxResearchRun.created_at.desc()).limit(2000).all())
    items: List[Dict[str, Any]] = []
    ql = (q or "").strip().lower()
    for r in rows:
        rec = _rec_of(r)
        if _kind_of(rec) != "investigation":
            continue
        decisions = _decisions_for(db, r.run_id)
        st = "reviewed" if decisions else "pending"
        if status in ("pending", "reviewed") and st != status:
            continue
        parent_id = _parent_of(rec)
        analysis = (rec.get("metrics") or {}).get("analysis") or ""
        if ql:
            hay = " ".join([r.run_id, r.researcher_id or "", parent_id or "", analysis]).lower()
            if ql not in hay:
                continue
        items.append({
            "investigation_id": r.run_id, "researcher_id": r.researcher_id,
            "evidence_run_id": parent_id, "status": st,
            "signature_verifies": bool(signing.verify(rec, r.signature, kid=r.signing_kid)),
            "latest_decision": (decisions[-1]["decision"] if decisions else None),
            "decision_count": len(decisions),
            "analysis_excerpt": analysis[:160],
            "submitted_at": r.created_at.isoformat() if r.created_at else None,
        })
        if len(items) >= limit:
            break
    return items


def get_investigation_detail(db, *, run_id: str) -> Optional[Dict[str, Any]]:
    """Reviewer/admin READ-ONLY detail for ONE investigation: researcher ref, full analysis, linked
    evidence summary + verification, cryptographic verify status, decision history. Not owner-scoped
    (admin/reviewer authority governs access at the route). Sanitized: no signatures/keys/raw bytes.
    Returns None if the id is not an investigation."""
    from models import ParallaxResearchRun
    row = ParallaxResearchRun.query.filter_by(run_id=run_id).first()
    if row is None:
        return None
    rec = _rec_of(row)
    if _kind_of(rec) != "investigation":
        return None
    parent_id = _parent_of(rec)
    decisions = _decisions_for(db, run_id)
    ev = _evidence_summary(db, parent_id, row.researcher_id) if parent_id else None
    return {
        "investigation_id": run_id, "researcher_id": row.researcher_id,
        "analysis": (rec.get("metrics") or {}).get("analysis"),
        "submitted_at": row.created_at.isoformat() if row.created_at else None,
        "signature_verifies": bool(signing.verify(rec, row.signature, kid=row.signing_kid)),
        "evidence": ev,
        "status": "reviewed" if decisions else "pending",
        "decisions": decisions,
        "assessment_only": True, "pathway_qualified": False,
    }


def review_status_for(db, *, run_id: str, authenticated_researcher_id: str) -> Optional[Dict[str, Any]]:
    """Candidate OWNER-SCOPED view of their OWN investigation's review status + authorized feedback.
    Raises if the investigation belongs to someone else (never reveals another researcher's work)."""
    from models import ParallaxResearchRun
    row = ParallaxResearchRun.query.filter_by(run_id=run_id).first()
    if row is None:
        return None
    if row.researcher_id != authenticated_researcher_id:
        raise ResearchStoreError("a researcher may only read their own investigations")
    rec = _rec_of(row)
    if _kind_of(rec) != "investigation":
        return None
    decisions = _decisions_for(db, run_id)
    latest = decisions[-1] if decisions else None
    return {
        "investigation_id": run_id,
        "status": "reviewed" if decisions else "pending_review",
        "decision": (latest["decision"] if latest else None),
        "feedback": (latest["comment"] if latest else None),
        "reviewed_at": (latest["at"] if latest else None),
        "bound_to": _parent_of(rec),
        "assessment_only": True, "pathway_qualified": False,
    }


def find_identical_investigation(db, *, researcher_id: str, parent_run: str, analysis: str):
    """Return an EXISTING investigation by this researcher with the same evidence + identical analysis
    (for idempotent handling of accidental resubmits), or None. Does not match a different analysis."""
    from models import ParallaxResearchRun
    rows = (ParallaxResearchRun.query.filter_by(researcher_id=researcher_id)
            .filter(ParallaxResearchRun.run_record.contains('"kind":"investigation"')).all())
    for r in rows:
        rec = _rec_of(r)
        m = rec.get("metrics") or {}
        if (_kind_of(rec) == "investigation" and m.get("parent_run") == parent_run
                and (m.get("analysis") or "") == analysis):
            return r
    return None


def adjudicate_investigation(db, *, investigation_id: str, reviewer_id: str, decision: str,
                             comment: str = ""):
    """HARDENED adjudication core: before creating any signed decision it REQUIRES the target to be an
    existing, signature-verified PARALLAX investigation whose linked evidence exists, verifies, and is
    owned by the same researcher; it prohibits self-review; and it rejects invalid decisions. Persists
    ONE signed adjudication (assessment-only; no qualification). Raises ResearchStoreError (with .http)
    on any failure, BEFORE signing anything."""
    from models import ParallaxResearchRun
    if decision not in INVESTIGATION_DECISIONS:
        raise _err("decision must be met|not_met|inconclusive", 400)
    if not reviewer_id:
        raise _err("reviewer identity required", 401)
    if not investigation_id:
        raise _err("investigation_id required", 400)
    row = ParallaxResearchRun.query.filter_by(run_id=investigation_id).first()
    if row is None:
        raise _err("investigation not found", 404)
    rec = _rec_of(row)
    if _kind_of(rec) != "investigation":
        raise _err("target is not a research investigation", 404)
    if row.researcher_id == reviewer_id:
        raise _err("a reviewer may not adjudicate their own investigation", 403)
    if not signing.verify(rec, row.signature, kid=row.signing_kid):
        raise _err("investigation signature does not verify", 409)
    parent_id = _parent_of(rec)
    if not parent_id:
        raise _err("investigation has no linked evidence", 409)
    prow = ParallaxResearchRun.query.filter_by(run_id=parent_id).first()
    if prow is None:
        raise _err("linked evidence not found", 409)
    prec = _rec_of(prow)
    if not signing.verify(prec, prow.signature, kid=prow.signing_kid):
        raise _err("linked evidence signature does not verify", 409)
    if prow.researcher_id != row.researcher_id:
        raise _err("linked evidence ownership mismatch", 409)
    campaign = {"manifest": {"kind": "adjudication", "backend": {"is_real": False, "model_id": "n/a",
                "runtime": "n/a", "backend": "n/a"}, "n_records": 0, "target": investigation_id,
                "parent_run": parent_id},
                "metrics": {"kind": "adjudication", "target": investigation_id, "decision": decision,
                "reviewer_id": reviewer_id, "comment": str(comment or "")[:4000]}}
    return persist_run(db, researcher_id=reviewer_id, campaign=campaign)
