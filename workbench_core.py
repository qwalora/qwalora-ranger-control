"""F5 - Candidate Workbench core logic (server-side authorization and records).

This is the logic layer behind the pathway-aware Candidate Workbench. It REUSES the existing control
plane - Candidate, Cohort (pathway), Case, CaseSubmission, EvidenceArtifact, CustodyEvent,
ArtifactStore, AssessmentBlueprint and the assessment contract - and does NOT fork identity, case,
evidence or assessment systems. Every security decision is made here (server-side), never in the UI.

Guarantees enforced here:
  * a GitHub login is not admission: only Candidate.status == "active" may use the workbench;
  * pathway is derived from the candidate's cohort, never trusted from the client;
  * a candidate sees ONLY their own cases/evidence; an ownership mismatch is a 404, never a 403
    (so another candidate's resource is never even revealed to exist);
  * candidates cannot mark evidence validated, bypass scanning, or enter unsafe decoding workflows;
  * hidden scenario truth / expected answers / evaluator rules are never exposed by any view;
  * submission is not qualification; PARALLAX may be assessment-complete while qualification is
    inactive (parallax_qualification_active() == False), and that distinction is explicit;
  * reviewers are scoped to their authorized cohort(s)+pathway - no superuser bypass.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os

import signing
import pathways
from siem import evidence_persistence as ep
from siem import evidence_types as et
from siem import artifact_store as st
from siem import assessment_contract as ac


# --- feature flags (server-side; all OFF by default so production stays dark) ---------------
def _flag_on(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    return v.strip().lower() in ("1", "true", "yes", "on")


FLAG_WORKBENCH = "RANGER_WORKBENCH"                       # master visibility
FLAG_CASE_ACCESS = "RANGER_WORKBENCH_CASE_ACCESS"         # see assigned cases
FLAG_EVIDENCE_SUBMIT = "RANGER_WORKBENCH_EVIDENCE_SUBMIT"  # submit evidence
FLAG_FORENSIC_REQUESTS = "RANGER_WORKBENCH_FORENSIC_REQUESTS"  # request forensic processing
FLAG_ASSESSMENT_VISIBILITY = "RANGER_WORKBENCH_ASSESSMENT_VISIBILITY"  # show assessment status
FLAG_PARALLAX_QUAL = "RANGER_PARALLAX_QUALIFICATION_ACTIVE"  # reused; qualification activation


def workbench_enabled():
    return _flag_on(FLAG_WORKBENCH)


def flags_snapshot():
    return {
        "workbench": _flag_on(FLAG_WORKBENCH),
        "case_access": _flag_on(FLAG_CASE_ACCESS),
        "evidence_submit": _flag_on(FLAG_EVIDENCE_SUBMIT),
        "forensic_requests": _flag_on(FLAG_FORENSIC_REQUESTS),
        "assessment_visibility": _flag_on(FLAG_ASSESSMENT_VISIBILITY),
        "parallax_qualification_active": ac.parallax_qualification_active(),
    }


class WorkbenchError(Exception):
    def __init__(self, code, http, message):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.http = http
        self.message = message


def _iso(ts=None):
    return (ts or _dt.datetime.now(_dt.timezone.utc)).isoformat()


# --- evidence object store ------------------------------------------------------------------
def evidence_store():
    path = os.environ.get("RANGER_EVIDENCE_DIR") or os.path.join("instance", "evidence")
    os.makedirs(path, exist_ok=True)
    return st.FilesystemArtifactStore(path)


# --- pathway resolution (from the candidate's cohort; never from the client) ----------------
def resolve_pathway(db, candidate):
    from models import Cohort
    co = Cohort.query.filter_by(name=candidate.cohort).first() if candidate.cohort else None
    return pathways.normalize_pathway(co.pathway if co and co.pathway else pathways.DEFAULT_PATHWAY)


# evidence categories a candidate may submit (all are typed, blob-backed F2 types)
PERMITTED_EVIDENCE = {
    pathways.PATHWAY_STRATA: (et.EV_TECHNICAL_REPORT, et.EV_MEDIA_IMAGE),
    pathways.PATHWAY_PARALLAX: (et.EV_AGENT_TRACE, et.EV_MODEL_TRACE, et.EV_MEDIA_IMAGE,
                                et.EV_MEDIA_VIDEO, et.EV_MEDIA_AUDIO, et.EV_PROVENANCE_MANIFEST,
                                et.EV_TECHNICAL_REPORT),
}


def permitted_evidence_types(pathway):
    return PERMITTED_EVIDENCE.get(pathways.normalize_pathway(pathway), (et.EV_TECHNICAL_REPORT,))


# --- candidate case access ------------------------------------------------------------------
def list_cases(db, candidate):
    from models import Case
    return Case.query.filter_by(candidate_id=candidate.id).order_by(Case.id).all()


def own_case(db, candidate, case_id):
    """Fetch a case ONLY if it belongs to this candidate; otherwise raise 404 (never reveal it)."""
    from models import Case
    case = Case.query.filter_by(id=case_id).first()
    if case is None or case.candidate_id != candidate.id:
        raise WorkbenchError("CASE_NOT_FOUND", 404, "no such case")
    return case


def case_meta(case):
    """APPROVED, candidate-safe scenario metadata for THIS case (by scenario_ref + version), or
    None when no approved instructions are assigned. Never contains truth."""
    import workbench_scenarios as sc
    return sc.get(getattr(case, "scenario_ref", None), case.scenario_version)


def case_scope_view(case, pathway):
    """A truth-safe projection of a case using its APPROVED per-case scenario metadata. When no
    approved instructions are assigned, returns an accurate 'not available' state rather than
    generic content. Hidden scenarios, answers, exploits, cohort variants and evaluator rules are
    never included."""
    meta = case_meta(case)
    base = {
        "case_id": case.id, "scenario_version": case.scenario_version,
        "scenario_ref": getattr(case, "scenario_ref", None),
        "rubric_version": case.rubric_version, "pathway": pathway, "plane": case.plane,
        "workflow": case.workflow, "status": case.status,
        "assigned_at": _s(case.assigned_at), "started_at": _s(case.started_at),
        "submitted_at": _s(case.submitted_at),
        "instructions_available": meta is not None,
    }
    if meta is None:
        base.update({
            "title": None,
            "authorized_scope": None, "technical_objectives": [], "permitted_operations": [],
            "environment_interfaces": [], "evidence_requirements": [],
            "submission_conditions": None, "assessment_boundaries": None,
            "unavailable_reason": "Approved case instructions have not been assigned for this case."})
        return base
    base.update({
        "title": meta.get("title"),
        "authorized_scope": meta.get("authorized_scope"),
        "technical_objectives": meta.get("technical_objectives", []),
        "permitted_operations": meta.get("permitted_operations", []),
        "environment_interfaces": meta.get("environment_interfaces", []),
        "evidence_requirements": meta.get("evidence_requirements", []),
        "submission_conditions": meta.get("submission_conditions"),
        "assessment_boundaries": meta.get("assessment_boundaries"),
    })
    return base


def _case_required_kinds(case):
    meta = case_meta(case)
    if not meta:
        return set()
    return {r["kind"] for r in meta.get("evidence_requirements", []) if r.get("required")}


# --- candidate write authorization (shared by draft/evidence/submit) -------------------------
UNAVAILABLE_CASE_STATES = ("closed", "withdrawn", "expired", "revoked", "canceled")
FINALIZED_CASE_STATES = ("submitted", "under_review", "evaluated")


def remediation_allowed():
    return _flag_on("RANGER_WORKBENCH_REMEDIATION")


def _require_write_flags(action):
    if not _flag_on(FLAG_WORKBENCH):
        raise WorkbenchError("WORKBENCH_DISABLED", 404, "not found")
    if not _flag_on(FLAG_CASE_ACCESS):
        raise WorkbenchError("CASE_ACCESS_DISABLED", 404, "not found")
    if action == "evidence" and not _flag_on(FLAG_EVIDENCE_SUBMIT):
        raise WorkbenchError("EVIDENCE_SUBMIT_DISABLED", 404, "not found")


def authorize_case_write(db, candidate, case_id, *, action):
    """Single server-side gate for every candidate WRITE (draft/evidence/submit). Enforces flags,
    admission, ownership, cohort+pathway match, case lifecycle validity, and finalization rules.
    Every unauthorized/unavailable resource returns a NON-DISCLOSING 404. Returns (case, pathway)."""
    _require_write_flags(action)
    if candidate is None or candidate.status != "active":
        raise WorkbenchError("NOT_ADMITTED", 403, "not admitted")
    case = own_case(db, candidate, case_id)                 # 404 if not owner / not found
    pathway = resolve_pathway(db, candidate)
    # cohort + pathway assignment must match (never serve a case from another cohort/pathway)
    if (case.cohort or "") != (candidate.cohort or ""):
        raise WorkbenchError("CASE_NOT_FOUND", 404, "no such case")
    if pathways.normalize_pathway(case.cohort and _cohort_pathway_name(db, case.cohort)) != pathway:
        raise WorkbenchError("CASE_NOT_FOUND", 404, "no such case")
    if case.status in UNAVAILABLE_CASE_STATES:
        raise WorkbenchError("CASE_UNAVAILABLE", 404, "no such case")
    if case.status in FINALIZED_CASE_STATES and not remediation_allowed():
        raise WorkbenchError("CASE_FINALIZED", 409, "this investigation is already final")
    return case, pathway


def _cohort_pathway_name(db, cohort_name):
    from models import Cohort
    co = Cohort.query.filter_by(name=cohort_name).first() if cohort_name else None
    return pathways.normalize_pathway(co.pathway if co and co.pathway else pathways.DEFAULT_PATHWAY)


# --- evidence submission (reuses F2/F3/F4; candidate can never self-validate) -----------------
def submit_evidence(db, store, case, candidate, pathway, fileobj, *, evidence_type,
                    declared_media_type=None, source_identity="candidate-upload"):
    if not _flag_on(FLAG_EVIDENCE_SUBMIT):
        raise WorkbenchError("EVIDENCE_SUBMIT_DISABLED", 404, "evidence submission is not enabled")
    allowed = permitted_evidence_types(pathway)
    if evidence_type not in allowed:
        raise WorkbenchError("EVIDENCE_TYPE_NOT_PERMITTED", 400,
                             f"{evidence_type} is not permitted for this pathway")
    try:
        acq = ep.acquire(store, fileobj, evidence_type=evidence_type, case_id=case.id,
                         candidate_id=candidate.id, cohort=candidate.cohort, pathway=pathway,
                         source_identity=source_identity, declared_media_type=declared_media_type,
                         retention_class="active_assessment")
    except ep.AcquisitionError as e:
        # malformed / oversized / unsupported media -> safe, explicit failure; nothing persisted
        raise WorkbenchError(e.code, 400, e.message)
    art = acq["artifact"]
    # candidate-submitted evidence is ALWAYS needs_review + unscanned; a candidate cannot promote it
    art["validation_state"] = "needs_review"
    key = art.get("object_key")
    newly_created = bool((acq.get("put") or {}).get("created"))
    try:
        # join the F4 per-object locking protocol across the reference insert (dedup-safe; blocks a
        # concurrent sweep/delete), then persist EvidenceArtifact + CustodyEvent + BlobReference
        # atomically in one transaction.
        from siem import forensic_jobs_db as fjdb
        if key:
            fjdb._xact_lock_text(db, key)
        _persist_artifact(db, art, backend="filesystem")
        _persist_custody(db, acq["custody"])
        _persist_blobref(db, art)
        db.session.commit()
    except Exception as e:  # noqa
        # reference-safe rollback: drop the pending rows; delete the object ONLY if this upload
        # newly created it AND no committed reference remains (a dedup hit onto another artifact's
        # bytes is never deleted). Shared evidence is always preserved.
        db.session.rollback()
        if newly_created and key:
            _safe_sweep(db, store, key)
        raise WorkbenchError("EVIDENCE_PERSIST_FAILED", 500, f"{type(e).__name__}: {e}")
    return art


def _safe_sweep(db, store, object_key):
    from siem import forensic_jobs_db as fjdb
    try:
        fjdb.SqlBlobLifecycle(db, store).sweep_object(object_key, reason="upload_rollback")
    except Exception:
        db.session.rollback()


def candidate_evidence(db, candidate, case_id=None):
    from models import EvidenceArtifact
    q = EvidenceArtifact.query.filter_by(candidate_id=candidate.id)
    if case_id is not None:
        q = q.filter_by(case_id=case_id)
    return q.order_by(EvidenceArtifact.id).all()


def candidate_evidence_by_case(db, candidate_id, case_id):
    from models import EvidenceArtifact
    return EvidenceArtifact.query.filter_by(candidate_id=candidate_id, case_id=case_id).order_by(
        EvidenceArtifact.id).all()


def retrieve_evidence(db, store, candidate, pathway, evidence_id):
    """Access-controlled download: authorize by ownership+cohort+pathway, verify integrity, stream."""
    from models import EvidenceArtifact
    row = EvidenceArtifact.query.filter_by(evidence_id=evidence_id).first()
    if row is None or row.candidate_id != candidate.id:
        raise WorkbenchError("EVIDENCE_NOT_FOUND", 404, "no such evidence")
    artifact = _artifact_dict(row)
    requester = {"candidate_id": candidate.id, "cohort": candidate.cohort, "pathway": pathway,
                 "role": "candidate"}
    res = ep.retrieve(store, artifact, requester=requester)
    if not res["ok"]:
        raise WorkbenchError("EVIDENCE_ACCESS_DENIED", 403, res["reason"])
    return row, res["bytes"]


# --- draft + final submission (reuses CaseSubmission; signed receipt) ------------------------
def _submission(db, case, candidate):
    from models import CaseSubmission
    sub = CaseSubmission.query.filter_by(case_id=case.id, candidate_id=candidate.id).order_by(
        CaseSubmission.id.desc()).first()
    return sub


def save_draft(db, case, candidate, payload):
    from models import CaseSubmission
    sub = _submission(db, case, candidate)
    if sub and sub.submission_status not in ("draft",):
        raise WorkbenchError("SUBMISSION_LOCKED", 409, "submission is already final")
    if sub is None:
        sub = CaseSubmission(case_id=case.id, candidate_id=candidate.id, attempt=case.attempt,
                             submission_status="draft")
        db.session.add(sub)
    sub.payload = json.dumps(_sanitize_payload(payload))
    if case.status == "assigned":
        case.status = "investigating"
        case.started_at = _dt.datetime.now(_dt.timezone.utc)
    db.session.commit()
    return sub


WB_RECEIPT_CONTRACT_VERSION = 2   # v2 binds evidence content hashes + full payload hash


def _evidence_binding(db, refs):
    """Immutable binding for each referenced evidence: id -> {content_hash, version, type}.
    A substituted artifact, altered content hash, or version change breaks the receipt."""
    from models import EvidenceArtifact
    out = {}
    rows = EvidenceArtifact.query.filter(EvidenceArtifact.evidence_id.in_(refs or [""])).all()
    by_id = {e.evidence_id: e for e in rows}
    for r in sorted(refs):
        e = by_id.get(r)
        if e is None:
            continue
        out[r] = {"content_hash": e.content_hash, "version": e.version, "type": e.evidence_type}
    return out


def _payload_core(payload):
    """The candidate-authored content the receipt binds, excluding volatile metadata
    (submission_version), so the bound hash is stable across the version bump at finalize."""
    p = _sanitize_payload(payload)
    p.pop("submission_version", None)
    return p


def _build_receipt(db, case, candidate, pathway, sub, payload, refs):
    findings = payload.get("findings") or []
    binding = _evidence_binding(db, refs)
    version = int(payload.get("submission_version", 0)) + 1
    record = {
        "type": "workbench_submission_receipt",
        "contract_version": WB_RECEIPT_CONTRACT_VERSION,
        "case_id": case.id, "candidate_id": candidate.id, "cohort": candidate.cohort,
        "pathway": pathway, "attempt": sub.attempt, "submission_version": version,
        "scenario_ref": getattr(case, "scenario_ref", None),
        "scenario_version": case.scenario_version,
        # bind the FULL submitted payload (minus volatile metadata) and the findings specifically
        "payload_hash": hashlib.sha256(signing.canonical(_payload_core(payload))).hexdigest(),
        "findings_hash": hashlib.sha256(signing.canonical(findings)).hexdigest(),
        "findings_count": len(findings),
        "evidence_refs": sorted(refs),
        # bind each referenced evidence's immutable content hash + version (substitution-proof)
        "evidence_binding": binding,
        "submitted_ts": _iso(),
    }
    record["receipt_hash"] = hashlib.sha256(signing.canonical(record)).hexdigest()
    return record, signing.sign(record), version


def finalize_submission(db, store, case, candidate, pathway):
    """Validate references + required fields, then produce an IMMUTABLE signed submission receipt
    bound to the submitted payload AND to each referenced evidence's content hash + version. The
    receipt lives in its OWN columns (wb_receipt*), never STRATA's evidence_record/evidence_sig.
    Duplicate final submission -> 409."""
    from models import EvidenceArtifact
    sub = _submission(db, case, candidate)
    if sub is None:
        raise WorkbenchError("NO_DRAFT", 400, "there is no draft to submit")
    if sub.submission_status != "draft":
        raise WorkbenchError("ALREADY_SUBMITTED", 409, "this investigation was already submitted")
    payload = json.loads(sub.payload or "{}")
    findings = payload.get("findings") or []
    refs = payload.get("evidence_refs") or []
    if not findings:
        raise WorkbenchError("MISSING_FINDINGS", 400, "at least one technical finding is required")
    # every referenced evidence must belong to THIS candidate AND THIS case (no forged refs)
    owned = {e.evidence_id for e in EvidenceArtifact.query.filter_by(
        candidate_id=candidate.id, case_id=case.id).all()}
    bad = [r for r in refs if r not in owned]
    if bad:
        raise WorkbenchError("INVALID_EVIDENCE_REFS", 400,
                             f"evidence references not owned by this case: {bad[:5]}")
    # required evidence comes from the APPROVED per-case scenario metadata (not generic pathway)
    req_kinds = _case_required_kinds(case)
    have_kinds = {e.evidence_type for e in EvidenceArtifact.query.filter(
        EvidenceArtifact.evidence_id.in_(refs or [""])).all()}
    missing = [k for k in req_kinds if k != et.EV_TECHNICAL_REPORT and k not in have_kinds]
    if missing:
        raise WorkbenchError("MISSING_REQUIRED_EVIDENCE", 400,
                             f"required evidence not attached: {missing}")

    record, sig, version = _build_receipt(db, case, candidate, pathway, sub, payload, refs)
    payload["submission_version"] = version
    ts = record["submitted_ts"]

    # ATOMIC, concurrency-safe transition: only the first caller flips draft -> submitted. The
    # receipt is written to its OWN columns; STRATA's evidence_record/evidence_sig are NOT touched.
    from sqlalchemy import text
    res = db.session.execute(text(
        "UPDATE case_submissions SET submission_status='submitted', submitted_at=:ts, payload=:p, "
        "wb_receipt=:wr, wb_receipt_sig=:ws, wb_receipt_version=:wv "
        "WHERE id=:id AND submission_status='draft'"),
        {"ts": ts, "p": json.dumps(payload), "wr": json.dumps(record), "ws": sig,
         "wv": WB_RECEIPT_CONTRACT_VERSION, "id": sub.id})
    if res.rowcount != 1:
        db.session.rollback()
        raise WorkbenchError("ALREADY_SUBMITTED", 409, "this investigation was already submitted")
    db.session.execute(text("UPDATE cases SET status='submitted', submitted_at=:ts WHERE id=:id"),
                       {"ts": ts, "id": case.id})
    db.session.commit()
    sub = _submission(db, case, candidate)
    return sub, {"record": record, "signature": sig}


def submission_readiness(db, case, candidate, payload, evidence_vms):
    """A truthful checklist of what is / isn't ready for final submission (no fabricated status)."""
    findings = payload.get("findings") or []
    refs = set(payload.get("evidence_refs") or [])
    req = _case_required_kinds(case)
    have_types = {e["evidence_type"] for e in evidence_vms if e["evidence_id"] in refs}
    missing = [k for k in req if k != et.EV_TECHNICAL_REPORT and k not in have_types]
    items = [
        {"label": "At least one technical finding recorded", "ok": bool(findings)},
        {"label": "Required evidence attached to the package", "ok": not missing},
        {"label": "Evidence references selected", "ok": bool(refs)},
    ]
    return {"checks": items, "ready": all(i["ok"] for i in items), "missing_evidence": missing}


def verify_receipt(sub, db=None):
    """Integrity verification (NOT correctness). A receipt verifies only if its signature is valid,
    its self-hash matches, AND it still binds the CURRENT submitted payload and the CURRENT evidence
    content hashes/versions. Modified findings, substituted or altered evidence, or changed metadata
    all break verification. `db` is optional; when given, the live evidence binding is re-checked."""
    if not sub or not sub.wb_receipt or not sub.wb_receipt_sig:
        return False
    try:
        record = json.loads(sub.wb_receipt)
    except Exception:
        return False
    # 1. self-hash + signature
    expect = hashlib.sha256(signing.canonical(
        {k: record.get(k) for k in record if k != "receipt_hash"})).hexdigest()
    if record.get("receipt_hash") != expect:
        return False
    if not signing.verify(record, sub.wb_receipt_sig):
        return False
    # 2. still bound to the CURRENT submitted payload (tampered findings/payload -> fail)
    try:
        payload = json.loads(sub.payload or "{}")
    except Exception:
        return False
    if record.get("payload_hash") != hashlib.sha256(
            signing.canonical(_payload_core(payload))).hexdigest():
        return False
    if record.get("findings_hash") != hashlib.sha256(
            signing.canonical(payload.get("findings") or [])).hexdigest():
        return False
    # 3. identity binding
    if record.get("case_id") != sub.case_id or record.get("candidate_id") != sub.candidate_id:
        return False
    # 4. evidence binding still matches live content hashes + versions (substitution/alteration -> fail)
    if db is not None:
        live = _evidence_binding(db, record.get("evidence_refs") or [])
        if live != (record.get("evidence_binding") or {}):
            return False
    return True


# --- assessment status (policy-authorized; never leaks truth) -------------------------------
def assessment_status_view(case, sub, pathway):
    """Only states the assessment policy authorizes a candidate to see. Never an invented result,
    never protected truth. For PARALLAX, an assessment may be complete while qualification is
    inactive - stated explicitly."""
    if not _flag_on(FLAG_ASSESSMENT_VISIBILITY):
        return {"state": "assessment_status_hidden",
                "detail": "assessment status display is not enabled for this environment"}
    status = sub.submission_status if sub else None
    state = {
        None: "not_started", "draft": "in_progress", "submitted": "submitted",
        "under_review": "under_technical_verification", "evaluated": "assessment_completed",
        "closed": "final_outcome_available",
    }.get(status, "in_progress")
    out = {"state": state, "submission_status": status}
    if pathways.normalize_pathway(pathway) == pathways.PATHWAY_PARALLAX:
        out["qualification_active"] = ac.parallax_qualification_active()
        out["note"] = ("PARALLAX assessment can be technically complete while final qualification "
                       "remains inactive. No qualification is conferred.")
        out["qualified"] = False  # never true while qualification is inactive
    return out


# --- reviewer scope (no superuser bypass; scoped to authorized cohorts) ---------------------
def reviewer_scope(login):
    """Server-side reviewer authorization: {login: {"cohorts": [...], "pathway": "..."}} from
    RANGER_WB_REVIEWERS. A reviewer with no entry has NO workbench review access (safe default)."""
    try:
        table = json.loads(os.environ.get("RANGER_WB_REVIEWERS", "{}"))
    except Exception:
        table = {}
    entry = table.get(login or "")
    if not entry:
        return None
    return {"cohorts": set(entry.get("cohorts") or []),
            "pathway": pathways.normalize_pathway(entry.get("pathway")) if entry.get("pathway") else None}


def reviewer_can_see(scope, *, cohort, pathway):
    if not scope:
        return False
    if cohort not in scope["cohorts"]:
        return False
    if scope["pathway"] is not None and pathways.normalize_pathway(pathway) != scope["pathway"]:
        return False
    return True


# --- persistence helpers (map evidence dicts <-> rows) --------------------------------------
def _persist_artifact(db, art, *, backend):
    from models import EvidenceArtifact
    db.session.add(EvidenceArtifact(
        evidence_id=art["evidence_id"], evidence_type=art["evidence_type"],
        evidence_schema_version=art.get("evidence_schema_version", 1),
        contract_version=art.get("contract_version", 1), case_id=art.get("case_id"),
        candidate_id=art["candidate_id"], cohort=art["cohort"], pathway=art["pathway"],
        source_identity=art.get("source_identity"), content_hash=art["content_hash"],
        acquisition_ts=art.get("acquisition_ts"), version=art.get("version", 1),
        validation_state=art.get("validation_state", "needs_review"),
        blob_uri=(art.get("blob_ref") or {}).get("uri"), blob_sha256=art["content_hash"],
        blob_media_type=(art.get("blob_ref") or {}).get("media_type"),
        blob_bytes=(art.get("blob_ref") or {}).get("bytes"), object_key=art.get("object_key"),
        storage_backend=backend, scan_state=art.get("scan_state", "unscanned"),
        retention_class=art.get("retention_class", "default"),
        derived_from=json.dumps(art.get("derived_from") or []), supersedes=art.get("supersedes")))


def _persist_custody(db, signed):
    from models import CustodyEvent
    db.session.add(CustodyEvent(**ep.custody_row(signed)))


def _persist_blobref(db, art):
    """Register the F4 reference-counted BlobReference for an uploaded artifact (dedup-safe; one
    reference per (object_key, evidence_id)). Keeps cross-candidate/cross-cohort isolation."""
    from models import BlobReference
    key = art.get("object_key")
    if not key:
        return
    if BlobReference.query.filter_by(object_key=key, evidence_id=art["evidence_id"]).first():
        return
    db.session.add(BlobReference(object_key=key, evidence_id=art["evidence_id"],
                                 candidate_id=art.get("candidate_id"), cohort=art.get("cohort"),
                                 pathway=art.get("pathway"), active=True))


def _artifact_dict(row):
    return {"evidence_id": row.evidence_id, "evidence_type": row.evidence_type,
            "case_id": row.case_id, "candidate_id": row.candidate_id, "cohort": row.cohort,
            "pathway": row.pathway, "content_hash": row.content_hash,
            "validation_state": row.validation_state, "scan_state": row.scan_state,
            "object_key": row.object_key, "revoked": row.revoked,
            "retention_class": row.retention_class, "retention_until": row.retention_until,
            "blob_ref": {"uri": row.blob_uri, "sha256": row.blob_sha256,
                         "media_type": row.blob_media_type, "bytes": row.blob_bytes}}


def _sanitize_payload(payload):
    """Keep only candidate-authored fields; never store anything that could carry protected truth
    injected by the client beyond the candidate's own notes/findings."""
    findings = []
    for f in (payload.get("findings") or [])[:50]:
        if not isinstance(f, dict):
            continue
        findings.append({k: _bounded(f.get(k)) for k in
                         ("claim", "scope", "evidence_refs", "methodology", "observed_outcome",
                          "significance", "remediation", "limitations")})
    return {"findings": findings,
            "notes": [_bounded(n) for n in (payload.get("notes") or [])[:100]],
            "evidence_refs": [str(r)[:80] for r in (payload.get("evidence_refs") or [])[:100]],
            "approach": _bounded(payload.get("approach")),
            "submission_version": int(payload.get("submission_version", 0) or 0)}


def _bounded(v, n=8000):
    if v is None:
        return None
    if isinstance(v, list):
        return [str(x)[:800] for x in v[:50]]
    return str(v)[:n]


def _s(ts):
    try:
        return ts.isoformat() if ts else None
    except Exception:
        return None
