"""F2 - the common, versioned, typed evidence contract (both pathways).

One evidence architecture serves STRATA and PARALLAX. An evidence artifact is a signed
metadata ENVELOPE; large or binary payloads (media, model traces, manifests) are never
stored inline in Postgres/OpenSearch - they are referenced by a content-addressed BlobRef
(the object store itself is NOT provisioned here; only the interface + validation). The
contract reuses Ed25519 signing and binds every artifact to its Case, owner, cohort and
pathway so authorization and lineage travel with the evidence.

Security posture (validate_artifact):
  - content-type verification against a per-category allowlist (unsafe formats rejected);
  - size limits per category; path-traversal-safe BlobRef uris only;
  - tamper check (BlobRef hash must equal the envelope content_hash);
  - derived-artifact lineage (a derived artifact must name its parents);
  - immutability by version (revisions create a new version referencing the prior; a signed
    artifact cannot be mutated without breaking its signature);
  - access revocation + retention enforced at authorize_access.

Authenticity is never inferred unsafely: a MISSING C2PA / provenance manifest does NOT make
media "manipulated" (validation stays unvalidated/needs-review), and a model-generated
authenticity score is advisory only - it never sets an authoritative validation_state.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import re

import signing
import pathways

EVIDENCE_CONTRACT_VERSION = 1
EVIDENCE_SCHEMA_VERSION = 1
SUPPORTED_CONTRACT_VERSIONS = {1}
SUPPORTED_SCHEMA_VERSIONS = {1}

# --- evidence categories -----------------------------------------------------
EV_OPENSEARCH_EVENT = "opensearch_event"
EV_OPENSEARCH_FINDING = "opensearch_finding"
EV_MEDIA_AUDIO = "media_audio"
EV_MEDIA_VIDEO = "media_video"
EV_MEDIA_IMAGE = "media_image"
EV_FORENSIC_METADATA = "forensic_metadata"
EV_PROVENANCE_MANIFEST = "provenance_manifest"
EV_MODEL_TRACE = "model_trace"
EV_AGENT_TRACE = "agent_trace"
EV_TOOL_AUTHORIZATION = "tool_authorization"
EV_API_EXECUTION = "api_execution"
EV_CONFIG_SYSTEM_STATE = "config_system_state"
EV_TECHNICAL_REPORT = "technical_report"
EV_DERIVED_ARTIFACT = "derived_artifact"

MB = 1024 * 1024
# per-category: needs a BlobRef (large/binary)?, allowed media types, max bytes
EVIDENCE_TYPES = {
    EV_OPENSEARCH_EVENT:    {"blob": False, "media": None, "max_bytes": None},
    EV_OPENSEARCH_FINDING:  {"blob": False, "media": None, "max_bytes": None},
    EV_MEDIA_AUDIO:         {"blob": True, "media": {"audio/wav", "audio/x-wav", "audio/mpeg",
                                                     "audio/mp4", "audio/flac", "audio/ogg"},
                             "max_bytes": 200 * MB},
    EV_MEDIA_VIDEO:         {"blob": True, "media": {"video/mp4", "video/quicktime",
                                                     "video/webm", "video/x-matroska"},
                             "max_bytes": 1024 * MB},
    EV_MEDIA_IMAGE:         {"blob": True, "media": {"image/jpeg", "image/png", "image/tiff",
                                                     "image/webp", "image/heic"},
                             "max_bytes": 100 * MB},
    EV_FORENSIC_METADATA:   {"blob": False, "media": None, "max_bytes": None},
    EV_PROVENANCE_MANIFEST: {"blob": True, "media": {"application/json", "application/c2pa",
                                                     "application/octet-stream"},
                             "max_bytes": 25 * MB},
    EV_MODEL_TRACE:         {"blob": False, "media": None, "max_bytes": 25 * MB},
    EV_AGENT_TRACE:         {"blob": False, "media": None, "max_bytes": 25 * MB},
    EV_TOOL_AUTHORIZATION:  {"blob": False, "media": None, "max_bytes": None},
    EV_API_EXECUTION:       {"blob": False, "media": None, "max_bytes": None},
    EV_CONFIG_SYSTEM_STATE: {"blob": False, "media": None, "max_bytes": 25 * MB},
    EV_TECHNICAL_REPORT:    {"blob": True, "media": {"application/pdf", "text/markdown",
                                                     "text/plain"}, "max_bytes": 50 * MB},
    EV_DERIVED_ARTIFACT:    {"blob": True, "media": None, "max_bytes": 1024 * MB},
}

VALIDATION_STATES = ("unvalidated", "needs_review", "validated", "invalid", "revoked", "expired")

ENVELOPE_FIELDS = {
    "evidence_id", "evidence_type", "evidence_schema_version", "contract_version",
    "case_id", "candidate_id", "cohort", "pathway", "source_identity", "provenance",
    "content_hash", "acquisition_ts", "version", "validation_state", "parent_case",
    "derived_from", "supersedes", "blob_ref", "authenticity_assessment",
}

# A BlobRef uri must be a safe, content-addressed key - no traversal, no scheme, no abs path.
_SAFE_KEY = re.compile(r"^blob/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$")


def _now_iso():
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _err(code, msg, **kv):
    d = {"code": code, "message": msg}; d.update(kv); return d


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_hex64(s) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s.lower())


def blob_ref(uri, sha256, media_type, size_bytes, *, provenance=None, rights_consent=None,
             authenticity_assessment=None) -> dict:
    """Build a BlobRef - a reference to out-of-DB content (never the bytes themselves).
    authenticity_assessment, if given, is advisory and tagged as such."""
    ref = {"uri": uri, "sha256": sha256, "media_type": media_type, "bytes": size_bytes,
           "provenance": provenance or {}, "rights_consent": rights_consent or {}}
    if authenticity_assessment is not None:
        # advisory only: a model score, never authoritative ground truth
        ref["authenticity_assessment"] = {"advisory": True, "score": authenticity_assessment}
    return ref


def new_artifact(*, evidence_type, case_id, candidate_id, cohort, pathway, source_identity,
                 content=None, content_hash=None, blob=None, provenance=None,
                 derived_from=None, validation_state="unvalidated") -> dict:
    """Construct an evidence envelope (version 1). content_hash is derived from `content`
    bytes when given, else taken as provided (e.g. a BlobRef's sha256)."""
    if content is not None and content_hash is None:
        content_hash = _sha256_hex(content if isinstance(content, bytes) else str(content).encode())
    art = {
        "evidence_id": "ev-" + _sha256_hex(f"{case_id}|{candidate_id}|{evidence_type}|{_now_iso()}|"
                                           f"{content_hash}".encode())[:24],
        "evidence_type": evidence_type, "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
        "contract_version": EVIDENCE_CONTRACT_VERSION,
        "case_id": case_id, "candidate_id": candidate_id, "cohort": cohort,
        "pathway": pathways.normalize_pathway(pathway), "source_identity": source_identity,
        "provenance": provenance or {}, "content_hash": content_hash,
        "acquisition_ts": _now_iso(), "version": 1, "validation_state": validation_state,
        "parent_case": case_id, "derived_from": list(derived_from or []), "supersedes": None,
        "blob_ref": blob, "authenticity_assessment": None,
    }
    return art


def validate_artifact(artifact: dict, *, now=None) -> dict:
    """Full structural + security validation. Returns {ok, errors}. Never infers
    manipulation from a missing manifest or a model score."""
    errors = []
    if not isinstance(artifact, dict):
        return {"ok": False, "errors": [_err("BAD_ARTIFACT", "artifact must be an object")]}
    for k in artifact:
        if k not in ENVELOPE_FIELDS:
            errors.append(_err("UNKNOWN_FIELD", f"unknown field {k!r}", field=k))
    et = artifact.get("evidence_type")
    if et not in EVIDENCE_TYPES:
        return {"ok": False, "errors": [_err("UNSUPPORTED_EVIDENCE_TYPE", f"unknown type {et!r}")]}
    if artifact.get("contract_version") not in SUPPORTED_CONTRACT_VERSIONS:
        errors.append(_err("UNSUPPORTED_CONTRACT_VERSION",
                           f"contract_version {artifact.get('contract_version')!r} unsupported"))
    if artifact.get("evidence_schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append(_err("UNSUPPORTED_SCHEMA_VERSION",
                           f"schema_version {artifact.get('evidence_schema_version')!r} unsupported"))
    for req in ("evidence_id", "case_id", "candidate_id", "cohort", "pathway",
                "source_identity", "content_hash", "acquisition_ts"):
        if artifact.get(req) in (None, ""):
            errors.append(_err("MISSING_FIELD", f"{req} required", field=req))
    if not pathways.is_valid_pathway(artifact.get("pathway")):
        errors.append(_err("INVALID_PATHWAY", f"unknown pathway {artifact.get('pathway')!r}"))
    if not _is_hex64(artifact.get("content_hash")):
        errors.append(_err("BAD_CONTENT_HASH", "content_hash must be a sha256 hex digest"))
    if not isinstance(artifact.get("version"), int) or artifact.get("version", 0) < 1:
        errors.append(_err("BAD_VERSION", "version must be an int >= 1"))
    if artifact.get("validation_state") not in VALIDATION_STATES:
        errors.append(_err("BAD_VALIDATION_STATE", f"unknown state {artifact.get('validation_state')!r}"))
    if et == EV_DERIVED_ARTIFACT and not artifact.get("derived_from"):
        errors.append(_err("MISSING_LINEAGE", "a derived artifact must name its parent(s)"))

    spec = EVIDENCE_TYPES[et]
    blob = artifact.get("blob_ref")
    if spec["blob"]:
        if not isinstance(blob, dict):
            errors.append(_err("MISSING_BLOB_REF", f"{et} requires a BlobRef"))
        else:
            errors += _validate_blob(et, spec, blob, artifact.get("content_hash"))
    elif blob is not None:
        errors.append(_err("UNEXPECTED_BLOB_REF", f"{et} does not take a BlobRef"))

    # authenticity_assessment, if present, must be advisory (never authoritative)
    aa = artifact.get("authenticity_assessment")
    if aa is not None and not (isinstance(aa, dict) and aa.get("advisory") is True):
        errors.append(_err("NON_ADVISORY_AUTHENTICITY",
                           "authenticity_assessment must be advisory; it is never authoritative truth"))
    return {"ok": not errors, "errors": errors}


def _validate_blob(et, spec, blob, content_hash) -> list:
    errors = []
    uri = blob.get("uri")
    if not isinstance(uri, str) or not _SAFE_KEY.match(uri) or ".." in uri or "\\" in uri:
        errors.append(_err("UNSAFE_BLOB_URI",
                           "BlobRef uri must be a safe content-addressed key (no traversal/scheme/abs path)"))
    mt = blob.get("media_type")
    if spec["media"] is not None and mt not in spec["media"]:
        errors.append(_err("UNSUPPORTED_MEDIA_TYPE", f"media_type {mt!r} not allowed for {et}",
                           allowed=sorted(spec["media"])))
    size = blob.get("bytes")
    if not isinstance(size, int) or size < 0:
        errors.append(_err("BAD_BLOB_SIZE", "BlobRef bytes must be a non-negative int"))
    elif spec["max_bytes"] is not None and size > spec["max_bytes"]:
        errors.append(_err("BLOB_TOO_LARGE", f"{size} bytes exceeds {spec['max_bytes']} for {et}"))
    if not _is_hex64(blob.get("sha256")):
        errors.append(_err("BAD_BLOB_HASH", "BlobRef sha256 must be a sha256 hex digest"))
    elif content_hash and blob.get("sha256") != content_hash:
        # tamper / mismatch between the envelope hash and the referenced content hash
        errors.append(_err("HASH_MISMATCH", "BlobRef sha256 does not match envelope content_hash"))
    aa = blob.get("authenticity_assessment")
    if aa is not None and not (isinstance(aa, dict) and aa.get("advisory") is True):
        errors.append(_err("NON_ADVISORY_AUTHENTICITY", "blob authenticity_assessment must be advisory"))
    return errors


def interpret_provenance(artifact: dict) -> dict:
    """Safe reading of provenance/authenticity. A missing C2PA manifest is 'indeterminate',
    never 'manipulated'; a model score is reported as advisory only. Returns a dict the UI/
    evaluator may show but that NEVER sets an authoritative verdict here."""
    blob = artifact.get("blob_ref") or {}
    prov = blob.get("provenance") or artifact.get("provenance") or {}
    has_c2pa = bool(prov.get("c2pa") or prov.get("content_credentials"))
    aa = (blob.get("authenticity_assessment") or artifact.get("authenticity_assessment") or {})
    return {
        "provenance_present": has_c2pa,
        "provenance_verdict": "verified" if has_c2pa else "indeterminate",  # NOT 'manipulated'
        "model_authenticity_advisory": aa.get("score") if aa.get("advisory") else None,
        "authoritative": False,   # this function never yields ground truth
    }


# --- signing + immutability --------------------------------------------------
def artifact_hash(artifact: dict) -> str:
    return hashlib.sha256(signing.canonical(artifact)).hexdigest()


def sign_artifact(artifact: dict) -> dict:
    body = dict(artifact)
    body["artifact_hash"] = artifact_hash(artifact)
    return {"artifact": artifact, "artifact_hash": body["artifact_hash"],
            "signature": signing.sign(body)}


def verify_artifact(signed: dict) -> bool:
    art = signed.get("artifact", {})
    expect = artifact_hash(art)
    body = dict(art); body["artifact_hash"] = expect
    return signed.get("artifact_hash") == expect and signing.verify(body, signed.get("signature"))


def revise(prior: dict, changes: dict) -> dict:
    """Immutable revision: returns a NEW artifact (version+1) that supersedes `prior`; the
    prior is never mutated. Identity (evidence_id lineage) and case/owner are preserved."""
    nxt = dict(prior)
    nxt.update(changes)
    nxt["version"] = int(prior.get("version", 1)) + 1
    nxt["supersedes"] = prior.get("evidence_id")
    nxt["acquisition_ts"] = _now_iso()
    return nxt


def derive(parent: dict, *, evidence_type, blob=None, content=None, content_hash=None,
           source_identity="forensic-tool", provenance=None) -> dict:
    """Create a derived artifact (e.g. an extracted frame, ELA map, spectrogram) whose
    lineage names its parent. Inherits case/owner/cohort/pathway (authorization travels)."""
    art = new_artifact(evidence_type=evidence_type, case_id=parent["case_id"],
                       candidate_id=parent["candidate_id"], cohort=parent["cohort"],
                       pathway=parent["pathway"], source_identity=source_identity,
                       content=content, content_hash=content_hash, blob=blob,
                       provenance=provenance, derived_from=[parent["evidence_id"]])
    art["evidence_type"] = evidence_type
    return art


# --- authorization + retention -----------------------------------------------
def authorize_access(artifact: dict, *, requester: dict, now=None) -> tuple:
    """Return (allowed: bool, reason). Enforces ownership (same candidate), cohort and
    pathway isolation, revocation, and retention expiry. A reviewer/admin role may read
    within the same cohort+pathway. Never reveals another candidate's data."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    state = artifact.get("validation_state")
    if state == "revoked" or artifact.get("revoked"):
        return (False, "revoked")
    ret = artifact.get("retention_until")
    if ret:
        try:
            if _dt.datetime.fromisoformat(ret) < now:
                return (False, "expired")
        except Exception:
            return (False, "bad_retention")
    if pathways.normalize_pathway(requester.get("pathway")) != pathways.normalize_pathway(artifact.get("pathway")):
        return (False, "pathway_isolation")
    if requester.get("cohort") != artifact.get("cohort"):
        return (False, "cohort_isolation")
    role = requester.get("role")
    if role in ("reviewer", "admin"):
        return (True, "reviewer_scope")
    if requester.get("candidate_id") == artifact.get("candidate_id"):
        return (True, "owner")
    return (False, "not_owner")


# --- integration with the assessment contract --------------------------------
def satisfies_requirement(artifact: dict, requirement: dict, *, requester: dict) -> tuple:
    """True iff the artifact is of the required kind, validates, is 'validated', and the
    requester is authorized to use it. Used to connect typed evidence to an assessment
    blueprint's evidence_requirements. Returns (ok, reason)."""
    if artifact.get("evidence_type") != requirement.get("evidence_type") \
       and requirement.get("evidence_type") is not None:
        return (False, "type_mismatch")
    v = validate_artifact(artifact)
    if not v["ok"]:
        return (False, "invalid_artifact")
    if artifact.get("validation_state") != "validated":
        return (False, f"state_{artifact.get('validation_state')}")
    allowed, why = authorize_access(artifact, requester=requester)
    if not allowed:
        return (False, why)
    return (True, "ok")
