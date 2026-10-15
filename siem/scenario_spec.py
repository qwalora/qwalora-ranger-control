"""M4.3.1 - the versioned, extensible ScenarioSpec.

A ScenarioSpec is a DECLARATIVE description of a scenario, authored identically by a
human or (later) by the AI Scenario Architect. It is data, never executable: a
proposal cannot inject commands or privileged configuration by presenting them as
fields (see _reject_privileged).

Ranger is a two-track platform (cybersecurity, AI). To support future AI-security
specializations (deepfake forensics, LLM/agent security, etc.) WITHOUT a second
qualification platform or a rebuild, the spec is a common ENVELOPE plus a TYPED
PAYLOAD selected by `spec_type`. The envelope (track, specialization,
environment_type, spec_type, version, difficulty, provenance, evidence_kinds) is
stable; each `spec_type` registers its own payload validator. Today only the SOC
investigation payload (`soc-investigation`) is implemented; the registry is the seam
for the rest.

Three authorization layers are separated at the schema level so protected material
never leaks into candidate-facing contexts:
  - candidate_visible: brief/business context the candidate may see
  - admin: configuration (families, targets, capability refs, calibration)
  - evaluator_only: protected truth reference, answer-key hints (NEVER candidate-facing)
"""
from __future__ import annotations

import hashlib

import signing  # canonical JSON for content hashing
import pathways  # stable pathway ids + legacy normalization (strata/parallax)
from . import capability_inventory as capinv

SCENARIO_SPEC_VERSION = 1

# Envelope fields (common to every pathway/spec_type).
#   pathway: strata (STRATA, existing six-board SOC program) | parallax (PARALLAX,
#            digital-forensics & AI-security). Stable internal ids only (see root
#            `pathways`); legacy 'cyber-ops'/'cyber-ai' are normalized, never emitted.
#   specialization: optional sub-area (e.g. deepfake-forensics) for parallax
#   curriculum_version: the versioned assessment blueprint this spec belongs to
ENVELOPE_KEYS = {
    "spec_id", "spec_version", "pathway", "specialization", "curriculum_version",
    "environment_type", "spec_type", "board_compat", "difficulty_profile",
    "enterprise_version", "required_capabilities", "evidence_kinds", "provenance",
    "payload",
}
# Payload layer keys (inside `payload`), separated by authorization.
LAYER_KEYS = {"candidate_visible", "admin", "evaluator_only"}

# Keys that must NEVER appear anywhere in a spec: a declarative spec cannot carry
# executable or privileged configuration. Presence => hard rejection.
PRIVILEGED_DENYLIST = {
    "command", "cmd", "exec", "shell", "script", "run", "credential", "credentials",
    "password", "secret", "token", "private_key", "signing_key", "index_settings",
    "cluster_settings", "role_mapping", "sql", "eval", "__proto__",
}

# Evidence-artifact kinds (polymorphic, provenance-preserving). SOC uses event
# references today; media_asset is DECLARED for future AI/deepfake tracks and is not
# implemented. Large binaries are never stored in Postgres/OpenSearch: a media_asset
# is a content-addressed BlobRef into object storage (see BLOB_REF_CONTRACT).
EVIDENCE_KIND_EVENT_REFERENCE = "event_reference"   # {event_uid, index, query, role} - case_contract (implemented)
EVIDENCE_KIND_MEDIA_ASSET = "media_asset"           # future: BlobRef + provenance + consent (deepfake forensics)
EVIDENCE_KIND_FILE_HASH = "file_hash"               # future: sha256 + provenance
EVIDENCE_KIND_MODEL_TRACE = "model_trace"           # future: LLM/agent trace (parallax)
EVIDENCE_KIND_DOCUMENT = "document"                 # future: document artifact + hash
EVIDENCE_KIND_SYSTEM_STATE = "system_state"         # future: verified system-state capture
KNOWN_EVIDENCE_KINDS = (EVIDENCE_KIND_EVENT_REFERENCE, EVIDENCE_KIND_MEDIA_ASSET,
                        EVIDENCE_KIND_FILE_HASH, EVIDENCE_KIND_MODEL_TRACE,
                        EVIDENCE_KIND_DOCUMENT, EVIDENCE_KIND_SYSTEM_STATE)
IMPLEMENTED_EVIDENCE_KINDS = (EVIDENCE_KIND_EVENT_REFERENCE,)

# Contract (declared, not implemented) for out-of-DB media/binary evidence so large
# payloads never land in Postgres or OpenSearch:
BLOB_REF_CONTRACT = {
    "fields": ["uri", "sha256", "media_type", "bytes", "provenance", "rights_consent",
               "authenticity_assessment"],
    "storage": "content-addressed object storage (e.g. a bucket); only the ref + hash in DB",
    "privacy": "biometric/privacy-sensitive; requires rights+consent; access-controlled",
    "integrity": "sha256 content hash; provenance chain preserved",
    "authenticity": "model-generated authenticity assessment is marked distinct from "
                    "independently-verified provenance; never conflated",
}

# payload-validator registry: spec_type -> callable(payload, inv) -> list[error]
_PAYLOAD_VALIDATORS = {}


def register_payload_validator(spec_type: str, fn):
    _PAYLOAD_VALIDATORS[spec_type] = fn


def _err(code, path, msg):
    return {"code": code, "path": path, "message": msg}


def _walk_keys(obj, path=""):
    """Yield every dict key anywhere in the structure, with its path."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield path + "." + str(k) if path else str(k), k
            yield from _walk_keys(v, (path + "." + str(k)) if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_keys(v, f"{path}[{i}]")


def _reject_privileged(spec) -> list:
    """A spec is declarative data. Any key resembling an executable/privileged
    directive is rejected, so a proposal cannot smuggle commands as fields."""
    errs = []
    for kpath, key in _walk_keys(spec):
        if str(key).lower() in PRIVILEGED_DENYLIST:
            errs.append(_err("PRIVILEGED_FIELD", kpath,
                             f"disallowed key {key!r}: a ScenarioSpec is declarative, not executable"))
    return errs


def validate_schema(spec: dict) -> dict:
    """Envelope + layer + privileged-key validation, then dispatch to the typed
    payload validator. Returns {"ok", "errors": [...]} with actionable codes."""
    errors = []
    if not isinstance(spec, dict):
        return {"ok": False, "errors": [_err("BAD_SPEC", "", "spec must be an object")]}

    # unknown top-level keys (no arbitrary fields)
    for k in spec:
        if k not in ENVELOPE_KEYS:
            errors.append(_err("UNKNOWN_FIELD", k, f"unknown envelope field {k!r}"))

    for req in ("spec_id", "spec_type", "pathway", "environment_type", "difficulty_profile"):
        if not str(spec.get(req) or "").strip():
            errors.append(_err("MISSING_MANDATORY_FIELD", req, f"{req} is required"))

    if spec.get("spec_version") != SCENARIO_SPEC_VERSION:
        errors.append(_err("BAD_SPEC_VERSION", "spec_version",
                           f"spec_version must be {SCENARIO_SPEC_VERSION}"))

    # pathway must be a known stable id (legacy 'cyber-ops'/'cyber-ai' accepted and
    # normalized). Marketing names are never valid pathway values.
    pw = spec.get("pathway")
    if str(pw or "").strip() and not pathways.is_valid_pathway(pw):
        errors.append(_err("INVALID_PATHWAY", "pathway",
                           f"unknown pathway {pw!r}; expected one of {pathways.PATHWAYS}"))

    # evidence kinds must be known and implemented
    for ek in (spec.get("evidence_kinds") or []):
        if ek not in KNOWN_EVIDENCE_KINDS:
            errors.append(_err("UNKNOWN_EVIDENCE_KIND", "evidence_kinds", f"unknown evidence kind {ek!r}"))
        elif ek not in IMPLEMENTED_EVIDENCE_KINDS:
            errors.append(_err("EVIDENCE_KIND_NOT_IMPLEMENTED", "evidence_kinds",
                               f"evidence kind {ek!r} is declared but not implemented yet"))

    # payload layers
    payload = spec.get("payload")
    if not isinstance(payload, dict):
        errors.append(_err("MISSING_MANDATORY_FIELD", "payload", "payload object is required"))
    else:
        for k in payload:
            if k not in LAYER_KEYS:
                errors.append(_err("UNKNOWN_FIELD", f"payload.{k}", f"unknown payload layer {k!r}"))

    errors += _reject_privileged(spec)

    # typed payload validation
    st = spec.get("spec_type")
    if st and st not in _PAYLOAD_VALIDATORS:
        errors.append(_err("UNSUPPORTED_SPEC_TYPE", "spec_type",
                           f"no payload validator registered for spec_type {st!r}"))
    elif st and isinstance(payload, dict) and not errors:
        inv = capinv.build_inventory(spec.get("environment_type"))
        errors += _PAYLOAD_VALIDATORS[st](payload, inv)

    return {"ok": not errors, "errors": errors}


# --- authorization-layer views ----------------------------------------------
def candidate_view(spec: dict) -> dict:
    """What a candidate may see: the envelope minus admin/evaluator payload layers.
    The evaluator_only layer (protected truth ref) is NEVER included."""
    p = spec.get("payload", {}) or {}
    out = {k: spec.get(k) for k in ("spec_id", "pathway", "specialization",
                                    "environment_type", "spec_type", "board_compat",
                                    "difficulty_profile")}
    out["brief"] = (p.get("candidate_visible") or {})
    return out


def admin_view(spec: dict) -> dict:
    """Admin configuration view: envelope + candidate_visible + admin, but still NOT
    evaluator_only."""
    p = spec.get("payload", {}) or {}
    out = {k: spec.get(k) for k in ENVELOPE_KEYS if k != "payload"}
    out["payload"] = {"candidate_visible": p.get("candidate_visible"),
                      "admin": p.get("admin")}
    return out


def content_hash(spec: dict) -> str:
    """Stable content hash of the full spec (for immutable catalog versioning)."""
    return hashlib.sha256(signing.canonical(spec)).hexdigest()


# --- SOC investigation payload (the one implemented spec_type) ---------------
def _validate_soc_investigation(payload: dict, inv: dict) -> list:
    """Validate the SOC payload against the capability inventory: every referenced
    capability (families, hosts, identities, datasets, techniques via rules,
    dispositions, response actions) must exist. No invented infrastructure."""
    errors = []
    admin = payload.get("admin") or {}
    refs = list(admin.get("required_capabilities") or [])
    # families
    for fam in (admin.get("families") or []):
        refs.append(f"family:{fam}")
    # affected assets/identities
    aff = admin.get("affected") or {}
    for h in (aff.get("systems") or []):
        refs.append(f"host:{h}")
    for u in (aff.get("identities") or []):
        refs.append(f"identity:{u}")
    for app in (aff.get("services") or []):
        refs.append(f"app:{app}")
    # response actions
    for act in (admin.get("response_requirements") or []):
        refs.append(f"response:{act}")
    bad = capinv.validate_refs(refs, inv)
    for b in bad:
        errors.append(_err("UNSUPPORTED_CAPABILITY", "payload.admin",
                           f"references a capability Ranger cannot produce: {b!r}"))
    # mandatory SOC fields
    cv = payload.get("candidate_visible") or {}
    if not str(cv.get("business_context") or "").strip():
        errors.append(_err("MISSING_MANDATORY_FIELD", "payload.candidate_visible.business_context",
                           "SOC scenarios need a business context brief"))
    if not (admin.get("families")):
        errors.append(_err("MISSING_MANDATORY_FIELD", "payload.admin.families",
                           "SOC scenarios must declare at least one incident family"))
    # evaluator_only must reference truth by generation, never embed answers
    ev = payload.get("evaluator_only") or {}
    if ev and not ev.get("protected_truth_ref"):
        errors.append(_err("MISSING_TRUTH_REF", "payload.evaluator_only",
                           "evaluator_only must reference truth generation, not embed answers"))
    return errors


register_payload_validator("soc-investigation", _validate_soc_investigation)
