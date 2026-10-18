"""F4 correction (A) - separate the decisions that F3 collapsed, and close candidate self-promotion.

F3 marked every acquired artifact `needs_review` + `unscanned` and never promoted it, which was
safe but ran four distinct decisions together. This module makes them explicit and independent, and
makes `validated` reachable only through an authorized, scanned (or explicitly trusted) promotion -
never by a candidate, and never by merely acquiring or deriving evidence.

The four layers (a later layer NEVER substitutes for an earlier one):

  1. SCREEN   - malware screening. A verdict is recorded ONLY from a real scanner that actually ran.
                We never claim an artifact is clean because "no scanner was configured".
  2. FORMAT   - structural/format validation (evidence_types.validate_artifact). Well-formed != safe
                and != authentic.
  3. OBSERVE  - forensic observation (siem/forensic_ops). Produces facts/interpretations and confers
                NOTHING about assessment validity. A tool's output is never a qualification signal.
  4. ACCEPT   - assessment acceptance. Only a reviewer/admin may promote an artifact to `validated`,
                and only when it passed FORMAT and either SCREEN=clean or it is an explicitly
                registered trusted synthetic fixture. Candidates can never promote their own evidence.

Until a malware-scan policy and scanner are approved, externally-submitted evidence stays `unscanned`
and is BLOCKED from unsafe workflows (decoding untrusted media). Development demos run only on
explicitly trusted synthetic fixtures registered here.
"""
from __future__ import annotations

from . import evidence_persistence as ep
from . import evidence_types as et

# scan verdicts we accept from a real scanner
SCAN_CLEAN = "clean"
SCAN_INFECTED = "infected"
SCAN_UNSUPPORTED = "unsupported"       # scanner ran but cannot assess this type
SCAN_ERROR = "error"
REAL_VERDICTS = {SCAN_CLEAN, SCAN_INFECTED, SCAN_UNSUPPORTED, SCAN_ERROR}

PROMOTER_ROLES = ("reviewer", "admin")   # never "candidate"

class ValidationError(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# Explicitly trusted synthetic fixtures (by SERVER-computed content sha256) for development demos
# ONLY. Registration is an authenticated administrative act; it is the ONLY way media may be
# processed or promoted without a real clean scan. Trust is ALWAYS derived server-side from the
# active registry keyed by content hash - never from a job parameter, submitted metadata, or a
# caller-controlled flag. Real candidate uploads are never registered.
#
# The registry is pluggable: the default is in-memory (unit tests / single process); production
# installs the DB-backed registry (siem/forensic_jobs_db.SqlTrustedFixtureRegistry) via
# set_fixture_registry so trust is durable and administrator-approved.
class InMemoryFixtureRegistry:
    def __init__(self):
        self._by_hash = {}

    def register(self, sha256, *, note, approver):
        if (approver or {}).get("role") != "admin":
            raise ValidationError("NOT_ADMIN", "only an administrator may register a trusted fixture")
        self._by_hash[sha256] = {"note": note, "approved_by": approver.get("id") or "admin"}
        return sha256

    def is_trusted(self, sha256) -> bool:
        return sha256 in self._by_hash


_REGISTRY = InMemoryFixtureRegistry()


def set_fixture_registry(registry):
    """Install the active trusted-fixture registry (e.g. the DB-backed one in production)."""
    global _REGISTRY
    _REGISTRY = registry
    return _REGISTRY


def fixture_registry():
    return _REGISTRY


def register_trusted_fixture(sha256, *, note, approver=None, registered_by=None):
    """Register a synthetic fixture's content hash as trusted. Requires an admin `approver` (a
    principal dict with role 'admin'). `registered_by` is a legacy alias accepted only when it is
    itself an admin principal dict; there is no non-admin path to registration."""
    if approver is None and isinstance(registered_by, dict):
        approver = registered_by
    if approver is None:
        raise ValidationError("NOT_ADMIN", "fixture registration requires an admin approver principal")
    return _REGISTRY.register(sha256, note=note, approver=approver)


def is_trusted_fixture(artifact_or_hash) -> bool:
    h = artifact_or_hash if isinstance(artifact_or_hash, str) else artifact_or_hash.get("content_hash")
    return bool(h) and _REGISTRY.is_trusted(h)


# --- layer 1: SCREEN ---------------------------------------------------------
def record_scan(artifact, *, verdict, scanner, scanner_version, actor="ranger-server", seq=None):
    """Record a malware-scan RESULT from a scanner that actually ran. Sets scan_state honestly:
    clean -> 'clean', infected -> 'quarantined', unsupported/error -> stays 'unscanned'. Refuses to
    record a verdict with no named scanner (we never fabricate that scanning occurred)."""
    if verdict not in REAL_VERDICTS:
        raise ValidationError("BAD_VERDICT", f"unknown scan verdict {verdict!r}")
    if not scanner or not scanner_version:
        raise ValidationError("NO_SCANNER", "a scan verdict requires the real scanner's identity+version")
    if verdict == SCAN_CLEAN:
        artifact["scan_state"] = "clean"
        kind, detail = "verify", {"scan": "clean", "scanner": scanner, "scanner_version": scanner_version}
    elif verdict == SCAN_INFECTED:
        artifact["scan_state"] = "quarantined"
        artifact["validation_state"] = "invalid"
        kind, detail = "quarantine", {"scan": "infected", "scanner": scanner,
                                      "scanner_version": scanner_version}
    else:
        artifact["scan_state"] = "unscanned"   # scanner could not assess -> remain blocked
        kind, detail = "verify", {"scan": verdict, "scanner": scanner,
                                  "scanner_version": scanner_version}
    cev = ep.custody_event(kind, evidence_id=artifact["evidence_id"], actor=actor,
                           candidate_id=artifact.get("candidate_id"), cohort=artifact.get("cohort"),
                           pathway=artifact.get("pathway"), detail=detail, seq=seq)
    return {"scan_state": artifact["scan_state"], "custody": cev}


# --- gate for unsafe workflows (untrusted media decoding) --------------------
def can_enter_unsafe_workflow(artifact) -> tuple:
    """(allowed, reason). Decoding untrusted media is permitted only for a clean-scanned artifact or
    an explicitly trusted synthetic fixture. Unscanned external evidence is blocked (fail closed)."""
    if artifact.get("revoked") or artifact.get("validation_state") == "revoked":
        return (False, "revoked")
    if is_trusted_fixture(artifact):
        return (True, "trusted_fixture")
    if artifact.get("scan_state") == "clean":
        return (True, "scanned_clean")
    if artifact.get("scan_state") == "quarantined":
        return (False, "quarantined")
    return (False, "unscanned_external_evidence_blocked")


# --- layer 4: ACCEPT (the only path to 'validated') --------------------------
def promote_to_validated(artifact, *, promoter, actor=None, seq=None):
    """The ONLY way an artifact becomes `validated`. Enforces:
      - promoter role in reviewer/admin (a candidate can NEVER promote, even their own evidence),
      - promoter is in the artifact's cohort+pathway (reviewer scope),
      - artifact passes structural FORMAT validation,
      - SCREEN is clean OR the artifact is an explicitly trusted synthetic fixture,
      - artifact is not revoked.
    Returns {ok, artifact?, reason, custody?}. Never mutates on failure."""
    role = (promoter or {}).get("role")
    if role not in PROMOTER_ROLES:
        return {"ok": False, "reason": "promoter_not_authorized", "custody": None}
    # reviewer/admin must be within the same cohort+pathway as the evidence (reuse access scope)
    allowed, why = et.authorize_access(artifact, requester={
        "role": role, "cohort": promoter.get("cohort"), "pathway": promoter.get("pathway"),
        "candidate_id": promoter.get("candidate_id")})
    if not allowed:
        return {"ok": False, "reason": f"scope_{why}", "custody": None}
    if artifact.get("revoked") or artifact.get("validation_state") == "revoked":
        return {"ok": False, "reason": "revoked", "custody": None}
    # validate the signed ENVELOPE only; persistence-layer fields (object_key, scan_state, ...) are
    # legitimate columns, not part of the envelope schema, so they are excluded from the check.
    envelope = {k: v for k, v in artifact.items() if k in et.ENVELOPE_FIELDS}
    v = et.validate_artifact(envelope)
    if not v["ok"]:
        return {"ok": False, "reason": "format_invalid",
                "errors": v["errors"], "custody": None}
    if not (artifact.get("scan_state") == "clean" or is_trusted_fixture(artifact)):
        return {"ok": False, "reason": "not_scanned_clean_or_trusted", "custody": None}
    # all gates passed -> promote
    artifact["validation_state"] = "validated"
    cev = ep.custody_event("verify", evidence_id=artifact["evidence_id"],
                           actor=actor or f"{role}:{promoter.get('candidate_id') or promoter.get('id')}",
                           candidate_id=artifact.get("candidate_id"), cohort=artifact.get("cohort"),
                           pathway=artifact.get("pathway"),
                           detail={"promoted_to": "validated", "promoter_role": role,
                                   "basis": ("trusted_fixture" if is_trusted_fixture(artifact)
                                             else "scanned_clean")}, seq=seq)
    return {"ok": True, "artifact": artifact, "reason": "validated", "custody": cev}


# --- guarded revision (close the revise() auth gap) --------------------------
# Fields a non-reviewer must never be able to change via a revision.
_PRIVILEGED_FIELDS = ("validation_state", "scan_state", "revoked", "retention_class",
                      "retention_until", "signature")


def guard_revision(prior, changes, *, actor_role):
    """Wrap evidence_types.revise with authorization. A candidate may revise only non-privileged
    fields (never promote themselves to validated, un-revoke, mark clean, or extend retention). A
    reviewer/admin may change privileged fields. Returns the new artifact; raises on violation."""
    privileged = [k for k in changes if k in _PRIVILEGED_FIELDS]
    if privileged and actor_role not in PROMOTER_ROLES:
        raise ValidationError("UNAUTHORIZED_REVISION",
                              f"role {actor_role!r} may not change {privileged} via a revision")
    return et.revise(prior, changes)
