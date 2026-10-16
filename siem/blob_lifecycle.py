"""F4 correction (B) - reference-counted lifecycle for the content-addressed object store.

ArtifactStore de-duplicates by content: two artifacts with identical bytes share one blob/<sha256>
object. F3's delete() physically removed that object, so deleting, revoking or quarantining one
artifact could destroy bytes another artifact (possibly another candidate's) still relies on, and a
plain delete ignored retention and legal holds.

This module reference-counts the objects. Each artifact that points at an object holds one
`BlobReference`, scoped to its own candidate/cohort/pathway. Lifecycle actions operate on references:

  * logical revocation / quarantine / delete release only THIS artifact's reference, scoped to the
    artifact (or, in bulk, to a candidate or cohort) - another tenant's reference is untouched;
  * the physical object is removed only when no ACTIVE reference and no HOLD remains, and retention
    is satisfied (F3's can_delete still gates the artifact itself);
  * de-duplication never discloses cross-tenant sharing: authorization is always per-artifact
    (evidence_types.authorize_access), references are per-artifact, and nothing in a put result or a
    release reveals that another candidate holds the same bytes.

The core functions are pure (they operate on a list of reference dicts) so they are unit-testable
without a database; `managed_delete` ties them to a real ArtifactStore. A thin DB adapter at the
bottom maps models.BlobReference rows to/from these dicts.
"""
from __future__ import annotations

import datetime as _dt

from . import evidence_persistence as ep


def _iso(ts=None):
    return (ts or _dt.datetime.now(_dt.timezone.utc)).isoformat()


def make_reference(object_key, evidence_id, *, candidate_id=None, cohort=None, pathway=None):
    return {"object_key": object_key, "evidence_id": evidence_id, "candidate_id": candidate_id,
            "cohort": cohort, "pathway": pathway, "active": True, "hold": False,
            "released_at": None, "release_reason": None}


# --- pure reference-counting logic -------------------------------------------
def active_references(refs, object_key):
    return [r for r in refs if r["object_key"] == object_key and r.get("active")]


def any_hold(refs, object_key):
    return any(r.get("hold") for r in refs if r["object_key"] == object_key)


def release_reference(refs, object_key, evidence_id, *, reason, now=None):
    """Mark one artifact's reference to an object inactive (logical release). Returns the updated
    reference, or None if not found. Other references to the same object are untouched."""
    for r in refs:
        if r["object_key"] == object_key and r["evidence_id"] == evidence_id and r.get("active"):
            r["active"] = False
            r["released_at"] = _iso(now)
            r["release_reason"] = reason
            return r
    return None


def place_hold(refs, *, object_key=None, evidence_id=None, candidate_id=None, cohort=None, on=True):
    """Place/remove a retention or legal hold on references matched by any given scope. A held
    reference blocks physical deletion of its object even once logically released."""
    n = 0
    for r in refs:
        if object_key and r["object_key"] != object_key:
            continue
        if evidence_id and r["evidence_id"] != evidence_id:
            continue
        if candidate_id is not None and r.get("candidate_id") != candidate_id:
            continue
        if cohort and r.get("cohort") != cohort:
            continue
        r["hold"] = bool(on)
        n += 1
    return n


def safe_to_physically_delete(refs, object_key) -> tuple:
    """(ok, reason): the object's bytes may be removed only when it has no active reference and no
    hold. Shared objects with another active reference are NEVER physically deleted."""
    if any_hold(refs, object_key):
        return (False, "hold")
    if active_references(refs, object_key):
        return (False, "shared_active_reference")
    return (True, "no_active_reference")


def scope_revocation(refs, *, artifact=None, candidate_id=None, cohort=None, reason, now=None):
    """Logically revoke references by scope (artifact | candidate | cohort). Returns the list of
    released references. Byte removal is a SEPARATE step (sweep_orphans) that respects other tenants."""
    released = []
    for r in refs:
        if not r.get("active"):
            continue
        if artifact is not None and r["evidence_id"] != artifact.get("evidence_id"):
            continue
        if candidate_id is not None and r.get("candidate_id") != candidate_id:
            continue
        if cohort is not None and r.get("cohort") != cohort:
            continue
        if artifact is None and candidate_id is None and cohort is None:
            continue  # refuse an unscoped mass-revocation
        r["active"] = False
        r["released_at"] = _iso(now)
        r["release_reason"] = reason
        released.append(r)
    return released


def orphaned_objects(refs):
    """Object keys that have at least one (now inactive) reference but no active reference and no
    hold - i.e. safe to physically remove."""
    keys = {r["object_key"] for r in refs}
    out = []
    for k in keys:
        ok, _why = safe_to_physically_delete(refs, k)
        if ok:
            out.append(k)
    return out


# --- tie to a real ArtifactStore ---------------------------------------------
def managed_delete(store, refs, artifact, *, reason, now=None):
    """Release THIS artifact's reference, then physically delete the object ONLY if no active
    reference and no hold remain (and F3's can_delete gate passes). Returns {ok, physical, reason,
    custody}. A shared object is preserved for the remaining references (physical=False)."""
    ok, why = ep.can_delete(artifact, reason=reason, now=now)
    if not ok:
        return {"ok": False, "physical": False, "reason": why, "custody": None}
    key = artifact.get("object_key")
    release_reference(refs, key, artifact["evidence_id"], reason=reason, now=now)
    phys_ok, phys_why = safe_to_physically_delete(refs, key)
    physical = False
    if phys_ok:
        store.delete(key, authorized_reason=reason)
        physical = True
    cev = ep.custody_event("retain", evidence_id=artifact["evidence_id"], actor="ranger-server",
                           candidate_id=artifact.get("candidate_id"), cohort=artifact.get("cohort"),
                           pathway=artifact.get("pathway"),
                           detail={"action": "deleted", "reason": reason,
                                   "physical_delete": physical,
                                   "preserved_for": ("other_references" if not physical else None),
                                   "detail": phys_why})
    return {"ok": True, "physical": physical,
            "reason": ("physically_deleted" if physical else "logically_released_object_preserved"),
            "custody": cev}


def sweep_orphans(store, refs, *, reason="retention_sweep"):
    """Physically remove every object that is now orphaned (no active ref, no hold). Returns the
    list of removed keys. Objects still referenced by any tenant are left intact."""
    removed = []
    for key in orphaned_objects(refs):
        try:
            if store.delete(key, authorized_reason=reason):
                removed.append(key)
        except Exception:
            pass
    return removed


# --- DB adapter (models.BlobReference <-> reference dicts) -------------------
def row_to_ref(row):
    return {"object_key": row.object_key, "evidence_id": row.evidence_id,
            "candidate_id": row.candidate_id, "cohort": row.cohort, "pathway": row.pathway,
            "active": row.active, "hold": row.hold, "released_at": row.released_at,
            "release_reason": row.release_reason}


def ref_row_kwargs(ref):
    return {"object_key": ref["object_key"], "evidence_id": ref["evidence_id"],
            "candidate_id": ref.get("candidate_id"), "cohort": ref.get("cohort"),
            "pathway": ref.get("pathway"), "active": ref.get("active", True),
            "hold": ref.get("hold", False), "released_at": ref.get("released_at"),
            "release_reason": ref.get("release_reason")}
