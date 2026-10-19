"""Shared, secure server-side draft (autosave) infrastructure.

A draft preserves a candidate's IN-PROGRESS inputs for a workspace across navigation, refresh,
logout/login and session changes. It is NEVER graded and NEVER a submission; final adjudication
stays a separate, explicit submit. Drafts are scoped to one candidate + program + board + case
(+ dataset version), so distinct candidates, programs, boards and attempts never share a draft.

Optimistic concurrency: a save carries the `base_version` the client last saw. The write is a
conditional UPDATE guarded by that version, so a save built on a stale version is rejected (with
the current server draft returned) rather than silently overwriting a newer one from another tab
or session. This module couples no program data: the payload is opaque per-kind and validated by
a per-kind validator.
"""
import json

from models import WorkspaceDraft, db as _db, _now

MAX_PAYLOAD_BYTES = 262144  # 256 KiB hard cap on a serialized draft payload (holds long reports)
MAX_REPORT_BODY_CHARS = 100000  # generous ceiling for a long technical report draft

_VERDICTS = {"", "true_positive", "false_positive"}
_SEVERITIES = {"", "low", "medium", "high", "critical"}


class DraftError(ValueError):
    """Raised when a draft payload fails validation (caller maps to HTTP 400)."""


def _validate_board1_triage(payload):
    """Board-1 SOC triage draft: {"adjudications": {alert_id: {verdict,severity,technique,iocs}}}.
    Values are the candidate's own inputs (never an answer key). Bounded and type-checked."""
    if not isinstance(payload, dict):
        raise DraftError("payload must be an object")
    adj = payload.get("adjudications", {})
    if not isinstance(adj, dict):
        raise DraftError("adjudications must be an object")
    if len(adj) > 1000:
        raise DraftError("too many adjudications")
    clean = {}
    for aid, v in adj.items():
        if not isinstance(aid, str) or not aid or len(aid) > 40:
            raise DraftError("invalid alert id")
        if not isinstance(v, dict):
            raise DraftError("invalid adjudication entry")
        verdict = v.get("verdict", "")
        severity = v.get("severity", "")
        technique = v.get("technique", "")
        iocs = v.get("iocs", "")
        if verdict not in _VERDICTS:
            raise DraftError("invalid verdict")
        if severity not in _SEVERITIES:
            raise DraftError("invalid severity")
        if not isinstance(technique, str) or len(technique) > 80:
            raise DraftError("invalid technique")
        if not isinstance(iocs, str) or len(iocs) > 600:
            raise DraftError("invalid iocs")
        # keep only entries that carry some content, so an empty touch does not grow the draft
        if verdict or severity or technique.strip() or iocs.strip():
            clean[aid] = {"verdict": verdict, "severity": severity,
                          "technique": technique, "iocs": iocs}
    return {"adjudications": clean}


def _s(v, cap):
    """Coerce to a string and cap its length; reject non-strings."""
    if not isinstance(v, str):
        raise DraftError("expected a string field")
    if len(v) > cap:
        raise DraftError("field too long")
    return v


def _validate_board1_incident(payload):
    """Board-1 incident investigation draft:
       {"incidents":[{key,label,entry,chain,hosts,accts,evidence}],
        "assign":{alert_id: incident_key}, "nextInc": int, "selKey": str|null}
    Values are the candidate's own in-progress inputs (never an answer key). Bounded + type-checked."""
    if not isinstance(payload, dict):
        raise DraftError("payload must be an object")
    incs_in = payload.get("incidents", [])
    assign_in = payload.get("assign", {})
    if not isinstance(incs_in, list) or len(incs_in) > 200:
        raise DraftError("invalid incidents")
    if not isinstance(assign_in, dict) or len(assign_in) > 5000:
        raise DraftError("invalid assign")
    keys = set()
    incidents = []
    for it in incs_in:
        if not isinstance(it, dict):
            raise DraftError("invalid incident entry")
        key = _s(it.get("key", ""), 40)
        if not key or key in keys:
            raise DraftError("invalid or duplicate incident key")
        keys.add(key)
        incidents.append({
            "key": key,
            "label": _s(it.get("label", ""), 80),
            "entry": _s(it.get("entry", ""), 40),
            "chain": _s(it.get("chain", ""), 600),
            "hosts": _s(it.get("hosts", ""), 800),
            "accts": _s(it.get("accts", ""), 800),
            "evidence": _s(it.get("evidence", ""), 4000),
        })
    assign = {}
    for aid, k in assign_in.items():
        if not isinstance(aid, str) or len(aid) > 40:
            raise DraftError("invalid alert id in assign")
        kk = _s(k if k is not None else "", 40)
        if kk:  # only keep real assignments; an assignment to a missing incident is dropped
            if kk in keys:
                assign[aid] = kk
    nxt = payload.get("nextInc", 1)
    if not isinstance(nxt, int) or nxt < 1 or nxt > 100000:
        raise DraftError("invalid nextInc")
    sel = payload.get("selKey", "")
    sel = _s(sel if sel is not None else "", 40)
    if sel and sel not in keys:
        sel = ""
    return {"incidents": incidents, "assign": assign, "nextInc": nxt, "selKey": sel}


def _validate_strata_report(payload):
    """STRATA written-report draft: {"body": "<markdown text>"}. The body is the candidate's own
    in-progress writing (any length up to a generous cap; emptiness is fine for a draft, and the
    SUBMIT route enforces the real non-empty report policy). Bounded to protect storage."""
    if not isinstance(payload, dict):
        raise DraftError("payload must be an object")
    body = payload.get("body", "")
    if not isinstance(body, str):
        raise DraftError("body must be a string")
    if len(body) > MAX_REPORT_BODY_CHARS:
        raise DraftError("report draft too long")
    return {"body": body}


_VALIDATORS = {"board1_triage": _validate_board1_triage,
               "board1_incident": _validate_board1_incident,
               "strata_report": _validate_strata_report}


def validate(kind, payload):
    fn = _VALIDATORS.get(kind)
    if fn is None:
        raise DraftError("unknown draft kind")
    clean = fn(payload)
    if len(json.dumps(clean)) > MAX_PAYLOAD_BYTES:
        raise DraftError("draft too large")
    return clean


def _as_view(row):
    try:
        payload = json.loads(row.payload or "{}")
    except ValueError:
        payload = {}
    return {"payload": payload, "version": row.version,
            "dataset_version": row.dataset_version,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None}


def load(candidate_id, program, board, kind, case_key):
    """Return the candidate's own current draft for this scope, or None. Program is checked as
    defence in depth (the unique key is candidate+kind+board+case; program must still match)."""
    row = (WorkspaceDraft.query
           .filter_by(candidate_id=candidate_id, kind=kind, board=board, case_key=case_key)
           .first())
    if row is None or row.program != program:
        return None
    return _as_view(row)


def delete(candidate_id, program, board, kind, case_key):
    """Remove the candidate's own draft for this scope (e.g. after a successful final submission,
    so a submitted report's draft does not resurface). Program-checked as defence in depth."""
    row = (WorkspaceDraft.query
           .filter_by(candidate_id=candidate_id, kind=kind, board=board, case_key=case_key)
           .first())
    if row is not None and row.program == program:
        _db.session.delete(row)
        _db.session.commit()
        return True
    return False


def save(candidate_id, program, board, kind, case_key, dataset_version, payload, base_version):
    """Autosave with optimistic concurrency. Returns {"ok":True,"version","updated_at"} on success
    or {"conflict":True,"current":<view|None>} when base_version is stale. Never grades."""
    clean = validate(kind, payload)
    body = json.dumps(clean)
    row = (WorkspaceDraft.query
           .filter_by(candidate_id=candidate_id, kind=kind, board=board, case_key=case_key)
           .first())

    if row is None:
        # creating: the client must not believe a draft already exists
        if base_version not in (0, None):
            return {"conflict": True, "current": {"payload": {"adjudications": {}}, "version": 0,
                                                  "dataset_version": dataset_version,
                                                  "updated_at": None}}
        row = WorkspaceDraft(candidate_id=candidate_id, program=program, board=board, kind=kind,
                             case_key=case_key, dataset_version=dataset_version,
                             payload=body, version=1)
        _db.session.add(row)
        try:
            _db.session.commit()
        except Exception:  # noqa: BLE001 - unique-race: another request created it first
            _db.session.rollback()
            existing = (WorkspaceDraft.query
                        .filter_by(candidate_id=candidate_id, kind=kind, board=board,
                                   case_key=case_key).first())
            return {"conflict": True, "current": (_as_view(existing) if existing else None)}
        return {"ok": True, "version": row.version,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None}

    if row.program != program:
        # cross-program draft collision on the same scope must never be overwritten
        return {"conflict": True, "current": None}

    # existing row: race-safe conditional update guarded by the version the client last saw
    base = base_version if isinstance(base_version, int) else 0
    updated = (WorkspaceDraft.query
               .filter_by(id=row.id, version=base)
               .update({"payload": body, "version": base + 1,
                        "dataset_version": dataset_version, "updated_at": _now()},
                       synchronize_session=False))
    _db.session.commit()
    if not updated:
        current = WorkspaceDraft.query.get(row.id)
        return {"conflict": True, "current": (_as_view(current) if current else None)}
    fresh = WorkspaceDraft.query.get(row.id)
    return {"ok": True, "version": fresh.version,
            "updated_at": fresh.updated_at.isoformat() if fresh.updated_at else None}
