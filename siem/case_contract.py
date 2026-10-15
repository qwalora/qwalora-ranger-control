"""Board 2 SOC case contract: lifecycle, submission schema + validation, and the
server-side evidence verification/preservation procedure.

This module is the single, reproducible contract behind every Board 2 enterprise
submission (design: siem/BOARD2_SOC_CONTRACT.md). It is intentionally free of any
grading/scoring: it establishes WHAT a submission must contain and verifies evidence
against the candidate's authorized index. The enterprise grader (shadow only) and the
HTTP/UI layer are built on top of this in later milestones.

Security invariants honored here:
  - The hidden scenario truth is NEVER embedded in a candidate-facing artifact. The
    candidate brief (candidate_brief) discloses no incident count, no "missed
    detection", and no scenario structure.
  - Evidence credit requires more than a valid reference: a cited event must exist in
    the candidate's own authorized index, be reproducible by the candidate's own
    query, and (at grade time, when truth is supplied) actually be part of a real
    incident. A valid-but-unsupported reference earns nothing.
  - The Ed25519 signature over the preserved evidence record proves INTEGRITY and
    ORIGIN only. It is NOT a measure of investigative correctness.
"""
from __future__ import annotations

import hashlib
import re

import signing  # repo-root module (Ed25519 canonical sign/verify)

# Versioned contracts. A submission records the exact versions it was made under so a
# candidate is always evaluated by the dataset+rubric they faced.
SCENARIO_VERSION = 1
RUBRIC_VERSION = 2

# --- Lifecycle ---------------------------------------------------------------
CASE_STATES = (
    "assigned", "authorized", "investigating", "evidence_collected",
    "draft", "submitted", "under_review", "evaluated", "feedback", "closed",
)
CASE_TRANSITIONS = {
    "assigned": {"authorized"},
    "authorized": {"investigating"},
    "investigating": {"evidence_collected", "draft"},
    "evidence_collected": {"draft", "submitted"},
    "draft": {"evidence_collected", "submitted"},
    "submitted": {"under_review", "evaluated"},
    "under_review": {"evaluated"},
    "evaluated": {"feedback"},
    "feedback": {"closed"},
    "closed": set(),
}
SUBMISSION_STATES = ("draft", "submitted", "under_review", "evaluated", "closed")

WORKFLOWS = ("qualification", "assigned", "practice")
PLANES = ("qualification", "operational")
DISPOSITIONS = ("confirmed_incident", "no_incident", "inconclusive")
SEVERITIES = ("low", "medium", "high", "critical")
# The role a citation plays in the argument. Benign events are legitimate in
# non-primary roles (baseline comparison, timeline exclusion, alternative
# hypothesis, context) and for false-positive dispositions; they are NOT
# auto-zeroed. "primary" means the citation is offered as direct proof of the
# incident/disposition, where the event's true nature must be consistent.
ROLES = ("primary", "baseline", "exclusion", "alternative", "context")
_DEFAULT_ROLE = "primary"
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def can_transition(frm: str, to: str) -> bool:
    return to in CASE_TRANSITIONS.get(frm, set())


# --- Candidate-facing brief (NO disclosures) ---------------------------------
def candidate_brief(org: str, window_from: str, window_to: str) -> str:
    """The instruction text a candidate sees for a qualification case.

    Intentionally omits the number of incidents, whether any activity is
    un-alerted, and any scenario structure. It states the task and the required
    deliverable only; discovery is the candidate's job.
    """
    return (
        f"Investigate activity in {org} across the assessment window "
        f"({window_from} to {window_to}). Identify and document any security "
        "incidents you find. For each incident, provide a disposition, severity, "
        "a calibrated confidence, the affected identities and systems, the ATT&CK "
        "techniques, a reconstructed timeline, and cited evidence (each citation is "
        "an event_uid plus the exact query you ran). Assess detection coverage and "
        "note any gaps with a concrete, testable detection proposal. Record your "
        "overall conclusion and any limitations, then submit. Your findings are "
        "evaluated against the authorized dataset; cite only events from your own "
        "assigned index, and make sure each cited event supports your conclusion."
    )


# --- Submission validation (cluster-free: shape + mandatory) -----------------
def validate_submission(payload: dict) -> dict:
    """Shape and mandatory-field validation that needs no cluster. Returns
    {"ok": bool, "errors": [...], "warnings": [...]}. Evidence existence/scope/
    reproducibility are checked separately by verify_evidence (cluster-dependent)."""
    errors: list[dict] = []
    warnings: list[dict] = []

    def err(code, path, msg):
        errors.append({"code": code, "path": path, "message": msg})

    if not isinstance(payload, dict):
        return {"ok": False, "errors": [{"code": "BAD_PAYLOAD", "path": "",
                                         "message": "submission must be an object"}],
                "warnings": []}

    for field in ("baseline_summary", "overall_conclusion"):
        if not str(payload.get(field) or "").strip():
            err("MISSING_MANDATORY_FIELD", field, f"{field} is required")

    incidents = payload.get("incidents")
    if not isinstance(incidents, list) or not incidents:
        err("MISSING_MANDATORY_FIELD", "incidents", "at least one incident is required")
        incidents = []

    for i, inc in enumerate(incidents):
        p = f"incidents[{i}]"
        if not isinstance(inc, dict):
            err("BAD_PAYLOAD", p, "incident must be an object")
            continue
        if not str(inc.get("label") or "").strip():
            err("MISSING_MANDATORY_FIELD", f"{p}.label", "label is required")
        disp = inc.get("disposition")
        if disp not in DISPOSITIONS:
            err("MISSING_MANDATORY_FIELD", f"{p}.disposition",
                f"disposition must be one of {DISPOSITIONS}")
        if inc.get("severity") not in SEVERITIES:
            err("MISSING_MANDATORY_FIELD", f"{p}.severity",
                f"severity must be one of {SEVERITIES}")
        conf = inc.get("confidence")
        if not isinstance(conf, (int, float)) or not (0 <= conf <= 100):
            err("CONFIDENCE_OUT_OF_RANGE", f"{p}.confidence", "confidence must be 0..100")
        for t in (inc.get("attack_techniques") or []):
            if not _TECH_RE.match(str(t)):
                err("BAD_TECHNIQUE_ID", f"{p}.attack_techniques",
                    f"'{t}' is not a valid ATT&CK technique id")
        # Fields mandatory only when the candidate confirms an incident.
        if disp == "confirmed_incident":
            if not str(inc.get("primary_identity") or "").strip():
                err("MISSING_MANDATORY_FIELD", f"{p}.primary_identity",
                    "primary_identity is required for a confirmed incident")
            if not (inc.get("affected_assets") or []):
                err("MISSING_MANDATORY_FIELD", f"{p}.affected_assets",
                    "affected_assets is required for a confirmed incident")
            if not str(inc.get("analyst_conclusion") or "").strip():
                err("MISSING_MANDATORY_FIELD", f"{p}.analyst_conclusion",
                    "analyst_conclusion is required for a confirmed incident")
            cites = inc.get("cited_evidence") or []
            if not cites:
                err("EMPTY_EVIDENCE_FOR_CONFIRMED", f"{p}.cited_evidence",
                    "a confirmed incident must cite at least one event")
        for j, cite in enumerate(inc.get("cited_evidence") or []):
            cp = f"{p}.cited_evidence[{j}]"
            if not str((cite or {}).get("event_uid") or "").strip():
                err("MISSING_MANDATORY_FIELD", f"{cp}.event_uid", "event_uid is required")
            if not isinstance((cite or {}).get("query"), dict):
                err("MISSING_MANDATORY_FIELD", f"{cp}.query",
                    "the exact query (DSL object) is required for each citation")
            role = (cite or {}).get("role")
            if role is not None and role not in ROLES:
                err("BAD_CITATION_ROLE", f"{cp}.role", f"role must be one of {ROLES}")

    return {"ok": not errors, "errors": errors, "warnings": warnings}


# --- Evidence verification (cluster-dependent, via a Reader) -----------------
# Reader protocol (duck-typed):
#   get_source(index, event_uid) -> dict | None
#   query_matches(index, query, event_uid, time_context) -> bool
# A live adapter wraps LiveCluster; tests use InMemoryReader below.

def _truth_member_uids(truth) -> set:
    uids: set = set()
    if not truth:
        return uids
    for inc in truth.get("incidents", []):
        uids.update(inc.get("event_uids", []))
    return uids


def _claim_consistent(disposition, role, is_member):
    """Does the cited event's true nature support the candidate's SPECIFIC claim?

    Benign (non-member) events are legitimate and not auto-failed: only a citation
    offered as PRIMARY proof must be consistent with the disposition. Supporting roles
    (baseline/exclusion/alternative/context) and the inconclusive disposition are left
    to reviewer judgment (returns None), never silently zeroed.
    Returns True (consistent), False (primary proof contradicts its own disposition),
    or None (no automated determination; reviewer decides)."""
    if role != "primary":
        return None
    if disposition == "confirmed_incident":
        return bool(is_member)            # primary proof of an incident must be a real incident event
    if disposition == "no_incident":
        return (is_member is False)       # primary proof of a false positive must be a benign event
    return None                           # inconclusive: either nature is acceptable


def verify_evidence(payload: dict, reader, candidate_index: str, truth=None,
                    candidate_safe: bool = False) -> dict:
    """Verify every cited event against the candidate's OWN authorized index.

    Always checks, per citation: exists (in the candidate's index), in_scope (the
    citation's index is the candidate's), and reproduces (the candidate's own query
    returns it in context). A citation is `reference_valid` when all three hold; a
    valid document reference alone does NOT establish that it supports the claim.

    At grade time (`truth` supplied and not candidate_safe) each citation also gets
    `claim_consistent` (disposition + role aware; benign events are fine in supporting
    roles and for false-positive dispositions), and a `review_flag` when a PRIMARY
    citation contradicts its own disposition. In candidate-safe mode truth is never
    consulted or exposed, so the candidate can self-check existence/scope/
    reproducibility without learning anything about the hidden scenario.
    """
    use_truth = (truth is not None) and not candidate_safe
    member_uids = _truth_member_uids(truth) if use_truth else set()
    out_incidents = []
    agg = {"citations": 0, "exists": 0, "in_scope": 0, "reproduces": 0,
           "reference_valid": 0, "claim_consistent": 0, "review_flags": 0}

    for inc in (payload.get("incidents") or []):
        disp = inc.get("disposition")
        cites_out = []
        for cite in (inc.get("cited_evidence") or []):
            uid = str((cite or {}).get("event_uid") or "")
            idx = (cite or {}).get("index") or candidate_index
            query = (cite or {}).get("query") or {}
            tctx = (cite or {}).get("time_context")
            role = (cite or {}).get("role") or _DEFAULT_ROLE
            errs = []
            in_scope = (idx == candidate_index)
            if not in_scope:
                errs.append("EVIDENCE_OUT_OF_SCOPE")
            src = reader.get_source(candidate_index, uid) if uid else None
            exists = src is not None
            if uid and not exists:
                errs.append("EVIDENCE_UID_NOT_FOUND")
            reproduces = False
            if exists and in_scope:
                try:
                    reproduces = bool(reader.query_matches(candidate_index, query, uid, tctx))
                except Exception:  # noqa: BLE001
                    reproduces = False
                if not reproduces:
                    errs.append("QUERY_DOES_NOT_REPRODUCE")
            reference_valid = bool(exists and in_scope and reproduces)
            claim_consistent = None
            review_flag = None
            if use_truth:
                claim_consistent = _claim_consistent(disp, role, uid in member_uids)
                if role == "primary" and claim_consistent is False:
                    review_flag = "PRIMARY_EVIDENCE_INCONSISTENT_WITH_DISPOSITION"
            v = {"event_uid": uid, "role": role, "exists": exists, "in_scope": in_scope,
                 "reproduces": reproduces, "reference_valid": reference_valid,
                 "errors": errs}
            if use_truth:
                v["claim_consistent"] = claim_consistent
                if review_flag:
                    v["review_flag"] = review_flag
            cites_out.append(v)
            agg["citations"] += 1
            agg["exists"] += int(exists)
            agg["in_scope"] += int(in_scope)
            agg["reproduces"] += int(reproduces)
            agg["reference_valid"] += int(reference_valid)
            agg["claim_consistent"] += int(claim_consistent is True)
            agg["review_flags"] += int(review_flag is not None)
        out_incidents.append({"label": inc.get("label"), "disposition": disp,
                              "citations": cites_out})

    return {"summary": agg, "incidents": out_incidents,
            "truth_consulted": use_truth}


def candidate_verification(payload: dict, reader, candidate_index: str) -> dict:
    """Candidate-safe verification: existence, scope, and query reproducibility only.
    Never consults or reveals the hidden truth, so it is safe to return to the
    candidate during drafting/verify-before-submit."""
    return verify_evidence(payload, reader, candidate_index, truth=None, candidate_safe=True)


# --- Evidence preservation + signing -----------------------------------------
def _sha256_source(src: dict) -> str:
    return hashlib.sha256(signing.canonical(src)).hexdigest()


def preserve_and_sign(payload: dict, reader, candidate_index: str, meta: dict):
    """Snapshot every cited event that exists as {event_uid, sha256(canonical _source)},
    assemble a case evidence record from meta, and Ed25519-sign it. The signature
    proves the record was not altered and came from Ranger; it is NOT proof the
    investigation was correct. Returns (record, signature_b64)."""
    cited = []
    seen = set()
    for inc in (payload.get("incidents") or []):
        for cite in (inc.get("cited_evidence") or []):
            uid = str((cite or {}).get("event_uid") or "")
            if not uid or uid in seen:
                continue
            src = reader.get_source(candidate_index, uid)
            if src is None:
                continue
            seen.add(uid)
            cited.append({"event_uid": uid, "sha256": _sha256_source(src)})
    cited.sort(key=lambda c: c["event_uid"])
    record = {
        "candidate": meta.get("candidate"),
        "board": meta.get("board"),
        "cohort": meta.get("cohort"),
        "seed": meta.get("seed"),
        "scenario_version": meta.get("scenario_version", SCENARIO_VERSION),
        "rubric_version": meta.get("rubric_version", RUBRIC_VERSION),
        "case_id": meta.get("case_id"),
        "index": candidate_index,
        "submitted_at": meta.get("submitted_at"),
        "cited": cited,
    }
    return record, signing.sign(record)


def verify_evidence_record(record: dict, signature: str, public_key_b64=None) -> bool:
    """Verify the signature over a preserved evidence record (integrity/origin)."""
    return signing.verify(record, signature, public_key_b64)


def reverify_integrity(record: dict, reader) -> dict:
    """Recompute each cited event's hash from the live index and compare to the
    preserved record. Proves the cited evidence has not changed since submission.
    Returns {"ok": bool, "mismatches": [...], "missing": [...]}"""
    mismatches, missing = [], []
    idx = record.get("index")
    for c in record.get("cited", []):
        src = reader.get_source(idx, c["event_uid"])
        if src is None:
            missing.append(c["event_uid"])
            continue
        if _sha256_source(src) != c["sha256"]:
            mismatches.append(c["event_uid"])
    return {"ok": not mismatches and not missing,
            "mismatches": mismatches, "missing": missing}


# --- In-memory reader for tests ----------------------------------------------
class InMemoryReader:
    """A Reader backed by a list of indexed events ({"_id","_source"} or
    {"_id","_source","_malicious"}). Implements enough DSL to exercise the evidence
    contract: match_all, ids, term (ECS dotted path), range on @timestamp, and a
    bool/must combination. The LIVE adapter (M2) runs real DSL against OpenSearch."""

    def __init__(self, index: str, events: list[dict]):
        self.index = index
        self._by_uid = {e["_id"]: e["_source"] for e in events}

    def get_source(self, index, event_uid):
        if index != self.index:
            return None
        return self._by_uid.get(event_uid)

    @staticmethod
    def _dotted(src, path):
        cur = src
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur

    def _matches_clause(self, src, clause):
        if "match_all" in clause:
            return True
        if "ids" in clause:
            return None  # handled by caller (needs the uid)
        if "term" in clause:
            (field, value), = clause["term"].items()
            return self._dotted(src, field) == value
        if "match" in clause:
            (field, value), = clause["match"].items()
            got = self._dotted(src, field)
            return got is not None and str(value).lower() in str(got).lower()
        if "range" in clause:
            (field, cond), = clause["range"].items()
            got = self._dotted(src, field)
            if got is None:
                return False
            if "gte" in cond and str(got) < str(cond["gte"]):
                return False
            if "lte" in cond and str(got) > str(cond["lte"]):
                return False
            return True
        if "bool" in clause:
            b = clause["bool"]
            for m in b.get("must", []):
                r = self._matches_clause(src, m)
                if r is None:  # ids within bool
                    continue
                if not r:
                    return False
            for m in b.get("must_not", []):
                r = self._matches_clause(src, m)
                if r:
                    return False
            return True
        return False

    def query_matches(self, index, query, event_uid, time_context=None):
        if index != self.index:
            return False
        src = self._by_uid.get(event_uid)
        if src is None:
            return False
        q = (query or {}).get("query", query) or {"match_all": {}}
        # ids query: the uid must be explicitly listed
        def _ids_ok(clause):
            vals = clause.get("ids", {}).get("values", [])
            return event_uid in vals
        if "ids" in q:
            ok = _ids_ok(q)
        elif "bool" in q and any("ids" in m for m in q["bool"].get("must", [])):
            ok = all(_ids_ok(m) if "ids" in m else self._matches_clause(src, m)
                     for m in q["bool"]["must"])
        else:
            ok = bool(self._matches_clause(src, q))
        if ok and time_context:
            ts = self._dotted(src, "@timestamp")
            if ts is not None:
                if "gte" in time_context and str(ts) < str(time_context["gte"]):
                    return False
                if "lte" in time_context and str(ts) > str(time_context["lte"]):
                    return False
        return ok
