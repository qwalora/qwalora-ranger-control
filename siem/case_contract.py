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
#   primary       - direct proof of the disposition (nature must match the claim)
#   corroborating - strengthens a confirmed finding (member expected, benign weak)
#   precursor     - an earlier-stage event of the same chain (member expected)
#   baseline      - a normal-behaviour reference for contrast (benign by design)
#   exclusion     - evidence used to rule something out (benign by design)
#   alternative   - evidence for an alternative hypothesis (reviewer judgment)
#   context       - background colour, low weight (reviewer judgment)
ROLES = ("primary", "corroborating", "precursor", "baseline", "exclusion",
         "alternative", "context")
_DEFAULT_ROLE = "primary"

# M3 evidence relevance: the three NON-INTERCHANGEABLE properties of a citation.
#   A. reference validity  - exists in the candidate's own index + reproduces (truth-free)
#   B. claim support       - does the evidence support THIS role's claim (role+disposition aware)
#   C. malicious activity  - is the event actually part of a real incident (truth-only fact)
# Membership (C) alone never grants credit: a benign event correctly used as a
# baseline is fully supporting (B), while a real attack event mis-filed as a
# "baseline" is misclassified (B=unsupported) despite being malicious (C=True).
CLAIM_SUPPORT = ("supported", "partial", "unsupported", "misclassified", "indeterminate")
# Human-review triggers raised at the citation level.
FLAG_PRIMARY_INCONSISTENT = "PRIMARY_EVIDENCE_INCONSISTENT_WITH_DISPOSITION"
FLAG_MALICIOUS_AS_REFERENCE = "MALICIOUS_EVENT_CITED_AS_BENIGN_REFERENCE"
FLAG_BENIGN_DISP_CITES_MALICIOUS = "BENIGN_DISPOSITION_CITES_MALICIOUS_EVENT"
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


def _truth_uid_incident(truth) -> dict:
    """Map each malicious event_uid to its incident family (property C detail)."""
    out: dict = {}
    if not truth:
        return out
    for inc in truth.get("incidents", []):
        fam = inc.get("family")
        for uid in inc.get("event_uids", []):
            out[uid] = fam
    return out


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


def _assess_claim(disposition, role, is_member):
    """Property B (claim support), assessed with property C (membership) as INPUT
    but never as the sole criterion.

    Returns (claim_support, relevance, review_flag):
      - claim_support in CLAIM_SUPPORT
      - relevance is the weight this citation carries toward the claim [0..1]
      - review_flag is a human-review trigger string or None

    Design: membership alone never grants credit. The role declares what the
    candidate intends the event to prove, and B is whether the event's true
    nature fits THAT intent. A benign event legitimately used as a baseline or
    exclusion is fully supporting; a real incident event mis-filed as a "benign
    baseline" is misclassified (a missed detection), not rewarded for being
    malicious."""
    # inconclusive: no automated determination for any role.
    if disposition == "inconclusive":
        return "indeterminate", 0.5, None

    if disposition == "confirmed_incident":
        if role == "primary":
            if is_member:
                return "supported", 1.0, None
            return "unsupported", 0.0, FLAG_PRIMARY_INCONSISTENT
        if role in ("corroborating", "precursor"):
            # member strengthens the chain; a benign event can still provide
            # legitimate context but carries far less weight (reviewer may lift).
            return ("supported", 1.0, None) if is_member else ("partial", 0.4, None)
        if role in ("baseline", "exclusion"):
            # These are benign-by-design comparative references. A real attack
            # event used here means the candidate mistook malicious for normal.
            if is_member:
                return "misclassified", 0.0, FLAG_MALICIOUS_AS_REFERENCE
            return "supported", 1.0, None
        # alternative / context: reviewer judgment, modest weight.
        return "indeterminate", (0.5 if role == "alternative" else 0.3), None

    # no_incident (false positive): the whole claim is that nothing is malicious.
    if role == "primary":
        if is_member is False:
            return "supported", 1.0, None
        return "unsupported", 0.0, FLAG_PRIMARY_INCONSISTENT
    # any supporting citation of a member event under a benign disposition is a
    # missed detection; benign supporting evidence is fine.
    if is_member:
        return "misclassified", 0.0, FLAG_BENIGN_DISP_CITES_MALICIOUS
    if role in ("baseline", "exclusion", "corroborating", "precursor"):
        return "supported", 1.0, None
    return "indeterminate", (0.5 if role == "alternative" else 0.3), None


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
    uid_to_incident = _truth_uid_incident(truth) if use_truth else {}
    out_incidents = []
    agg = {"citations": 0, "exists": 0, "in_scope": 0, "reproduces": 0,
           "reference_valid": 0, "claim_consistent": 0, "review_flags": 0,
           "supported": 0, "misclassified": 0, "malicious": 0}

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
            reference_valid = bool(exists and in_scope and reproduces)   # property A
            claim_consistent = None
            review_flag = None
            claim_support = None
            relevance = None
            malicious_activity = None
            incident_family = None
            if use_truth:
                is_member = uid in member_uids
                # property C: malicious-activity determination (a fact of the event)
                malicious_activity = bool(is_member)
                incident_family = uid_to_incident.get(uid)
                # legacy primary-only consistency (unchanged semantics for M1/M2)
                claim_consistent = _claim_consistent(disp, role, is_member)
                if role == "primary" and claim_consistent is False:
                    review_flag = FLAG_PRIMARY_INCONSISTENT
                # property B: role+disposition-aware claim support (M3)
                claim_support, relevance, b_flag = _assess_claim(disp, role, is_member)
                if b_flag and not review_flag:
                    review_flag = b_flag
            v = {"event_uid": uid, "role": role, "exists": exists, "in_scope": in_scope,
                 "reproduces": reproduces, "reference_valid": reference_valid,
                 "errors": errs}
            if use_truth:
                v["claim_consistent"] = claim_consistent
                v["malicious_activity"] = malicious_activity    # property C
                v["incident_family"] = incident_family
                v["claim_support"] = claim_support              # property B
                v["relevance"] = relevance
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
            agg["supported"] += int(claim_support == "supported")
            agg["misclassified"] += int(claim_support == "misclassified")
            agg["malicious"] += int(malicious_activity is True)
        out_incidents.append({"label": inc.get("label"), "disposition": disp,
                              "citations": cites_out})

    if not use_truth:
        # candidate-safe: never expose truth-derived counters (property B/C), not
        # even as zeroed keys, so the result leaks nothing about the scenario.
        for k in ("claim_consistent", "supported", "misclassified", "malicious", "review_flags"):
            agg.pop(k, None)

    return {"summary": agg, "incidents": out_incidents,
            "truth_consulted": use_truth}


def candidate_verification(payload: dict, reader, candidate_index: str) -> dict:
    """Candidate-safe verification: existence, scope, and query reproducibility only.
    Never consults or reveals the hidden truth, so it is safe to return to the
    candidate during drafting/verify-before-submit."""
    return verify_evidence(payload, reader, candidate_index, truth=None, candidate_safe=True)


# --- Evidence preservation + signing -----------------------------------------
# Preservation format version. Bumped when the record schema changes so an old
# record is still verifiable under the format it was signed with.
PRESERVATION_VERSION = 3   # v3: the protected seed is no longer embedded; an opaque scenario_ref is
#
# Retention & access model (enforced by the storage/HTTP layers, documented here
# so the contract is self-describing):
#   - WHERE: the signed record lives in CaseSubmission.evidence_record /
#     .evidence_sig (Postgres), alongside the submission it preserves. It is NOT
#     written to any candidate-readable index or tenant.
#   - RETENTION: kept for the lifetime of the BoardResult it supports plus the
#     appeal/audit window; it outlives the candidate's OpenSearch index, which may
#     be reclaimed between cohorts. The embedded source snapshots make the record
#     self-verifying after the live index is gone (verify_record_self_consistent).
#   - ACCESS: readable by Super Admin / reviewers only (authz.require_* in the HTTP
#     layer). A candidate may learn that their evidence was preserved and that the
#     signature is valid, but never reads another candidate's record and never sees
#     any hidden-truth field — there is none in the record by construction.
#   - INTEGRITY: Ed25519 over the canonical record (origin + tamper-evidence) PLUS
#     a per-citation SHA-256 of the canonical source snapshot (content integrity).
#     Neither is a measure of investigative correctness.


def _sha256_source(src: dict) -> str:
    return hashlib.sha256(signing.canonical(src)).hexdigest()


def preserve_and_sign(payload: dict, reader, candidate_index: str, meta: dict,
                      embed_snapshots: bool = True):
    """Preserve every cited event and Ed25519-sign the whole record.

    For each distinct cited event that exists in the candidate's authorized index
    we record its provenance (index, the candidate's own query), a SHA-256 of the
    canonical ``_source`` (content digest), and — when ``embed_snapshots`` — the
    full ``_source`` snapshot so the citation stays verifiable after the live index
    is reclaimed. No hidden-truth field is ever written: the candidate index has no
    truth labels, so a snapshot of it leaks nothing about the scenario.

    The signature proves the record was not altered and originated from Ranger; it
    is NOT proof the investigation was correct. Returns (record, signature_b64)."""
    # Collect role/query provenance per uid (first citation wins for the query shown).
    cited = []
    seen = set()
    for inc in (payload.get("incidents") or []):
        for cite in (inc.get("cited_evidence") or []):
            uid = str((cite or {}).get("event_uid") or "")
            if not uid or uid in seen:
                continue
            src = reader.get_source(candidate_index, uid)
            if src is None:
                # Cannot preserve what does not exist; record the gap honestly.
                seen.add(uid)
                cited.append({"event_uid": uid, "index": candidate_index,
                              "role": (cite or {}).get("role") or _DEFAULT_ROLE,
                              "query": (cite or {}).get("query") or {},
                              "sha256": None, "preserved": False})
                continue
            seen.add(uid)
            entry = {"event_uid": uid, "index": candidate_index,
                     "role": (cite or {}).get("role") or _DEFAULT_ROLE,
                     "query": (cite or {}).get("query") or {},
                     "sha256": _sha256_source(src), "preserved": True}
            if embed_snapshots:
                entry["source_snapshot"] = src
            cited.append(entry)
    cited.sort(key=lambda c: c["event_uid"])
    record = {
        "preservation_version": PRESERVATION_VERSION,
        "candidate": meta.get("candidate"),
        "board": meta.get("board"),
        "cohort": meta.get("cohort"),
        # The protected generator seed is NEVER embedded in the preservation artifact. An opaque
        # case reference correlates the record without allowing reconstruction of the grading world;
        # server-side replay/regrading uses the seed held on the Case row, not this record.
        "scenario_ref": meta.get("scenario_ref"),
        "scenario_version": meta.get("scenario_version", SCENARIO_VERSION),
        "rubric_version": meta.get("rubric_version", RUBRIC_VERSION),
        "case_id": meta.get("case_id"),
        "index": candidate_index,
        "submitted_at": meta.get("submitted_at"),
        "preserved_at": meta.get("preserved_at") or meta.get("submitted_at"),
        "cited": cited,
    }
    return record, signing.sign(record)


def verify_evidence_record(record: dict, signature: str, public_key_b64=None) -> bool:
    """Verify the signature over a preserved evidence record (integrity/origin)."""
    return signing.verify(record, signature, public_key_b64)


def verify_record_self_consistent(record: dict) -> dict:
    """Offline integrity check that needs NO cluster: recompute each citation's
    digest from its embedded snapshot and compare to the stored sha256. Proves the
    record is internally intact even after the source index is gone. Citations
    preserved without a snapshot (embed_snapshots=False) are reported as
    unverifiable, not as failures.
    Returns {"ok", "mismatches", "unverifiable"}."""
    mismatches, unverifiable = [], []
    for c in record.get("cited", []):
        if c.get("sha256") is None:
            unverifiable.append(c["event_uid"]); continue
        snap = c.get("source_snapshot")
        if snap is None:
            unverifiable.append(c["event_uid"]); continue
        if _sha256_source(snap) != c["sha256"]:
            mismatches.append(c["event_uid"])
    return {"ok": not mismatches, "mismatches": mismatches, "unverifiable": unverifiable}


def reverify_integrity(record: dict, reader) -> dict:
    """Recompute each cited event's hash from the LIVE index and compare to the
    preserved record. Proves the cited evidence has not changed since submission.

    When the live index is unavailable (reclaimed between cohorts) the reader
    returns None for every uid; rather than report a flood of false "missing" we
    fall back to the embedded snapshot and verify the record against itself, and
    flag ``index_unavailable``. Returns
    {"ok", "mismatches", "missing", "index_unavailable", "verified_offline"}."""
    mismatches, missing = [], []
    idx = record.get("index")
    cited = record.get("cited", [])
    live_hits = 0
    for c in cited:
        if c.get("sha256") is None:
            continue  # was never preserved; nothing to compare
        src = reader.get_source(idx, c["event_uid"])
        if src is None:
            missing.append(c["event_uid"])
            continue
        live_hits += 1
        if _sha256_source(src) != c["sha256"]:
            mismatches.append(c["event_uid"])
    preservable = [c for c in cited if c.get("sha256") is not None]
    index_unavailable = bool(preservable) and live_hits == 0
    if index_unavailable:
        # The live index is gone; verify the record against its own snapshots.
        self_check = verify_record_self_consistent(record)
        return {"ok": self_check["ok"], "mismatches": self_check["mismatches"],
                "missing": [], "index_unavailable": True,
                "verified_offline": True}
    return {"ok": not mismatches and not missing,
            "mismatches": mismatches, "missing": missing,
            "index_unavailable": False, "verified_offline": False}


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
