"""F1 - the least-privilege evaluator contract.

An Evaluator verifies an ACTUAL technical outcome against PROTECTED lab state and returns
a machine-checked ObjectiveCheckResult. Two invariants hold by construction:

  1. The candidate never supplies authoritative truth and never self-certifies success.
     Truth is recomputed server-side behind a ProtectedTruthHandle; any self-certifying
     field in a candidate submission is rejected (reject_candidate_truth).
  2. An evaluator receives ONLY the permissions it needs for its assigned evidence
     (EvaluatorScope): one index/truth handle, nothing else. It cannot read another
     candidate's data or truth outside its scope.

Today the event_reference evaluator is implemented (wrapping case_contract.verify_evidence
over a server-side truth). The future STRATA-independent checks PARALLAX will need - agent
authorization, tool-execution boundaries, RAG data isolation, model-artifact integrity,
media-evidence provenance - are DECLARED in the registry and raise until built and gated.
"""
from __future__ import annotations

import hashlib

import signing
from . import case_contract


def _fingerprint(index, event_uid):
    """One-way, stable fingerprint of a rejected foreign reference for audit correlation.
    It does NOT reveal the index/uid value, so logging it cannot confirm whether another
    candidate's evidence exists."""
    return hashlib.sha256(f"ranger-evref|{index}|{event_uid}".encode()).hexdigest()[:16]

# Self-certification / authoritative-truth keys a candidate may never set. If a candidate
# submission carries any of these, it is rejected: candidates prove outcomes with evidence,
# they do not declare the verdict.
CANDIDATE_TRUTH_KEYS = frozenset({
    "ground_truth", "truth", "verdict_truth", "remediation_success", "remediated",
    "passed", "qualified", "critical_failure_cleared", "authoritative", "answer_key",
})


def reject_candidate_truth(submission: dict) -> list:
    """Return a list of forbidden self-certification keys found anywhere in a candidate
    submission (recursively). Empty => clean. The evaluator refuses to proceed otherwise."""
    bad = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if str(k).lower() in CANDIDATE_TRUTH_KEYS:
                    bad.append(str(k))
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(submission)
    return sorted(set(bad))


class ProtectedTruthHandle:
    """A server-side source of truth for one assigned challenge. Constructed only by the
    backend (from the scenario seed / generated world), never from candidate input. The
    evaluator reads truth THROUGH this handle; the raw truth is not otherwise exposed and
    never travels to a candidate-facing context."""

    def __init__(self, resolver, label: str = ""):
        self._resolver = resolver   # callable() -> truth dict, evaluated server-side
        self.label = label

    def resolve(self):
        return self._resolver()


class EvaluatorScope:
    """Least-privilege grant: the single index the evaluator may honor citations into, and
    the single ProtectedTruthHandle it may consult. Anything outside this scope is invisible
    to the evaluator, so one challenge's evaluator cannot read another's evidence or truth."""

    def __init__(self, allowed_index: str, truth_handle: ProtectedTruthHandle):
        self.allowed_index = allowed_index
        self.truth_handle = truth_handle


def _signed_body(r):
    return {"check_id": r.get("check_id"), "passed": r.get("passed"),
            "critical": r.get("critical"), "detail": r.get("detail"), "score": r.get("score")}


def _result(check_id, passed, detail, critical=False, score=None):
    r = {"check_id": check_id, "passed": bool(passed), "verified": True,
         "critical": bool(critical), "detail": detail, "score": score}
    # the evaluator signs its own result (incl. score) so a downstream decision detects tampering
    r["evidence_sig"] = signing.sign(_signed_body(r))
    return r


def signed_check(check_id, passed, detail=None, critical=False, score=None):
    """Public helper: build an evaluator-signed ObjectiveCheckResult. Used by the backend
    evaluator layer (and tests) to represent a verified check - e.g. a STRATA objective
    score, or a PARALLAX outcome gate - that the assessment contract can trust. Candidates
    never call this; results originate server-side only."""
    return _result(check_id, passed, detail or {}, critical=critical, score=score)


def verify_result_integrity(result: dict) -> bool:
    """True if an ObjectiveCheckResult still matches its evaluator signature (not tampered)."""
    sig = result.get("evidence_sig")
    if not sig:
        return False
    return signing.verify(_signed_body(result), sig)


class Evaluator:
    """Protocol: verify(submission, scope, reader) -> ObjectiveCheckResult. Implementations
    must recompute truth via scope.truth_handle and honor only scope.allowed_index."""
    kind = "abstract"

    def verify(self, submission, scope: EvaluatorScope, reader):  # pragma: no cover
        raise NotImplementedError


class EventReferenceEvaluator(Evaluator):
    """Implemented. Verifies cited OpenSearch event evidence against server-side truth using
    case_contract.verify_evidence, restricted to scope.allowed_index. Produces a pass/fail
    check (STRATA/SOC and PARALLAX D6-style telemetry evidence)."""
    kind = "event_reference"

    def verify(self, submission, scope: EvaluatorScope, reader):
        bad = reject_candidate_truth(submission)
        if bad:
            return _result(self.kind, False,
                           {"error": "candidate_supplied_truth", "keys": bad})
        # FAIL CLOSED on any unauthorized reference BEFORE touching underlying data. We do
        # not silently drop out-of-scope citations and grade the rest; an evaluation that
        # cites outside its authorized scope is an explicit validation failure. We never
        # read the foreign data and never reveal whether another candidate's evidence
        # exists - foreign refs are recorded only as salted fingerprints for audit.
        total_cited = 0
        rejected = []
        for inc in (submission.get("incidents") or []):
            for c in (inc.get("cited_evidence") or []):
                total_cited += 1
                ref_index = c.get("index", scope.allowed_index)
                if ref_index != scope.allowed_index:
                    rejected.append(_fingerprint(ref_index, c.get("event_uid")))
        if rejected:
            # explicit, safe failure; auditable; discloses no foreign existence
            return _result(self.kind, False,
                           {"error": "unauthorized_reference_outside_scope",
                            "rejected_count": len(rejected),
                            "rejected_fingerprints": rejected,     # salted hashes, not values
                            "total_cited": total_cited,
                            "data_accessed": False})
        truth = scope.truth_handle.resolve()            # server-side, never candidate input
        v = case_contract.verify_evidence(submission, reader, scope.allowed_index, truth=truth)
        cits = [c for inc in v.get("incidents", []) for c in inc.get("citations", [])]
        valid = [c for c in cits if c.get("reference_valid")]
        passed = bool(valid) and len(valid) == len(cits)
        return _result(self.kind, passed,
                       {"citations_in_scope": len(cits), "reference_valid": len(valid),
                        "total_cited": total_cited, "data_accessed": True})


class _Declared(Evaluator):
    """A declared-but-unimplemented evaluator (gated). It names the protected state it will
    verify, and raises until built and approved, so the contract knows the check exists
    without pretending it works."""

    def __init__(self, kind, verifies):
        self.kind = kind
        self.verifies = verifies

    def verify(self, submission, scope, reader):
        raise NotImplementedError(
            f"evaluator {self.kind!r} (verifies {self.verifies}) is declared but not "
            f"implemented; a PARALLAX lab milestone builds and gates it")


# Registry: implemented + declared. The decision contract may reference only kinds here.
EVALUATORS = {
    "event_reference": EventReferenceEvaluator(),
    # PARALLAX future checks - declared, gated (built in later lab milestones):
    "agent_authorization": _Declared("agent_authorization",
                                     "a tool-using agent stays within its authorized tool scope"),
    "tool_execution_boundary": _Declared("tool_execution_boundary",
                                         "no out-of-scope tool side effects occur"),
    "rag_data_isolation": _Declared("rag_data_isolation",
                                    "retrieval honors tenant/authorization isolation"),
    "model_artifact_integrity": _Declared("model_artifact_integrity",
                                          "a model artifact's hash + provenance verify"),
    "media_provenance": _Declared("media_provenance",
                                  "media hash/metadata/C2PA provenance verify"),
}
IMPLEMENTED_EVALUATORS = ("event_reference",)


def get_evaluator(kind: str) -> Evaluator:
    if kind not in EVALUATORS:
        raise KeyError(f"unknown evaluator kind {kind!r}")
    return EVALUATORS[kind]
