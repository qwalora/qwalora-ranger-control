"""STRATA S5 - the single authoritative Board 2 enterprise SOC qualification assignment.

This module is the ONE place that ties an S3/S4 approved, pinned ScenarioBinding to the Board 2
enterprise world, so the /soc environment, the /case investigation and server-side grading all refer
to the SAME pinned assignment and never independently generate a different incident world.

Design:
  * resolve_assignment() turns a candidate into an authoritative Board2Assignment: it reuses the
    S3/S4 cohort-portfolio governance (strata_assignment.assign with require_portfolio) to bind an
    APPROVED, cohort-specific scenario, validates the binding's pinned generation contract
    (strata_assignment.resolve, which fails closed on tamper/drift), and derives the qualification
    index name, the dataset fingerprint and the rubric version. Candidate-controlled scenario
    selection is impossible - the cohort portfolio + CSPRNG decide.
  * dataset_fingerprint() is a KEYED MAC over the WHOLE identity tuple (candidate, cohort, board,
    attempt, seed, spec identity, content hash, variant, generation-contract hash) - not merely the
    serialized parameter object - so a reused index can be positively tied to the exact assignment.
  * provision() generates the approved telemetry FROM the binding and ingests it into the
    candidate-authorized qualification index, idempotently: an existing index is reused only when its
    stored fingerprint matches exactly; an index whose contents belong to another seed/variant/
    attempt/candidate is REFUSED; an interrupted ingest converges on retry (bulk upsert by _id, meta
    written last). Hidden truth and the protected seed never enter the index. Operational SOC data
    (plane=operational) and qualification data (plane=qualification) stay in separate indices.

Nothing here opens candidate access, enables grading, or touches production. Grading is
strata_qualification; this module only establishes the one authoritative world.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

import strata_assignment as asn
import strata_catalog as cat
from siem import authz, schema


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

BOARD = 2
# Integrity metadata (fingerprint, variant/spec identity, completion state) lives in a PROTECTED
# SYSTEM index, NOT in the candidate's own index. Its name is dotted and carries no cohort/slug/-b
# segment, so it is not matched by any candidate role pattern (ranger-<cohort>-<slug>-b*) and cannot
# be read by a candidate's scoped OpenSearch role at all - by document id, search, or any index API.
# Only the broker (cluster admin) reads/writes it. This keeps variant ids and incident-family
# metadata off every candidate-readable surface, enforced by authorization, not a frontend filter.
SYSTEM_META_INDEX = ".ranger-qualmeta"
DATA_PLANE = "qualification"


class Board2AssignmentError(RuntimeError):
    """The authoritative Board 2 assignment could not be resolved (missing/revoked/incompatible/
    corrupt). Always fail closed - never fall back to a legacy or generic world."""


class Board2ProvisionError(RuntimeError):
    """The qualification index could not be provisioned or was refused (foreign/mismatched)."""


@dataclass(frozen=True)
class Board2Assignment:
    candidate_id: int
    github_id: str
    slug: str
    cohort: str
    pathway: str
    board: int
    attempt: int
    spec_id: str
    spec_version: int
    content_hash: str
    variant_id: str
    family: str
    seed: str
    gen_hash: str
    rubric_version: int
    index_name: str
    dataset_fingerprint: str
    binding_id: int


def _profile() -> str:
    # Profile B is enterprise scale; an approved test profile may be selected explicitly for speed in
    # isolated integration tests, never implicitly in a real qualification.
    return os.environ.get("RANGER_B2_PROFILE", "B")


def dataset_fingerprint(binding, slug: str, rubric_version: int) -> str:
    """A keyed MAC binding the index to the COMPLETE assignment identity - candidate, cohort, board,
    attempt, seed, spec id+version, immutable content hash, variant, and the generation-contract
    MAC - not just the serialized gen_params. Any change to any of these yields a different
    fingerprint, so an index can be positively matched to its assignment and refused otherwise."""
    material = "\x1f".join(str(x) for x in (
        "ranger-b2-qual-fingerprint-v1",
        slug, binding.cohort, BOARD, binding.attempt, binding.seed,
        binding.spec_id, binding.spec_version, binding.content_hash,
        binding.variant_id, binding.gen_hash or "", rubric_version))
    return schema.keyed_mac(material.encode("utf-8"))


def resolve_assignment(db, candidate, *, attempt=1, cohort=None, rubric_version=None):
    """Resolve the ONE authoritative Board 2 assignment for a candidate, fail-closed.

    Reuses S3/S4 governance: the cohort's APPROVED portfolio + CSPRNG pick an approved variant
    (no candidate choice), and the binding's pinned contract is validated here (tamper/drift -> raise).
    Returns a Board2Assignment that /soc, /case and grading all consume."""
    from siem import case_contract as cc
    cohort = cohort or candidate.cohort
    if not cohort:
        raise Board2AssignmentError("candidate has no cohort; cannot resolve a Board 2 assignment")
    rubric_version = rubric_version if rubric_version is not None else cc.RUBRIC_VERSION
    # Resolve the cohort portfolio fail-closed (missing/empty/malformed/unapproved -> raise).
    try:
        portfolio = asn.resolve_portfolio(db, cohort, BOARD, required=True)
        binding = asn.assign(db, candidate, BOARD, cohort=cohort, attempt=attempt,
                             portfolio=portfolio, require_portfolio=True)
    except asn.AssignmentError as e:
        raise Board2AssignmentError(f"no authoritative Board 2 assignment: {e}") from e
    # Validate the pinned generation contract NOW (integrity + anti-drift). This raises on a tampered
    # contract or a drifted legacy binding, so a corrupt assignment can never be provisioned.
    try:
        rb, variant_id, seed, _gp = asn.resolve(binding)
    except asn.AssignmentError as e:
        raise Board2AssignmentError(f"binding {binding.id} failed integrity validation: {e}") from e
    if rb != BOARD or variant_id != binding.variant_id or seed != binding.seed:
        raise Board2AssignmentError("resolved binding does not match its own identity (corrupt)")
    # Confirm the bound variant is still an APPROVED, eligible catalog entry (revocation check).
    eligible = {cat.entry_variant(e) for e in cat.eligible(db, BOARD)}
    if binding.variant_id not in eligible:
        raise Board2AssignmentError(
            f"bound variant {binding.variant_id} is no longer approved/eligible (revoked); "
            f"refusing to provision (fail-closed)")
    slug = authz._slug(candidate.github_id or candidate.handle)
    idx = authz.qualification_index_name(cohort, slug, BOARD, binding.attempt)
    fp = dataset_fingerprint(binding, slug, rubric_version)
    return Board2Assignment(
        candidate_id=candidate.id, github_id=binding.github_id, slug=slug, cohort=cohort,
        pathway=cat.PATHWAY, board=BOARD, attempt=binding.attempt,
        spec_id=binding.spec_id, spec_version=binding.spec_version, content_hash=binding.content_hash,
        variant_id=binding.variant_id, family=binding.family or "", seed=binding.seed,
        gen_hash=binding.gen_hash or "", rubric_version=rubric_version,
        index_name=idx, dataset_fingerprint=fp, binding_id=binding.id)


# ------------------------------------------------------------------ world generation + truth -----
def _resolve_pinned(assignment: Board2Assignment):
    """Load the binding and return the integrity-verified PINNED generation inputs, validating that
    the binding still matches the assignment's full identity. Generation parameters come ONLY from
    the pinned ScenarioBinding.gen_contract (via strata_assignment.resolve, which verifies the keyed
    contract MAC and fails closed on tamper/drift), never from live board_variants.gen_params."""
    from models import ScenarioBinding
    binding = ScenarioBinding.query.get(assignment.binding_id)
    if binding is None:
        raise Board2ProvisionError(f"pinned binding {assignment.binding_id} not found (fail closed)")
    # the binding must match the assignment's candidate/board/scenario identity exactly
    identity = {
        "candidate_id": (int(binding.candidate_id), int(assignment.candidate_id)),
        "github_id": (binding.github_id, assignment.github_id),
        "cohort": (binding.cohort, assignment.cohort),
        "board": (int(binding.board), BOARD),
        "attempt": (int(binding.attempt), int(assignment.attempt)),
        "seed": (binding.seed, assignment.seed),
        "spec_id": (binding.spec_id, assignment.spec_id),
        "spec_version": (int(binding.spec_version), int(assignment.spec_version)),
        "content_hash": (binding.content_hash, assignment.content_hash),
        "variant_id": (binding.variant_id, assignment.variant_id),
    }
    mism = [k for k, (a, b) in identity.items() if a != b]
    if mism:
        raise Board2ProvisionError(f"pinned binding does not match assignment on {mism} (fail closed)")
    try:
        board, variant_id, seed, gp = asn.resolve(binding)   # verifies the pinned contract MAC
    except asn.AssignmentError as e:
        raise Board2ProvisionError(f"pinned contract failed integrity validation: {e}") from e
    if board != BOARD or variant_id != assignment.variant_id or seed != assignment.seed:
        raise Board2ProvisionError("resolved pinned contract disagrees with the assignment identity")
    if "families" not in gp:
        raise Board2ProvisionError("pinned contract carries no families for a board-2 scenario")
    return binding, seed, gp


def generate_world(assignment: Board2Assignment, *, candidate_id=None):
    """The pinned (events, truth) for an assignment. events carry NO truth labels and NO seed; truth
    stays server-side for grading. The incident families + seed come from the integrity-verified
    PINNED contract, so a variant edited after assignment cannot change an existing case's world."""
    from siem import enterprise
    _binding, seed, gp = _resolve_pinned(assignment)
    profile = gp.get("profile") or _profile()
    subject = candidate_id or assignment.github_id
    events, truth = enterprise.generate(subject, BOARD, seed, profile, families=gp["families"])
    return events, truth


def dataset_manifest(docs) -> str:
    """A deterministic, keyed integrity manifest over the WHOLE dataset: a keyed MAC over the sorted
    (event id, content digest) pairs. Two indices with the same document COUNT but different ids or
    mutated content yield different manifests, so a same-count substitution/mutation is detectable.
    Bounded: one linear pass over the events (cheap enough for Profile B)."""
    items = sorted((d["_id"], hashlib.sha256(_canon(d["_source"])).hexdigest()) for d in docs)
    return schema.keyed_mac(_canon(items))


def _meta_doc(assignment: Board2Assignment, count: int, status: str, manifest=None) -> dict:
    """The system-side index stamp, stored in SYSTEM_META_INDEX keyed by the qualification index
    name. Carries the fingerprint + assignment identity (variant/spec/etc.) + a dataset manifest,
    NEVER the seed or truth. Never written to the candidate index; unreadable by any candidate role."""
    return {"_id": assignment.index_name, "_source": {
        "ranger": {"candidate_id": "__system__", "board": BOARD, "meta": True},
        "data": {"synthetic": True, "plane": DATA_PLANE, "meta": True},
        "qual": {"index": assignment.index_name, "candidate": assignment.slug,
                 "fingerprint": assignment.dataset_fingerprint, "spec_id": assignment.spec_id,
                 "spec_version": assignment.spec_version, "content_hash": assignment.content_hash,
                 "variant_id": assignment.variant_id, "attempt": assignment.attempt,
                 "cohort": assignment.cohort, "event_count": count, "status": status,
                 "manifest": manifest}}}


def _stamp_plane(events: list) -> list:
    """Tag every indexed event with the qualification plane, keeping qualification and operational
    SOC data separable. Never adds truth. Returns a new list of {_id,_source}."""
    out = []
    for e in events:
        src = dict(e["_source"])
        data = dict(src.get("data") or {})
        data["plane"] = DATA_PLANE
        src["data"] = data
        out.append({"_id": e["_id"], "_source": src})
    return out


def _fetch_all(cluster, index, size):
    """Fetch all docs (with _id) from an index via the broker, for manifest verification. One
    bounded search; Profile B fits in a single request."""
    code, resp = cluster._req("GET", f"/{index}/_search",
                              body={"size": int(size), "query": {"match_all": {}}})
    if code != 200:
        raise Board2ProvisionError(f"search {index} failed to verify dataset: {code}")
    return [{"_id": h.get("_id"), "_source": h.get("_source")}
            for h in (resp.get("hits", {}) or {}).get("hits", [])]


def read_index_meta(cluster, index):
    """Return the stored qual-meta for a qualification index from the PROTECTED system meta index, or
    None. Read with the broker (admin) credential; candidates can never reach this index."""
    try:
        code, body = cluster._req("GET", f"/{SYSTEM_META_INDEX}/_doc/{index}")
        if code == 200 and isinstance(body, dict) and body.get("found"):
            return (body.get("_source") or {}).get("qual")
    except Exception:  # noqa: BLE001
        return None
    return None


def provision(cluster, assignment: Board2Assignment, *, batch=1000):
    """Idempotently provision the candidate's qualification index from the pinned assignment.

    Guarantees:
      * The index content is the approved telemetry for THIS binding (variant+seed+profile), tagged
        plane=qualification, with no truth labels and no seed.
      * Reuse is positive: an existing index is reused only when its stored fingerprint equals this
        assignment's. A fingerprint mismatch (another seed/variant/attempt/candidate) is REFUSED.
      * Retry-safe: events bulk-upsert by _id and the completion meta is written LAST, so an
        interrupted ingest converges on the next call rather than leaving a mixed/partial world.
      * Never deletes or re-indexes an index that is not our own incomplete qualification index.
    Returns a dict describing what happened."""
    idx = assignment.index_name
    idx_exists = cluster.index_exists(idx)
    meta = read_index_meta(cluster, idx)

    # Fail-closed classification. An index is only ours if the PROTECTED system meta says so and its
    # fingerprint matches; an unknown pre-existing index is never proof of ownership.
    if meta is not None:
        if meta.get("fingerprint") != assignment.dataset_fingerprint:
            raise Board2ProvisionError(
                f"index {idx} is claimed by a DIFFERENT assignment "
                f"(stored fp {str(meta.get('fingerprint'))[:12]} != "
                f"{assignment.dataset_fingerprint[:12]}); refusing (no write/delete/reindex)")
        status = meta.get("status")
        if status == "complete":
            # verify the document inventory AND the dataset manifest before trusting reuse. A count
            # match alone does not prove the dataset is intact, so a keyed manifest over the actual
            # index contents must also equal the one recorded at provision time; a same-count
            # substitution or mutation is therefore rejected, not silently reused.
            expected = int(meta.get("event_count") or -1)
            stored_manifest = meta.get("manifest")
            try:
                rows = _fetch_all(cluster, idx, max(expected, 1) + 8)
            except Exception as e:  # noqa: BLE001
                raise Board2ProvisionError(f"cannot verify inventory of {idx}: {e}")
            if expected < 0 or len(rows) != expected:
                raise Board2ProvisionError(
                    f"index {idx} completion record is corrupted "
                    f"(expected {expected} docs, found {len(rows)}); refusing to reuse")
            if not stored_manifest or dataset_manifest(rows) != stored_manifest:
                raise Board2ProvisionError(
                    f"index {idx} dataset manifest does not match the recorded one "
                    f"(same-count substitution/mutation); refusing to reuse")
            return {"index": idx, "action": "reused", "event_count": expected}
        if status != "incomplete":
            raise Board2ProvisionError(
                f"index {idx} has a corrupted completion state {status!r}; refusing")
        # verified same-assignment INCOMPLETE -> safe to converge (idempotent upsert).
    elif idx_exists:
        # index exists but NO system meta claims it -> unknown/foreign. Do not touch it.
        raise Board2ProvisionError(
            f"index {idx} already exists but is not claimed by any S5 assignment "
            f"(no system meta); refusing to write, delete or re-index an unknown index")

    events, _truth = generate_world(assignment)
    indexed = _stamp_plane(events)

    # mark the claim as INCOMPLETE in the system meta BEFORE ingesting, so a crash mid-ingest leaves
    # a verifiable same-assignment incomplete index (retryable) rather than an unknown one.
    cluster.create_index(SYSTEM_META_INDEX)
    cluster.bulk_index(SYSTEM_META_INDEX, [_meta_doc(assignment, len(indexed), "incomplete")])
    if not cluster.index_exists(idx):
        cluster.create_index(idx, schema.INDEX_MAPPING)
    for i in range(0, len(indexed), batch):
        res = cluster.bulk_index(idx, indexed[i:i + batch])
        if isinstance(res, dict) and res.get("errors"):
            raise Board2ProvisionError(f"bulk ingest into {idx} reported errors: {res}")
    cluster.refresh(idx)
    # confirm the full inventory landed AND its manifest matches what we ingested, then stamp
    # complete LAST (with the manifest) so reuse can verify dataset integrity, not just count.
    rows = _fetch_all(cluster, idx, len(indexed) + 8)
    if len(rows) != len(indexed):
        raise Board2ProvisionError(
            f"ingest into {idx} is incomplete ({len(rows)}/{len(indexed)}); left claim incomplete "
            f"for a safe retry")
    want_manifest = dataset_manifest(indexed)
    if dataset_manifest(rows) != want_manifest:
        raise Board2ProvisionError(
            f"ingested dataset for {idx} does not match what was generated; left claim incomplete")
    cluster.bulk_index(SYSTEM_META_INDEX,
                       [_meta_doc(assignment, len(indexed), "complete", manifest=want_manifest)])
    cluster.refresh(SYSTEM_META_INDEX)
    return {"index": idx, "action": "provisioned", "event_count": len(indexed)}


_DETECTION_FAILURE_VERDICT = "true_positive_missed_by_detector"


def board2_reference_submission(events, truth, index_name):
    """A truth-derived, reference-correct Board 2 investigation - the 'fully correct' archetype used
    for calibration, the authorized TEST qualification evaluator, and the E2E demonstration (the
    board-2 analogue of strata_catalog.board1_correct / board4_correct). It consumes protected truth,
    so it is NEVER candidate-facing; it exists only to prove the grader and the decision path award a
    legitimate pass to a genuinely complete, correct investigation, and only then."""
    src_by_uid = {e["_id"]: e["_source"] for e in events}

    def _dot(src, path):
        cur = src
        for p in path.split("."):
            if not isinstance(cur, dict) or p not in cur:
                return None
            cur = cur[p]
        return cur

    incidents = []
    for t in truth.get("incidents", []):
        uids = list(t.get("event_uids", []))
        order = sorted(uids, key=lambda u: str(_dot(src_by_uid.get(u, {}), "@timestamp") or ""))
        assets = sorted({(_dot(src_by_uid.get(u, {}), "host.name") or "") for u in uids} - {""})
        inc = {
            "label": t.get("family", "incident"),
            "disposition": "confirmed_incident",
            "severity": "high",
            "confidence": 100,
            "attack_techniques": list(t.get("techniques", [])),
            "primary_identity": t.get("primary_identity"),
            "affected_assets": assets,
            "timeline": [{"event_uid": u,
                          "ts": _dot(src_by_uid.get(u, {}), "@timestamp"), "note": "chain"}
                         for u in order],
            "cited_evidence": [{"event_uid": u, "index": index_name,
                                "query": {"query": {"match_all": {}}},
                                "role": "primary"} for u in uids],
            "response_recommendations": ["isolate affected hosts", "reset exposed credentials",
                                         "revoke suspicious sessions"],
            "analyst_conclusion": "Confirmed malicious activity substantiated by the cited chain.",
        }
        if t.get("verdict") == _DETECTION_FAILURE_VERDICT:
            inc["detection_assessment"] = {
                "detector_should_have_fired": True,
                "gap": "the existing narrow rule did not cover this behaviour",
                "proposed_detection": "broaden the rule to the observed technique and tune thresholds",
            }
        incidents.append(inc)
    return {
        "baseline_summary": "Reviewed the window and separated malicious chains from benign baseline.",
        "overall_conclusion": "Confirmed the incidents below with cited, reproducible evidence.",
        "stated_limitations": "Analysis is bounded to the authorized index and the assessment window.",
        "incidents": incidents,
    }


def grading_truth(assignment: Board2Assignment, *, candidate_id=None):
    """The hidden truth for server-side grading only. Regenerated from the pinned assignment; never
    stored, never candidate-facing."""
    _events, truth = generate_world(assignment, candidate_id=candidate_id)
    return truth
