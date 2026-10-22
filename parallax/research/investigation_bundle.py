"""Reproducible, privacy-safe investigation bundles (px-ibundle-v1).

Packages a security investigation (a normalized px-trace-v1 trace, its px-trust-v1 analysis, evidence
references, human-review decisions and coverage metrics) into a deterministic, verifiable export
directory, and verifies such a bundle back. Reuses the evidence-verifier's path-safety and checksum
conventions. It never invents missing evidence, never copies secret material (scrubbed on the way out),
and keeps cryptographic consistency distinct from independent evidence custody.

The build is deterministic where practical: the content files are canonical JSON (sorted keys), the
`bundle_hash` is computed over the sorted {file -> sha256} map EXCLUDING the manifest's own creation
time, so re-running with identical inputs yields an identical `bundle_hash`.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from typing import Any, Dict, List, Optional

from . import agent_trace as AT
from . import trust_analysis as TA
from . import evidence_verifier as EV

BUNDLE_SCHEMA_VERSION = "px-ibundle-v1"


class BundleError(Exception):
    """Raised on invalid inputs, unsafe destinations, or a bundle that fails verification."""


def _canon_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _write(dest: str, rel: str, obj: Any, checksums: Dict[str, str]) -> None:
    EV.assert_safe_archive_member(rel)
    data = json.dumps(obj, sort_keys=True, indent=2).encode("utf-8")
    full = os.path.join(dest, rel)
    if os.path.realpath(full) != dest and not os.path.realpath(full).startswith(dest + os.sep):
        raise BundleError("resolved write path escapes the bundle directory: %s" % rel)
    with open(full, "wb") as fh:
        fh.write(data)
    # checksum over the canonical form so it is stable regardless of indentation
    checksums[rel] = _sha_bytes(_canon_bytes(obj))


def build_bundle(dest_dir: str, *, trace: Dict[str, Any], analysis: Optional[Dict[str, Any]] = None,
                 campaign_meta: Optional[Dict[str, Any]] = None,
                 evidence_refs: Optional[List[Dict[str, Any]]] = None,
                 review_decisions: Optional[List[Dict[str, Any]]] = None,
                 coverage_metrics: Optional[Dict[str, Any]] = None,
                 protocol_version: Optional[str] = None) -> Dict[str, Any]:
    """Produce a bundle directory. Inputs must be already-authorized, owner-scoped data; this function
    does no DB access. Trace is validated and scrubbed; analysis (if given) must bind to the trace."""
    if not isinstance(trace, dict) or trace.get("schema_version") != AT.SCHEMA_VERSION:
        raise BundleError("trace must be a %s object" % AT.SCHEMA_VERSION)
    probs = AT.validate_trace(trace)
    if probs:
        raise BundleError("trace failed validation: %s" % "; ".join(probs[:5]))
    if analysis is not None:
        if analysis.get("schema_version") != TA.ANALYSIS_VERSION:
            raise BundleError("analysis must be a %s object" % TA.ANALYSIS_VERSION)
        if analysis.get("trace_hash") != trace.get("trace_hash"):
            raise BundleError("analysis.trace_hash does not bind to the trace")

    # path safety: fresh, empty, non-symlink destination not inside an unrelated sentinel (reuses the
    # evidence-verifier's hardening without exporting into a real evidence directory).
    sentinel = tempfile.mkdtemp(prefix="px-ibundle-sentinel-")
    dest_real = EV.assert_safe_export_dir(dest_dir, sentinel)
    os.makedirs(dest_real, exist_ok=True)

    scrubbed_trace = AT.scrub_for_fixture(trace)
    checksums: Dict[str, str] = {}

    _write(dest_real, "trace.json", scrubbed_trace, checksums)
    _write(dest_real, "events.json", scrubbed_trace.get("events", []), checksums)
    if analysis is not None:
        _write(dest_real, "analysis.json", AT.scrub_for_fixture(analysis), checksums)
    # human review: provenance preserved, never fabricated. A decision with no verifying signature is
    # carried through with verified=false; a missing decision set is simply empty, not invented.
    review = {"decisions": AT.scrub_for_fixture(review_decisions or []),
              "note": "human-review decisions as recorded; a decision is authoritative only when its "
                      "signature verifies and the reviewer differs from the producer (separation of "
                      "duties); none are invented."}
    _write(dest_real, "review.json", review, checksums)
    _write(dest_real, "coverage.json", coverage_metrics or {"note": "no coverage metrics supplied"},
           checksums)
    _write(dest_real, "evidence_refs.json", AT.scrub_for_fixture(evidence_refs or []), checksums)

    summary = build_summary(trace, analysis, review_decisions or [], coverage_metrics or {})
    _write(dest_real, "summary.json", summary, checksums)

    _write(dest_real, "VERIFY.json",
           {"how_to_verify": [
               "1. For each file in CHECKSUMS.sha256.json, recompute sha256 over its canonical JSON "
               "(sorted keys, compact separators) and compare.",
               "2. Confirm analysis.json.trace_hash == trace.json.trace_hash.",
               "3. Recompute the bundle_hash as sha256 of the sorted {file: sha256} map (excluding "
               "manifest.json) and compare to manifest.bundle_hash.",
               "4. Cryptographic consistency is NOT independent custody: verify signed evidence against "
               "an independently held public key, and treat heuristic analysis as candidate, not "
               "confirmed."]},
           checksums)

    bundle_hash = _sha_bytes(_canon_bytes(dict(sorted(checksums.items()))))
    manifest = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "trace_id": trace.get("trace_id"),
        "trace_hash": trace.get("trace_hash"),
        "analysis_version": (analysis or {}).get("analysis_version"),
        "trace_schema_version": AT.SCHEMA_VERSION,
        "protocol_version": protocol_version or (campaign_meta or {}).get("protocol_version"),
        "campaign": {k: (campaign_meta or {}).get(k) for k in ("campaign_id", "model_id",
                                                               "backend_provenance")},
        "created_at": time.time(),                 # excluded from bundle_hash so builds stay deterministic
        "files": dict(sorted(checksums.items())),
        "bundle_hash": bundle_hash,
        "custody_note": "bundle_hash proves internal consistency only; it does NOT attest independent "
                        "custody of the evidence or independent human validation.",
    }
    with open(os.path.join(dest_real, "manifest.json"), "wb") as fh:
        fh.write(json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8"))
    with open(os.path.join(dest_real, "CHECKSUMS.sha256.json"), "wb") as fh:
        fh.write(json.dumps({"algorithm": "sha256-canonical", "files": dict(sorted(checksums.items()))},
                            sort_keys=True, indent=2).encode("utf-8"))
    manifest["bundle_dir"] = dest_real
    return manifest


def build_summary(trace: Dict[str, Any], analysis: Optional[Dict[str, Any]],
                  review_decisions: List[Dict[str, Any]], coverage: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic, machine-readable investigation summary. Uses only recorded facts; never turns an
    unsupported observation into a factual conclusion."""
    auth = trace.get("authorization") or {}
    obs = (analysis or {}).get("observations", [])
    confirmed = [o for o in obs if o.get("unauthorized_behavior_observed")]
    suspicious = [o for o in obs if not o.get("unauthorized_behavior_observed")]
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "authorized_task": auth.get("user_request"),
        "authorized_scope": auth.get("authorized_scope"),
        "observed_activity": {"event_count": trace.get("event_count"),
                              "trust_zones": sorted({e.get("trust_zone") for e in trace.get("events", [])})},
        "suspicious_events": [{"observation_id": o["observation_id"], "pattern": o["pattern"],
                               "severity": o["severity"]} for o in suspicious],
        "confirmed_observations": [{"observation_id": o["observation_id"], "pattern": o["pattern"]}
                                   for o in confirmed],
        "unresolved_questions": sorted(set(
            m for o in obs for m in o.get("missing_evidence", [])) | set(trace.get("gaps", []))),
        "review_status": ("reviewed" if review_decisions else "unreviewed"),
        "review_decisions": [{"decision": d.get("decision"), "reviewer_id": d.get("reviewer_id"),
                              "verified": bool(d.get("verified"))} for d in review_decisions],
        "evidence_integrity": {"trace_hash": trace.get("trace_hash"),
                               "analysis_binds": bool(analysis and
                                                      analysis.get("trace_hash") == trace.get("trace_hash"))},
        "coverage": coverage,
        "scientific_status": {
            "candidate_vs_confirmed": "Observations are automated candidates unless human-confirmed; "
                                      "this summary does not assert confirmed compromise.",
            "independent_validation": "none claimed",
            "inferential_findings": "disabled_pending_external_statistical_review",
        },
        "known_limitations": (analysis or {}).get("limitations", []),
    }


# ------------------------------------------------------------------ verification

def verify_bundle(bundle_dir: str) -> Dict[str, Any]:
    """Verify a bundle: recompute each file's canonical checksum, confirm the manifest binding, the
    bundle_hash, and the analysis<->trace binding. Returns a report; detects tampered, incomplete,
    mismatched, and unverifiable bundles. Read-only."""
    report: Dict[str, Any] = {"schema_version": BUNDLE_SCHEMA_VERSION, "bundle_dir": bundle_dir,
                              "ok": False, "problems": [], "checked_files": 0}
    mpath = os.path.join(bundle_dir, "manifest.json")
    cpath = os.path.join(bundle_dir, "CHECKSUMS.sha256.json")
    if not os.path.exists(mpath) or not os.path.exists(cpath):
        report["problems"].append("missing manifest.json or CHECKSUMS.sha256.json")
        return report
    try:
        manifest = json.load(open(mpath, encoding="utf-8"))
        checks = json.load(open(cpath, encoding="utf-8")).get("files", {})
    except Exception:  # noqa: BLE001
        report["problems"].append("manifest or checksums unparseable")
        return report

    files = manifest.get("files", {})
    if files != checks:
        report["problems"].append("manifest file map and CHECKSUMS disagree")
    for rel, want in files.items():
        full = os.path.join(bundle_dir, rel)
        if not os.path.exists(full):
            report["problems"].append("missing file: %s" % rel); continue
        try:
            obj = json.load(open(full, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            report["problems"].append("unparseable file: %s" % rel); continue
        got = _sha_bytes(_canon_bytes(obj))
        report["checked_files"] += 1
        if got != want:
            report["problems"].append("checksum mismatch (tampered): %s" % rel)

    # bundle_hash recomputation (excludes manifest.json by construction)
    recomputed = _sha_bytes(_canon_bytes(dict(sorted(files.items()))))
    if recomputed != manifest.get("bundle_hash"):
        report["problems"].append("bundle_hash mismatch")

    # analysis <-> trace binding
    tpath = os.path.join(bundle_dir, "trace.json")
    apath = os.path.join(bundle_dir, "analysis.json")
    if os.path.exists(tpath) and os.path.exists(apath):
        try:
            th = json.load(open(tpath)).get("trace_hash")
            ah = json.load(open(apath)).get("trace_hash")
            if th != ah:
                report["problems"].append("analysis does not bind to trace (trace_hash mismatch)")
        except Exception:  # noqa: BLE001
            report["problems"].append("trace/analysis unparseable for binding check")

    report["ok"] = not report["problems"]
    report["custody_note"] = ("verification proves internal cryptographic consistency only; it does not "
                              "attest independent evidence custody or independent human validation")
    return report
