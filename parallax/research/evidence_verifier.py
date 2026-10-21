"""Standalone, READ-ONLY evidence verification and sanitized export for PARALLAX campaigns.

This tool verifies the integrity, signatures, commitments, completeness, and failure accounting of a
campaign's on-disk evidence (the artifacts written by `parallax.research.checkpoint.CampaignRunner`:
``records.jsonl``, ``state.json``, ``ledger.jsonl``, ``manifest.json``), and produces a
reviewer-ready, sanitized export bundle. It is deliberately DECOUPLED from the producing code:

* It never writes to, repairs, reorders, or re-signs the original evidence. Verification only reads.
* It verifies signatures ONLY against public keys the verifier EXPLICITLY trusts (passed in), never
  against the running process's own signing registry. Trust is an input, not an ambient capability.
* It fails CLOSED: any parse error, hash mismatch, unknown key, unsafe path, or ambiguous state
  degrades the verdict rather than being silently tolerated.
* It separates two questions that must never be conflated: did the campaign COMPLETE (every planned
  trial accounted for, chain intact), and is the result SCIENTIFICALLY ELIGIBLE (real backend, findings
  available, integrity clean). A complete campaign on a simulated backend is complete but NOT eligible.
* The sanitized export is a SEPARATE derived artifact. Redactions are explicit and individually logged;
  the original signed bytes are never mutated, and the export never claims to preserve an original
  signature for a record whose bytes it changed. It binds the sanitized bundle to the original evidence
  through a verifiable manifest (per-record original evidence hash + sanitized hash + redaction log).
* Failures are never dropped from the exported accounting: the failure ledger and the plan
  reconciliation travel with the export.

Trust model for signatures
---------------------------
The caller supplies ``trusted_keys`` as ``[{"kid","public_b64"[,"alg"]}]``. A record's signature (from
the ``signatures`` sidecar mapping evidence_hash -> {"signature_b64","kid"?}) is classified as:

  unsigned       no signature was supplied for this record.
  valid          a signature verifies under an explicitly trusted key (by kid when the sidecar names a
                 trusted kid; otherwise under any trusted key).
  invalid        a signature was checked against the relevant trusted key(s) and did NOT verify
                 (tampered bytes, wrong key, or a kid the verifier marked untrusted/revoked).
  incomplete     signature material is present but malformed or partial (unparseable, missing fields).
  unverifiable   a verdict cannot be rendered: no trusted keys were supplied, or the sidecar names a kid
                 that is not in the trusted set (we refuse to verify against keys we do not trust).

``unverifiable`` and ``invalid`` are kept distinct on purpose: "we could not check" is not "we checked
and it failed".
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import signing
from . import commitments as CM

TOOL_VERSION = "evidence-verifier/1.0"

# Signature classification states (requirement 3).
SIG_UNSIGNED = "unsigned"
SIG_VALID = "valid"
SIG_INVALID = "invalid"
SIG_INCOMPLETE = "incomplete"
SIG_UNVERIFIABLE = "unverifiable"

# Record integrity states.
INTEG_OK = "ok"
INTEG_CORRUPT = "corrupt"          # self-inconsistent: recomputed evidence_hash != stored
INTEG_UNPARSEABLE = "unparseable"  # not valid JSON (truncation / corruption)


# --------------------------------------------------------------------------- hashing / canonical

def _sha_obj(obj: Any) -> str:
    return hashlib.sha256(signing.canonical(obj)).hexdigest()


def _recompute_evidence_hash(record: Dict[str, Any]) -> str:
    """Mirror of harness/checkpoint evidence_hash: sha256(canonical(record without evidence_hash))."""
    return _sha_obj({k: v for k, v in record.items() if k != "evidence_hash"})


def _unit_key(rec: Dict[str, Any]) -> Tuple:
    """The identity of a planned trial unit: (repetition, condition, task_id, variant_id|none)."""
    return (rec.get("repetition"), rec.get("condition"), rec.get("legitimate_task_id"),
            rec.get("adversarial_input_id") or "none")


def _ledger_unit_key(entry: Dict[str, Any]) -> Tuple:
    return (entry.get("repetition"), entry.get("condition"), entry.get("task_id"),
            entry.get("variant_id") or "none")


def _chain_fold(evidence_hashes: List[str]) -> str:
    """Reproduce checkpoint._chain_head: an order-sensitive sha256 fold over evidence hashes."""
    head = ""
    for h in evidence_hashes:
        head = hashlib.sha256((head + (h or "")).encode("utf-8")).hexdigest()
    return head


# --------------------------------------------------------------------------- loading (read-only)

def load_evidence(evidence_dir: str) -> Dict[str, Any]:
    """Read the four checkpoint artifacts. Never writes. Returns raw lines plus parsed structures and a
    list of load-time problems. A truncated/corrupt record line is retained as a problem, not dropped
    silently, so downstream reconciliation can see the gap."""
    rp = os.path.join(evidence_dir, "records.jsonl")
    sp = os.path.join(evidence_dir, "state.json")
    lp = os.path.join(evidence_dir, "ledger.jsonl")
    mp = os.path.join(evidence_dir, "manifest.json")

    records: List[Dict[str, Any]] = []
    raw_integrity: List[str] = []          # per-line integrity state, aligned with records_or_none
    records_or_none: List[Optional[Dict[str, Any]]] = []
    problems: List[str] = []

    if os.path.exists(rp):
        with open(rp, "r", encoding="utf-8") as fh:
            for i, raw in enumerate(fh.readlines()):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except Exception:
                    records_or_none.append(None)
                    raw_integrity.append(INTEG_UNPARSEABLE)
                    problems.append("records.jsonl line %d: unparseable (truncated/corrupt)" % (i + 1))
                    continue
                recomputed = _recompute_evidence_hash(rec)
                if recomputed != rec.get("evidence_hash"):
                    records_or_none.append(rec)
                    raw_integrity.append(INTEG_CORRUPT)
                    problems.append("records.jsonl line %d: evidence_hash mismatch (tampered/corrupt)"
                                    % (i + 1))
                else:
                    records_or_none.append(rec)
                    raw_integrity.append(INTEG_OK)
                    records.append(rec)

    state = _read_json(sp, problems, "state.json")
    manifest = _read_json(mp, problems, "manifest.json")
    ledger: List[Dict[str, Any]] = []
    if os.path.exists(lp):
        with open(lp, "r", encoding="utf-8") as fh:
            for i, raw in enumerate(fh.readlines()):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ledger.append(json.loads(raw))
                except Exception:
                    problems.append("ledger.jsonl line %d: unparseable, ignored" % (i + 1))

    return {"evidence_dir": evidence_dir,
            "records": records,                      # integrity-valid records only
            "records_or_none": records_or_none,      # every line, aligned with raw_integrity
            "raw_integrity": raw_integrity,
            "state": state, "manifest": manifest, "ledger": ledger,
            "load_problems": problems}


def _read_json(path: str, problems: List[str], label: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(path):
        problems.append("%s: missing" % label)
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        problems.append("%s: unparseable" % label)
        return None


# --------------------------------------------------------------------------- signatures (R2, R3)

def _normalize_trusted(trusted_keys: Optional[List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for k in (trusted_keys or []):
        kid = k.get("kid")
        pub = k.get("public_b64")
        if kid and pub:
            out[kid] = {"public_b64": pub, "alg": k.get("alg", signing.ALG)}
    return out


def classify_signature(record: Dict[str, Any], sig_entry: Optional[Dict[str, Any]],
                       trusted: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Classify one record's signature against EXPLICITLY trusted keys. Never consults the process's own
    signing registry. The signed payload is the full record exactly as stored (so the signature binds
    to the same bytes whose evidence_hash we verified)."""
    if sig_entry is None:
        return {"status": SIG_UNSIGNED, "kid": None}
    sig_b64 = sig_entry.get("signature_b64")
    kid = sig_entry.get("kid")
    if not sig_b64 or not isinstance(sig_b64, str):
        return {"status": SIG_INCOMPLETE, "kid": kid, "reason": "missing/invalid signature material"}
    try:
        base64.b64decode(sig_b64, validate=True)
    except Exception:
        return {"status": SIG_INCOMPLETE, "kid": kid, "reason": "signature not valid base64"}
    if not trusted:
        return {"status": SIG_UNVERIFIABLE, "kid": kid, "reason": "no trusted keys supplied"}
    # When the sidecar names a kid, we only honor it if it is in the trusted set. We never fall back to
    # untrusted keys, and we never try keys the verifier did not explicitly trust.
    if kid is not None:
        if kid not in trusted:
            return {"status": SIG_UNVERIFIABLE, "kid": kid,
                    "reason": "named kid is not in the trusted set"}
        ok = _verify_explicit(record, sig_b64, trusted[kid]["public_b64"])
        return {"status": SIG_VALID if ok else SIG_INVALID, "kid": kid,
                "verified_against": kid if ok else None}
    # No kid named: a signature is valid if it verifies under ANY explicitly trusted key.
    for tkid, t in trusted.items():
        if _verify_explicit(record, sig_b64, t["public_b64"]):
            return {"status": SIG_VALID, "kid": None, "verified_against": tkid}
    return {"status": SIG_INVALID, "kid": None, "reason": "no trusted key verifies this signature"}


def _verify_explicit(record: Dict[str, Any], sig_b64: str, public_b64: str) -> bool:
    try:
        return bool(signing.verify(record, sig_b64, public_key_b64_str=public_b64))
    except Exception:
        return False


# --------------------------------------------------------------------------- core verification

def verify_campaign(evidence_dir: str, *,
                    trusted_keys: Optional[List[Dict[str, Any]]] = None,
                    signatures: Optional[Dict[str, Dict[str, Any]]] = None,
                    expected_plan: Optional[List[Any]] = None,
                    committed_commitments: Optional[Dict[str, Dict[str, str]]] = None,
                    expected_config_identity: Optional[str] = None,
                    exclusion_rate_ceiling: float = 0.20) -> Dict[str, Any]:
    """Full read-only verification of a campaign evidence directory.

    trusted_keys           public keys the verifier explicitly trusts (R2).
    signatures             evidence_hash -> {"signature_b64","kid"?} sidecar (R3). Checkpoint records are
                           not signed inline; signatures are supplied out of band.
    expected_plan          the PREREGISTERED planned unit keys (list of unit-key tuples/lists) used for
                           missing/duplicate/reconciliation checks (R5, R7). Supplied independently of
                           the (possibly tampered) evidence so the plan is not self-attested.
    committed_commitments  evidence_hash -> {"reproducible_content_sha256","config_identity_sha256",
                           "full_record_sha256"?} to check the three commitments (R4).
    """
    ev = load_evidence(evidence_dir)
    trusted = _normalize_trusted(trusted_keys)
    signatures = signatures or {}
    report: Dict[str, Any] = {
        "tool_version": TOOL_VERSION,
        "verified_at": time.time(),
        "evidence_dir": evidence_dir,
        "inputs": {
            "trusted_kids": sorted(trusted.keys()),
            "plan_supplied": expected_plan is not None,
            "signatures_supplied": bool(signatures),
            "commitments_supplied": bool(committed_commitments),
        },
        "load_problems": ev["load_problems"],
    }

    records = ev["records"]

    # ---- R1 + R5: per-record integrity, corruption, duplicates -------------------------------
    corrupted: List[str] = []
    for state_i, integ in zip(ev["records_or_none"], ev["raw_integrity"]):
        if integ == INTEG_UNPARSEABLE:
            corrupted.append("unparseable line")
        elif integ == INTEG_CORRUPT:
            corrupted.append((state_i or {}).get("experiment_id", "?"))

    seen: Dict[Tuple, int] = {}
    duplicates: List[Dict[str, Any]] = []
    for r in records:
        k = _unit_key(r)
        seen[k] = seen.get(k, 0) + 1
    for k, n in seen.items():
        if n > 1:
            duplicates.append({"unit_key": list(k), "count": n})

    # ---- R1: checkpoint-chain continuity ------------------------------------------------------
    committed_head = (ev["state"] or {}).get("chain_head")
    recomputed_head = _chain_fold([r.get("evidence_hash", "") for r in records])
    continuous = (committed_head is not None and recomputed_head == committed_head)
    reordering_detected = False
    if committed_head is not None and not continuous and records:
        # same multiset of evidence hashes in a different order would be a reordering, not substitution
        from itertools import permutations
        hs = [r.get("evidence_hash", "") for r in records]
        if len(hs) <= 7:  # bounded; larger campaigns rely on duplicate/missing + per-record checks
            reordering_detected = any(_chain_fold(list(p)) == committed_head
                                      for p in permutations(hs))

    chain = {"committed_head": committed_head, "recomputed_head": recomputed_head,
             "continuous": continuous, "reordering_detected": reordering_detected}

    # ---- R3: signatures ----------------------------------------------------------------------
    sig_summary = {SIG_UNSIGNED: 0, SIG_VALID: 0, SIG_INVALID: 0, SIG_INCOMPLETE: 0,
                   SIG_UNVERIFIABLE: 0}
    per_record: List[Dict[str, Any]] = []
    # signatures supplied for records that are not present at all -> accounted as incomplete coverage
    present_hashes = {r.get("evidence_hash") for r in records}
    orphan_signatures = [h for h in signatures if h not in present_hashes]

    # ---- R4: commitments ---------------------------------------------------------------------
    repro_mismatch: List[str] = []
    config_mismatch: List[str] = []
    full_mismatch: List[str] = []
    commitments_checked = 0

    for r in records:
        eh = r.get("evidence_hash")
        sig_entry = signatures.get(eh)
        sig_class = classify_signature(r, sig_entry, trusted)
        sig_summary[sig_class["status"]] += 1

        rec_out: Dict[str, Any] = {
            "experiment_id": r.get("experiment_id"),
            "unit_key": list(_unit_key(r)),
            "evidence_hash": eh,
            "integrity": INTEG_OK,
            "signature": sig_class,
            "backend_is_real": bool(r.get("backend_is_real")),
            "outcome": r.get("outcome"),
        }

        if committed_commitments and eh in committed_commitments:
            commitments_checked += 1
            want = committed_commitments[eh]
            got = CM.commitments(r)
            rc = {}
            if "reproducible_content_sha256" in want:
                ok = got["reproducible_content_sha256"] == want["reproducible_content_sha256"]
                rc["reproducible_content"] = ok
                if not ok:
                    repro_mismatch.append(eh)
            if "config_identity_sha256" in want:
                ok = got["config_identity_sha256"] == want["config_identity_sha256"]
                rc["config_identity"] = ok
                if not ok:
                    config_mismatch.append(eh)
            if "full_record_sha256" in want:
                ok = got["full_record_sha256"] == want["full_record_sha256"]
                rc["full_record"] = ok
                if not ok:
                    full_mismatch.append(eh)
            rec_out["commitments"] = rc
        per_record.append(rec_out)

    # ---- R4 (cross-record): config-identity homogeneity --------------------------------------
    # A single campaign must be a like-for-like comparison: every record should share ONE material
    # configuration. A mid-campaign model/prompt/decoding swap yields >1 distinct config identity and
    # invalidates cross-condition comparison even when every individual record is intact and signed.
    config_consistency = _assess_config_consistency(records, expected_config_identity)

    # ---- R5 + R7: plan reconciliation ---------------------------------------------------------
    reconciliation = _reconcile(records, ev["ledger"], expected_plan)

    # ---- R6: completion vs eligibility --------------------------------------------------------
    committed_state = (ev["state"] or {}).get("campaign_state")
    integrity_ok = (not corrupted and not duplicates and not ev["load_problems"]
                    and continuous and sig_summary[SIG_INVALID] == 0)

    completion = _assess_completion(records, chain, reconciliation, corrupted, duplicates,
                                    committed_state)
    eligibility = _assess_eligibility(records, ev["manifest"], completion, integrity_ok,
                                      reconciliation, exclusion_rate_ceiling, config_consistency)

    # Trust basis (F-G): record which anchors the caller SUPPLIED. The tool CANNOT verify their custody
    # or source, so it never claims the run was independently validated: `anchors_supplied` means only
    # that a key set and a plan were provided, not that they came from an independent source.
    # `independence_attested_by_tool` is always False by construction, because establishing that the
    # anchors are independent of the evidence is an external control the tool has no way to check (keys
    # and a plan regenerated from the same untrusted evidence would set `anchors_supplied` True too).
    trust_basis = {
        "trusted_keys_supplied": bool(trusted),
        "plan_supplied": expected_plan is not None,
        "commitments_supplied": bool(committed_commitments),
        "expected_config_identity_supplied": expected_config_identity is not None,
        "anchors_supplied": bool(trusted) and expected_plan is not None,
        "independence_attested_by_tool": False,
        "custody_requirement": ("trusted_keys, expected_plan, committed_commitments and "
                                "expected_config_identity MUST be supplied from a source controlled "
                                "independently of this evidence directory (e.g. preregistered/escrowed "
                                "at campaign time). A manifest or anchors generated from the same "
                                "evidence are NOT independent; the tool records that anchors were "
                                "supplied but cannot and does not attest that they are independent."),
    }

    # An off-plan exclusion means the failure ledger references a trial that is not in the preregistered
    # plan: an accounting-integrity violation, not mere noise. It must fail the run and block eligibility
    # even though it never moves the exclusion RATE (F-B keeps the rate on-plan only).
    offplan = reconciliation.get("exclusions_off_plan") or []
    overall_pass = (integrity_ok and completion["complete"]
                    and not reconciliation["unaccounted"] and not reconciliation["double_counted"]
                    and not offplan)

    report.update({
        "integrity": {
            "records_lines": len(ev["raw_integrity"]),
            "records_valid": len(records),
            "corrupted": corrupted,
            "duplicates": duplicates,
            "chain": chain,
        },
        "signatures": {
            "summary": sig_summary,
            "orphan_signatures": orphan_signatures,
            "trusted_kids": sorted(trusted.keys()),
        },
        "commitments": {
            "checked": commitments_checked,
            "reproducible_content_mismatch": repro_mismatch,
            "config_identity_mismatch": config_mismatch,
            "full_record_mismatch": full_mismatch,
        },
        "reconciliation": reconciliation,
        "config_consistency": config_consistency,
        "committed_state": committed_state,
        "trust_basis": trust_basis,
        "records": per_record,
        "verdicts": {
            "integrity_ok": integrity_ok,
            "campaign_complete": completion,
            "result_eligible": eligibility,
        },
        "overall": "PASS" if overall_pass else "FAIL",
    })
    return report


def _assess_config_consistency(records: List[Dict[str, Any]],
                               expected_config_identity: Optional[str]) -> Dict[str, Any]:
    """Group records by material config identity. A scientifically valid campaign has exactly one
    config identity across all records (baseline and experimental differ only by injected attack, which
    is NOT part of config identity). More than one distinct config means a swap occurred mid-campaign."""
    digests: Dict[str, int] = {}
    for r in records:
        d = CM.config_identity_digest(r)
        digests[d] = digests.get(d, 0) + 1
    distinct = sorted(digests.keys())
    homogeneous = len(distinct) <= 1
    matches_expected = None
    if expected_config_identity is not None:
        matches_expected = (len(distinct) == 1 and distinct[0] == expected_config_identity)
    return {"distinct_configs": len(distinct), "digests": {d[:16]: n for d, n in digests.items()},
            "homogeneous": homogeneous, "expected_config_identity": expected_config_identity,
            "matches_expected": matches_expected}


def _reconcile(records: List[Dict[str, Any]], ledger: List[Dict[str, Any]],
               expected_plan: Optional[List[Any]]) -> Dict[str, Any]:
    """Reconcile planned trials against present records and ledgered exclusions (R7). Every planned unit
    must be accounted for exactly once: either a present integrity-valid record OR a ledgered exclusion.
    Nothing is silently dropped; contradictions (both, or neither) are surfaced."""
    rec_keys: Dict[Tuple, int] = {}
    for r in records:
        rec_keys[_unit_key(r)] = rec_keys.get(_unit_key(r), 0) + 1

    excluded_keys = {}
    for e in ledger:
        if e.get("status") == "excluded":
            k = _ledger_unit_key(e)
            excluded_keys[k] = excluded_keys.get(k, 0) + 1

    out: Dict[str, Any] = {
        "plan_supplied": expected_plan is not None,
        "planned": None, "with_record": len(rec_keys), "excluded": len(excluded_keys),
        "excluded_on_plan": 0, "unaccounted": [], "double_counted": [], "exclusions_off_plan": [],
    }
    if expected_plan is None:
        # Without a preregistered plan we can still flag record/exclusion contradictions.
        for k in set(rec_keys) & set(excluded_keys):
            out["double_counted"].append(list(k))
        return out

    planned = {tuple(k) for k in (tuple(x) for x in expected_plan)}
    out["planned"] = len(planned)
    out["excluded_on_plan"] = len(set(excluded_keys) & planned)
    for k in planned:
        has_rec = k in rec_keys
        has_exc = k in excluded_keys
        if has_rec and has_exc:
            out["double_counted"].append(list(k))
        elif not has_rec and not has_exc:
            out["unaccounted"].append(list(k))
    for k in set(excluded_keys) - planned:
        out["exclusions_off_plan"].append(list(k))
    for k in set(rec_keys) - planned:
        out["unaccounted"].append(list(k) + ["unplanned_record"])
    return out


def _assess_completion(records, chain, reconciliation, corrupted, duplicates,
                       committed_state=None) -> Dict[str, Any]:
    reasons: List[str] = []
    if corrupted:
        reasons.append("%d corrupted/unparseable record line(s)" % len(corrupted))
    if duplicates:
        reasons.append("%d duplicated trial unit(s)" % len(duplicates))
    if not chain["continuous"]:
        reasons.append("checkpoint chain does not match committed head"
                       + (" (reordering detected)" if chain["reordering_detected"] else ""))
    planned = reconciliation.get("planned")
    if reconciliation["plan_supplied"]:
        if not planned:
            reasons.append("preregistered plan is empty: completeness is not meaningfully established")
        if reconciliation["unaccounted"]:
            reasons.append("%d planned trial(s) neither recorded nor ledgered as excluded"
                           % len(reconciliation["unaccounted"]))
        if reconciliation["double_counted"]:
            reasons.append("%d trial(s) both recorded and excluded" % len(reconciliation["double_counted"]))
    else:
        reasons.append("no preregistered plan supplied: completeness is not independently established")
    complete = (not corrupted and not duplicates and chain["continuous"]
                and reconciliation["plan_supplied"] and bool(planned)
                and not reconciliation["unaccounted"] and not reconciliation["double_counted"])
    # Defense in depth: surface any disagreement with the producer's own committed campaign_state. The
    # independent plan reconciliation is authoritative; a mismatch is a transparency signal, not proof.
    state_disagreement = None
    if committed_state is not None:
        producer_says_done = (committed_state == "completed")
        if producer_says_done and not complete:
            state_disagreement = "producer marked 'completed' but independent verification finds it incomplete"
            reasons.append(state_disagreement)
        elif not producer_says_done and complete:
            state_disagreement = ("producer marked '%s' yet all planned trials reconcile as accounted; "
                                  "treating as complete on the independent plan" % committed_state)
    return {"complete": complete, "reasons": reasons, "committed_state": committed_state,
            "state_disagreement": state_disagreement}


def _assess_eligibility(records, manifest, completion, integrity_ok, reconciliation,
                        ceiling, config_consistency=None) -> Dict[str, Any]:
    """Scientific-result eligibility is STRICTLY stronger than completion and is reported separately: a
    complete campaign on a simulated backend is complete but not eligible (simulated = plumbing only)."""
    reasons: List[str] = []
    if not completion["complete"]:
        reasons.append("campaign is not complete")
    if not integrity_ok:
        reasons.append("integrity is not clean")
    any_real = any(r.get("backend_is_real") for r in records)
    all_real = bool(records) and all(r.get("backend_is_real") for r in records)
    if not any_real:
        reasons.append("no real-backend records (simulated plumbing is never a finding)")
    elif not all_real:
        reasons.append("mixed simulated/real records: not a like-for-like scientific set")
    # a mixed material configuration (model/prompt/decoding swapped mid-campaign) is not comparable
    if config_consistency is not None:
        if not config_consistency.get("homogeneous"):
            reasons.append("multiple material configurations present (%d distinct): not a like-for-like set"
                           % config_consistency.get("distinct_configs", 0))
        if config_consistency.get("matches_expected") is False:
            reasons.append("campaign config identity does not match the expected/preregistered config")
    # exclusion rate must be within policy so results are not quietly salvaged by dropping trials. Only
    # ON-PLAN exclusions count toward the rate; off-plan ledger noise cannot move it.
    planned = reconciliation.get("planned")
    excluded_on_plan = reconciliation.get("excluded_on_plan") or 0
    rate = (excluded_on_plan / planned) if planned else None
    if planned and rate > ceiling:
        reasons.append("on-plan exclusion rate %.3f exceeds ceiling %.3f" % (rate, ceiling))
    # off-plan exclusions are a reconciliation violation (the ledger references trials outside the plan)
    # and are never silently ignored, even though they do not move the rate above.
    offplan = reconciliation.get("exclusions_off_plan") or []
    if offplan:
        reasons.append("%d ledgered exclusion(s) reference trials outside the preregistered plan "
                       "(reconciliation violation)" % len(offplan))
    unaccounted = reconciliation.get("unaccounted") or []
    if unaccounted:
        reasons.append("%d planned trial(s) unaccounted for" % len(unaccounted))
    eligible = not reasons
    return {"eligible": eligible, "reasons": reasons,
            "any_real": any_real, "all_real": all_real,
            "exclusion_rate": rate}


# =========================================================================== sanitized export
# Requirements 8, 9, 10 and the EXPORT SECURITY constraints. The export is a SEPARATE derived
# artifact: the original evidence directory is never read-modified-written, and redactions are applied
# only to deep copies. Redaction is explicit and individually logged; a record whose bytes we change is
# never claimed to retain its original signature. The sanitized bundle is bound to the original through
# a manifest that records, per record, the original evidence_hash, the sanitized hash, and every
# redaction applied. Failures are carried through, never dropped.

# Patterns that must never leak into a reviewer-facing export: internal hostnames, private connectivity
# endpoints, operator home paths, loopback/private URLs, and tokens/secrets.
#
# HIGH_CONFIDENCE patterns are specific enough that a match anywhere - including inside a protected
# scientific field - is treated as a genuine exposure and FAILS the export closed (we neither leak it
# nor silently rewrite a result). HEURISTIC patterns are prone to false positives (a base64 blob, a
# path-like string) and are therefore applied ONLY to non-protected free-text fields: they never touch
# or fail on protected content such as hashes, outcomes, or decoding parameters.
_HIGH_CONFIDENCE = [
    ("internal_host", re.compile(r"\b[\w.-]+\.railway\.internal\b", re.I)),
    ("railway_public", re.compile(r"\b[\w.-]+\.up\.railway\.app\b", re.I)),
    ("railway_ssh", re.compile(r"\bssh\.railway\.com\b", re.I)),
    ("private_url", re.compile(r"https?://(?:127\.0\.0\.1|localhost|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)[\w.:/%-]*", re.I)),
    ("bearer_token", re.compile(r"\b(?:ghp|gho|ghs|github_pat|xox[baprs]|AKIA)[A-Za-z0-9_\-]{10,}\b")),
]
_HEURISTIC = [
    ("operator_home", re.compile(r"/home/[A-Za-z0-9_.-]+")),
    # base64-shaped secret: requires BOTH upper and lower case so it never matches a lowercase hex
    # digest (sha256/model digest), which is legitimate protected content, not a secret.
    ("base64_secret", re.compile(r"\b(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])[A-Za-z0-9+/]{40,}={0,2}\b")),
]
_SECRET_PATTERNS = _HIGH_CONFIDENCE + _HEURISTIC

# Scientific fields whose values a redaction must never touch: doing so would corrupt the very content
# a reviewer needs. If a sensitive pattern were ever to appear inside one of these, we FAIL the export
# rather than silently altering a result (see redaction_failure).
_PROTECTED_CONTENT_KEYS = {
    "outcome", "evaluation", "attempts_injection", "condition", "repetition",
    "reproducible_content_sha256", "config_identity_sha256", "evidence_hash",
    "corpus_hash", "manifest_hash", "expected_authorized_behavior",
}


class UnsafeExportPath(Exception):
    """Raised when an export destination is unsafe (traversal, symlink, inside the source, non-empty)."""


class RedactionFailure(Exception):
    """Raised when a sensitive value is detected inside protected scientific content: we refuse to
    either leak it or silently rewrite a result."""


def assert_safe_export_dir(dest_dir: str, evidence_dir: str) -> str:
    """Validate the export destination FAILS CLOSED against path-traversal and symlink attacks (R10).

    * The real parent must exist and be a real directory (not a symlink redirecting writes elsewhere).
    * No path component may be a symlink.
    * The destination must not be inside the evidence directory (never write the export into its source).
    * The destination must be absent or an empty directory (no overwriting existing evidence).
    Returns the realpath of the destination.
    """
    parent = os.path.dirname(os.path.abspath(dest_dir.rstrip("/"))) or "/"
    if not os.path.isdir(parent):
        raise UnsafeExportPath("export parent directory does not exist: %s" % parent)
    # reject symlink components up to and including the parent
    probe = parent
    seen = set()
    while probe and probe not in seen:
        seen.add(probe)
        if os.path.islink(probe):
            raise UnsafeExportPath("refusing export: path component is a symlink: %s" % probe)
        nxt = os.path.dirname(probe)
        if nxt == probe:
            break
        probe = nxt
    real_parent = os.path.realpath(parent)
    real_dest = os.path.join(real_parent, os.path.basename(dest_dir.rstrip("/")))
    real_ev = os.path.realpath(evidence_dir)
    if real_dest == real_ev or (real_dest + os.sep).startswith(real_ev + os.sep):
        raise UnsafeExportPath("refusing to export inside the source evidence directory")
    if os.path.lexists(real_dest):
        if os.path.islink(real_dest):
            raise UnsafeExportPath("refusing export: destination is a symlink")
        if not os.path.isdir(real_dest):
            raise UnsafeExportPath("export destination exists and is not a directory")
        if os.listdir(real_dest):
            raise UnsafeExportPath("export destination is not empty; refusing to overwrite")
    return real_dest


def assert_safe_archive_member(name: str) -> None:
    """Guard used when emitting a tar member (anti zip-slip). Member names must be relative, free of
    parent traversal and absolute roots; symlink/hardlink members are refused by the writer itself."""
    if name.startswith("/") or name.startswith("\\"):
        raise UnsafeExportPath("archive member is absolute: %s" % name)
    parts = re.split(r"[\\/]+", name)
    if any(p == ".." for p in parts):
        raise UnsafeExportPath("archive member escapes with '..': %s" % name)
    if os.path.isabs(name) or (len(name) > 1 and name[1] == ":"):
        raise UnsafeExportPath("archive member has a drive/abs root: %s" % name)


def _redact_value(val: str, patterns=_SECRET_PATTERNS) -> Tuple[str, List[str]]:
    hits: List[str] = []
    out = val
    for label, pat in patterns:
        if pat.search(out):
            hits.append(label)
            out = pat.sub("[REDACTED:%s]" % label, out)
    return out, hits


def _sanitize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return (sanitized_copy, redaction_log). Operates on a DEEP COPY; the original is untouched.

    Non-protected free-text fields get the full pattern set redacted and logged. Protected scientific
    fields (hashes, outcomes, decoding params) are left byte-for-byte intact; a HIGH_CONFIDENCE secret
    appearing inside one of them raises RedactionFailure (we refuse to either leak it or silently
    rewrite a result), while a merely heuristic match there is ignored so legitimate content such as a
    digest is never mistaken for a secret."""
    sanitized = copy.deepcopy(record)
    log: List[Dict[str, Any]] = []

    def walk(node, path, protected):
        if isinstance(node, dict):
            return {k: walk(v, path + [str(k)], protected or (k in _PROTECTED_CONTENT_KEYS))
                    for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, path + [str(i)], protected) for i, v in enumerate(node)]
        if isinstance(node, str):
            if protected:
                # Only a high-confidence secret in protected content is an exposure worth failing on.
                _, hc_hits = _redact_value(node, _HIGH_CONFIDENCE)
                if hc_hits:
                    raise RedactionFailure(
                        "high-confidence secret %s found in protected content at %s"
                        % (hc_hits, ".".join(path)))
                return node
            new, hits = _redact_value(node)
            if hits:
                log.append({"path": ".".join(path), "patterns": hits,
                            "original_value_sha256": hashlib.sha256(node.encode("utf-8")).hexdigest()})
                return new
        return node

    sanitized = walk(sanitized, [], False)
    return sanitized, log


def _write_file(dest_real: str, rel: str, data: bytes, checksums: Dict[str, str]) -> None:
    assert_safe_archive_member(rel)
    full = os.path.join(dest_real, rel)
    if not os.path.realpath(full).startswith(dest_real + os.sep) and os.path.realpath(full) != dest_real:
        raise UnsafeExportPath("resolved write path escapes the export directory: %s" % rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as fh:
        fh.write(data)
    checksums[rel] = hashlib.sha256(data).hexdigest()


def build_sanitized_export(evidence_dir: str, dest_dir: str, *,
                           report: Optional[Dict[str, Any]] = None,
                           signatures: Optional[Dict[str, Dict[str, Any]]] = None,
                           trusted_keys: Optional[List[Dict[str, Any]]] = None,
                           expected_plan: Optional[List[Any]] = None,
                           committed_commitments: Optional[Dict[str, Dict[str, str]]] = None,
                           expected_config_identity: Optional[str] = None,
                           allow_ineligible: bool = True) -> Dict[str, Any]:
    """Produce a reviewer-ready, sanitized export bundle bound to the original evidence (R8, R9, R10).

    Refuses to export when integrity verification fails (tampered evidence) or the destination is unsafe.
    The original evidence directory is only read. Returns the export's binding manifest.
    """
    if report is None:
        report = verify_campaign(evidence_dir, trusted_keys=trusted_keys, signatures=signatures,
                                 expected_plan=expected_plan,
                                 committed_commitments=committed_commitments,
                                 expected_config_identity=expected_config_identity)
    # R10: never export tampered evidence.
    if report["verdicts"]["integrity_ok"] is not True:
        raise RedactionFailure("refusing to export: integrity verification did not pass (%s)"
                               % "; ".join(report["verdicts"]["campaign_complete"]["reasons"]
                                           or ["integrity not ok"]))
    dest_real = assert_safe_export_dir(dest_dir, evidence_dir)
    os.makedirs(dest_real, exist_ok=True)

    ev = load_evidence(evidence_dir)
    signatures = signatures or {}
    checksums: Dict[str, str] = {}
    record_bindings: List[Dict[str, Any]] = []
    sanitized_records: List[Dict[str, Any]] = []

    for r in ev["records"]:
        eh = r.get("evidence_hash")
        # Sanitized records are kept PRISTINE (no injected fields). For a record that needed no
        # redaction, the sanitized record is therefore byte-identical to the original, so a preserved
        # signature verifies directly against the record in records_sanitized.json. All binding data
        # lives in export_manifest.json, never inside the scientific record itself.
        sanitized, redaction_log = _sanitize_record(r)
        modified = bool(redaction_log)
        sanitized_sha = hashlib.sha256(signing.canonical(sanitized)).hexdigest()
        # Signature preservation ONLY when the signed bytes are unchanged (no redaction touched it).
        sig_entry = signatures.get(eh)
        if sig_entry and not modified:
            sig_binding = {"original_signature_preserved": True,
                           "signature_b64": sig_entry.get("signature_b64"),
                           "kid": sig_entry.get("kid"),
                           "verify_against": "records_sanitized.json entry with this experiment_id "
                                             "(byte-identical to the original; recompute evidence_hash "
                                             "to confirm it matches original_evidence_hash)"}
        elif sig_entry and modified:
            sig_binding = {"original_signature_preserved": False,
                           "reason": "record was redacted; original signature does not cover sanitized bytes"}
        else:
            sig_binding = {"original_signature_preserved": False, "reason": "record was unsigned"}
        sanitized_records.append(sanitized)
        record_bindings.append({
            "experiment_id": r.get("experiment_id"),
            "original_evidence_hash": eh,
            "unit_key": list(_unit_key(r)),
            "sanitized_sha256": sanitized_sha,
            "redacted": modified,
            "redactions": redaction_log,
            "signature": sig_binding,
        })

    # Sanitize the failure ledger too, but NEVER drop entries (failures stay in the accounting).
    sanitized_ledger = []
    for e in ev["ledger"]:
        se = copy.deepcopy(e)
        if isinstance(se.get("error"), str):
            se["error"], _ = _redact_value(se["error"])
        sanitized_ledger.append(se)

    # Write artifacts (fixed, safe basenames only; no record-controlled filenames -> no traversal).
    _write_file(dest_real, "records_sanitized.json",
                json.dumps(sanitized_records, sort_keys=True, indent=2).encode("utf-8"), checksums)
    _write_file(dest_real, "failure_ledger.json",
                json.dumps(sanitized_ledger, sort_keys=True, indent=2).encode("utf-8"), checksums)
    _write_file(dest_real, "verification_report.json",
                json.dumps(report, sort_keys=True, indent=2).encode("utf-8"), checksums)
    _write_file(dest_real, "reconciliation.json",
                json.dumps(report["reconciliation"], sort_keys=True, indent=2).encode("utf-8"), checksums)
    if trusted_keys:
        _write_file(dest_real, "trusted_keys.json",
                    json.dumps([{"kid": k.get("kid"), "public_b64": k.get("public_b64"),
                                 "alg": k.get("alg", signing.ALG)} for k in trusted_keys],
                               sort_keys=True, indent=2).encode("utf-8"), checksums)

    binding_manifest = {
        "tool_version": TOOL_VERSION,
        "created_at": time.time(),
        "source_evidence_dir": os.path.basename(evidence_dir.rstrip("/")),
        "overall_verification": report["overall"],
        "result_eligible": report["verdicts"]["result_eligible"]["eligible"],
        "campaign_complete": report["verdicts"]["campaign_complete"]["complete"],
        "records": record_bindings,
        "redaction_summary": {
            "records_redacted": sum(1 for b in record_bindings if b["redactions"]),
            "records_total": len(record_bindings),
            "signatures_preserved": sum(1 for b in record_bindings
                                        if b["signature"].get("original_signature_preserved")),
        },
        "note": ("Sanitized records are DERIVED artifacts, kept byte-identical to the original when no "
                 "redaction was needed. A preserved signature is verified against the matching "
                 "records_sanitized.json entry (which equals the original bytes for a non-redacted "
                 "record; recompute its evidence_hash to confirm it matches original_evidence_hash). A "
                 "redacted record carries no original signature by construction, and its stored "
                 "evidence_hash is the ORIGINAL (it will not match the redacted content, by design)."),
    }
    _write_file(dest_real, "export_manifest.json",
                json.dumps(binding_manifest, sort_keys=True, indent=2).encode("utf-8"), checksums)

    # SHA-256 checksums over every emitted file (R9). Written last; lists all siblings.
    checksums_doc = {"algorithm": "sha256", "files": checksums}
    with open(os.path.join(dest_real, "CHECKSUMS.sha256.json"), "wb") as fh:
        fh.write(json.dumps(checksums_doc, sort_keys=True, indent=2).encode("utf-8"))

    binding_manifest["export_dir"] = dest_real
    binding_manifest["checksums"] = checksums
    if not allow_ineligible and not binding_manifest["result_eligible"]:
        # Caller demanded an eligibility gate; the bundle exists but we signal the gate explicitly.
        binding_manifest["gated_ineligible"] = True
    return binding_manifest
