# PARALLAX evidence verification and sanitized export

A standalone, **read-only** tool (`parallax/research/evidence_verifier.py`, CLI
`scripts/research/verify_evidence.py`) that lets a third party independently verify a campaign's
on-disk evidence and produce a reviewer-ready, sanitized export bundle. It never writes to, repairs,
reorders, re-signs, or deletes the original evidence; verification only reads, and export writes only
to a destination the caller names.

It operates on the artifacts written by `CampaignRunner` (`records.jsonl`, `state.json`,
`ledger.jsonl`, `manifest.json`). It does not import or modify the statistical inference layer (whose
v2.3 calibration phase is permanently closed) and does not touch signing keys or any signed historical
record.

## Trust model

Trust is an **input, not an ambient capability**. The verifier checks signatures only against public
keys the caller EXPLICITLY supplies (`--trusted-keys`), never against the running process's own signing
registry. The preregistered plan (`--plan`) is likewise supplied independently of the evidence, so a
campaign cannot self-attest its own completeness. Everything fails **closed**: any parse error, hash
mismatch, unknown key, unsafe path, or ambiguous state degrades the verdict rather than being tolerated.

## Requirement mapping

| # | Requirement | Where |
|---|---|---|
| R1 | Full-record integrity + checkpoint-chain continuity | `load_evidence` recomputes each `evidence_hash = sha256(canonical(record\evidence_hash))`; `_chain_fold` reproduces the order-sensitive chain head and compares it to `state.json.chain_head`. |
| R2 | Verify signatures against explicitly trusted public keys | `classify_signature` verifies via `signing.verify(record, sig, public_key_b64_str=...)` against the supplied `trusted_keys` only. |
| R3 | Distinguish unsigned / valid / invalid / incomplete / unverifiable | Five-state classifier; "we could not check" (`unverifiable`) is kept distinct from "we checked and it failed" (`invalid`). |
| R4 | Verify full-record, reproducible-content, and config-identity commitments | Recomputed with `commitments.commitments()` and compared against `--commitments`. |
| R5 | Detect missing / duplicate / reordered / corrupted / substituted records | Corruption via hash recompute; duplicates via unit-key multiset; reordering via a bounded permutation search that reproduces the committed head from the same multiset; missing/substituted via plan reconciliation. |
| R6 | Validate completion separately from scientific-result eligibility | `_assess_completion` (all planned trials accounted for + chain intact) vs `_assess_eligibility` (strictly stronger: real backend, exclusion rate within ceiling, integrity clean). A complete simulated campaign is complete but **not eligible**. |
| R7 | Reconcile failure ledger / exclusions against all planned trials | `_reconcile`: every planned unit is a record XOR a ledgered exclusion; surfaces `unaccounted`, `double_counted`, `exclusions_off_plan`. |
| R8 | Sanitized, reviewer-ready export bundle | `build_sanitized_export` writes a separate derived bundle; redaction is explicit and per-value logged. |
| R9 | Machine-readable results, file manifest, SHA-256 checksums, provenance | `verification_report.json`, `export_manifest.json`, `CHECKSUMS.sha256.json`, reconciliation + ledger. |
| R10 | Reject tampered evidence and unsafe export paths | Export refuses unless `integrity_ok`; `assert_safe_export_dir` / `assert_safe_archive_member` block traversal, symlinks, non-empty and in-source destinations, and zip-slip member names. |

## Signature states

`unsigned` (no signature supplied) · `valid` (verifies under an explicitly trusted key) · `invalid`
(checked against the relevant trusted key and failed) · `incomplete` (signature material malformed) ·
`unverifiable` (no trusted key available, or the sidecar names a kid outside the trusted set, so the
verifier refuses to check against keys it does not trust).

## Export-security guarantees

- The original evidence directory is only read; redactions apply to deep copies.
- Redaction is explicit and **auditable**: `export_manifest.json` logs, per record, every redacted path,
  the pattern class matched, and the SHA-256 of the original value (so a reviewer can confirm what was
  removed without seeing it). High-confidence secrets (GitHub/Slack/AWS tokens, internal Railway hosts,
  private/loopback URLs) found inside protected scientific fields (hashes, outcomes, decoding params)
  **fail the export closed** rather than being leaked or silently rewritten; low-confidence heuristics
  (base64 blobs, home paths) never touch protected content, so a legitimate SHA-256 digest is never
  mistaken for a secret.
- The sanitized bundle is **bound** to the original via per-record `original_evidence_hash` +
  `sanitized_sha256` + redaction log. An original signature is reported as preserved **only** when the
  record's bytes were not changed; a redacted record explicitly carries
  `original_signature_preserved: false`. A preserved signature must be verified against the *original*
  record bytes (identified by `original_evidence_hash`), never against the sanitized record.
- Failures are **never dropped** from the exported accounting: the failure ledger and the plan
  reconciliation travel with the bundle (the ledger's free-text errors are themselves scrubbed of infra
  leaks, but no entry is removed).
- Path hardening: destination must be new/empty, not a symlink (nor under a symlinked parent), and not
  inside the source evidence directory; every write is confined to the destination; archive member
  names are rejected if absolute or containing `..`.

## CLI

```
python -m scripts.research.verify_evidence <evidence_dir> \
    --trusted-keys trusted_keys.json --signatures signatures.json \
    --plan plan.json --commitments commitments.json \
    --export out_dir --report-out report.json [--require-eligible]
```
Exit 0 on overall PASS (and, with `--require-eligible`, scientifically eligible); 1 otherwise; 2 on a
refused/unsafe operation. No network calls; writes only to `--report-out` and `--export`.

## Independent verification against synthetic evidence

Run on a freshly produced 6-trial synthetic campaign (deterministic stub backend; a fresh Ed25519 key
supplied as the only trusted key; preregistered plan and recomputed commitments provided):

```
OVERALL           PASS
signatures        unsigned=0 valid=6 invalid=0 incomplete=0 unverifiable=0
chain continuous  True
reconciliation    planned=6 with_record=6 excluded=0 unaccounted=0 double_counted=0
campaign_complete True
result_eligible   False  -> "no real-backend records (simulated plumbing is never a finding)"
```

This is the correct, honest outcome: the evidence is intact, signed, and complete, yet **not
scientifically eligible** because the backend was simulated. Completion and eligibility are reported
separately, by design.

## Adversarial test coverage

`tests/test_evidence_verifier.py` (26 tests) exercises: the five signature states; corrupted,
unparseable, duplicated, reordered, and chain-broken records; tampered `state.json` and tampered
commitments; missing/unaccounted trials and ledger reconciliation (excluded, double-counted, off-plan);
export path attacks (traversal into source, symlinked destination, symlinked parent, non-empty
destination) and zip-slip member names; refusal to export tampered evidence; auditable redaction with
signature preservation only on unchanged bytes; a high-confidence secret in protected content failing
closed; and failures surviving into the export with infra leaks scrubbed from the ledger.

## Scope and standing constraints

Read-only; no merges, deployments, real-model runs, or infrastructure provisioning. Does not modify the
statistical inference layer or its permanent stopping rule, signed historical evidence, or signing keys.
Delivered on `feature/parallax-evidence-verification` as a draft PR.
