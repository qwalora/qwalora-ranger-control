# F2 — Typed Evidence & Media Artifact Interfaces (implemented; for review)

Scope: **F2 only.** F3, Lab A, Lab B, paid inference, media-processing workloads, candidate
activation, and infrastructure purchases are not started. One evidence architecture for both
pathways; reuses `Case`/`CaseSubmission`, the preserved-evidence record (`case_contract`), Ed25519
signing, and the F1 assessment contract — not a parallel system. STRATA unchanged; PARALLAX
qualification stays inactive.

## F1 corrections landed first

1. **Qualification ambiguity closed.** `decide()` now returns `assessment_outcome` /
   `assessment_passed` separately from `qualified`. A PARALLAX decision can be a signed,
   independently verifiable **assessment result** while `qualified=False`
   (`reason="qualification_inactive"`). Final PARALLAX qualification is gated by a platform-level
   flag `parallax_qualification_active()` (env `RANGER_PARALLAX_QUALIFICATION_ACTIVE`, **off**),
   which no blueprint field, score, remediation, reviewer approval, or signature can bypass —
   proven by `test_assessment_contract.py` ("no combination bypasses the inactive gate"; platform
   activation is the sole control). STRATA (`PASS_BAR=95.0`) unchanged.
2. **Unauthorized evidence rejected explicitly, fail-closed.** The evaluator no longer silently
   strips out-of-scope citations and grades the rest. Any citation outside the evaluator's scoped
   index is an explicit validation failure **before any data access** (`data_accessed: False`),
   recorded as salted one-way fingerprints so the failure never reveals whether another candidate's
   evidence exists. Protected truth remains server-side only.
3. **Migration-wide atomicity.** `normalize_persisted_pathways` now runs **all** pathway-bearing
   tables in a single transaction (all tables migrate or none); a failure on the second table rolls
   back the first. Validated on real PostgreSQL (`test_pathway_migration_pg.py`). Startup stays
   detection-only; the remap runs only under explicit authorization.

## Evidence schema & interfaces (`siem/evidence_types.py`)

A versioned, typed envelope; large/binary payloads are referenced by a content-addressed **BlobRef**
(object storage not provisioned here — interface + validation only).

Categories (`EVIDENCE_TYPES`): `opensearch_event`, `opensearch_finding`, `media_audio`,
`media_video`, `media_image`, `forensic_metadata`, `provenance_manifest`, `model_trace`,
`agent_trace`, `tool_authorization`, `api_execution`, `config_system_state`, `technical_report`,
`derived_artifact`. Each declares whether it needs a BlobRef, its allowed media types, and a size
cap.

Envelope fields (every artifact): `evidence_id`, `evidence_type`, `evidence_schema_version`,
`contract_version`, `case_id`, `candidate_id` (ownership), `cohort` + `pathway` (authorization),
`source_identity`, `provenance`, `content_hash` (sha256), `acquisition_ts`, `version` (immutable),
`validation_state`, `parent_case`, `derived_from` (lineage), `supersedes`, `blob_ref`,
`authenticity_assessment` (advisory only).

BlobRef: `{uri, sha256, media_type, bytes, provenance, rights_consent, authenticity_assessment?}` —
`uri` must be a safe content-addressed key (`blob/…`; no traversal, scheme, or absolute path).

Interfaces: `new_artifact`, `validate_artifact`, `blob_ref`, `sign_artifact`/`verify_artifact`
(immutable), `revise` (new version, supersedes prior), `derive` (lineage-preserving derived
artifact), `authorize_access`, `interpret_provenance`, `satisfies_requirement` (assessment
integration). Persistence: additive `models.EvidenceArtifact` (BlobRef columns only; no bytes in DB;
bound to `Case` + owner + cohort + pathway).

## Security & validation

- Content-type verification against a per-category allowlist (unsafe formats, e.g. `image/svg+xml`,
  rejected); per-category size caps; path-traversal-safe BlobRef uris only.
- Tamper check: BlobRef `sha256` must equal the envelope `content_hash` (forged hash → rejected).
- Immutability: a signed artifact cannot be mutated without breaking its signature; revisions create
  a new version that `supersedes` the prior.
- Unsupported contract/schema/evidence-type/evaluator → fail closed.
- Authorization: ownership (same candidate), cohort isolation, pathway isolation, reviewer scope;
  revoked and past-retention access denied. Cross-candidate/cohort/pathway all denied.
- **Authenticity is never inferred unsafely:** a missing C2PA/provenance manifest yields
  `provenance_verdict="indeterminate"` (never "manipulated"); a model authenticity score is stored
  and reported **advisory-only** and never sets an authoritative `validation_state`; a non-advisory
  authenticity claim is rejected.

## Integration with the assessment contract

`satisfies_requirement(artifact, requirement, requester)` connects a typed artifact to a blueprint
`evidence_requirements` entry: the artifact must be the required type, validate, be in
`validated` state, and the requester must be authorized. Demonstrated end to end: a validated,
authorized media artifact satisfies a requirement → the objective check passes → the PARALLAX
decision's `assessment_outcome="met"` while `qualified=False` (gate inactive).

## Validation evidence

- `siem/tests/test_evidence_types.py` — 33 checks (malformed refs; cross-candidate/cohort/pathway
  isolation; forged hashes; unauthorized artifacts; immutable versioned revisions + signature
  tamper; unsupported artifact/contract/schema versions; revoked/expired; media safety:
  content-type, size, path traversal, unsafe format; C2PA-missing ≠ manipulated; advisory-only
  model scores; unsupported evaluator fails closed; PARALLAX inactive; STRATA unchanged;
  persistence).
- `siem/tests/test_assessment_contract.py` — 30 (incl. the F1 corrections and the inactive-gate
  bypass tests). `siem/tests/test_pathway_migration_pg.py` — 9 on **real PostgreSQL 16** (incl.
  migration-wide atomicity). Full offline suite green; contract + evidence also green on Postgres.

## Remaining implementation blockers (next milestones, each separately gated)

- **Object storage** for BlobRef payloads is not provisioned (needs cost approval); the interface
  and validation are ready but no bytes are stored yet.
- **F3** secure media/artifact persistence + provenance pipeline; **F4** bounded forensic
  processing; **F5** candidate workbench; **Lab A/Lab B** — not started.
- The media/agent/RAG/artifact evaluators remain **declared and gated** (raise) until their lab
  milestones build and verify them.

Stop here for review after F2. Do not begin F3 or any paid/infra work.
