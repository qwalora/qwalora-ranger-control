# F3 — Secure Evidence Persistence & Provenance (implemented; for review)

Scope: **F3 only.** No paid object storage was provisioned (dev filesystem + an in-memory
S3-compatible fake exercise the full contract), so no provider-approval request is triggered. F4,
F5, Lab A/B, and paid LLM inference are not started. Reuses the existing `Case`/`CaseSubmission`,
`EvidenceArtifact`, Ed25519 signing, and the F1/F2 contracts — no second case or qualification
system. STRATA unchanged; PARALLAX qualification inactive.

## 1. Storage architecture — `siem/artifact_store.py`

Provider-neutral `ArtifactStore` (content-addressed, immutable, private; object key = `blob/<sha256>`):
- **Immutable content-addressed writes**, **server-computed SHA-256** during streaming (a
  candidate-supplied hash is never trusted), **bounded upload size** (abort on overflow),
  **streaming upload/download**, **dedup** (identical content stored once), **integrity verify**
  (re-read bytes, recompute digest), **retention/deletion** via guarded `delete`, and a **scoped
  short-lived access-grant** descriptor (`presign`) where the backend supports it.
- `FilesystemArtifactStore` — deterministic dev/test backend. Strict **path containment** (keys
  must match `blob/<hex64>`; resolved path must stay under `<root>/blob`), **atomic publish**
  (temp file + fsync + rename, so an interrupted or oversized upload leaves **no** visible object
  and no temp residue), private file mode, no public serving.
- `S3ArtifactStore` — S3-compatible, driven by an **injected client** (`put/get/head/delete/
  generate_presigned_url`). No bucket is provisioned and no network call is made here; inject a
  configured client at deploy time (or a fake in tests). Without a client it **fails closed**
  (`NOT_PROVISIONED`). Same content-addressed + server-hash + size-cap contract, so future S3
  deployment is a config change, not a redesign.
- Uploaded content is never executed, decompressed, or rendered.

## 2. Secure acquisition — `siem/evidence_persistence.acquire`

The server independently computes the SHA-256, **sniffs the file signature** (magic bytes, not the
declared MIME/filename), enforces the per-category size cap, and validates the format against the
`EVIDENCE_TYPES` allowlist. Malformed, truncated, oversized, unsupported-container, and partial
uploads fail safely with nothing persisted (atomic store). Duplicate content dedups. An
artifact is marked **`scan_state="unscanned"`** and **`validation_state="needs_review"`** (never
auto-`validated`) until an approved malware-scan policy runs — unscanned evidence does not satisfy
a `validated` evidence requirement.

## 3. Evidence provenance — signed chain of custody

Integrated with `EvidenceArtifact` + `Case` + Ed25519 signing. Each artifact records source
identity + acquisition context, candidate/cohort/pathway ownership, original content digest,
immutable object version, parent references + transformation type + tool version (derived), derived
hashes, acquisition/preservation timestamps, authorization + retention metadata. `CustodyEvent`
(new table) is an **append-only, signed** chain — events are never mutated; each references the
prior by `parent_hash` (`verify_custody_chain`). **Deriving never overwrites the source**:
`persist_derived` writes a new object + envelope referencing the parent and emits a `derive` event
with the transform + tool version.

## 4. Secure retrieval — `retrieve` / `issue_access_grant`

All retrieval passes Ranger server-side authorization (`evidence_types.authorize_access`):
ownership, cohort isolation, pathway restriction, revocation, retention. The storage path and any
credentials are never exposed to the caller — only bytes are returned, after an on-read integrity
re-verify (a hash mismatch yields `corrupted` + a `quarantine` custody event, not data). Presigned
grants are issued **only after authorization**, scoped to one object + operation, short-lived.
**Revocation limitation (documented):** an already-issued presigned grant cannot be revoked before
its TTL expires without rotating the backend credential/policy — so TTLs are kept short.

## 5. Integrity & retention

`reverify` independently re-checks stored bytes against the preserved hash and returns
`ok | missing | corrupted | revoked | expired`; retrieval refuses anything but `ok`. `can_delete`/
`delete_evidence` enforce an explicit retention policy: evidence in `active_assessment` or
`signed_qualification` classes is **never auto-deletable** (only after an explicit expiry), deletion
needs an authorized reason, and **case submission or cohort retirement is not a reason**.
Integrity-repair note: because the store is content-addressed and dedups by key, re-putting
identical bytes will not overwrite a corrupted object — repair is an explicit delete + re-ingest.

## 6. Schema changes (additive)

- `EvidenceArtifact` gains `object_key`, `storage_backend`, `scan_state`, `transform`,
  `tool_version`, `retention_class` (idempotent `ensure_schema` ALTERs; no existing column changed).
- New `CustodyEvent` table (append-only signed chain). Created by `create_all`; no existing table
  altered. Validated on real PostgreSQL 16 (tables + columns) and SQLite.

## 7. Tests (real bytes) & end-to-end demo

`siem/tests/test_evidence_persistence.py` — 42 checks, real bytes, both adapters: streaming
up/download; duplicate content; content-hash mismatch / corruption at rest; interrupted write
(atomic, no object, no temp residue); unauthorized + cross-candidate + cross-cohort + cross-pathway
access; forged artifact reference (hash mismatch → corrupted + quarantine); missing object; path
traversal / malformed keys; malformed + oversized media; immutable source on derive; derived-artifact
provenance (lineage + transform + tool version); signed custody chain + tamper detection;
revoked/expired; retention/deletion constraints; **restart persistence + recovery** (a new store
instance over the same root recovers + re-verifies objects); `NOT_PROVISIONED` fail-closed; presign
revocation descriptor. End-to-end demo persists `EvidenceArtifact` + `CustodyEvent` to the DB,
retrieves under authorization, derives, and integrates with the assessment contract (unscanned
evidence not yet usable; a validated artifact drives a **met** assessment with PARALLAX
qualification still **inactive**). Full offline suite green; F3 + migration also green on Postgres.

## Restrictions honored / blockers

- No paid object storage provisioned; candidate access and paid infra stay disabled; STRATA
  behavior and PARALLAX inactivity preserved; all existing gates held.
- If/when real external object storage is needed, that requires a separate approval with provider,
  configuration, expected cost, and security implications — not triggered by F3 (dev FS + injected
  S3 client suffice for the interface and tests).
- Not started: F4 forensic processing, F5 candidate workbench, Lab A, Lab B, paid inference. The
  media/agent/RAG/artifact evaluators remain declared and gated.

Stop here for review after F3.
