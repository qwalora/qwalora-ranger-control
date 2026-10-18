# PARALLAX Independent Audit-Anchor — Integration Design (Phase 1E Workstream E)

Status: **OPEN**. Phase 1D added the in-process export/verify interface (`parallax.audit_integrity.
export_anchor` / `verify_against_external_anchor` / `anchor_record`). This document specifies how an
*independent* anchor destination would integrate with Ranger's existing infrastructure, the threat it
closes, and why it remains OPEN until a founder authorizes a destination. No external or paid service is
activated by this phase.

## Why it is still OPEN

The Phase 1D threat model (`audit_integrity.THREAT_MODEL`) shows the in-DB, same-key checkpoint does NOT
mitigate **simultaneous compromise of the primary database and the signing key**: an attacker with both
can forge events and a matching checkpoint. Closing that gap requires a checkpoint commitment stored in
a trust domain the application principal does **not** control. No such destination is currently
provisioned or authorized in this environment, so the capability is OPEN. A destination controlled by
the same application principal is not an independent anchor.

## The nine integration questions

1. **What system currently owns the primary audit records?** The application's PostgreSQL database
   (`parallax_audit_events`, `parallax_audit_checkpoints`), written by the portal process.
2. **What signing authority protects checkpoints?** The single application Ed25519 key resolved by
   `signing` (the versioned key registry from Phase 1C). Events and checkpoints share this authority —
   the crux of the gap.
3. **What independent trust domain could store verified checkpoint commitments?** Candidates, in order
   of preference among existing/authorizable components: (a) object storage with Object-Lock / WORM
   immutability (e.g. a dedicated write-once bucket) administered by a different principal than the
   portal; (b) an append-only external log / transparency-log service; (c) the Ranger SIEM
   (OpenSearch) telemetry domain as a write-only anchor index, IF it is administered separately and is
   itself OPEN today. None is provisioned/authorized now.
4. **Who would administer that destination?** A principal distinct from the portal deploy identity
   (e.g. a security/ops owner), so a portal+DB compromise cannot also rewrite the anchor. This is a
   founder/ops decision, not a code change.
5. **How would checkpoint submission and verification operate?** On each `write_checkpoint`, the portal
   calls `export_anchor(db, sink=<independent sink>)`, emitting `anchor_record` (stream, event_count,
   head_hash, checkpoint_hash, ts, signing_kid — no secrets, no payloads). Verification periodically
   pulls the latest externally-held anchor and calls `verify_against_external_anchor(db, anchor)`; a
   `truncated`/`rewritten` result against a verifying in-DB checkpoint is positive evidence of a dual
   compromise.
6. **How would tampering, deletion, and rollback be detected?** The external anchor commits to a
   monotonic `event_count` + `head_hash`. Truncation ⇒ live count < anchored count. Head rewrite ⇒
   equal count, different head. Checkpoint rollback ⇒ the external anchor's `checkpoint_hash` chain
   (each checkpoint carries `prev_checkpoint_hash`) exposes a missing/younger checkpoint. Deletion of
   in-DB checkpoints is caught because the external anchor still commits to the prior state.
7. **How would anchoring behave during outages?** Export is best-effort and queued: if the independent
   sink is unreachable, checkpoints still commit locally and the un-exported anchors are retried; the
   verifier reports `no_external_anchor_since <ts>` (a degraded, visible state) rather than silently
   trusting the in-DB view. Anchoring is never on the critical path of an assessment.
8. **How would historical verification survive signing-key rotation?** The anchor records the
   `signing_kid`; verification uses the Phase 1C key registry, so an anchor signed by a rotated-out
   (verify_only/retired) key still verifies, and a revoked key fails closed — identical to event
   verification. The external store keeps anchors across rotations.
9. **What operational cost and security responsibilities would be introduced?** A small, separately
   administered write-once store (cost minimal); the responsibility to keep its admin principal
   disjoint from the portal's; a periodic verification job; and incident runbooks for an anchor
   mismatch. These are founder/ops commitments, not engineering unknowns.

## Safe internal preparation implemented now

- `export_anchor(db, sink)` / `anchor_record(cp)` emit a secrets-free commitment to any callable sink.
- `verify_against_external_anchor(db, anchor)` is the detection path and is unit-tested
  (`test_parallax_audit_trust_model.py`), including the dual-compromise scenario where only a
  pre-existing external anchor exposes truncation.
- The in-DB checkpoint is always labeled `not_independent_same_store_same_key` so it is never mistaken
  for an independent anchor.

## Founder decision required

Authorize and provision ONE independent, separately-administered anchor destination (option 3a/3b/3c),
name its administering principal, and approve the periodic verification job. Until then, protection
against simultaneous DB + signing-key compromise is **OPEN** and is not claimed.
