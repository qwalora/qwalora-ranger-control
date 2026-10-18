"""PARALLAX - Qwalora Ranger's AI-security / adversarial-systems / digital-trust qualification track.

A second qualification pathway that shares the Ranger platform with STRATA (cybersecurity) while
staying architecturally distinct. PARALLAX reuses the platform's pathway-neutral primitives rather
than duplicating them:

  - pathway identity:        `pathways.PATHWAY_PARALLAX` / `normalize_pathway`
  - assessment engine:       `siem.assessment_contract.decide` (PARALLAX policy branch + platform gate)
  - objective-check contract:`siem.evaluator` (Evaluator / signed ObjectiveCheckResult / integrity)
  - signing:                 top-level `signing` (Ed25519)
  - contract integrity MAC:  `siem.schema.keyed_mac`
  - signed record of work:   `models.UnitResult` (pathway-scoped, signed, append-only)

PARALLAX-specific assessment labs: Lab A (`laba_*`) exercises agent/tool-authorization security and
retrieval (RAG) trust-boundary analysis; PX-1 (`px1_*`, `contracts`, `px1_dataset`) is retained as an
EXPERIMENTAL ML-engineering instance, not a general-ML qualification.

Two independent boundaries, each enforced separately (Phase-1 qualification-boundary closure):

  1. ASSESSMENT vs QUALIFICATION. A single assessment is evidence of one competency, never a
     qualification. `assessment_contract.decide` on the PARALLAX branch therefore returns
     `qualified=False` for every individual assessment regardless of any flag; it yields a signed
     ASSESSMENT RESULT, nothing more. No single assessment can independently establish pathway
     qualification.
  2. PATHWAY QUALIFICATION. A pathway award is decided only by `pathway_qualification.decide_pathway`
     over (a) a signed, versioned, authorized PORTFOLIO policy binding the exact required-competency
     inventory - never a hardcoded `approved=True` - (b) the candidate's persisted, signature-valid
     assessment records covering that inventory, and (c) the separately-approved activation gate
     `RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE`. No approved PARALLAX portfolio exists, so pathway
     qualification is impossible by construction, independent of either flag.

Hard isolation invariant (enforced by `assessment_contract.decide`): a PARALLAX decision requires a
PARALLAX-scoped authorization and a PARALLAX blueprint, so a PARALLAX submission can never award
STRATA credit and vice versa.

Phase 1B makes the governance, reviewer-authority and assessment-evidence layers DURABLE and
independently verifiable across restarts and concurrent operations, all server-side:

  - `registry`            persistent, signed, authorized-admin-bound scoring-spec and portfolio
                          approvals (`models.ParallaxApproval`), immutable content + revocable status.
  - `reviewer_store`      authoritative reviewer identity and assignment
                          (`models.ParallaxReviewerAssignment`) bound to AdminUser authority.
  - `assessment_store`    durable signed assessment records persisted in `models.UnitResult`,
                          idempotent and substitution-proof, re-verified on read.
  - `pathway_persistent`  `decide_pathway` fed entirely from persisted, verified records; fails closed.
  - `auditlog`            append-only, signed, hash-chained governance/reviewer audit trail
                          (`models.ParallaxAuditEvent`).

Phase 1 / 1B enable no public enrollment and no real awards.
"""
import pathways

PATHWAY = pathways.PATHWAY_PARALLAX

__all__ = ["PATHWAY"]
