"""PARALLAX - Qwalora Ranger's AI-engineering qualification track.

A second qualification pathway that shares the Ranger platform with STRATA (cybersecurity) while
staying architecturally distinct. PARALLAX reuses the platform's pathway-neutral primitives rather
than duplicating them:

  - pathway identity:        `pathways.PATHWAY_PARALLAX` / `normalize_pathway`
  - qualification engine:    `siem.assessment_contract.decide` (PARALLAX policy branch + platform gate)
  - objective-check contract:`siem.evaluator` (Evaluator / signed ObjectiveCheckResult / integrity)
  - signing:                 top-level `signing` (Ed25519)
  - contract integrity MAC:  `siem.schema.keyed_mac`
  - qualification record:    `models.UnitResult` (pathway-scoped, signed, append-only)

This package adds only what is genuinely PARALLAX-specific: per-candidate ASSESSMENT INSTANCES with a
sealed holdout (`px1_dataset`), the PX-1 instance binding (`contracts`), the PX-1 objective ML
evaluation + leakage veto (`px1_score`, `px1_evaluator`), the PX-1 blueprint (`px1_blueprint`), the
candidate-safe brief (`brief`), and the end-to-end orchestration (`px1_assessment`).

Hard isolation invariant (enforced by `assessment_contract.decide`): a PARALLAX decision requires a
PARALLAX-scoped authorization and a PARALLAX blueprint, so a PARALLAX submission can never award
STRATA credit and vice versa. FINAL PARALLAX qualification is withheld until the separately-approved
platform gate `RANGER_PARALLAX_QUALIFICATION_ACTIVE` is set; until then PARALLAX yields a signed
ASSESSMENT RESULT but never `qualified=True`. Phase 1 enables no public enrollment and no real awards.
"""
import pathways

PATHWAY = pathways.PATHWAY_PARALLAX

__all__ = ["PATHWAY"]
