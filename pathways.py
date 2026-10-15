"""Canonical Ranger pathway identity (single source of truth).

RANGER is the master qualification brand. It has two pathways, each with a STABLE
INTERNAL ID that is the only value ever used in authorization, grading, qualification,
persistence, validation, catalog records, and tests:

  strata    - RANGER STRATA  - the existing 26-week, six-board enterprise-defense /
              adversarial-systems program (OpenSearch SOC, future Ludus/GOAD). Its
              curriculum, grading, and 95% qualification standard are unchanged.
  parallax  - RANGER PARALLAX - the digital-forensics & AI-security pathway (deepfake
              investigation, synthetic-identity fraud, LLM/agent security, adversarial
              AI assessment). Independently defined curriculum, assessment blueprint,
              evidence requirements, and qualification policy. It does NOT inherit the
              six-board sequence or STRATA's 95% bar.

Design rules this module enforces:
  1. Logic uses IDs, never marketing names. Public branding labels (PATHWAY_BRANDING)
     are display-only and configurable independently of the IDs; nothing in authz,
     grading, or qualification may branch on them.
  2. Backward compatibility is non-destructive. Earlier foundation code persisted the
     interim ids 'cyber-ops' / 'cyber-ai'. LEGACY_PATHWAY_ALIASES maps them to the
     canonical ids at read time via normalize_pathway(), so correctness never depends
     on rewriting any row. A data realignment (if run) is an optional, reversible
     UPDATE, not required for the system to be correct.
"""
from __future__ import annotations

PATHWAY_STRATA = "strata"
PATHWAY_PARALLAX = "parallax"
PATHWAYS = (PATHWAY_STRATA, PATHWAY_PARALLAX)
DEFAULT_PATHWAY = PATHWAY_STRATA

# Interim ids used by the pre-naming foundation (commit 5518796) -> canonical ids.
# Read-time normalization only; no destructive migration implied.
LEGACY_PATHWAY_ALIASES = {
    "cyber-ops": PATHWAY_STRATA,
    "cyber-ai": PATHWAY_PARALLAX,
}


def normalize_pathway(value) -> str:
    """Canonicalize any stored/supplied pathway value. None -> default; legacy interim
    ids -> their canonical id; everything else lower-cased and trimmed. Pure; safe to
    call on every read so a legacy 'cyber-ops' row behaves exactly like 'strata'."""
    if value is None:
        return DEFAULT_PATHWAY
    v = str(value).strip().lower()
    if not v:
        return DEFAULT_PATHWAY
    return LEGACY_PATHWAY_ALIASES.get(v, v)


def is_valid_pathway(value) -> bool:
    """True if value canonicalizes to a known pathway (legacy ids accepted)."""
    return normalize_pathway(value) in PATHWAYS


# Display-only. Configurable independently of the stable ids; NEVER referenced by
# authorization, grading, or qualification logic. Names are approved for the current
# working design, subject to final branding clearance before public launch.
PATHWAY_BRANDING = {
    PATHWAY_STRATA: {
        "name": "RANGER STRATA",
        "tagline": "Enterprise Defense & Adversarial Systems",
    },
    PATHWAY_PARALLAX: {
        "name": "RANGER PARALLAX",
        "tagline": "Synthetic Reality, AI Systems & Digital Trust",
    },
}


def branding(pathway) -> dict:
    """Display label/tagline for a pathway id (legacy ids normalized). Display only."""
    return PATHWAY_BRANDING.get(normalize_pathway(pathway), {"name": "", "tagline": ""})
