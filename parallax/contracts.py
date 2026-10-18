"""PARALLAX assessment specs and integrity-verified instance contracts (PX-1 and later).

Mirrors the STRATA governance pattern - a versioned, approval-gated spec pinned to a per-attempt
generation contract whose integrity is a keyed MAC - but reuses the platform's single keyed primitive
`siem.schema.keyed_mac` (the same one STRATA's generation-contract integrity uses) instead of a second
keying scheme. STRATA's assignment is board-keyed; PARALLAX instances are keyed on (assessment, cohort,
candidate, attempt), so the two never collide.

The per-candidate seed is derived from the keyed MAC of the binding identity, so (a) every
(candidate, attempt) gets a distinct instance (non-transfer / cohort isolation), (b) the grader
reproduces the exact instance from the signed contract, and (c) without the server key the seed is not
predictable from public fields.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional

import pathways
from siem.schema import keyed_mac

CONTRACT_VERSION = 1


@dataclass(frozen=True)
class AssessmentSpec:
    """A versioned, approval-gated PARALLAX assessment specification."""
    assessment_id: str              # e.g. "PX-1"
    version: str                    # semantic version, e.g. "1.0.0"
    title: str
    competency: str                 # the competency domain this measures
    metric: str                     # headline metric, e.g. "roc_auc"
    pass_threshold: float           # minimum holdout metric for an objective pass
    params: Dict[str, Any] = field(default_factory=dict)
    approved: bool = False          # only approved specs may bind

    def content_hash(self) -> str:
        """Stable hash of the graded content. A change here is a new spec version; a binding pinned to
        an old content_hash is refused if the spec was edited after assignment (drift)."""
        payload = {"assessment_id": self.assessment_id, "version": self.version,
                   "metric": self.metric, "pass_threshold": self.pass_threshold,
                   "params": self.params}
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class ContractError(Exception):
    """Raised when an instance contract fails integrity verification or references a drifted spec."""


@dataclass(frozen=True)
class GenerationContract:
    """A pinned, integrity-verified PARALLAX instance contract. `verify()`/`resolve()` fail closed."""
    assessment_id: str
    spec_version: str
    content_hash: str
    pathway: str
    cohort: str
    candidate_key: str
    attempt: int
    params: Dict[str, Any] = field(default_factory=dict)
    contract_version: int = CONTRACT_VERSION
    mac: Optional[str] = None

    def _mac_payload(self) -> bytes:
        body = {"assessment_id": self.assessment_id, "spec_version": self.spec_version,
                "content_hash": self.content_hash, "pathway": self.pathway, "cohort": self.cohort,
                "candidate_key": self.candidate_key, "attempt": self.attempt, "params": self.params,
                "contract_version": self.contract_version}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_mac(self) -> str:
        return keyed_mac(self._mac_payload())

    def signed(self) -> "GenerationContract":
        return GenerationContract(**{**asdict(self), "mac": self.compute_mac()})

    def verify(self) -> None:
        if pathways.normalize_pathway(self.pathway) != pathways.PATHWAY_PARALLAX:
            raise ContractError("contract pathway is not parallax: %r" % self.pathway)
        if not self.mac or not hmac.compare_digest(self.mac, self.compute_mac()):
            raise ContractError("instance contract integrity check failed (tampered or wrong key)")

    def seed(self) -> int:
        """Deterministic per-instance seed, keyed so it is not predictable from public fields."""
        return int(keyed_mac(b"parallax-seed\x1f" + self._mac_payload())[:16], 16)


def bind(spec: AssessmentSpec, *, cohort: str, candidate_key: str, attempt: int = 1,
         pathway: str = pathways.PATHWAY_PARALLAX) -> GenerationContract:
    """Mint a signed instance contract for a candidate's attempt at an APPROVED PARALLAX spec. This is
    the only place an instance is minted, so an unapproved or cross-pathway spec can never produce one."""
    if pathways.normalize_pathway(pathway) != pathways.PATHWAY_PARALLAX:
        raise ContractError("PARALLAX bindings are parallax-only; refused pathway %r" % pathway)
    if not spec.approved:
        raise ContractError("refusing to bind an unapproved assessment spec %s@%s"
                            % (spec.assessment_id, spec.version))
    return GenerationContract(
        assessment_id=spec.assessment_id, spec_version=spec.version, content_hash=spec.content_hash(),
        pathway=pathways.PATHWAY_PARALLAX, cohort=cohort, candidate_key=candidate_key,
        attempt=attempt, params=dict(spec.params)).signed()


def resolve(spec: AssessmentSpec, contract: GenerationContract) -> GenerationContract:
    """Verify a contract against the current spec. Fails closed on an integrity failure or on
    content-hash drift (the spec was edited/superseded after the binding was minted)."""
    contract.verify()
    if contract.assessment_id != spec.assessment_id:
        raise ContractError("contract/spec assessment mismatch")
    if contract.content_hash != spec.content_hash():
        raise ContractError("spec content drifted since binding; refusing a mismatched instance")
    return contract
