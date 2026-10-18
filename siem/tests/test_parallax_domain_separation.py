"""PARALLAX Phase 1D Workstream D - cryptographic context separation review.

Two parts:
  1. DETERMINE whether cross-context signature reuse is possible among the EXISTING signed artifact
     types. They are mutually non-verifiable because their canonical payloads have disjoint required
     fields (structural domain separation) - demonstrated here.
  2. The explicit domain-separation primitive (signing.sign_domain / verify_domain) for NEW types:
     round-trip, cross-domain rejection, kid-aware, and - critically - it does not change plain
     sign()/verify() or any existing signature (compatibility).
"""
import base64
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1d-domain")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402

import signing  # noqa: E402


def _seed_b64():
    k = Ed25519PrivateKey.generate()
    return base64.b64encode(
        k.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption())).decode()


@pytest.fixture(autouse=True)
def _reset_keys():
    yield
    signing._reset_registry()


# --- part 1: existing types are mutually non-verifiable (structural separation) ------------------
def test_existing_signed_types_do_not_cross_verify():
    # representative canonical shapes of the existing signed artifact types
    approval = {"competency": "agent-authz", "content_hash": "h", "assessment_id": "LAB-A", "version": 1}
    audit = {"stream": "parallax-governance", "seq": 0, "action": "approve_scoring_spec",
             "actor_id": "a", "subject_kind": "scoring_spec", "subject_ref": "h", "detail": {},
             "parent_hash": None}
    decision = {"pathway": "parallax", "unit_ref": "LAB-A@1", "decision": {"qualified": False}}
    sigs = {k: signing.sign(v) for k, v in (("approval", approval), ("audit", audit),
                                            ("decision", decision))}
    payloads = {"approval": approval, "audit": audit, "decision": decision}
    # each signature verifies ONLY its own payload; no cross-type verification
    for sk, sig in sigs.items():
        for pk, pl in payloads.items():
            assert signing.verify(pl, sig) is (sk == pk), (sk, pk)


# --- part 2: explicit domain-separation primitive for new types ----------------------------------
def test_domain_round_trip_and_cross_domain_rejection():
    A = _seed_b64()
    signing._install_registry([{"kid": "A", "state": "active", "seed_b64": A}], "A")
    payload = {"x": 1, "ctx": "demo"}
    sig, kid = signing.sign_domain("parallax.newtype.v1", payload)
    assert kid == "A"
    assert signing.verify_domain("parallax.newtype.v1", payload, sig, kid="A") is True
    # a different domain label fails closed
    assert signing.verify_domain("parallax.newtype.v2", payload, sig, kid="A") is False
    assert signing.verify_domain("strata.newtype.v1", payload, sig, kid="A") is False
    # a plain (non-domain) verify of the same payload must NOT accept a domain signature, and vice versa
    assert signing.verify(payload, sig, kid="A") is False
    plain = signing.sign(payload)
    assert signing.verify_domain("parallax.newtype.v1", payload, plain, kid="A") is False


def test_domain_separation_is_kid_aware_and_fails_closed_on_rotation():
    A, B = _seed_b64(), _seed_b64()
    signing._install_registry([{"kid": "A", "state": "active", "seed_b64": A}], "A")
    payload = {"n": 7}
    sig, _ = signing.sign_domain("parallax.newtype.v1", payload)
    # rotate: A verify_only, B active -> historical domain signature still verifies under A
    signing._install_registry([{"kid": "A", "state": "verify_only", "seed_b64": A},
                               {"kid": "B", "state": "active", "seed_b64": B}], "B")
    assert signing.verify_domain("parallax.newtype.v1", payload, sig, kid="A") is True
    # revoke A -> fails closed
    signing._install_registry([{"kid": "A", "state": "revoked", "seed_b64": A},
                               {"kid": "B", "state": "active", "seed_b64": B}], "B")
    assert signing.verify_domain("parallax.newtype.v1", payload, sig, kid="A") is False


def test_plain_signing_unchanged_by_domain_additions():
    # the default (no multi-key config) plain sign/verify path is byte-for-byte the pre-1D behavior:
    # a signature made by the raw Ed25519 key over canonical(payload) still verifies via verify().
    signing._reset_registry()
    payload = {"clearance": "board-2", "candidate": "gh-alice", "rank": 2}
    seed = signing._legacy_seed()
    raw_sig = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(seed[:32]).sign(signing.canonical(payload))).decode()
    assert signing.verify(payload, raw_sig) is True          # STRATA-style signature unaffected
    assert signing.verify(payload, signing.sign(payload)) is True
