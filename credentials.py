"""Portable, externally verifiable credentials for Qwalora Ranger.

A Badge is already signed at mint time (Ed25519 over a canonical claim, see app._mint_badge).
This module exports that signed badge as a standards-shaped credential (W3C Verifiable
Credentials / Open Badges 3.0) that ANY third party can verify OFFLINE against the
platform's published Ed25519 public key, without trusting a Ranger web page.

It never re-signs and never changes how badges are minted. It reproduces the exact bytes
that were signed and carries the ORIGINAL signature as the proof, plus the public key that
verifies it. Verification is therefore a pure cryptographic check a verifier can run with
nothing but a standard Ed25519 library:

    canon = json.dumps(proof["signedClaim"], sort_keys=True, separators=(",", ":")).encode()
    Ed25519PublicKey.from_public_bytes(b64decode(proof["publicKeyBase64"])).verify(
        b64decode(proof["proofValue"]), canon)

The public key set is published at /.well-known/ranger-credentials.json so a verifier can
pin the issuer's trusted keys across rotation and confirm the key in a credential is one of
them.
"""
import datetime as _dt

import signing

ISSUER_ID = "https://ranger.qwalora.com"
ISSUER_NAME = "Qwalora Ranger"
PROOF_TYPE = "RangerEd25519Signature2020"
OB_CONTEXT = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"


def iso(dt):
    """UTC ISO string identical to app._iso, so a reproduced claim signs/verifies identically
    regardless of DB backend (SQLite reads timestamps back naive)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).isoformat()


def badge_claim(handle, cohort, level, name, role, issued_at):
    """Reproduce EXACTLY the dict signed at mint time in app._mint_badge. Key order is
    irrelevant because signing.canonical sorts keys; the VALUES must match byte for byte."""
    return {"kind": "badge", "handle": handle, "cohort": cohort,
            "level": level, "name": name, "role": role,
            "issued_at": iso(issued_at)}


def verify_badge(handle, cohort, level, name, role, issued_at, signature, kid=None):
    """True if `signature` is a trusted Ed25519 signature over the reproduced badge claim."""
    claim = badge_claim(handle, cohort, level, name, role, issued_at)
    return bool(signing.verify(claim, signature, kid=kid))


def public_key_set():
    """The publishable trusted-key set (no private material), for /.well-known. Shapes the
    signing registry into an issuer-scoped document a verifier can pin."""
    return {"issuer": ISSUER_ID, "name": ISSUER_NAME, "alg": "Ed25519",
            "keys": signing.public_registry()}


def to_open_badge(*, handle, person_name, cohort, level, badge_name, role, issued_at,
                  signature, cert_id=None, base_url=None):
    """Export one signed badge as a self-contained, offline-verifiable Open Badge 3.0 credential.

    The ORIGINAL signed claim and signature are embedded under `proof`, together with the exact
    public key that verifies them, so no issuer endpoint has to be trusted or even reachable to
    verify. `kid` and the published key set let a verifier confirm the key is an issuer key.
    """
    base = (base_url or ISSUER_ID).rstrip("/")
    claim = badge_claim(handle, cohort, level, badge_name, role, issued_at)
    kid = signing.kid_for(claim, signature)            # which trusted key verifies it (None if none)
    pub = signing.public_key_b64(kid) if kid else signing.public_key_b64()
    cred_id = ("%s/credentials/%s" % (base, cert_id)) if cert_id else ("%s/verify/%s" % (base, handle))
    keyset_url = "%s/.well-known/ranger-credentials.json" % base
    return {
        "@context": [VC_CONTEXT, OB_CONTEXT],
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "id": cred_id,
        "issuer": {"id": ISSUER_ID, "type": ["Profile"], "name": ISSUER_NAME,
                   "url": base, "publicKeySet": keyset_url},
        "validFrom": iso(issued_at),
        "credentialSubject": {
            "type": ["AchievementSubject"],
            "identifier": handle,
            "name": person_name,
            "achievement": {
                "type": ["Achievement"],
                "id": "%s/achievements/%s" % (base, level),
                "name": badge_name,
                "description": role or badge_name,
                "criteria": {"id": "%s/handbook" % base},
            },
        },
        # Ranger-native, self-contained proof. A verifier recomputes the canonical bytes of
        # signedClaim and checks proofValue against publicKeyBase64 with any Ed25519 library.
        "proof": {
            "type": PROOF_TYPE,
            "cryptosuite": "ed25519",
            "created": iso(issued_at),
            "verificationMethod": "%s#%s" % (keyset_url, kid or "active"),
            "kid": kid,
            "publicKeyBase64": pub,
            "canonicalization": "json(sort_keys,separators=(',',':'),ensure_ascii)",
            "signedClaim": claim,
            "proofValue": signature,
        },
    }


def verify_open_badge(vc):
    """Offline verification of an exported credential: recompute the canonical bytes of the
    embedded signedClaim and check the Ed25519 signature against the issuer's trusted key set.
    Fail-closed on any missing field or error."""
    proof = (vc or {}).get("proof") or {}
    claim = proof.get("signedClaim")
    sig = proof.get("proofValue")
    if not isinstance(claim, dict) or not sig:
        return False
    return bool(signing.verify(claim, sig, kid=proof.get("kid")))
