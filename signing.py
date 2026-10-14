"""Ed25519 signing for board clearances and badges.

Every clearance and badge is signed so the public status page can verify it
in-browser and nobody can self-report a rank. The private key comes from
RANGER_SIGNING_KEY (base64 of the 32-byte Ed25519 seed). If unset, a key is
derived from SECRET_KEY so dev/mock works, but that derived key is not stable
across SECRET_KEY rotation: set RANGER_SIGNING_KEY in production and publish
its public key once.

Generate a production key:
    python -c "import base64,os;from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey;from cryptography.hazmat.primitives import serialization as s;k=Ed25519PrivateKey.generate();print(base64.b64encode(k.private_bytes(s.Encoding.Raw,s.PrivateFormat.Raw,s.NoEncryption())).decode())"
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

_cached = {}


def _seed():
    raw = os.environ.get("RANGER_SIGNING_KEY")
    if raw:
        try:
            return base64.b64decode(raw)
        except Exception:  # noqa: BLE001
            pass
    # Dev/mock fallback: deterministic 32 bytes from SECRET_KEY.
    base = (os.environ.get("SECRET_KEY") or "qwalora-ranger-dev").encode()
    return hashlib.sha256(base).digest()


def _priv():
    if "priv" not in _cached:
        _cached["priv"] = Ed25519PrivateKey.from_private_bytes(_seed()[:32])
    return _cached["priv"]


def canonical(payload):
    """Deterministic JSON so the same claim always signs/verifies identically."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign(payload):
    """Return base64 Ed25519 signature over the canonical payload."""
    return base64.b64encode(_priv().sign(canonical(payload))).decode()


def public_key_b64():
    pub = _priv().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode()


def verify(payload, signature, public_key_b64_str=None):
    """Verify a signature (used by tests and any verifier)."""
    try:
        if public_key_b64_str:
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64_str))
        else:
            pub = _priv().public_key()
        pub.verify(base64.b64decode(signature), canonical(payload))
        return True
    except Exception:  # noqa: BLE001
        return False
