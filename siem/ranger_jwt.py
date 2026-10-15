"""Ranger candidate JWT minting (RS256), on the stdlib + cryptography only.

The Ranger backend (the broker) holds the PRIVATE signing key and mints a
short-lived token after it has validated the candidate's GitHub-authenticated
session, admission status, board authorization, and identity. OpenSearch holds
only the PUBLIC key and verifies signature + issuer + audience + expiry.

Authorization is by identity: the token's `sub` is the candidate's OpenSearch
username, and a server-side roles_mapping grants that username only its own
per-candidate role. The `roles` claim is NOT trusted for authorization (the JWT
auth domain sets no roles_key), so a forged or inflated roles claim grants nothing
even if it were validly signed. Only the portal can sign, so claims cannot be
manufactured by a candidate.
"""
from __future__ import annotations

import base64
import json
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ISSUER = "qwalora-ranger"
AUDIENCE = "qwalora-siem"
DEFAULT_TTL = 600  # 10 minutes


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mint(sub: str, private_key_pem: bytes, *, board: int, cohort: str,
         ttl: int = DEFAULT_TTL, jti: str | None = None,
         extra: dict | None = None, now: int | None = None) -> str:
    """Mint a short-lived RS256 JWT for a candidate. `sub` is the candidate's
    OpenSearch username (e.g. cand_<id>)."""
    import secrets
    now = int(now if now is not None else time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": sub,
        "iat": now, "nbf": now, "exp": now + ttl,
        "jti": jti or secrets.token_hex(16),
        "ranger": {"cohort": cohort, "board": board},
    }
    if extra:
        payload.update(extra)
    signing_input = (_b64url(json.dumps(header, separators=(",", ":")).encode())
                     + "." + _b64url(json.dumps(payload, separators=(",", ":")).encode()))
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    sig = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return signing_input + "." + _b64url(sig)


def tamper_payload(token: str, patch: dict) -> str:
    """Return a token whose payload is modified but whose signature is left as-is
    (for a negative test: must be rejected)."""
    h, p, s = token.split(".")
    pad = "=" * (-len(p) % 4)
    payload = json.loads(base64.urlsafe_b64decode(p + pad))
    payload.update(patch)
    p2 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p2}.{s}"
