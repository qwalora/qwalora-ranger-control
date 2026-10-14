"""Symmetric encryption for secrets at rest (the per-candidate Ludus API key).

The key material comes from LUDUS_KEY_SECRET (a urlsafe-base64 32-byte Fernet
key). If it is unset, a key is derived from SECRET_KEY so dev/mock still works;
in that case tokens are scoped to the current SECRET_KEY. For production, set a
stable LUDUS_KEY_SECRET so stored keys survive restarts and secret rotation.

Generate one with:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""
import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken


def _fernet():
    secret = os.environ.get("LUDUS_KEY_SECRET")
    if not secret:
        # Derive a deterministic Fernet key from SECRET_KEY (dev/mock fallback).
        base = (os.environ.get("SECRET_KEY") or "qwalora-ranger-dev").encode()
        secret = base64.urlsafe_b64encode(hashlib.sha256(base).digest()).decode()
    if isinstance(secret, str):
        secret = secret.encode()
    return Fernet(secret)


def encrypt(plaintext):
    if plaintext is None:
        return None
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token):
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return None
