"""Fail-closed production secret configuration contract.

Centralizes two things so the rest of the app does not each reinvent them:

1. Whether this process is running in PRODUCTION (an explicit, operator-set environment marker), and
2. The rules that REJECT missing, malformed, or unsafe secret material in production.

Design goals
------------
- Development and disposable-test workflows are unchanged: outside production the historical
  behavior (ephemeral SECRET_KEY fallback with a warning; signing-seed derivation) is preserved.
- Development defaults are NEVER accepted in production: a missing, too-short, or placeholder
  SECRET_KEY, and signing material derived from SECRET_KEY or a hardcoded development literal, all
  fail closed at startup in production.
- This module reads only environment variable NAMES. It never logs, returns, or embeds a secret
  VALUE in an error message. Errors name the offending variable and what is required, nothing more.

Production is declared by an explicit marker; nonproduction and local/dev/test are the default.
"""
import os

# Markers that mean "production". RANGER_ENV is authoritative; the others are honored defensively so
# a single stray production marker still forces fail-closed behavior rather than silently relaxing it.
_PROD_MARKERS = ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV")
_PROD_VALUES = ("prod", "production")

# Minimum SECRET_KEY length accepted in production (characters). A 32-byte os.urandom hex is 64 chars.
MIN_SECRET_LEN = 32

# Known development/placeholder secrets that must never be accepted in production (exact,
# case-insensitive match; we do NOT substring-match so a strong random key is never falsely rejected).
_FORBIDDEN_SECRET_EXACT = frozenset({
    "qwalora-ranger-dev", "changeme", "change-me", "secret", "secret-key", "secretkey",
    "dev", "development", "test", "testing", "placeholder", "password", "default",
})


class InsecureConfigError(RuntimeError):
    """Raised at startup when production secret configuration is missing, malformed, or unsafe.

    The message names the environment variable at fault and what is required. It never contains a
    secret value.
    """


def is_production(env=None):
    """True when an explicit production marker is set. Nonproduction is the default."""
    env = env if env is not None else os.environ
    for marker in _PROD_MARKERS:
        if (env.get(marker) or "").strip().lower() in _PROD_VALUES:
            return True
    return False


def require_secret_key(env=None):
    """Return the SECRET_KEY the app should use.

    In production: fail closed (InsecureConfigError) when SECRET_KEY is missing, too short, or a known
    development placeholder; otherwise return the configured value.

    Outside production: return the configured value as-is (possibly None/empty) so the caller keeps
    its existing development fallback. Never raises outside production.
    """
    env = env if env is not None else os.environ
    val = env.get("SECRET_KEY")
    if not is_production(env):
        return val
    if not val or not val.strip():
        raise InsecureConfigError(
            "SECRET_KEY is required in production but is not set. Generate a stable, securely random "
            "value of at least %d characters and set SECRET_KEY (do not reuse the signing key)."
            % MIN_SECRET_LEN)
    if len(val) < MIN_SECRET_LEN:
        raise InsecureConfigError(
            "SECRET_KEY is too short for production: it must be at least %d characters." % MIN_SECRET_LEN)
    if val.strip().lower() in _FORBIDDEN_SECRET_EXACT:
        raise InsecureConfigError(
            "SECRET_KEY is a known development placeholder and must not be used in production. "
            "Set a securely random value.")
    return val
