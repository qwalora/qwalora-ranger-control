"""Fail-closed production secret configuration contract.

Centralizes two things so the rest of the app does not each reinvent them:

1. Whether this process must enforce SECURE (production) secret handling, and
2. The rules that REJECT missing, malformed, unsafe, or ambiguous secret material.

Design goals
------------
- Development and disposable-test workflows are unchanged: when no secure/production marker is set
  the historical behavior (ephemeral SECRET_KEY fallback with a warning; signing-seed derivation)
  is preserved.
- Development defaults are NEVER accepted in production: a missing, too-short, low-entropy, or
  placeholder SECRET_KEY, and signing material derived from SECRET_KEY or a hardcoded development
  literal, all fail closed at startup in production.
- Ambiguity fails closed, not open: a RANGER_ENV set to an unrecognized value (a misspelling such as
  "produciton") raises rather than silently being treated as development.
- This module reads only environment variable NAMES. It never logs, returns, or embeds a secret
  VALUE in an error message. Errors name the offending variable and what is required, nothing more.

Declaring production
--------------------
Secure mode is ON when any of these is true:
- `RANGER_REQUIRE_SECURE_SECRETS` is truthy (1/true/yes/on) -- the authoritative, unambiguous switch;
- `RANGER_ENV` is a recognized production value (prod/production/prd/live);
- a generic marker (`APP_ENV`/`ENVIRONMENT`/`FLASK_ENV`) is a recognized production value.
A `RANGER_ENV` set to an unrecognized, non-development value raises InsecureConfigError (ambiguous).
"""
import math
import os

# The authoritative, unambiguous switch an operator/platform can set to force secure handling.
FORCE_FLAG = "RANGER_REQUIRE_SECURE_SECRETS"
# Generic markers honored as POSITIVE production signals only (their unknown values are ignored, since
# these vars are platform-generic and may legitimately hold arbitrary names).
_GENERIC_MARKERS = ("APP_ENV", "ENVIRONMENT", "FLASK_ENV")
_PROD_VALUES = frozenset({"prod", "production", "prd", "live"})
# Recognized non-production tokens for the authoritative RANGER_ENV marker. Anything else set on
# RANGER_ENV is ambiguous and fails closed.
_DEV_VALUES = frozenset({
    "dev", "development", "local", "localhost", "test", "testing", "ci",
    "staging", "stage", "qa", "sandbox", "preview", "nonprod", "nonproduction", "non-production",
})
_TRUTHY = frozenset({"1", "true", "yes", "on"})

# SECRET_KEY strength floors (production). Length alone is insufficient, so entropy is also checked.
MIN_SECRET_LEN = 32
MIN_SECRET_DISTINCT = 10          # distinct characters
MIN_SECRET_SHANNON_BITS = 2.5     # Shannon entropy per character

_FORBIDDEN_SECRET_EXACT = frozenset({
    "qwalora-ranger-dev", "changeme", "change-me", "secret", "secret-key", "secretkey",
    "dev", "development", "test", "testing", "placeholder", "password", "default",
})


class InsecureConfigError(RuntimeError):
    """Raised at startup when secret configuration is missing, malformed, unsafe, or ambiguous.
    The message names the environment variable at fault and what is required; never a secret value.
    """


def _truthy(val):
    return (val or "").strip().lower() in _TRUTHY


def is_production(env=None):
    """True when secure (production) secret handling must be enforced.

    Raises InsecureConfigError when RANGER_ENV is set to an unrecognized, non-development value, so a
    misspelled production marker fails closed instead of silently relaxing to development.
    """
    env = env if env is not None else os.environ
    if _truthy(env.get(FORCE_FLAG)):
        return True
    ranger_env = (env.get("RANGER_ENV") or "").strip().lower()
    if ranger_env:
        if ranger_env in _PROD_VALUES:
            return True
        if ranger_env not in _DEV_VALUES:
            raise InsecureConfigError(
                "RANGER_ENV is set to an unrecognized value; refusing to guess the environment. "
                "Set RANGER_ENV to a known value (production or development/test/staging), or set "
                "%s=1 to force secure handling." % FORCE_FLAG)
    for marker in _GENERIC_MARKERS:
        if (env.get(marker) or "").strip().lower() in _PROD_VALUES:
            return True
    return False


def _shannon_bits_per_char(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _secret_is_weak(val):
    """Heuristic entropy check (not a substitute for a CSPRNG): reject obviously low-entropy keys
    such as a repeated character or a short repeating pattern, independent of length."""
    if len(set(val)) < MIN_SECRET_DISTINCT:
        return True
    if _shannon_bits_per_char(val) < MIN_SECRET_SHANNON_BITS:
        return True
    return False


def require_secret_key(env=None):
    """Return the SECRET_KEY the app should use.

    In production: fail closed (InsecureConfigError) when SECRET_KEY is missing, too short, a known
    development placeholder, or low-entropy; otherwise return the configured value.

    Outside production: return the configured value as-is (possibly None/empty) so the caller keeps
    its existing development fallback. Never raises outside production (except on an ambiguous marker,
    surfaced by is_production).
    """
    env = env if env is not None else os.environ
    production = is_production(env)
    val = env.get("SECRET_KEY")
    if not production:
        return val
    if not val or not val.strip():
        raise InsecureConfigError(
            "SECRET_KEY is required in production but is not set. Generate a securely random value of "
            "at least %d characters and set SECRET_KEY (do not reuse the signing key)." % MIN_SECRET_LEN)
    if len(val) < MIN_SECRET_LEN:
        raise InsecureConfigError(
            "SECRET_KEY is too short for production: it must be at least %d characters." % MIN_SECRET_LEN)
    if val.strip().lower() in _FORBIDDEN_SECRET_EXACT:
        raise InsecureConfigError(
            "SECRET_KEY is a known development placeholder and must not be used in production. "
            "Set a securely random value.")
    if _secret_is_weak(val):
        raise InsecureConfigError(
            "SECRET_KEY has insufficient entropy for production (too few distinct characters or too "
            "repetitive). Use a securely random value, e.g. python -c \"import os;print(os.urandom(32).hex())\".")
    return val
