"""Ed25519 signing for board clearances, badges, and PARALLAX governance/evidence records.

Every clearance, badge, approval, assessment decision, and audit event is signed so a verifier can
confirm it independently and nobody can self-report a rank or forge a governance record.

Key material
------------
The signing key comes from `RANGER_SIGNING_KEY` (base64 of the 32-byte Ed25519 seed). If unset, a key
is derived from `SECRET_KEY` so dev/mock works, but that derived key is not stable across SECRET_KEY
rotation: set `RANGER_SIGNING_KEY` in production and publish its public key once.

Generate a production key:
    python -c "import base64,os;from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey;from cryptography.hazmat.primitives import serialization as s;k=Ed25519PrivateKey.generate();print(base64.b64encode(k.private_bytes(s.Encoding.Raw,s.PrivateFormat.Raw,s.NoEncryption())).decode())"

Key lifecycle and rotation (Phase 1C)
-------------------------------------
`signing` maintains a VERSIONED verification registry so signing keys can be rotated without losing the
ability to verify legitimate historical records. A key has a stable identifier (`kid`), an explicit
algorithm (`ed25519`), and one of four states:

  * active        - the single key used to SIGN new records; also verifies.
  * verify_only   - rotated out of signing but still fully trusted to VERIFY historical records.
  * retired       - normal end of life; still trusted to verify historical records, not used to sign.
  * revoked       - COMPROMISED; never trusted for anything, including historical verification
                    (fail closed). This is emergency revocation, distinct from planned retirement.

Trust for verification = {active, verify_only, retired}. revoked is never trusted.

Configuration. `RANGER_SIGNING_KEYS`, when set, is a JSON array of
  {"kid","alg","state","seed_b64"?,"public_b64"?}
and fully defines the registry; exactly one entry must be `active` and it must carry a private
`seed_b64` (so the process can sign). verify_only/retired/revoked entries normally carry only
`public_b64`. When `RANGER_SIGNING_KEYS` is unset, the registry is synthesized from the single
`RANGER_SIGNING_KEY`/`SECRET_KEY` key (kid `legacy:<hash>`, state active) so behavior is byte-for-byte
identical to the pre-1C single-key implementation.

`kid` travels ALONGSIDE a signature (e.g. a `signing_kid` column), never inside the canonical signed
bytes, so introducing it does not alter the signature of any existing record. A record with no stored
kid (legacy) is verified under the narrow trusted-key policy: it must verify under some key currently
in {active, verify_only, retired}; arbitrary keys are never accepted. Private seed material is never
logged, returned by `public_registry()`, or placed in exceptions.

Do not introduce a homegrown algorithm; this module uses the `cryptography` Ed25519 primitives only.
Do not embed production private keys in the repository or test fixtures.
"""
import base64
import hashlib
import json
import os

import prodconfig

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

ALG = "ed25519"
STATE_ACTIVE = "active"
STATE_VERIFY_ONLY = "verify_only"
STATE_RETIRED = "retired"
STATE_REVOKED = "revoked"
_STATES = (STATE_ACTIVE, STATE_VERIFY_ONLY, STATE_RETIRED, STATE_REVOKED)
_VERIFY_TRUSTED = (STATE_ACTIVE, STATE_VERIFY_ONLY, STATE_RETIRED)

_cached = {}


# --- low-level key helpers -----------------------------------------------------------------------
def _legacy_seed():
    raw = os.environ.get("RANGER_SIGNING_KEY")
    if raw:
        # An explicitly configured key must be well-formed. A malformed value is a misconfiguration,
        # never silently ignored (which would mask it behind a derived dev key).
        try:
            seed = base64.b64decode(raw)
        except Exception:  # noqa: BLE001
            seed = None
        if seed is None or len(seed) < 32:
            raise prodconfig.InsecureConfigError(
                "RANGER_SIGNING_KEY is malformed: expected base64 of a 32-byte Ed25519 seed.")
        return seed[:32]
    # No explicit signing material. In production this must fail closed: deriving a signing key from
    # SECRET_KEY or a hardcoded development literal would make signed evidence forgeable.
    if prodconfig.is_production():
        raise prodconfig.InsecureConfigError(
            "No signing key configured in production. Set RANGER_SIGNING_KEYS (versioned registry) "
            "or RANGER_SIGNING_KEY (base64 of a 32-byte Ed25519 seed). Derivation from SECRET_KEY or "
            "a development default is not permitted in production.")
    base = (os.environ.get("SECRET_KEY") or "qwalora-ranger-dev").encode()
    return hashlib.sha256(base).digest()


def _pub_b64_of_seed(seed):
    priv = Ed25519PrivateKey.from_private_bytes(seed[:32])
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode()


def _kid_for_pub(pub_b64):
    return "legacy:" + hashlib.sha256(pub_b64.encode()).hexdigest()[:16]


class _KeyEntry:
    """One registry key. Holds the private seed only for keys the process may sign with; never
    serializes or logs the seed."""
    __slots__ = ("kid", "alg", "state", "_seed", "public_b64")

    def __init__(self, kid, alg, state, seed=None, public_b64=None):
        if state not in _STATES:
            raise ValueError("unknown key state")
        self.kid = kid
        self.alg = alg or ALG
        self.state = state
        self._seed = seed[:32] if seed else None
        self.public_b64 = public_b64 or (_pub_b64_of_seed(seed) if seed else None)
        if not self.public_b64:
            raise ValueError("key %r has no public material" % kid)

    def private(self):
        if not self._seed:
            raise LookupError("no private material for kid %r" % self.kid)  # never includes the seed
        return Ed25519PrivateKey.from_private_bytes(self._seed)

    def public(self):
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public_b64))

    def __repr__(self):  # never leak seed
        return "<Key kid=%r alg=%r state=%r has_private=%s>" % (
            self.kid, self.alg, self.state, self._seed is not None)


# --- registry ------------------------------------------------------------------------------------
def _build_registry():
    """Build {kid: _KeyEntry} and the active kid from env. Cached; call _reset_registry() in tests."""
    raw = os.environ.get("RANGER_SIGNING_KEYS")
    single = os.environ.get("RANGER_SIGNING_KEY")
    # Exactly one source of signing identity. Both set is ambiguous (which key is active?) and fails
    # closed rather than silently preferring the registry and ignoring RANGER_SIGNING_KEY.
    if raw and single:
        raise prodconfig.InsecureConfigError(
            "Both RANGER_SIGNING_KEYS and RANGER_SIGNING_KEY are set; configure exactly one. Use "
            "RANGER_SIGNING_KEYS (versioned registry) for rotation, or RANGER_SIGNING_KEY alone.")
    reg = {}
    active = None
    if raw:
        # Parse and build defensively: a malformed registry must never surface its content (which
        # contains private seeds) in an exception message or traceback. Re-raise a sanitized error.
        try:
            entries = json.loads(raw)
            if not isinstance(entries, list):
                raise ValueError("not a list")
            for e in entries:
                seed = base64.b64decode(e["seed_b64"]) if e.get("seed_b64") else None
                ke = _KeyEntry(kid=e["kid"], alg=e.get("alg", ALG), state=e["state"],
                               seed=seed, public_b64=e.get("public_b64"))
                if ke.kid in reg:
                    raise ValueError("duplicate kid %r" % ke.kid)
                reg[ke.kid] = ke
                if ke.state == STATE_ACTIVE:
                    if active is not None:
                        raise ValueError("more than one active signing key")
                    active = ke.kid
        except prodconfig.InsecureConfigError:
            raise
        except Exception as exc:  # noqa: BLE001 - never echo the registry content (holds seeds)
            raise prodconfig.InsecureConfigError(
                "RANGER_SIGNING_KEYS is malformed or invalid (%s). It must be a JSON array of "
                "{kid, alg, state, seed_b64|public_b64} with exactly one active key holding a private "
                "seed." % type(exc).__name__) from None
        if active is None:
            raise prodconfig.InsecureConfigError("RANGER_SIGNING_KEYS defines no active signing key.")
        if reg[active]._seed is None:
            raise prodconfig.InsecureConfigError("the active signing key has no private seed.")
    else:
        seed = _legacy_seed()
        pub = _pub_b64_of_seed(seed)
        kid = _kid_for_pub(pub)
        reg[kid] = _KeyEntry(kid=kid, alg=ALG, state=STATE_ACTIVE, seed=seed, public_b64=pub)
        active = kid
    _assert_required_verify_kids(reg)
    return reg, active


def _assert_required_verify_kids(reg):
    """Optionally pin historical verification: if RANGER_SIGNING_VERIFY_KIDS is set (comma-separated
    kids), every listed kid must be present in the registry in a trusted (non-revoked) state, so a
    rotation that would silently drop the ability to verify existing evidence fails closed. No-op
    when unset."""
    pinned = [k.strip() for k in (os.environ.get("RANGER_SIGNING_VERIFY_KIDS") or "").split(",") if k.strip()]
    for kid in pinned:
        ke = reg.get(kid)
        if ke is None or ke.state not in _VERIFY_TRUSTED:
            raise prodconfig.InsecureConfigError(
                "RANGER_SIGNING_VERIFY_KIDS pins a key id that is not present in a trusted state; "
                "refusing to drop verification of existing evidence. Include every pinned kid as "
                "active, verify_only, or retired.")


def _registry():
    if "registry" not in _cached:
        reg, active = _build_registry()
        _cached["registry"] = reg
        _cached["active"] = active
    return _cached["registry"]


def _reset_registry():
    """Drop cached key material so the next call rebuilds from the current environment (tests only)."""
    _cached.pop("registry", None)
    _cached.pop("active", None)
    _cached.pop("priv", None)


def _install_registry(entries, active_kid):
    """Install an in-memory registry (tests only). `entries` is a list of dicts like RANGER_SIGNING_KEYS.
    Does not touch the environment and never persists seeds."""
    reg = {}
    for e in entries:
        seed = base64.b64decode(e["seed_b64"]) if e.get("seed_b64") else None
        reg[e["kid"]] = _KeyEntry(kid=e["kid"], alg=e.get("alg", ALG), state=e["state"],
                                  seed=seed, public_b64=e.get("public_b64"))
    if active_kid not in reg or reg[active_kid].state != STATE_ACTIVE:
        raise ValueError("active_kid must name an active key in the entries")
    _cached["registry"] = reg
    _cached["active"] = active_kid


def active_kid():
    _registry()
    return _cached["active"]


def assert_signing_ready():
    """Force-build the signing registry so missing, malformed, or (in production) implicitly derived
    key material fails CLOSED at startup rather than at first sign/verify. Returns the active kid.
    Never logs or returns key material. Safe to call once during app creation."""
    _reset_registry()  # ignore any stale cache so the current environment is validated now
    _registry()
    return _cached["active"]


def _active_entry():
    return _registry()[active_kid()]


# --- canonicalization ----------------------------------------------------------------------------
def canonical(payload):
    """Deterministic JSON so the same claim always signs/verifies identically.

    sort_keys + compact separators + the json default ensure_ascii=True (non-ASCII is \\uXXXX-escaped),
    which pins a single byte representation for a given object regardless of locale or insertion order.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


# --- signing -------------------------------------------------------------------------------------
def _priv():
    # Back-compat shim: the single active private key.
    if "priv" not in _cached:
        _cached["priv"] = _active_entry().private()
    return _cached["priv"]


def sign(payload):
    """Return base64 Ed25519 signature over the canonical payload, using the ACTIVE key. The caller
    should record active_kid() alongside the signature so it can be verified precisely after rotation."""
    return base64.b64encode(_active_entry().private().sign(canonical(payload))).decode()


def sign_versioned(payload):
    """Convenience: (signature_b64, kid) for the active key."""
    return sign(payload), active_kid()


def public_key_b64(kid=None):
    """Public key (base64 raw) of the active key, or of `kid` if given."""
    reg = _registry()
    entry = reg[kid] if kid else _active_entry()
    return entry.public_b64


def public_registry():
    """The verification registry WITHOUT any private material: list of {kid, alg, state, public_b64}.
    Safe to publish, log, or embed in an audit record."""
    return [{"kid": e.kid, "alg": e.alg, "state": e.state, "public_b64": e.public_b64}
            for e in _registry().values()]


def key_state(kid):
    e = _registry().get(kid)
    return e.state if e else None


def kid_for(payload, signature):
    """Return the kid of the trusted key that verifies this (payload, signature), or None if no
    currently-trusted key does. Used to record the actual signing key of a signature produced
    elsewhere (e.g. an assessment envelope), robust to rotation. Never raises."""
    message = canonical(payload)
    for entry in _registry().values():
        if entry.state in _VERIFY_TRUSTED and _verify_with_pub(entry.public(), signature, message):
            return entry.kid
    return None


# --- verification --------------------------------------------------------------------------------
def _verify_with_pub(pub, signature, message):
    try:
        pub.verify(base64.b64decode(signature), message)
        return True
    except Exception:  # noqa: BLE001 - never surface key material or crypto internals
        return False


def verify(payload, signature, public_key_b64_str=None, kid=None):
    """Verify a signature. Fail-closed on any error.

    - public_key_b64_str given: verify against exactly that key (explicit-key path, e.g. a published
      status-page key). Unchanged from the pre-1C behavior.
    - kid given (and no explicit key): resolve kid in the registry. Unknown kid -> False (fail closed).
      A key in `revoked` state -> False (compromised, never trusted). Otherwise verify against that
      key's public material. This rejects an altered kid (it will not match the signature) and an
      untrusted/unknown kid.
    - neither given (legacy record): verify under the narrow trusted-key policy - True only if the
      signature verifies under some key currently in {active, verify_only, retired}. Arbitrary keys are
      never accepted.
    """
    message = canonical(payload)
    if public_key_b64_str:
        try:
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64_str))
        except Exception:  # noqa: BLE001
            return False
        return _verify_with_pub(pub, signature, message)
    return _resolve_and_verify(message, signature, kid)


def _resolve_and_verify(message, signature, kid):
    """Shared kid-resolution + fail-closed policy over raw message bytes (used by verify and
    verify_domain)."""
    reg = _registry()
    if kid is not None:
        entry = reg.get(kid)
        if entry is None:
            return False                       # unknown key id -> fail closed
        if entry.state not in _VERIFY_TRUSTED:
            return False                       # revoked/untrusted -> fail closed
        return _verify_with_pub(entry.public(), signature, message)
    for entry in reg.values():
        if entry.state in _VERIFY_TRUSTED and _verify_with_pub(entry.public(), signature, message):
            return True
    return False


# --- explicit domain separation (Phase 1D Workstream D) ------------------------------------------
# For NEW signed artifact types, bind the artifact TYPE + SCHEMA VERSION + SECURITY CONTEXT into the
# signed bytes as a length/separator-delimited header, so a signature over one (domain, payload) can
# never verify a different domain or a plain (legacy) signature, and vice versa - cryptographic, not
# merely structural, context separation. This is ADDITIVE: plain sign()/verify() and every existing
# signed record are byte-for-byte unchanged, so no historical signature is invalidated. Existing record
# types are already mutually non-verifiable by structure (distinct required fields); this primitive is
# the explicit, forward-looking binding for new types and is the migration path should any type ever
# need it. `domain` is a stable ASCII label such as "parallax.audit_event.v1".
_SIG_SCHEME = b"ranger.sig.domain.v1"
_DOMAIN_SEP = b"\x1f"


def _domain_message(domain, payload):
    d = domain.encode("utf-8")
    # length-prefix the domain so it cannot be shifted into/out of the payload region.
    return b"%s%s%d%s%s%s%s" % (_SIG_SCHEME, _DOMAIN_SEP, len(d), _DOMAIN_SEP, d, _DOMAIN_SEP,
                                canonical(payload))


def sign_domain(domain, payload):
    """Sign (domain, payload) under the active key with explicit domain separation. Returns
    (signature_b64, kid)."""
    msg = _domain_message(domain, payload)
    return base64.b64encode(_active_entry().private().sign(msg)).decode(), active_kid()


def verify_domain(domain, payload, signature, kid=None):
    """Verify a domain-separated signature. Same kid-resolution and fail-closed policy as verify(); a
    mismatched domain, an unknown/revoked kid, or a plain (non-domain) signature all fail closed."""
    return _resolve_and_verify(_domain_message(domain, payload), signature, kid)
