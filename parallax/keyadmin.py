"""PARALLAX Phase 1C - authorized, audited signing-key lifecycle operations.

The signing-key REGISTRY itself is loaded from secure configuration (the `RANGER_SIGNING_KEYS` /
`RANGER_SIGNING_KEY` environment, backed by the deployment's secret store); private seed material is
never stored in the database, an API response, a log line, or an audit record. What this module adds
is the governance surface around key lifecycle: every activate / rotate / verify-only / retire /
revoke decision is (a) authorized against Ranger's server-side administrative identity and (b) written
to the signed, hash-chained PARALLAX audit trail, so the sequence of key-trust decisions is itself
tamper-evident. An unauthorized caller cannot record a key-lifecycle event.

This module does NOT hot-swap live key material - rotating the actual signing seed is a deliberate
operational procedure against the secret store, out of scope for this phase. What is durable and
in-scope here is the AUTHORIZED, AUDITED RECORD of each key-lifecycle action and a point-in-time
snapshot of the public (never private) verification registry.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import signing
from . import registry, auditlog

# The lifecycle actions an administrator may record, mapped to the target key state they assert.
KEY_ACTIONS = {
    "key_register": None,            # a new key introduced into the registry (any initial state)
    "key_activate": signing.STATE_ACTIVE,
    "key_verify_only": signing.STATE_VERIFY_ONLY,
    "key_retire": signing.STATE_RETIRED,
    "key_revoke": signing.STATE_REVOKED,      # emergency compromise revocation
}


class KeyAdminError(Exception):
    """A key-lifecycle operation is refused."""


def _public_only(detail: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Defensive: drop anything that could carry private material from an audit detail."""
    out = {}
    for k, v in (detail or {}).items():
        if "seed" in k.lower() or "private" in k.lower() or "secret" in k.lower():
            continue
        out[k] = v
    return out


def record_key_event(db, *, principal, action: str, kid: str,
                     detail: Optional[Dict[str, Any]] = None):
    """Authorize and audit one signing-key lifecycle action. Returns the audit row (committed with the
    caller's transaction via _commit_recover). Raises RegistryAuthError for an unauthorized caller and
    KeyAdminError for an unknown action."""
    if action not in KEY_ACTIONS:
        raise KeyAdminError("unknown key-lifecycle action %r" % action)
    who = registry._authorize(db, principal)   # RegistryAuthError if not an authorized admin
    safe = _public_only(detail)
    safe.setdefault("asserted_state", KEY_ACTIONS[action])
    # Record the public state of the key as the registry currently sees it (never private material).
    safe.setdefault("registry_state", signing.key_state(kid))
    row = auditlog.append(db, action=action, actor_id=who, subject_kind="signing_key",
                          subject_ref=kid, detail=safe)
    registry._commit_recover(db, lambda: None)
    return row


def snapshot_public_registry(db, *, principal):
    """Record a point-in-time snapshot of the PUBLIC verification registry (kid/alg/state/public_b64
    only) into the audit chain, so which keys were trusted at this time is itself attested. Authorized
    admins only."""
    who = registry._authorize(db, principal)
    pub = signing.public_registry()   # contains no private material by construction
    row = auditlog.append(db, action="key_registry_snapshot", actor_id=who,
                          subject_kind="signing_key_registry", subject_ref=signing.active_kid(),
                          detail={"keys": pub})
    registry._commit_recover(db, lambda: None)
    return row
