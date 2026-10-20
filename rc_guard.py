"""Release-candidate (RC) database-identity guard.

During isolated RC validation on Railway, the RC application must be provably unable to run against
the accepted operational database. This guard enforces that BEFORE any write-capable initialization
(db.create_all, ensure_schema, cohort/resource bootstrapping) runs.

Model (two environment variables; both required to run in RC mode):
- RANGER_RC_ALLOW=1        explicit opt-in to RC mode.
- RANGER_RC_EXPECT_TOKEN   the unique marker token the operator stamped on the disposable fork.

The disposable fork carries one marker row:
    CREATE TABLE rc_fork_marker (token text primary key);
    INSERT INTO rc_fork_marker VALUES ('<token>');
This guard performs a strictly READ-ONLY SELECT of that marker and fails closed unless exactly one
row is present and equals RANGER_RC_EXPECT_TOKEN. It NEVER creates or modifies the marker, so it
cannot alter the operational database; and because the accepted database is not marked, pointing an
RC deployment at it fails closed (the marker table is absent).

Enforcement points:
- A deployment that is NOT RC (neither variable set) is unaffected: the guard is a no-op, so
  production/nonprod/dev/test startup behavior is unchanged.
- A deployment that declares RC intent (RANGER_RC_EXPECT_TOKEN set) but omits RANGER_RC_ALLOW=1 fails
  closed, so the explicit opt-in cannot be forgotten.

No secret value is logged or embedded in an error.
"""
from __future__ import annotations

import os
import re

from sqlalchemy import text

ALLOW_ENV = "RANGER_RC_ALLOW"
EXPECT_ENV = "RANGER_RC_EXPECT_TOKEN"
MARKER_TABLE = "rc_fork_marker"
# Marker tokens are operator-chosen identifiers, not secrets; bound to a safe, bounded charset so a
# malformed value fails closed rather than being used in a query or comparison.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:\-]{8,128}$")
_TRUTHY = frozenset({"1", "true", "yes", "on"})


class RCGuardError(RuntimeError):
    """Raised when RC-mode database identity cannot be positively verified. The message states what
    failed; it never contains a secret value."""


def _truthy(val):
    return (val or "").strip().lower() in _TRUTHY


def rc_mode_declared(env=None):
    """True when this process is (or claims to be) an RC deployment."""
    env = env if env is not None else os.environ
    return _truthy(env.get(ALLOW_ENV)) or bool((env.get(EXPECT_ENV) or "").strip())


def assert_rc_identity(engine, env=None):
    """Fail closed unless RC mode is correctly declared AND the connected database carries the
    expected disposable-fork marker. Returns the verified token in RC mode, or None when this is not
    an RC deployment (no-op). Performs only a read-only SELECT; never writes.

    `engine` is a SQLAlchemy Engine (e.g. Flask-SQLAlchemy `db.engine`).
    """
    env = env if env is not None else os.environ
    allow = _truthy(env.get(ALLOW_ENV))
    expect = (env.get(EXPECT_ENV) or "").strip()

    # Not an RC deployment at all -> do nothing (normal startup unaffected).
    if not allow and not expect:
        return None

    # RC intent is present. Require the explicit opt-in and a well-formed expected token.
    if not allow:
        raise RCGuardError(
            "%s is set but %s=1 is not; refusing to start. RC mode must be opted into explicitly."
            % (EXPECT_ENV, ALLOW_ENV))
    if not expect:
        raise RCGuardError(
            "%s=1 is set but %s is empty; cannot verify the disposable database identity." % (ALLOW_ENV, EXPECT_ENV))
    if not _TOKEN_RE.match(expect):
        raise RCGuardError(
            "%s is malformed; expected 8-128 characters from [A-Za-z0-9._:-]." % EXPECT_ENV)

    # Read-only identity probe. A missing/unreadable marker table (the accepted database, or any
    # unmarked database) raises here and fails closed.
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT token FROM %s" % MARKER_TABLE)).fetchall()
    except Exception as e:  # noqa: BLE001 - any read failure is a fail-closed condition
        raise RCGuardError(
            "RC database identity cannot be verified: the disposable marker table %r is absent or "
            "unreadable. An unmarked database (including the accepted operational database) is "
            "rejected. [%s]" % (MARKER_TABLE, type(e).__name__))

    tokens = [r[0] for r in rows]
    if len(tokens) != 1:
        raise RCGuardError(
            "RC marker is missing or ambiguous: expected exactly one marker row, found %d." % len(tokens))
    if tokens[0] != expect:
        raise RCGuardError(
            "RC marker mismatch: the connected database is not the expected disposable fork.")
    return expect
