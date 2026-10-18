"""PARALLAX Phase 1D Workstream A - regression lock for the STRATA F4 cross-test contamination.

Root cause (Phase 1C): test_f41_persistence_pg.py installs a DB-backed trusted-fixture registry into
the process-global evidence_validation._REGISTRY (via set_fixture_registry / install_db_backends) and,
before the fix, never restored it. Later STRATA F4 tests call register_trusted_fixture while relying on
the process default (an in-memory registry usable with no active Flask application context); with the
DB-backed registry leaked in, that call executes `self.M.query` outside an app context and raises
"Working outside of application context".

These two tests encode the contract deterministically and clean up after themselves, so neither leaks:
  * the NEGATIVE test reproduces the original failure mode (unrestored DB-backed registry + no context);
  * the POSITIVE test proves that restoring the default registry (what the f41 autouse fixture now
    does) leaves register_trusted_fixture working with no app context, as F4 requires.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1d-f4iso")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

import siem.evidence_validation as valn  # noqa: E402
from siem import forensic_jobs_db as fjdb  # noqa: E402

ADMIN = {"role": "admin", "id": "admin-iso"}
H1 = "a" * 64
H2 = "b" * 64


def test_default_registry_is_inmemory_and_context_free():
    """F4 relies on the process default being an in-memory registry usable with no app context."""
    reg = valn.fixture_registry()
    assert type(reg).__name__ == "InMemoryFixtureRegistry"
    valn.register_trusted_fixture(H1, note="ok", approver=ADMIN)   # must not need an app context
    assert valn.is_trusted_fixture(H1) is True


def test_unrestored_db_registry_would_leak_outside_context():
    """NEGATIVE: an unrestored DB-backed registry makes a later context-free call fail - the original
    defect. This test restores the default in a finally, so it does not itself leak."""
    import app as appmod
    from models import db
    application = appmod.create_app()
    default = valn.fixture_registry()
    ctx = application.app_context(); ctx.push()
    try:
        db.create_all()
        valn.set_fixture_registry(fjdb.SqlTrustedFixtureRegistry(db))
    finally:
        ctx.pop()   # leave the DB-backed registry active but with NO app context (the leak condition)
    try:
        with pytest.raises(RuntimeError):
            valn.register_trusted_fixture(H2, note="x", approver=ADMIN)
    finally:
        valn.set_fixture_registry(default)   # clean up so this test cannot contaminate others


def test_restored_default_registry_works_without_context():
    """POSITIVE: after install + restore (the fixture's contract), register works with no context."""
    import app as appmod
    from models import db
    application = appmod.create_app()
    default = valn.fixture_registry()
    ctx = application.app_context(); ctx.push()
    try:
        db.create_all()
        valn.set_fixture_registry(fjdb.SqlTrustedFixtureRegistry(db))   # emulate an f41 test
    finally:
        valn.set_fixture_registry(default)   # the restoration f41's autouse fixture performs
        ctx.pop()
    # no app context is active now; the restored in-memory registry must work (what F4 needs)
    valn.register_trusted_fixture(H1, note="ok", approver=ADMIN)
    assert valn.is_trusted_fixture(H1) is True
    assert type(valn.fixture_registry()).__name__ == "InMemoryFixtureRegistry"
