"""Deterministic DB-session isolation for the siem test suites.

Several suites call app.create_app() per test, each building its own engine (an in-memory SQLite DB
pinned to a single StaticPool connection). The Flask-SQLAlchemy `db.session` is a process-global
scoped session: if it is left bound to a PRIOR test's app/engine, a later test writes through that
stale session (into the prior DB) while its Flask test-client requests correctly use the CURRENT
app's engine (a different in-memory DB), so writes and reads silently diverge. That is the shared-
state dependency behind "passes alone, fails combined".

Removing the scoped session before and after every test forces each test's first `db.session` use to
bind freshly to whatever app context that test establishes. This makes the combined run deterministic
and order-independent (verified in CI by running the whole siem/tests directory in one process). It is
standard test hygiene and changes no production behavior.
"""
import os
import random

import pytest

# Several suites set RANGER_ENV (and the other environment markers) at module import or in fixtures to
# exercise env-gated behavior, and some pop them without restoring. In a full run that leaks across
# tests: a suite that clears RANGER_ENV before test_strata_s5_board2 runs leaves its signed test
# activation seeing RANGER_ENV='' and failing. Establish a deterministic session baseline and restore
# the markers after every test so no test can leak a process-global marker into another. The test
# suite's intended environment is RANGER_ENV=test (strata test-qual grading requires test/ci); set it
# as the default without overriding an explicit value. Test-isolation hygiene only; no production code.
os.environ.setdefault("RANGER_ENV", "test")
_ENV_MARKERS = ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV")


@pytest.fixture(autouse=True)
def _restore_env_markers():
    snapshot = {k: os.environ.get(k) for k in _ENV_MARKERS}
    try:
        yield
    finally:
        for k, v in snapshot.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def pytest_collection_modifyitems(session, config, items):
    """Phase 1D (Workstream B): a narrowly-scoped, reproducible collection shuffler for test-order
    independence checks. A no-op unless RANGER_TEST_SHUFFLE_SEED is set; when set, the collected items
    are shuffled deterministically by that integer seed, so any failure is reproducible by re-running
    with the same seed. This adds no third-party dependency and never changes order in a normal run."""
    raw = os.environ.get("RANGER_TEST_SHUFFLE_SEED")
    if raw is None or raw == "":
        return
    try:
        seed = int(raw)
    except ValueError:
        seed = hash(raw)
    random.Random(seed).shuffle(items)
    try:
        session.config.pluginmanager.get_plugin("terminalreporter")._tw.line(
            "RANGER_TEST_SHUFFLE_SEED=%s applied: %d items shuffled" % (raw, len(items)))
    except Exception:  # noqa: BLE001
        pass


@pytest.fixture(autouse=True)
def _isolate_db_session():
    try:
        from models import db
    except Exception:  # noqa: BLE001 - if models is unavailable, there is nothing to isolate
        yield
        return
    try:
        db.session.remove()
    except Exception:  # noqa: BLE001
        pass
    yield
    try:
        db.session.remove()
    except Exception:  # noqa: BLE001
        pass
