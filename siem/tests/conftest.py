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
import pytest


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
