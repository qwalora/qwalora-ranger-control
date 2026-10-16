"""F5.1 - safe PostgreSQL test isolation.

Destructive PostgreSQL tests must NEVER run against a production or shared database. This helper
enforces that by refusing to mutate the DATABASE_URL that was provided and instead creating a
brand-new, disposable test database for the duration of a test, then dropping it. Cleanup therefore
affects only test-owned records (the whole throwaway database), and there are no table-wide DELETEs
against a shared database anywhere.

Protections:
  * requires an explicit opt-in (RANGER_TEST_ALLOW_DB_MUTATION) - without it, destructive PG tests
    are skipped, not run;
  * the disposable database name must match the safe test pattern (contains "test"); a
    production-like name is REFUSED before any action (UnsafeTestDatabase);
  * if a disposable database cannot be created (no privilege, server unreachable), the test is
    SKIPPED - "refuse execution when test isolation cannot be established";
  * the provided DATABASE_URL is used only to reach the server; its database is never created,
    truncated, or dropped.
"""
from __future__ import annotations

import os
import re
import uuid
from contextlib import contextmanager

import pytest
from sqlalchemy.engine import make_url

SAFE_TEST_DB = re.compile(r"test", re.IGNORECASE)


class UnsafeTestDatabase(RuntimeError):
    pass


def is_postgres(url=None):
    return "postgresql" in (url or os.environ.get("DATABASE_URL", ""))


def _opt_in():
    return os.environ.get("RANGER_TEST_ALLOW_DB_MUTATION", "").strip().lower() in ("1", "true", "yes")


def guard_disposable(db_name):
    """Refuse any database name that is not an obvious disposable test database. Called BEFORE any
    create/drop so a production-like database can never be touched."""
    if not db_name or not SAFE_TEST_DB.search(db_name):
        raise UnsafeTestDatabase(
            f"refusing to operate on non-disposable database {db_name!r}: "
            f"a test database name must contain 'test'")
    return db_name


def assert_production_like_rejected():
    """Demonstration hook: a production-like database name is rejected before any destructive act."""
    for name in ("ranger", "ranger_prod", "portal", "production", "qwalora"):
        try:
            guard_disposable(name)
        except UnsafeTestDatabase:
            continue
        raise AssertionError(f"guard failed to reject production-like name {name!r}")
    # and a disposable name is accepted
    guard_disposable("ranger_test_abc123")
    return True


def _connect_admin(url):
    import psycopg2
    return psycopg2.connect(host=url.host, port=url.port or 5432, user=url.username,
                            password=url.password, dbname="postgres")


def make_disposable_or_none():
    """Non-pytest variant: returns (new_url, cleanup_fn) for a fresh disposable database, or None
    when PG/opt-in/privileges are unavailable (so a mixed runner can skip gracefully without
    aborting its other checks). Sets os.environ['DATABASE_URL'] to the disposable database."""
    if not is_postgres() or not _opt_in():
        return None
    base = os.environ["DATABASE_URL"]
    url = make_url(base)
    name = "ranger_test_" + uuid.uuid4().hex[:10]
    guard_disposable(name)
    try:
        conn = _connect_admin(url)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{name}"')
        conn.close()
    except Exception:
        return None
    old = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = str(url.set(database=name))

    def cleanup():
        os.environ["DATABASE_URL"] = old or base
        try:
            c = _connect_admin(url)
            c.autocommit = True
            with c.cursor() as cur:
                cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                            "WHERE datname=%s AND pid<>pg_backend_pid()", (name,))
                cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
            c.close()
        except Exception:
            pass
    return os.environ["DATABASE_URL"], cleanup


@contextmanager
def isolated_pg_database():
    """Yield a disposable PostgreSQL DATABASE_URL (and set os.environ for the duration), or SKIP.
    Drops the throwaway database afterward. The provided shared/production DATABASE_URL is never
    mutated."""
    base = os.environ.get("DATABASE_URL", "")
    if "postgresql" not in base:
        pytest.skip("PostgreSQL DATABASE_URL not set; destructive PG test skipped")
    if not _opt_in():
        pytest.skip("RANGER_TEST_ALLOW_DB_MUTATION not set; refusing destructive PG test "
                    "(test isolation not established)")
    url = make_url(base)
    name = "ranger_test_" + uuid.uuid4().hex[:10]
    guard_disposable(name)
    try:
        conn = _connect_admin(url)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{name}"')
        conn.close()
    except Exception as e:  # noqa
        pytest.skip(f"cannot create a disposable test database ({type(e).__name__}: {e}); "
                    f"isolation not established")
    new_url = str(url.set(database=name))
    old = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = new_url
    try:
        yield new_url
    finally:
        os.environ["DATABASE_URL"] = old or base
        try:
            conn = _connect_admin(url)
            conn.autocommit = True
            with conn.cursor() as cur:
                # terminate any lingering connections, then drop the throwaway database
                cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                            "WHERE datname=%s AND pid<>pg_backend_pid()", (name,))
                cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
            conn.close()
        except Exception:
            pass
