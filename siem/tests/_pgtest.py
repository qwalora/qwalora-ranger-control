"""F5.1 - safe PostgreSQL test isolation with a POSITIVE test-environment authorization boundary.

Destructive PostgreSQL tests must NEVER run against a production or shared application database. A
disposable, uniquely-named database is not sufficient protection on its own: the test process still
connects to whatever server the URL points at and, with enough privilege, could create/drop
databases on a production server. So before any create/drop we POSITIVELY identify the target as an
authorized test instance; we do not infer safety from a database name containing "test", nor from a
hostname convention alone.

The boundary (all required, fail-closed):
  1. Opt-in. RANGER_TEST_ALLOW_DB_MUTATION must be set; without it destructive PG tests are SKIPPED.
  2. A DEDICATED test configuration. The target comes from RANGER_TEST_DATABASE_URL, a variable that
     exists only for tests - never the application's own DATABASE_URL and never production
     application credentials. If it is unset, destructive tests are skipped (fail-closed).
  3. A positively authorized server IDENTITY, established by ALL of:
       a. the target host is a local/dedicated test instance (loopback or unix socket) OR an
          explicitly allow-listed host (RANGER_TEST_PG_AUTHORIZED_HOSTS) - a non-local host that is
          not allow-listed is REFUSED before any connection is made;
       b. the server does NOT host a production/shared application database (a server carrying
          `ranger`, `portal`, `production`, ... is treated as production/shared and REFUSED);
       c. the server carries an explicit sentinel database (RANGER_TEST_SENTINEL_DB, default
          `ranger_test_sentinel`) that an operator creates ONCE to authorize a server for
          destructive tests - a production server never has it, so its absence fails closed.
  4. Disposable isolation. Each test runs in a brand-new `ranger_test_<uuid>` database created on the
     authorized server and dropped afterward; the provided URL's own database is never created,
     truncated, or dropped, and cleanup therefore cannot touch any unrelated resource.
  5. Refuse execution when the target cannot be positively identified as an authorized test
     environment (connection failure, missing sentinel, production DB present, remote host).

`assert_authorized_test_server()` performs the host check BEFORE opening any connection, so a
production-like/remote target is rejected before any database mutation could occur.
"""
from __future__ import annotations

import os
import re
import uuid
from contextlib import contextmanager

import pytest
from sqlalchemy.engine import make_url

SAFE_TEST_DB = re.compile(r"test", re.IGNORECASE)

OPT_IN_ENV = "RANGER_TEST_ALLOW_DB_MUTATION"
TEST_URL_ENV = "RANGER_TEST_DATABASE_URL"
SENTINEL_ENV = "RANGER_TEST_SENTINEL_DB"
AUTHORIZED_HOSTS_ENV = "RANGER_TEST_PG_AUTHORIZED_HOSTS"
DEFAULT_SENTINEL_DB = "ranger_test_sentinel"

# Exact database names that mark a server as a production / shared application server. If any of
# these exist on the target the server is refused for destructive tests - a dedicated test instance
# does not carry the live application database.
PRODUCTION_LIKE_DBS = frozenset({
    "ranger", "ranger_prod", "ranger_production", "portal", "production", "prod",
    "qwalora", "qwalora_ranger", "app", "application", "main",
})

# Local / dedicated test instance hosts (loopback or unix socket). A host ending in .localhost or
# .test is also treated as local by convention, but convention is never the ONLY signal (the
# sentinel + production-DB probe still have to pass).
_LOCAL_HOSTS = frozenset({"", "localhost", "127.0.0.1", "::1", "[::1]"})


class UnsafeTestDatabase(RuntimeError):
    """The disposable database NAME is not an obvious throwaway test database."""


class UnauthorizedTestServer(RuntimeError):
    """The target SERVER could not be positively identified as an authorized test instance."""


def is_postgres(url=None):
    return "postgresql" in (url or os.environ.get(TEST_URL_ENV) or os.environ.get("DATABASE_URL", ""))


def _opt_in():
    return os.environ.get(OPT_IN_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def _sentinel_db():
    return (os.environ.get(SENTINEL_ENV) or DEFAULT_SENTINEL_DB).strip()


def _authorized_hosts():
    raw = os.environ.get(AUTHORIZED_HOSTS_ENV, "") or ""
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def resolve_test_url():
    """The DEDICATED test database URL, or None. Deliberately does NOT fall back to the application's
    DATABASE_URL: a destructive test must never run against the app's own (possibly production) DB."""
    url = os.environ.get(TEST_URL_ENV)
    return url if url and "postgresql" in url else None


def _is_local_host(host):
    h = (host or "").strip().lower()
    if h in _LOCAL_HOSTS:
        return True
    if h.endswith(".localhost") or h.endswith(".test"):
        return True
    return h in _authorized_hosts()


def guard_disposable(db_name):
    """Refuse any database name that is not an obvious disposable test database. Called BEFORE any
    create/drop so a production-like database can never be the target of a create/drop."""
    if not db_name or not SAFE_TEST_DB.search(db_name):
        raise UnsafeTestDatabase(
            f"refusing to operate on non-disposable database {db_name!r}: "
            f"a test database name must contain 'test'")
    return db_name


def _connect_admin(url):
    import psycopg2
    return psycopg2.connect(host=url.host, port=url.port or 5432, user=url.username,
                            password=url.password, dbname="postgres", connect_timeout=5)


def _server_databases(url):
    conn = _connect_admin(url)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
            return {r[0] for r in cur.fetchall()}
    finally:
        conn.close()


def assert_authorized_test_server(url, *, probe=True):
    """Positively identify `url`'s SERVER as an authorized test instance, or raise
    UnauthorizedTestServer. The host check runs FIRST, with no connection, so a remote/production-like
    target is refused before any database mutation could occur. With probe=True a maintenance-DB
    connection then confirms no production/shared application database is present and that the
    authorizing sentinel database exists."""
    url = make_url(url) if isinstance(url, str) else url
    host = url.host or ""
    if not _is_local_host(host):
        raise UnauthorizedTestServer(
            f"refusing destructive tests against non-local host {host!r}: not a loopback/unix-socket "
            f"instance and not in {AUTHORIZED_HOSTS_ENV}")
    if not probe:
        return True
    try:
        present = _server_databases(url)
    except Exception as e:  # noqa: BLE001 - any connection/privilege failure => cannot identify
        raise UnauthorizedTestServer(
            f"cannot positively identify the target as an authorized test server "
            f"({type(e).__name__}: {e})")
    shared = sorted(present & PRODUCTION_LIKE_DBS)
    if shared:
        raise UnauthorizedTestServer(
            f"refusing: target server hosts production/shared application database(s) {shared}; "
            f"this is not a dedicated test instance")
    sentinel = _sentinel_db()
    if sentinel not in present:
        raise UnauthorizedTestServer(
            f"refusing: authorizing sentinel database {sentinel!r} is absent; create it once on a "
            f"dedicated test server to authorize destructive tests (fail-closed)")
    return True


def authorization_status():
    """(ok, reason) describing whether destructive PG tests may run. Never raises; used by runners
    and by the fail-closed tests."""
    if not _opt_in():
        return False, f"{OPT_IN_ENV} not set"
    url = resolve_test_url()
    if not url:
        return False, f"{TEST_URL_ENV} not set (dedicated test database required)"
    try:
        assert_authorized_test_server(url)
    except UnauthorizedTestServer as e:
        return False, str(e)
    return True, "authorized"


# --- demonstrations used by the required safety tests (no DB needed) ------------------------------
def assert_production_like_rejected():
    """A production-like disposable NAME is rejected before any destructive act; a throwaway name is
    accepted."""
    for name in ("ranger", "ranger_prod", "portal", "production", "qwalora"):
        try:
            guard_disposable(name)
        except UnsafeTestDatabase:
            continue
        raise AssertionError(f"guard failed to reject production-like name {name!r}")
    guard_disposable("ranger_test_abc123")
    return True


def assert_remote_server_rejected():
    """A non-local, non-allow-listed host is refused BEFORE any connection/mutation (host check
    precedes the probe)."""
    for host in ("db.prod.internal", "10.0.0.5", "prod-postgres.example.com"):
        u = make_url(f"postgresql+psycopg2://postgres:pw@{host}:5432/ranger_test_x")
        try:
            assert_authorized_test_server(u, probe=False)
        except UnauthorizedTestServer:
            continue
        raise AssertionError(f"guard failed to refuse remote host {host!r}")
    # a loopback host passes the host check
    assert_authorized_test_server(make_url("postgresql+psycopg2://postgres@127.0.0.1:5432/x"),
                                  probe=False)
    return True


def assert_missing_authorization_fails_closed():
    """With no opt-in OR no dedicated test URL, authorization is refused (fail-closed)."""
    saved = {k: os.environ.get(k) for k in (OPT_IN_ENV, TEST_URL_ENV)}
    try:
        os.environ.pop(OPT_IN_ENV, None)
        os.environ[TEST_URL_ENV] = "postgresql+psycopg2://postgres@127.0.0.1:5432/ranger_test_x"
        ok, _ = authorization_status()
        if ok:
            raise AssertionError("authorization did not fail closed with opt-in missing")
        os.environ[OPT_IN_ENV] = "1"
        os.environ.pop(TEST_URL_ENV, None)
        ok, _ = authorization_status()
        if ok:
            raise AssertionError("authorization did not fail closed with dedicated test URL missing")
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return True


# --- disposable database provisioning (only on a positively authorized server) --------------------
def provision_sentinel(url=None):
    """Create the authorizing sentinel database on a LOCAL server (idempotent). For test harness
    setup only; refuses to run against a non-local host."""
    url = make_url(url or resolve_test_url() or os.environ["DATABASE_URL"])
    if not _is_local_host(url.host or ""):
        raise UnauthorizedTestServer("will not provision a sentinel on a non-local host")
    name = _sentinel_db()
    guard_disposable(name)  # the sentinel name itself must look like a test database
    conn = _connect_admin(url)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,))
            if not cur.fetchone():
                cur.execute(f'CREATE DATABASE "{name}"')
    finally:
        conn.close()
    return name


def _create_disposable(url):
    name = "ranger_test_" + uuid.uuid4().hex[:10]
    guard_disposable(name)
    conn = _connect_admin(url)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{name}"')
    finally:
        conn.close()
    return name


def _drop_disposable(url, name):
    try:
        conn = _connect_admin(url)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname=%s AND pid<>pg_backend_pid()", (name,))
            cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
        conn.close()
    except Exception:  # noqa: BLE001 - best-effort cleanup
        pass


def make_disposable_or_none():
    """Non-pytest variant: returns (new_url, cleanup_fn) for a fresh disposable database on a
    positively authorized test server, or None when opt-in/dedicated-URL/authorization is unavailable
    (so a mixed runner can skip gracefully). Sets os.environ['DATABASE_URL'] to the disposable DB."""
    if not _opt_in():
        return None
    base = resolve_test_url()
    if not base:
        return None
    url = make_url(base)
    try:
        assert_authorized_test_server(url)
    except UnauthorizedTestServer:
        return None
    try:
        name = _create_disposable(url)
    except Exception:  # noqa: BLE001
        return None
    old = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = str(url.set(database=name))

    def cleanup():
        os.environ["DATABASE_URL"] = old or base
        _drop_disposable(url, name)
    return os.environ["DATABASE_URL"], cleanup


@contextmanager
def isolated_pg_database():
    """Yield a disposable PostgreSQL DATABASE_URL on a positively authorized test server (and set
    os.environ for the duration), or SKIP. Drops the throwaway database afterward. The provided
    dedicated test URL's own database is never mutated; a production/shared/remote server is refused
    (skipped), never touched."""
    if not _opt_in():
        pytest.skip(f"{OPT_IN_ENV} not set; refusing destructive PG test (fail-closed)")
    base = resolve_test_url()
    if not base:
        pytest.skip(f"{TEST_URL_ENV} not set; a dedicated test database is required (fail-closed)")
    url = make_url(base)
    try:
        assert_authorized_test_server(url)
    except UnauthorizedTestServer as e:
        pytest.skip(f"target is not an authorized test instance: {e}")
    try:
        name = _create_disposable(url)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"cannot create a disposable test database ({type(e).__name__}: {e}); "
                    f"isolation not established")
    new_url = str(url.set(database=name))
    old = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = new_url
    try:
        yield new_url
    finally:
        os.environ["DATABASE_URL"] = old or base
        _drop_disposable(url, name)
