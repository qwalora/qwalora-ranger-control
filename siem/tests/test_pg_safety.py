"""F5.1 Correction 1 - PostgreSQL test-environment authorization boundary.

The pure-logic checks (name guard, remote-host refusal, fail-closed on missing authorization) need
no database and always run, so the rejection behaviour is demonstrable offline. The live checks run
only when an authorized local test server is configured (RANGER_TEST_DATABASE_URL + opt-in +
sentinel); otherwise they SKIP (which is itself the fail-closed behaviour).
"""
import os
import sys

import pytest
from sqlalchemy.engine import make_url

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pgtest  # noqa: E402


# ---- offline, always-run: rejection is demonstrable without a database -----------------------
def test_production_like_name_rejected():
    assert _pgtest.assert_production_like_rejected()


def test_remote_or_unapproved_server_refused_before_mutation():
    # a non-local, non-allow-listed host is refused by the host check, before any connection
    assert _pgtest.assert_remote_server_rejected()


def test_missing_authorization_fails_closed():
    assert _pgtest.assert_missing_authorization_fails_closed()


# ---- live checks against a positively authorized local test server ----------------------------
def _live_or_skip():
    ok, reason = _pgtest.authorization_status()
    if not ok:
        pytest.skip(f"no authorized local PG test server: {reason}")
    return make_url(_pgtest.resolve_test_url())


def test_authorized_local_test_server_accepted():
    url = _live_or_skip()
    assert _pgtest.assert_authorized_test_server(url) is True


def test_shared_production_server_refused_live():
    """A server that hosts a production/shared application database is refused even though it is
    local and carries the sentinel: the production DB is the disqualifier."""
    url = _live_or_skip()
    name = "ranger"  # a production-like application database name
    conn = _pgtest._connect_admin(url)
    conn.autocommit = True
    created = False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,))
            if not cur.fetchone():
                cur.execute(f'CREATE DATABASE "{name}"')
                created = True
        refused = False
        try:
            _pgtest.assert_authorized_test_server(url)
        except _pgtest.UnauthorizedTestServer:
            refused = True
        assert refused, "a server hosting a production application DB must be refused"
    finally:
        if created:
            with conn.cursor() as cur:
                cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
        conn.close()


def test_sentinel_absence_fails_closed_live():
    """Without the authorizing sentinel database the server cannot be positively identified."""
    url = _live_or_skip()
    saved = os.environ.get(_pgtest.SENTINEL_ENV)
    try:
        # point the sentinel name at one that does not exist on the server
        os.environ[_pgtest.SENTINEL_ENV] = "ranger_test_sentinel_absent_" + os.urandom(3).hex()
        refused = False
        try:
            _pgtest.assert_authorized_test_server(url)
        except _pgtest.UnauthorizedTestServer:
            refused = True
        assert refused, "absence of the sentinel database must fail closed"
    finally:
        if saved is None:
            os.environ.pop(_pgtest.SENTINEL_ENV, None)
        else:
            os.environ[_pgtest.SENTINEL_ENV] = saved


def test_disposable_cleaned_up_and_original_unchanged_live():
    """A disposable database is created and dropped; the sentinel database and an unrelated marker
    table in it are untouched by the disposable's lifecycle."""
    url = _live_or_skip()
    sentinel = _pgtest._sentinel_db()
    import psycopg2
    # create an unrelated marker table in the sentinel (the "original" database) and record it
    sconn = psycopg2.connect(host=url.host, port=url.port or 5432, user=url.username,
                             password=url.password, dbname=sentinel)
    sconn.autocommit = True
    with sconn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS pgsafety_marker (id int)")
        cur.execute("DELETE FROM pgsafety_marker")
        cur.execute("INSERT INTO pgsafety_marker VALUES (42)")

    created_name = {}
    with _pgtest.isolated_pg_database() as disp_url:
        created_name["n"] = make_url(disp_url).database
        # the disposable is a NEW database, not the sentinel
        assert created_name["n"] != sentinel and "test" in created_name["n"]
        # it really exists while the block is active
        present = _pgtest._server_databases(url)
        assert created_name["n"] in present

    # after the block: disposable dropped, sentinel + marker intact
    present_after = _pgtest._server_databases(url)
    assert created_name["n"] not in present_after, "disposable database was not cleaned up"
    assert sentinel in present_after, "the original (sentinel) database must remain"
    with sconn.cursor() as cur:
        cur.execute("SELECT id FROM pgsafety_marker")
        rows = [r[0] for r in cur.fetchall()]
    assert rows == [42], "an unrelated table in the original database must be unchanged"
    with sconn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS pgsafety_marker")
    sconn.close()


if __name__ == "__main__":
    os.environ.setdefault("RANGER_TEST_DATABASE_URL",
                          "postgresql+psycopg2://postgres@127.0.0.1:5432/ranger_test_sentinel")
    os.environ.setdefault("RANGER_TEST_ALLOW_DB_MUTATION", "1")
    _pgtest.provision_sentinel()
    sys.exit(pytest.main([__file__, "-v"]))
