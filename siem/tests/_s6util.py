"""Shared S6 test helpers.

`expiring_client` wraps a Flask test client so that after EVERY request the test's own (long-lived,
outer) SQLAlchemy session is expired. Without this, a test that mutates a row through a request (whose
changes commit in the request-scoped session) and then re-reads the row through its own session gets a
STALE identity-map copy - a test-harness artifact of holding one outer session across many requests,
not a product defect (production runs one request per flow). Expiring after each request makes every
re-read a fresh DB read, so cross-suite ordering can no longer change the result.
"""


def expiring_client(application, db):
    client = application.test_client()
    _open = client.open

    def open_(*args, **kwargs):
        resp = _open(*args, **kwargs)
        try:
            db.session.expire_all()
        except Exception:  # noqa: BLE001 - never let test-session hygiene mask a real failure
            pass
        return resp

    client.open = open_
    return client
