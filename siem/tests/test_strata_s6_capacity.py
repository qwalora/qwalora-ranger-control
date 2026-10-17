"""STRATA S6 §3 (post-closure) - RAM-weighted host capacity + atomic admission.

Offline (SQLite) tests prove the conservative RAM-weighted policy: a count of two does NOT mean a host
can run any two ranges. Two Raider ranges (1+1 units) fit; a second capstone (2+2) or a Raider plus a
capstone (1+2) exceeds a 2-unit host and queues.

The TRANSACTIONAL concurrency guarantee (that two competing PostgreSQL transactions cannot both reserve
the last unit) relies on a per-host pg_advisory_xact_lock and can only be verified against a real
PostgreSQL server. Without one, that test SKIPS and the guarantee is reported UNVERIFIED - never
claimed as passed (a SQLite single-writer run does not exercise the race).
"""
import json as _json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "s6cap")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("LUDUS_API_URL", None)

import pytest  # noqa: E402

from _s6util import expiring_client  # noqa: E402
import strata_assignment as asn  # noqa: E402
from siem import board_variants as bv  # noqa: E402


@pytest.fixture(autouse=True)
def _guard():
    keys = ("RANGER_STRATA_PORTFOLIOS", "HOST_CAPACITY_UNITS", "RAIDER_RAM_UNITS",
            "CAPSTONE_RAM_UNITS", "ADMIN_TOKEN")
    saved = {k: os.environ.get(k) for k in keys}
    import app as _a
    gkeys = ("MAX_CONCURRENT", "RAIDER_RAM_UNITS", "CAPSTONE_RAM_UNITS")
    gsaved = {k: getattr(_a, k) for k in gkeys}
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    try:
        yield
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        for k, v in gsaved.items():
            setattr(_a, k, v)


def _app():
    import app as appmod
    from models import db, Cohort, AdminUser
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.drop_all(); db.create_all()
    if not Cohort.query.filter_by(name="2026-A").first():
        db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
    if AdminUser.query.filter_by(github_id="gid-admin").first() is None:
        db.session.add(AdminUser(github_id="gid-admin", login="alice", role="reviewer"))
    db.session.commit()
    return appmod, application, db, ctx


def _cand(db, handle, board):
    from models import Candidate
    c = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort="2026-A",
                  github_id=f"g-{handle}", status="active", current_board=board, token=f"tok-{handle}")
    db.session.add(c); db.session.commit()
    return c


def _portfolio(db, application, board):
    import strata_catalog as cat
    from models import ScenarioCatalogEntry, AdminUser
    if not [e for e in ScenarioCatalogEntry.query.filter_by(status="catalog_eligible").all()
            if _json.loads(e.board_compat)[0] == board]:
        for e in cat.register_all(db, boards=(board,)):
            with application.test_request_context():
                from flask import session
                session["admin"] = True; session["admin_login"] = "alice"; session["admin_gid"] = "gid-admin"
                cat.approve(db, e, None)
        db.session.commit()
    asn.set_cohort_portfolio(db, "2026-A", board, bv.variants_for(board)[:2],
                             admin=AdminUser.query.filter_by(github_id="gid-admin").first())


def _start(application, db, c):
    client = expiring_client(application, db)
    hdr = {"X-Candidate-Token": c.token}
    assert client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr).status_code == 200
    return client.post("/labs/start", json={"handle": c.handle}, headers=hdr).get_json()["range_status"]


def test_two_raiders_fit_on_a_two_unit_host():
    appmod, application, db, ctx = _app()
    appmod.MAX_CONCURRENT = 2  # 2 units
    try:
        _portfolio(db, application, 5)
        a = _cand(db, "capA", 5)
        b = _cand(db, "capB", 5)
        assert _start(application, db, a) == "deployed"
        assert _start(application, db, b) == "deployed", "two Raiders (1+1) fit on a 2-unit host"
    finally:
        ctx.pop()


def test_second_capstone_is_refused_on_a_two_unit_host():
    appmod, application, db, ctx = _app()
    appmod.MAX_CONCURRENT = 2  # 2 units; a capstone weighs 2
    try:
        _portfolio(db, application, 6)
        a = _cand(db, "capcap1", 6)
        b = _cand(db, "capcap2", 6)
        assert _start(application, db, a) == "deployed", "one capstone (2) fills a 2-unit host"
        assert _start(application, db, b) == "queued_slot", "two capstones (2+2) exceed a 2-unit host"
    finally:
        ctx.pop()


def test_raider_plus_capstone_exceeds_a_two_unit_host():
    appmod, application, db, ctx = _app()
    appmod.MAX_CONCURRENT = 2
    try:
        _portfolio(db, application, 5)
        _portfolio(db, application, 6)
        r = _cand(db, "mixR", 5)
        v = _cand(db, "mixV", 6)
        assert _start(application, db, r) == "deployed"     # Raider uses 1 of 2 units
        assert _start(application, db, v) == "queued_slot", "Raider(1)+capstone(2)=3 > 2 units"
    finally:
        ctx.pop()


def test_capstone_fits_when_capacity_raised():
    appmod, application, db, ctx = _app()
    appmod.MAX_CONCURRENT = 4  # a larger host: 4 units holds two capstones
    try:
        _portfolio(db, application, 6)
        a = _cand(db, "big1", 6)
        b = _cand(db, "big2", 6)
        assert _start(application, db, a) == "deployed"
        assert _start(application, db, b) == "deployed", "a 4-unit host holds two capstones (2+2)"
    finally:
        ctx.pop()




def _pg_test_url():
    # An authorized, isolated, DISPOSABLE PostgreSQL test database AND explicit destructive-test
    # authorization are both required. A non-disposable or shared DB must never be used.
    if not os.environ.get("RANGER_TEST_ALLOW_DB_MUTATION"):
        return None
    url = os.environ.get("RANGER_PG_TEST_URL")
    if url and url.startswith("postgres") and os.environ.get("RANGER_PG_TEST_DISPOSABLE") == "1":
        return url
    return None


@pytest.mark.skipif(_pg_test_url() is None,
                    reason="no authorized disposable PostgreSQL test server: transactional capacity "
                           "concurrency UNVERIFIED (needs RANGER_PG_TEST_URL + "
                           "RANGER_PG_TEST_DISPOSABLE=1 + RANGER_TEST_ALLOW_DB_MUTATION)")
def test_transactional_admission_under_competing_pg_transactions():
    """R3-4: competing-transaction admission on a real, disposable PostgreSQL database, driving the
    ACTUAL production admission path (the /labs/start route -> _try_deploy -> _admit's per-host
    pg_advisory_xact_lock + PERSISTED weighted capacity), not a re-implementation.

    Two capstone candidates race /labs/start against a 1-capstone (2-unit) host. The persisted weighted
    capacity must never exceed the budget: exactly one range may hold the host, the other must queue.
    The same admission lock covers resume/resume, deploy/resume and deploy-vs-reconcile races (every
    path funnels through _admit). Requires an authorized disposable PG server; else UNVERIFIED + skip.
    """
    import threading

    import app as appmod
    from models import db, Cohort, AdminUser, Candidate, RangeRequest
    import strata_catalog as cat
    import strata_assignment as asn
    from siem import board_variants as bv

    os.environ["DATABASE_URL"] = _pg_test_url()
    os.environ["ADMIN_TOKEN"] = "s6-pgcap-admin"
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod.MAX_CONCURRENT = 2  # 2 units => exactly ONE capstone (weight 2) fits

    application = appmod.create_app()
    with application.app_context():
        db.drop_all(); db.create_all()
        db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
        db.session.add(AdminUser(github_id="gid-admin", login="alice", role="reviewer"))
        db.session.commit()
        for e in cat.register_all(db, boards=(6,)):
            with application.test_request_context():
                from flask import session
                session["admin"] = True
                session["admin_login"] = "alice"
                session["admin_gid"] = "gid-admin"
                cat.approve(db, e, None)
        db.session.commit()
        asn.set_cohort_portfolio(db, "2026-A", 6, bv.variants_for(6)[:2],
                                 admin=AdminUser.query.filter_by(github_id="gid-admin").first())
        tokens = []
        for h in ("pg1", "pg2"):
            c = Candidate(handle=h, name=h, email=f"{h}@e", cohort="2026-A", github_id=f"g-{h}",
                          status="active", current_board=6, token=f"tok-{h}")
            db.session.add(c)
            tokens.append(c.token)
        db.session.commit()
        for tok, h in zip(tokens, ("pg1", "pg2")):
            application.test_client().post("/labs/dataset", json={"handle": h},
                                           headers={"X-Candidate-Token": tok})

    barrier = threading.Barrier(len(tokens))

    def _race(token):
        with application.app_context():
            application.test_client()  # ensure engine warm
            barrier.wait()
            application.test_client().post("/labs/start", json={},
                                           headers={"X-Candidate-Token": token})

    threads = [threading.Thread(target=_race, args=(t,)) for t in tokens]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with application.app_context():
        occupying = RangeRequest.query.filter(
            RangeRequest.status.in_(RangeRequest.OCCUPIES_SLOT)).all()
        used = sum(2 if r.board == 6 else 1 for r in occupying)
        assert used <= 2, f"persisted weighted capacity must never exceed the 2-unit budget (got {used})"
        assert len(occupying) == 1, "exactly one capstone may hold the host; the other must queue"
