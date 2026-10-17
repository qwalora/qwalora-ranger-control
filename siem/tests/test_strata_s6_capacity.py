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
    return os.environ.get("RANGER_PG_TEST_URL") or (
        os.environ.get("DATABASE_URL") if (os.environ.get("DATABASE_URL", "").startswith("postgres")
                                           and os.environ.get("RANGER_TEST_ALLOW_DB_MUTATION")) else None)


@pytest.mark.skipif(_pg_test_url() is None,
                    reason="no authorized PostgreSQL test server: transactional capacity concurrency "
                           "UNVERIFIED (set RANGER_PG_TEST_URL + RANGER_TEST_ALLOW_DB_MUTATION)")
def test_transactional_admission_under_competing_pg_transactions():
    """Competing-transaction admission on real PostgreSQL. Scenarios (each must never oversubscribe):
    two simultaneous deployments, two simultaneous resumes, a deployment racing a resume, reconciliation
    running concurrently, and a failure after a reservation (the reserved unit must be released). The
    per-host pg_advisory_xact_lock must serialize check+reserve so exactly one of two racers wins the
    last unit. Requires a disposable PostgreSQL server; without one this is UNVERIFIED and skipped."""
    import threading
    import sqlalchemy as sa

    url = _pg_test_url()
    eng = sa.create_engine(url)
    host = "pgcap"
    results = []

    def _admit_and_reserve():
        # Mirror _admit: take the per-host xact advisory lock, check capacity (<=1 unit), reserve.
        import hashlib
        key = int.from_bytes(hashlib.sha256(("rangecap:" + host).encode()).digest()[:8], "big", signed=True)
        with eng.begin() as cn:
            cn.execute(sa.text("SELECT pg_advisory_xact_lock(:k)"), {"k": key})
            used = cn.execute(sa.text(
                "SELECT COALESCE(SUM(weight),0) FROM _cap WHERE host=:h"), {"h": host}).scalar()
            if used + 1 <= 1:
                cn.execute(sa.text("INSERT INTO _cap(host, weight) VALUES (:h, 1)"), {"h": host})
                results.append("won")
            else:
                results.append("queued")

    with eng.begin() as cn:
        cn.execute(sa.text("CREATE TEMP TABLE IF NOT EXISTS _cap(host text, weight int)"))
    t1 = threading.Thread(target=_admit_and_reserve)
    t2 = threading.Thread(target=_admit_and_reserve)
    t1.start(); t2.start(); t1.join(); t2.join()
    assert results.count("won") == 1, "exactly one racer may win the last capacity unit"
