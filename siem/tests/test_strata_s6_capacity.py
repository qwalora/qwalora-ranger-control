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
            "CAPSTONE_RAM_UNITS", "ADMIN_TOKEN", "DATABASE_URL")
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


_PG_SKIP = pytest.mark.skipif(
    _pg_test_url() is None,
    reason="no authorized disposable PostgreSQL test server: transactional capacity concurrency "
           "UNVERIFIED (needs RANGER_PG_TEST_URL + RANGER_PG_TEST_DISPOSABLE=1 + "
           "RANGER_TEST_ALLOW_DB_MUTATION)")

_POST_ADMISSION_STATES = ("deployed", "deploying", "queued_slot", "resuming", "suspended")


def _pg_app(board=6, cap_units=2):
    """A fresh app bound to the disposable PG, schema reset, cohort + admin + an approved board
    portfolio seeded. Returns (appmod, application)."""
    import app as appmod
    from models import db, Cohort, AdminUser
    import strata_catalog as cat
    from siem import board_variants as bv

    os.environ["DATABASE_URL"] = _pg_test_url()
    os.environ["ADMIN_TOKEN"] = "s6-pgcap-admin"
    os.environ["RANGER_STRATA_PORTFOLIOS"] = "1"
    appmod.MAX_CONCURRENT = cap_units

    application = appmod.create_app()
    with application.app_context():
        db.drop_all(); db.create_all()
        db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
        db.session.add(AdminUser(github_id="gid-admin", login="alice", role="reviewer"))
        db.session.commit()
        for e in cat.register_all(db, boards=(board,)):
            with application.test_request_context():
                from flask import session
                session["admin"] = True
                session["admin_login"] = "alice"
                session["admin_gid"] = "gid-admin"
                cat.approve(db, e, None)
        db.session.commit()
        asn.set_cohort_portfolio(db, "2026-A", board, bv.variants_for(board)[:2],
                                 admin=AdminUser.query.filter_by(github_id="gid-admin").first())
    return appmod, application


def _pg_candidate(application, handle, board=6, *, bind=True, suspended=False):
    """Seed one active candidate on the disposable PG. bind -> open their dataset (creates the
    integrity-verified ScenarioBinding a governed deploy requires). suspended -> pre-seed a
    powered-off range on host 'primary' so a lab-start resumes (not fresh-deploys) it."""
    from models import db, Candidate, RangeRequest
    import datetime as _dt
    with application.app_context():
        c = Candidate(handle=handle, name=handle, email=f"{handle}@e", cohort="2026-A",
                      github_id=f"g-{handle}", status="active", current_board=board,
                      token=f"tok-{handle}")
        db.session.add(c); db.session.commit()
        tok = c.token
        cid = c.id
    if bind:
        with application.app_context():
            application.test_client().post("/labs/dataset", json={"handle": handle},
                                           headers={"X-Candidate-Token": tok})
    if suspended:
        with application.app_context():
            # remove any range the dataset call may have staged, then seed a clean suspended one
            RangeRequest.query.filter_by(candidate_id=cid).delete()
            rr = RangeRequest(candidate_id=cid, board=board, host="primary", status="suspended",
                              ludus_range_id=f"RID-{handle}", template="goad-capstone",
                              deployed_at=_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=1))
            db.session.add(rr); db.session.commit()
    return tok


def _labstart_worker(token, handle):
    def _w(client, rec):
        resp = client.post("/labs/start", json={"handle": handle},
                           headers={"X-Candidate-Token": token})
        rec["status"] = resp.status_code
        rec["body"] = resp.get_json(silent=True)
        rec["range_status"] = (rec["body"] or {}).get("range_status")
        rec["reached_admission"] = (resp.status_code == 200
                                    and rec["range_status"] in _POST_ADMISSION_STATES)
    _w.__name__ = f"labstart[{handle}]"
    return _w


def _reconcile_worker():
    def _w(client, rec):
        resp = client.post("/admin/reconcile",
                           headers={"Authorization": "Bearer s6-pgcap-admin",
                                    "Accept": "application/json"})
        rec["status"] = resp.status_code
        rec["body"] = resp.get_json(silent=True)
        rec["range_status"] = None
        rec["reached_admission"] = (resp.status_code == 200)  # maintenance pass completed
    _w.__name__ = "reconcile"
    return _w


def _run_pg_race(application, workers):
    """Run workers concurrently behind a shared barrier, each in its own app context / client /
    connection, and capture every outcome. A worker that raised (traceback), returned a non-200, or
    never reached admission is recorded as such, so an empty or failed worker can NEVER be mistaken
    for a successful race."""
    import threading
    import traceback
    n = len(workers)
    barrier = threading.Barrier(n)
    recs = [None] * n

    def _wrap(i, fn):
        rec = {"error": None, "status": None, "body": None, "range_status": None,
               "reached_admission": False, "label": getattr(fn, "__name__", str(i))}
        try:
            with application.app_context():
                client = application.test_client()
                barrier.wait()          # all workers fire their mutation together
                fn(client, rec)
        except BaseException:           # noqa: BLE001 - barrier breaks, request errors, driver faults
            rec["error"] = traceback.format_exc()
        recs[i] = rec

    threads = [threading.Thread(target=_wrap, args=(i, w)) for i, w in enumerate(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return recs


def _assert_all_reached_admission(recs, *, require_state=True):
    """Every worker must have run to completion AND actually invoked the admission path - no silent
    thread exceptions, no pre-admission 4xx (e.g. the old json={} -> 400 that never reached _admit)."""
    for rec in recs:
        assert rec["error"] is None, f"worker {rec['label']} raised:\n{rec['error']}"
        assert rec["status"] == 200, (
            f"worker {rec['label']} did not reach lab-start admission "
            f"(status={rec['status']!r}, body={rec['body']!r})")
        if require_state:
            assert rec["range_status"] in _POST_ADMISSION_STATES, (
                f"worker {rec['label']} produced no post-admission range state: "
                f"{rec['range_status']!r}")


def _weighted_capacity(application, host="primary"):
    from models import db, RangeRequest  # noqa: F401
    with application.app_context():
        occ = RangeRequest.query.filter(RangeRequest.host == host,
                                        RangeRequest.status.in_(RangeRequest.OCCUPIES_SLOT)).all()
        used = sum(2 if r.board == 6 else 1 for r in occ)
        return occ, used


@_PG_SKIP
def test_pg_race_deploy_vs_deploy():
    """R4-4 deploy/deploy: two capstone candidates race /labs/start against a 1-capstone (2-unit)
    host, driving the REAL path (/labs/start -> _try_deploy -> _admit pg_advisory_xact_lock +
    persisted weighted capacity). Exactly one deploys; the other queues; capacity never exceeds 2."""
    _appmod, application = _pg_app(board=6, cap_units=2)
    t1 = _pg_candidate(application, "pgdd1", 6)
    t2 = _pg_candidate(application, "pgdd2", 6)

    recs = _run_pg_race(application, [_labstart_worker(t1, "pgdd1"),
                                      _labstart_worker(t2, "pgdd2")])
    _assert_all_reached_admission(recs)

    occ, used = _weighted_capacity(application)
    assert used <= 2, f"persisted weighted capacity must never exceed the 2-unit budget (got {used})"
    assert len(occ) == 1, "exactly one capstone may hold the host; the other must queue"
    states = sorted(r["range_status"] for r in recs)
    assert states == ["deployed", "queued_slot"], f"expected one deploy + one queue, got {states}"


@_PG_SKIP
def test_pg_race_resume_vs_resume():
    """R4-4 resume/resume: two SUSPENDED capstones race /labs/start (-> _resume_range -> same
    _admit lock). Only one may re-take the 2-unit host; the loser stays suspended (evidence and slot
    intact), never oversubscribing. Capacity never exceeds 2."""
    _appmod, application = _pg_app(board=6, cap_units=2)
    t1 = _pg_candidate(application, "pgrr1", 6, suspended=True)
    t2 = _pg_candidate(application, "pgrr2", 6, suspended=True)

    recs = _run_pg_race(application, [_labstart_worker(t1, "pgrr1"),
                                      _labstart_worker(t2, "pgrr2")])
    _assert_all_reached_admission(recs)

    occ, used = _weighted_capacity(application)
    assert used <= 2, f"weighted capacity must never exceed 2 under a resume race (got {used})"
    assert len(occ) == 1, "exactly one resume may hold the host"
    # mock broker confirms power-on immediately, so the winner is 'deployed'; loser held 'suspended'
    states = sorted(r["range_status"] for r in recs)
    assert states == ["deployed", "suspended"], f"expected one resume + one held, got {states}"


@_PG_SKIP
def test_pg_race_deploy_vs_resume():
    """R4-4 deploy/resume: a fresh capstone deploy races a suspended capstone's resume for the last
    slot. Whichever wins, the other is turned away (queued_slot for the deploy, suspended for the
    resume) and the persisted weighted capacity never exceeds 2."""
    _appmod, application = _pg_app(board=6, cap_units=2)
    t_dep = _pg_candidate(application, "pgdr1", 6)                   # fresh deploy
    t_res = _pg_candidate(application, "pgdr2", 6, suspended=True)   # resume

    recs = _run_pg_race(application, [_labstart_worker(t_dep, "pgdr1"),
                                      _labstart_worker(t_res, "pgdr2")])
    _assert_all_reached_admission(recs)

    occ, used = _weighted_capacity(application)
    assert used <= 2, f"weighted capacity must never exceed 2 under a deploy/resume race (got {used})"
    assert len(occ) == 1, "exactly one of deploy|resume may hold the host"
    loser = [r["range_status"] for r in recs if r["range_status"] not in ("deployed", "deploying")]
    assert loser and loser[0] in ("queued_slot", "suspended"), (
        f"the turned-away range must queue or stay suspended, got {loser!r}")


@_PG_SKIP
def test_pg_race_deploy_vs_reconcile():
    """R4-4 deploy/reconcile: a capstone deploy races a full admin maintenance pass (/admin/reconcile
    -> _maintenance, which also takes the per-host lock to fill freed slots). The maintenance pass and
    the deploy must serialize on the lock: the deploy lands exactly once and persisted capacity never
    exceeds the 2-unit budget (no double-count, no lost reservation)."""
    _appmod, application = _pg_app(board=6, cap_units=2)
    t_dep = _pg_candidate(application, "pgrc1", 6)

    recs = _run_pg_race(application, [_labstart_worker(t_dep, "pgrc1"),
                                      _reconcile_worker()])
    # the deploy worker must reach admission with a state; the reconcile worker just returns 200
    _assert_all_reached_admission([recs[0]])
    assert recs[1]["error"] is None and recs[1]["status"] == 200, (
        f"reconcile worker failed: status={recs[1]['status']!r} err={recs[1]['error']}")

    occ, used = _weighted_capacity(application)
    assert used <= 2, f"weighted capacity must never exceed 2 under a deploy/reconcile race (got {used})"
    assert len(occ) == 1 and occ[0].board == 6, "the single capstone deploy must land exactly once"
    assert recs[0]["range_status"] in ("deployed", "deploying"), (
        f"the deploy must hold its slot through the reconcile, got {recs[0]['range_status']!r}")
