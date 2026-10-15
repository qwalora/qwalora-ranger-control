"""M4.1 tests: the continuous operational telemetry stream - deterministic
windowable planner, two-plane separation, and the recovery-safe driver under
partial bulk failure, worker interruption, delayed/out-of-order arrival, duplicate
delivery, backpressure, bounded queue, and dead-letter. Fully offline (no cluster)."""
import datetime as _dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from siem import telemetry_stream as ts
from siem import enterprise

OP_INDEX = "ranger-op-pilot-cand-a-b2"
START = _dt.datetime(2026, 10, 15, 12, 0, 0, tzinfo=_dt.timezone.utc)

P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


class FakeSink:
    """Controllable OpenSearch-bulk stand-in with op_type=create semantics.
      - store: uid -> source (created once; a second create returns 409)
      - throttle: this many upcoming bulk CALLS return 429 for all docs
      - fail_once: uids that return 503 on their first attempt then succeed
      - permafail: uids that always return 400 (-> dead-letter)
      - raise_times: this many upcoming bulk CALLS raise (transport failure)
    """
    def __init__(self):
        self.store = {}
        self.throttle = 0
        self.fail_once = set()
        self._failed_once = set()
        self.permafail = set()
        self.raise_times = 0
        self.calls = 0

    def bulk(self, index, docs):
        self.calls += 1
        if self.raise_times > 0:
            self.raise_times -= 1
            raise ConnectionError("simulated transport failure")
        throttling = self.throttle > 0
        if throttling:
            self.throttle -= 1
        out = []
        for d in docs:
            uid = d["uid"]
            if throttling:
                out.append({"uid": uid, "status": 429}); continue
            if uid in self.permafail:
                out.append({"uid": uid, "status": 400}); continue
            if uid in self.fail_once and uid not in self._failed_once:
                self._failed_once.add(uid)
                out.append({"uid": uid, "status": 503}); continue
            if uid in self.store:
                out.append({"uid": uid, "status": 409}); continue
            self.store[uid] = d["source"]
            out.append({"uid": uid, "status": 201})
        return out


def _plan(profile="functional", duration_s=3600):
    return ts.StreamPlan("cand-a", 2, "op-seed-01", profile, START, duration_s)


def run():
    # ---- determinism -------------------------------------------------------
    p1 = _plan(); p2 = _plan()
    u1 = [e["uid"] for e in p1.all()]; u2 = [e["uid"] for e in p2.all()]
    check("deterministic: identical uids across two builds", u1 == u2 and len(u1) > 0)
    check("deterministic: identical arrival order", [e["arrival"] for e in p1.all()] == [e["arrival"] for e in p2.all()])

    # ---- window partitioning (no gaps, no overlaps) ------------------------
    full = p1.all()
    mid = START + _dt.timedelta(seconds=1800)
    w1 = p1.window(START, mid)
    w2 = p1.window(mid, p1.end + _dt.timedelta(seconds=14400))  # include delayed arrivals
    uids_full = {e["uid"] for e in full}
    uids_parts = {e["uid"] for e in w1} | {e["uid"] for e in w2}
    overlap = {e["uid"] for e in w1} & {e["uid"] for e in w2}
    check("window partition covers every event", uids_parts == uids_full)
    check("window partition is disjoint (no duplicate delivery across windows)", not overlap)

    # ---- delayed / out-of-order arrival modeled ---------------------------
    delayed = [e for e in full if e["arrival"] > e["event_ts"]]
    check("some events arrive later than their event-time (delayed arrival modeled)", len(delayed) > 0)
    if delayed:
        e = delayed[0]
        # it belongs to the window containing its ARRIVAL, not its event-time
        win = p1.window(e["arrival"] - _dt.timedelta(seconds=1), e["arrival"] + _dt.timedelta(seconds=1))
        check("delayed event is placed by arrival-time, not event-time",
              any(x["uid"] == e["uid"] for x in win))

    # ---- two-plane separation ---------------------------------------------
    check("operational events are tagged plane=operational",
          all(e["source"]["ranger"].get("plane") == "operational" for e in full))
    check("operational events carry current-era timestamps (>= engagement start)",
          all(e["event_ts"] >= START for e in full))
    # qualification generator remains deterministic and untouched (fixed 2026-03 anchor)
    q1, _ = enterprise.generate("cand-a", 2, "q", "A")
    q2, _ = enterprise.generate("cand-a", 2, "q", "A")
    check("qualification plane still deterministic + anchored to scenario time (not now)",
          [d["_id"] for d in q1] == [d["_id"] for d in q2]
          and all(str(d["_source"]["@timestamp"]).startswith("2026-03") for d in q1))
    check("no hidden truth in operational event bodies",
          all("malicious" not in e["source"] and "verdict" not in e["source"] for e in full))

    now = p1.end + _dt.timedelta(seconds=15000)  # past all arrivals incl. max delay

    # ---- happy path: full stream indexed exactly once ----------------------
    sink = FakeSink(); wm = ts.InMemoryWatermarks()
    drv = ts.StreamDriver(sink, wm, OP_INDEX)
    r = drv.tick(p1, "cand-a", now)
    check("happy path advances watermark", r.advanced and wm.get("cand-a") == now)
    check("happy path indexes every event exactly once",
          len(sink.store) == len(full) and r.indexed == len(full) and not r.dead)

    # ---- duplicate delivery / replay idempotency ---------------------------
    sink2 = FakeSink(); wm2 = ts.InMemoryWatermarks()
    drv2 = ts.StreamDriver(sink2, wm2, OP_INDEX)
    drv2._drive(full, "cand-a", now)                 # first delivery
    before = dict(sink2.store)
    res = drv2._drive(full, "cand-a", now)           # replay same window
    check("replay is idempotent: no duplicates, all conflicts",
          sink2.store == before and res.conflicts == len(full) and res.indexed == 0)

    # ---- partial bulk failure (retryable) ----------------------------------
    sink3 = FakeSink(); wm3 = ts.InMemoryWatermarks()
    some = {e["uid"] for e in full[:5]}
    sink3.fail_once = set(some)
    drv3 = ts.StreamDriver(sink3, wm3, OP_INDEX)
    r3 = drv3.tick(p1, "cand-a", now)
    check("partial bulk failure retried to completion, no loss, no dead-letter",
          r3.advanced and len(sink3.store) == len(full) and not r3.dead)

    # ---- worker interruption (transport raises, then recovers) -------------
    sink4 = FakeSink(); wm4 = ts.InMemoryWatermarks()
    sink4.raise_times = 1   # first bulk call throws; driver retries
    drv4 = ts.StreamDriver(sink4, wm4, OP_INDEX)
    r4 = drv4.tick(p1, "cand-a", now)
    check("interruption mid-tick recovers with no loss / no dup",
          r4.advanced and len(sink4.store) == len(full))
    # simulate a crash where the watermark was NOT advanced, then resume
    sink4b = FakeSink(); wm4b = ts.InMemoryWatermarks()
    drv4b = ts.StreamDriver(sink4b, wm4b, OP_INDEX)
    drv4b._drive(full, "cand-a", now)   # "committed" to sink
    # watermark lost (crash before set) -> resume from plan.start reprocesses window
    wm4b.set("cand-a", p1.start)
    r4b = drv4b.tick(p1, "cand-a", now)
    check("resume after lost watermark reprocesses via create, no duplicates",
          r4b.advanced and len(sink4b.store) == len(full) and r4b.conflicts == len(full))

    # ---- backpressure: 429 holds the watermark, retries later --------------
    sink5 = FakeSink(); wm5 = ts.InMemoryWatermarks()
    sink5.throttle = 99   # every call throttles for now
    drv5 = ts.StreamDriver(sink5, wm5, OP_INDEX, max_retries=2)
    r5 = drv5.tick(p1, "cand-a", now)
    check("backpressure holds watermark (no advance) and drops nothing",
          (not r5.advanced) and r5.backpressure and wm5.get("cand-a") is None and not sink5.store)
    sink5.throttle = 0    # pressure clears
    r5b = drv5.tick(p1, "cand-a", now)
    check("after pressure clears, same window streams fully",
          r5b.advanced and len(sink5.store) == len(full))

    # ---- bounded queue -----------------------------------------------------
    sink6 = FakeSink(); wm6 = ts.InMemoryWatermarks()
    drv6 = ts.StreamDriver(sink6, wm6, OP_INDEX, queue_max=3)
    r6 = drv6.tick(p1, "cand-a", now)
    check("bounded queue refuses an oversized window without dropping or advancing",
          (not r6.advanced) and r6.backpressure and r6.reason == "queue_exceeded" and not sink6.store)

    # ---- dead-letter visibility + redrive ----------------------------------
    sink7 = FakeSink(); wm7 = ts.InMemoryWatermarks()
    bad = full[0]["uid"]
    sink7.permafail = {bad}
    drv7 = ts.StreamDriver(sink7, wm7, OP_INDEX)
    r7 = drv7.tick(p1, "cand-a", now)
    check("persistent failure -> dead-letter (visible), others indexed, watermark advances",
          r7.advanced and any(d["uid"] == bad for d in r7.dead)
          and len(sink7.store) == len(full) - 1)
    # redrive after the fault clears
    sink7.permafail = set()
    docs_by_uid = {e["uid"]: e for e in full}
    still = drv7.redrive(r7.dead, docs_by_uid)
    check("dead-letter is re-drivable once the fault clears",
          not still and bad in sink7.store)

    # ---- profiles + estimates ----------------------------------------------
    check("three workload profiles defined", set(ts.STREAM_PROFILES) == {"functional", "operational", "stress"})
    est = ts.estimate("operational", 86400, candidates=25)
    check("aggregate peak EPS = N x peak (25 x 8 = 200), not an average-based figure",
          est["aggregate_peak_eps"] == 200.0)

    print(f"\n{P} passed, {F} failed")
    return F == 0


def test_telemetry_stream():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
