"""Board 2 Milestone 4.1 - continuous operational telemetry stream.

The OPERATIONAL data plane: telemetry that arrives continuously with current
wall-clock timestamps, so a candidate's SOC is alive while they work. This is
distinct from the QUALIFICATION plane (siem/enterprise.py), which stays
deterministic, versioned, and reproducible for grading. The operational stream:

  - writes only to a candidate's own `ranger-op-*` index (never the qualification
    index), so it cannot alter qualification evidence, grades, or hidden truth;
  - is a deterministic function of (candidate, seed, profile, engagement_start):
    same inputs reproduce the same events and the same event ids, which is what
    makes restart recovery safe;
  - is windowed by ARRIVAL time, so delayed / out-of-order arrival is modeled and
    consecutive windows partition the stream exactly (no gaps, no overlaps).

This module is pure/offline: the planner materializes events and the driver moves
them through an injected sink. A live OpenSearch bulk sink and a Postgres watermark
store are wired in M4.2; here they are protocols exercised by in-memory fakes.

Nothing here is enabled in production: the portal gates the stream behind
`RANGER_TELEMETRY_STREAM` (default off), and general candidate access / act-as stay
disabled by their own flags.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import math
import random as _random

from .schema import normalized

OP_ORG = "valyria-financial"

# --- workload profiles (targets; measured numbers replace these in the benchmark) --
# avg_eps drives the materialized count; peak_eps is the diurnal peak used for
# aggregate planning (aggregate peak = N_candidates * peak_eps). incidents is the
# number of malicious chains injected across the engagement.
STREAM_PROFILES = {
    "functional":  {"avg_eps": 0.1, "peak_eps": 0.5,  "incidents": 1,
                    "desc": "low-rate ingestion + recovery testing; smoke only, NOT an enterprise workload"},
    "operational": {"avg_eps": 2.0, "peak_eps": 8.0,  "incidents": 3,
                    "desc": "realistic multi-source activity with a meaningful investigation workload"},
    "stress":      {"avg_eps": 8.0, "peak_eps": 25.0, "incidents": 5,
                    "desc": "bounded burst to find the safe ceiling; never continuous"},
}

# benign source mix (dataset, category, action, builder) - a trimmed, detector-
# compatible subset of the qualification generator's sources.
_EXTERNAL_BENIGN = ["windowsupdate.com", "github.com", "api.bloomberg.com",
                    "o365.microsoft.com", "ntp.pool.org"]
_WS = [f"ws-corp-{i:02d}" for i in range(1, 9)]
_EXTERNAL_SUS = "dns-tunnel.xyz"

# incident families, aligned with siem/enterprise.py so Security Analytics detectors
# (M4.2) fire on the same tradecraft. Each returns a short correlated chain.
_FAMILIES = ["privileged-identity-compromise", "data-exfiltration",
             "endpoint-lateral-movement", "detection-failure"]


def _uid(seed, profile, eng_iso, seq):
    """Deterministic, replay-stable event id."""
    return hashlib.sha256(f"op:{seed}:{profile}:{eng_iso}:{seq}".encode()).hexdigest()[:20]


def estimate(profile: str, duration_s: float, candidates: int = 1) -> dict:
    """Modeled event/storage expectations for a profile (pre-measurement)."""
    p = STREAM_PROFILES[profile]
    per_cand = int(p["avg_eps"] * duration_s)
    peak_aggregate = p["peak_eps"] * candidates
    return {"profile": profile, "events_per_candidate": per_cand,
            "events_total": per_cand * candidates,
            "aggregate_peak_eps": peak_aggregate,
            "approx_bytes_per_candidate": per_cand * 1024}  # ~1 KB/event, to be measured


class StreamPlan:
    """Materializes the operational stream for one engagement. Pure + deterministic.

    Events carry an event-time (@timestamp) and an arrival-time (event.ingested);
    windows are taken over ARRIVAL. Hidden truth (which uids are malicious) is kept
    in `.truth()` for the backend only and is never written to any event body."""

    def __init__(self, candidate_id, board, seed, profile, engagement_start, duration_s,
                 max_delay_s=None):
        if profile not in STREAM_PROFILES:
            raise ValueError(f"unknown profile {profile!r}")
        self.candidate_id = candidate_id
        self.board = board
        self.seed = seed
        self.profile = profile
        self.start = _as_utc(engagement_start)
        self.duration_s = float(duration_s)
        # Cap simulated log-shipping lag so a time-boxed live run can drain all
        # arrivals; default None keeps the full 1..240 min realism for offline use.
        self.max_delay_s = max_delay_s
        self.end = self.start + _dt.timedelta(seconds=self.duration_s)
        self._eng_iso = self.start.isoformat()
        self._r = _random.Random(f"opstream:{seed}:{profile}:{self._eng_iso}")
        self._seq = 0
        self._events: list[dict] = []
        self._truth: list[dict] = []
        self._materialize()

    # -- deterministic materialization --------------------------------------
    def _emit(self, event_offset_s, dataset, category, action, host, message, extra,
              malicious=False):
        ev_ts = self.start + _dt.timedelta(seconds=event_offset_s)
        # arrival delay: most prompt, some delayed (log-shipping lag) -> out-of-order
        if self.max_delay_s is not None:
            delay = 0 if self._r.random() < 0.9 else self._r.randint(1, int(self.max_delay_s))
        else:
            delay = 0 if self._r.random() < 0.9 else self._r.randint(1, 240) * 60
        arr_ts = ev_ts + _dt.timedelta(seconds=delay)
        uid = _uid(self.seed, self.profile, self._eng_iso, self._seq)
        self._seq += 1
        doc = normalized(self.candidate_id, self.board, self.seed, dataset, category,
                         action, host, message, ev_ts.isoformat(), extra)
        doc["host"]["segment"] = "corp"
        doc["event"]["ingested"] = arr_ts.isoformat()
        doc["ranger"]["event_uid"] = uid
        doc["ranger"]["plane"] = "operational"
        self._events.append({"uid": uid, "event_ts": ev_ts, "arrival": arr_ts,
                             "source": doc, "malicious": malicious})
        return uid

    def _diurnal_offset(self):
        """A business-hours-weighted offset within [0, duration_s)."""
        days = max(1, math.ceil(self.duration_s / 86400))
        for _ in range(8):
            day = self._r.randrange(days)
            hour = int(min(23, max(0, self._r.gauss(13, 3))))
            off = day * 86400 + hour * 3600 + self._r.randint(0, 59) * 60 + self._r.randint(0, 59)
            if off < self.duration_s:
                return off
        return self._r.random() * self.duration_s

    def _benign_one(self, off):
        pick = self._r.random()
        if pick < 0.4:
            host = self._r.choice(_WS)
            user = f"user{self._r.randint(1, 60)}"
            self._emit(off, "windows.security", "authentication", "logon", host,
                       f"Account logged on: {user}",
                       {"user.name": user, "winlog.event_id": 4624,
                        "winlog.logon_type": 2, "event.outcome": "success",
                        "source.ip": f"10.0.{self._r.randint(0,9)}.{self._r.randint(2,254)}"})
        elif pick < 0.62:
            host = self._r.choice(_WS)
            self._emit(off, "network.dns", "network", "dns_query", host,
                       f"query {self._r.choice(_EXTERNAL_BENIGN)} A",
                       {"dns.question.name": self._r.choice(_EXTERNAL_BENIGN)})
        elif pick < 0.78:
            host = self._r.choice(["web-portal", "web-payments"])
            self._emit(off, "network.http", "network", "http_request", host,
                       "GET /api/accounts 200",
                       {"http.request.method": "GET", "http.response.status_code": 200,
                        "url.original": "/api/accounts"})
        elif pick < 0.9:
            host = self._r.choice(_WS)
            user = f"user{self._r.randint(1, 60)}"
            self._emit(off, "windows.security", "authentication", "logon_failed", host,
                       f"Failed logon: {user} (bad password)",
                       {"user.name": user, "winlog.event_id": 4625, "event.outcome": "failure"})
        else:
            host = self._r.choice(_WS)
            self._emit(off, "edr.process", "process", "process_start", host,
                       f"{self._r.choice(['outlook.exe','chrome.exe','python3'])} started",
                       {"process.name": self._r.choice(["outlook.exe", "chrome.exe", "python3"])})

    def _incident(self, base_off, family, sidx):
        uids = []
        victim = f"user{self._r.randint(1, 60)}"
        actor_ip = f"198.51.100.{self._r.randint(2,254)}"   # TEST-NET-2

        def m(dmin, dataset, category, action, host, message, extra):
            uids.append(self._emit(base_off + dmin * 60, dataset, category, action,
                                   host, message, extra, malicious=True))

        if family == "privileged-identity-compromise":
            m(0, "cloud.signin", "authentication", "cloud_login", "vpn-gw",
              f"Risky sign-in for {victim} from {actor_ip} (impossible travel)",
              {"user.name": victim, "source.ip": actor_ip, "event.outcome": "success"})
            m(12, "windows.security", "iam", "group_member_added", "dc01",
              f"Member added to Domain Admins: {victim}",
              {"user.name": victim, "winlog.event_id": 4728})
            m(20, "edr.process", "process", "process_start", "app-core",
              "powershell.exe -enc <base64> (spawned by services.exe)",
              {"process.name": "powershell.exe", "process.command_line": "-enc"})
            tech, verdict = ["T1078", "T1098", "T1059.001"], "true_positive"
        elif family == "data-exfiltration":
            m(0, "network.http", "network", "http_request", "web-portal",
              "GET /api/export?all=true 200 (bytes=84211233)",
              {"http.request.method": "GET", "http.response.status_code": 200,
               "url.original": "/api/export"})
            m(10, "network.dns", "network", "dns_query", "ws-corp-03",
              f"query x.{_EXTERNAL_SUS} TXT",
              {"dns.question.name": f"x.{_EXTERNAL_SUS}", "destination.ip": actor_ip})
            m(25, "network.firewall", "network", "firewall_allow", "fw-edge",
              f"ALLOW ws-corp-03 -> {actor_ip}:443 (bytes=84000000)",
              {"destination.ip": actor_ip, "destination.port": 443, "network.action": "allowed"})
            tech, verdict = ["T1530", "T1048", "T1071.004"], "true_positive"
        elif family == "endpoint-lateral-movement":
            m(0, "edr.process", "process", "process_start", "ws-corp-05",
              "cmd.exe /c whoami (parent: winword.exe)",
              {"process.name": "cmd.exe", "process.command_line": "whoami"})
            m(10, "windows.security", "authentication", "logon", "app-core",
              f"Network logon from ws-corp-05 using {victim}",
              {"user.name": victim, "winlog.event_id": 4624, "winlog.logon_type": 3})
            m(30, "edr.process", "process", "process_start", "app-core",
              "psexesvc.exe installed (remote admin)", {"process.name": "psexesvc.exe"})
            tech, verdict = ["T1059", "T1021.002", "T1569.002"], "true_positive"
        else:   # detection-failure: present but over a channel a gapped rule misses
            m(0, "windows.security", "authentication", "logon", "ws-corp-07",
              f"Account logged on: {victim}", {"user.name": victim, "winlog.event_id": 4624})
            m(30, "network.dns", "network", "dns_query", "ws-corp-07",
              f"query {_EXTERNAL_SUS} TXT (long-label DNS tunneling)",
              {"dns.question.name": _EXTERNAL_SUS, "destination.ip": actor_ip})
            tech, verdict = ["T1071.004", "T1048.003"], "true_positive_missed_by_detector"

        self._truth.append({"family": family, "event_uids": uids, "techniques": tech,
                            "verdict": verdict, "actor_ip": actor_ip,
                            "primary_identity": victim})

    def _materialize(self):
        cfg = STREAM_PROFILES[self.profile]
        # incidents first, at seed-chosen base offsets inside the window
        fams = [_FAMILIES[i % len(_FAMILIES)] for i in range(cfg["incidents"])]
        for i, fam in enumerate(fams):
            base = self._r.random() * max(1.0, self.duration_s - 1800)
            self._incident(base, fam, i)
        # benign fill to the target average rate
        n_benign = int(cfg["avg_eps"] * self.duration_s)
        for _ in range(n_benign):
            self._benign_one(self._diurnal_offset())
        self._events.sort(key=lambda e: e["arrival"])

    # -- query interface -----------------------------------------------------
    def all(self):
        return list(self._events)

    def window(self, from_ts, to_ts):
        """Events whose ARRIVAL is in [from_ts, to_ts). Half-open so consecutive
        windows partition the stream exactly."""
        f, t = _as_utc(from_ts), _as_utc(to_ts)
        return [e for e in self._events if f <= e["arrival"] < t]

    def truth(self):
        """Hidden truth for the backend only; never written to event bodies."""
        member = set()
        for inc in self._truth:
            member.update(inc["event_uids"])
        return {"profile": self.profile, "incidents": list(self._truth),
                "counts": {"total": len(self._events), "malicious": len(member),
                           "benign": len(self._events) - len(member)}}


# --- recovery-safe driver ----------------------------------------------------
class InMemoryWatermarks:
    """Persistent-watermark protocol, in memory for tests. M4.2 uses Postgres.
    The DRIVER advances the watermark only after a window is fully processed."""
    def __init__(self):
        self._d = {}

    def get(self, key):
        return self._d.get(key)

    def set(self, key, ts):
        self._d[key] = _as_utc(ts)


class TickResult:
    def __init__(self, advanced, indexed=0, conflicts=0, dead=None, backpressure=False,
                 window=0, reason=None):
        self.advanced = advanced
        self.indexed = indexed
        self.conflicts = conflicts        # idempotent re-index hits (op_type=create 409)
        self.dead = dead or []            # dead-letter: visible, re-drivable
        self.backpressure = backpressure
        self.window = window              # docs in the window
        self.reason = reason

    def as_dict(self):
        return {"advanced": self.advanced, "indexed": self.indexed,
                "conflicts": self.conflicts, "dead": self.dead,
                "backpressure": self.backpressure, "window": self.window,
                "reason": self.reason}


class StreamDriver:
    """Moves a plan's events into a sink with safe-recovery semantics.

    Sink protocol: ``bulk(index, docs) -> [{"uid","status"}]`` where status is an
    HTTP-like code: 201 created, 409 already-indexed (idempotent create), 429
    throttled (backpressure), >=500 retryable, other 4xx -> dead-letter. The sink
    may also raise for a transient transport failure (retried).

    Guarantees: no silent loss (every window doc ends indexed or dead-lettered
    before the watermark advances); no duplicates (op_type=create); backpressure
    slows emission (watermark held) rather than dropping; a bounded queue caps
    per-tick work; dead-letter is visible and re-drivable."""

    def __init__(self, sink, watermarks, index_name, max_retries=3, queue_max=5000):
        self.sink = sink
        self.wm = watermarks
        self.index = index_name
        self.max_retries = max_retries
        self.queue_max = queue_max

    def tick(self, plan, key, now):
        now = _as_utc(now)
        start = self.wm.get(key) or plan.start
        if now <= start:
            return TickResult(advanced=False, window=0, reason="no_new_window")
        docs = plan.window(start, now)
        if not docs:
            self.wm.set(key, now)
            return TickResult(advanced=True, window=0)
        if len(docs) > self.queue_max:
            # bounded queue: too much backlog for one tick; hold the watermark and
            # signal backpressure so emission slows. Nothing is dropped.
            return TickResult(advanced=False, backpressure=True, window=len(docs),
                              reason="queue_exceeded")
        return self._drive(docs, key, now)

    def _drive(self, docs, key, now):
        done, created, conflicts, dead = set(), 0, 0, []
        dead_uids = set()
        attempt = 0
        while True:
            todo = [d for d in docs if d["uid"] not in done and d["uid"] not in dead_uids]
            if not todo:
                break
            try:
                results = self.sink.bulk(self.index, todo)
            except Exception as e:  # noqa: BLE001  transient transport failure
                attempt += 1
                if attempt > self.max_retries:
                    # could not even reach the sink: hold the watermark, retry next tick
                    return TickResult(advanced=False, backpressure=True,
                                      window=len(docs), indexed=created, conflicts=conflicts,
                                      dead=dead, reason=f"transport:{type(e).__name__}")
                continue
            throttled = False
            for r in results:
                s = r["status"]
                uid = r["uid"]
                if s == 201:
                    done.add(uid); created += 1
                elif s == 409:
                    done.add(uid); conflicts += 1
                elif s == 429:
                    throttled = True
                elif s >= 500:
                    pass  # retryable; left in todo
                else:      # other 4xx -> dead-letter (visible)
                    dead_uids.add(uid); dead.append({"uid": uid, "status": s})
            if throttled:
                attempt += 1
                if attempt > self.max_retries:
                    # persistent backpressure: hold the watermark, retry this window
                    # on a later tick. No loss, no dup.
                    return TickResult(advanced=False, backpressure=True, window=len(docs),
                                      indexed=created, conflicts=conflicts, dead=dead,
                                      reason="throttled")
                continue
            remaining = [d for d in docs if d["uid"] not in done and d["uid"] not in dead_uids]
            if remaining:
                attempt += 1
                if attempt > self.max_retries:
                    for d in remaining:
                        dead_uids.add(d["uid"]); dead.append({"uid": d["uid"], "status": "max_retries"})
                    break
                continue
            break
        # window fully processed (indexed or dead-lettered) -> advance watermark
        self.wm.set(key, now)
        return TickResult(advanced=True, indexed=created, conflicts=conflicts,
                          dead=dead, window=len(docs))

    def redrive(self, dead_entries, docs_by_uid):
        """Re-attempt dead-lettered docs (operator/visible recovery). Returns the
        subset still failing."""
        todo = [docs_by_uid[e["uid"]] for e in dead_entries if e["uid"] in docs_by_uid]
        if not todo:
            return []
        results = self.sink.bulk(self.index, todo)
        still = [{"uid": r["uid"], "status": r["status"]} for r in results
                 if r["status"] not in (201, 409)]
        return still


def _as_utc(ts):
    if isinstance(ts, _dt.datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=_dt.timezone.utc)
    if isinstance(ts, str):
        return _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    raise TypeError(f"unsupported timestamp {ts!r}")
