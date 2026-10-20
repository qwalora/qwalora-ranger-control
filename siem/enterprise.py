"""Enterprise financial-sector telemetry generation for Board 2.

Represents a fictional financial-services organization (Valyria Financial Group)
with a coherent topology: identities, assets, business applications, and network
segments with realistic relationships. Telemetry is generated across eleven data
sources with consistent identities, diurnal timestamps, plausible source and
destination relationships, heavy benign operational noise, and realistic
imperfections (delayed and out-of-order arrival, partial observability).

Benign background activity is generated INDEPENDENTLY of the incident truth model,
so candidates must separate relevant evidence from normal behavior. Each scenario
has a hidden truth model (the malicious event ids, the technique chain, the verdict)
that is returned to the Ranger backend for grading and is NEVER part of the
telemetry that reaches a candidate index.

Three workload profiles (A functional, B enterprise investigation, C stress) scale
the benign volume and incident count. All data is synthetic and clearly tagged so.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import random as _random

from .schema import normalized

ORG = "valyria-financial"

# --- topology --------------------------------------------------------------
SEGMENTS = ["corp", "dmz", "datacenter", "identity", "remote"]
DEPARTMENTS = ["trading", "retail-banking", "finance", "compliance", "it", "hr"]
BUSINESS_APPS = ["core-banking", "trading-platform", "customer-portal",
                 "payment-gateway", "hr-workday"]

# Identities: employees per department, service accounts, and tiered admins.
def _people():
    first = ["aria", "jon", "tyrion", "sansa", "davos", "brienne", "podrick", "missandei",
             "varys", "bronn", "gendry", "yara", "theon", "ellaria", "oberyn", "doran"]
    last = ["stark", "snow", "lannister", "tully", "seaworth", "tarth", "payne", "naath",
            "spider", "blackwater", "waters", "greyjoy", "sand", "martell"]
    r = _random.Random("people")
    ppl = []
    for dept in DEPARTMENTS:
        for _ in range(r.randint(6, 10)):
            ppl.append({"user": f"{r.choice(first)}.{r.choice(last)}{r.randint(1,9)}",
                        "dept": dept, "segment": "remote" if dept in ("trading",) and r.random() < .3 else "corp"})
    return ppl

PEOPLE = _people()
SERVICE_ACCOUNTS = [
    {"user": "svc-sql", "normal_hosts": ["db-core", "db-trading"], "pattern": "db-automation"},
    {"user": "svc-backup", "normal_hosts": ["app-core", "db-core", "db-trading"], "pattern": "nightly-backup"},
    {"user": "svc-web", "normal_hosts": ["web-portal", "web-payments"], "pattern": "app-pool"},
    {"user": "svc-scan", "normal_hosts": ["sec-scanner"], "pattern": "vuln-scan"},
]
ADMINS = [
    {"user": "adm.tier0", "tier": 0, "hosts": ["dc01", "dc02"]},        # domain admins
    {"user": "adm.servers", "tier": 1, "hosts": ["app-core", "db-core", "db-trading", "web-portal"]},
    {"user": "adm.helpdesk", "tier": 2, "hosts": ["ws-corp"]},
]
HOSTS = {
    "dc01": "identity", "dc02": "identity", "app-core": "datacenter", "db-core": "datacenter",
    "db-trading": "datacenter", "web-portal": "dmz", "web-payments": "dmz", "sec-scanner": "datacenter",
    "fw-edge": "dmz", "dns01": "identity", "vpn-gw": "remote",
}
for i in range(1, 9):
    HOSTS[f"ws-corp-{i:02d}"] = "corp"

EXTERNAL_BENIGN = ["windowsupdate.com", "github.com", "api.bloomberg.com", "o365.microsoft.com",
                   "ntp.pool.org", "symantec-liveupdate.com"]
EXTERNAL_SUS = ["cdn-metrics.ru", "a7f3k.ddns.net", "paste.ee", "transfer-sh.io", "dns-tunnel.xyz"]


def _uid(scope: str, n: int) -> str:
    return hashlib.sha256(f"{scope}:{n}".encode()).hexdigest()[:20]


# --- workload profiles -----------------------------------------------------
PROFILES = {
    # (benign events, incident scenarios, span days)
    "A": {"benign": 400, "incidents": 1, "days": 2, "desc": "Functional: dev, grading regression, authz tests"},
    "B": {"benign": 8000, "incidents": 3, "days": 14, "desc": "Enterprise investigation (the Board 2 experience)"},
    "C": {"benign": 40000, "incidents": 5, "days": 30, "desc": "Stress benchmark (bounded, not continuous)"},
}
# Profile B's 8000 is the default per-candidate size that fits the pilot envelope;
# it scales with a multiplier for larger cohorts/benchmarks (Profile C) under approval.


class _Clock:
    """Diurnal business-hours-weighted timestamps over a span, with occasional
    delayed and out-of-order arrival to mimic real ingestion."""
    def __init__(self, rng, start, days):
        self.r = rng
        self.start = start
        self.days = days

    def business_ts(self):
        day = self.r.randint(0, self.days - 1)
        # weight toward 08:00-18:00 local, with a long tail
        if self.r.random() < 0.8:
            hour = int(min(23, max(0, self.r.gauss(13, 3))))
        else:
            hour = self.r.randint(0, 23)
        t = self.start + _dt.timedelta(days=day, hours=hour,
                                       minutes=self.r.randint(0, 59), seconds=self.r.randint(0, 59))
        return t

    def arrival_delay(self):
        # most events arrive promptly; some are delayed (log shipping lag)
        return _dt.timedelta(seconds=0) if self.r.random() < 0.9 else _dt.timedelta(minutes=self.r.randint(1, 240))


def _ev(events, candidate_id, board, seed, ts_event, ts_ingest, dataset, category, action,
        host, message, extra, scope, n, malicious=False):
    doc = normalized(candidate_id, board, seed, dataset, category, action, host, message,
                     ts_event.isoformat(), extra)
    doc["host"]["segment"] = HOSTS.get(host, "corp")
    doc["event"]["ingested"] = ts_ingest.isoformat()      # may differ from @timestamp (delay/out-of-order)
    uid = _uid(scope, n)
    doc["ranger"]["event_uid"] = uid
    # The truth label is NEVER written to the candidate index; we track it only in
    # the returned truth model, keyed by uid.
    events.append({"_id": uid, "_source": doc, "_malicious": malicious})
    return uid


def _benign(events, r, clock, candidate_id, board, seed):
    """Normal operations, maintenance, failed-auth noise, legitimate privileged admin,
    and false-positive-shaped events. Independent of any incident."""
    n = 0
    count = events.__len__
    target = r._benign_target
    while len([e for e in events if not e["_malicious"]]) < target:
        te = clock.business_ts()
        ti = te + clock.arrival_delay()
        pick = r.random()
        if pick < 0.34:                                   # workstation / app logons
            p = r.choice(PEOPLE)
            host = ("vpn-gw" if p["segment"] == "remote" else r.choice([h for h in HOSTS if h.startswith("ws-corp")]))
            _ev(events, candidate_id, board, seed, te, ti, "windows.security", "authentication",
                "logon", host, f"Account logged on: {p['user']}",
                {"user.name": p["user"], "winlog.event_id": 4624,
                 "winlog.logon_type": 10 if host == "vpn-gw" else 2, "event.outcome": "success",
                 "source.ip": f"10.{SEGMENTS.index(HOSTS[host])}.{r.randint(0,9)}.{r.randint(2,254)}"},
                "benign", n)
        elif pick < 0.5:                                  # DNS to benign externals
            host = r.choice(list(HOSTS))
            _ev(events, candidate_id, board, seed, te, ti, "network.dns", "network", "dns_query",
                host, f"query {r.choice(EXTERNAL_BENIGN)} A",
                {"dns.question.name": r.choice(EXTERNAL_BENIGN)}, "benign", n)
        elif pick < 0.62:                                 # web app requests
            host = r.choice(["web-portal", "web-payments"])
            app = "customer-portal" if host == "web-portal" else "payment-gateway"
            _ev(events, candidate_id, board, seed, te, ti, "network.http", "network", "http_request",
                host, "GET /api/accounts 200",
                {"http.request.method": "GET", "http.response.status_code": 200,
                 "url.original": "/api/accounts", "ranger_app": app}, "benign", n)
        elif pick < 0.72:                                 # failed-auth noise (benign: typos, locked)
            p = r.choice(PEOPLE)
            host = r.choice([h for h in HOSTS if h.startswith("ws-corp")])
            _ev(events, candidate_id, board, seed, te, ti, "windows.security", "authentication",
                "logon_failed", host, f"Failed logon: {p['user']} (bad password)",
                {"user.name": p["user"], "winlog.event_id": 4625, "event.outcome": "failure"},
                "benign", n)
        elif pick < 0.82:                                 # legitimate service automation
            s = r.choice(SERVICE_ACCOUNTS)
            host = r.choice(s["normal_hosts"])
            _ev(events, candidate_id, board, seed, te, ti, "database.audit", "database", "query",
                host, f"{s['user']} ran scheduled {s['pattern']}",
                {"user.name": s["user"], "ranger_pattern": s["pattern"]}, "benign", n)
        elif pick < 0.9:                                  # legitimate privileged admin
            a = r.choice(ADMINS)
            host = r.choice(a["hosts"])
            _ev(events, candidate_id, board, seed, te, ti, "linux.sudo" if host.startswith(("app", "db")) else "windows.security",
                "process" if host.startswith(("app", "db")) else "authentication",
                "sudo" if host.startswith(("app", "db")) else "privileged_logon", host,
                f"{a['user']} performed admin action on {host}",
                {"user.name": a["user"], "winlog.event_id": 4672}, "benign", n)
        else:                                             # firewall allow (normal egress) + EDR benign process
            host = r.choice(list(HOSTS))
            _ev(events, candidate_id, board, seed, te, ti, "edr.process", "process", "process_start",
                host, f"{r.choice(['outlook.exe','chrome.exe','python3','java'])} started",
                {"process.name": r.choice(["outlook.exe", "chrome.exe", "python3", "java"]),
                 "process.pid": r.randint(1000, 40000)}, "benign", n)
        n += 1
        if n > target * 4:      # safety bound
            break


# --- incident scenarios (hidden truth models) ------------------------------
def _scenario(events, r, clock, candidate_id, board, seed, family, sidx):
    """Emit one incident's malicious events and return its truth model. The chain
    is coherent (same actor, hosts, timeline). Labels stay in the truth model, not
    the index."""
    uids = []
    t0 = clock.business_ts().replace(hour=r.choice([2, 3, 22, 23]))   # off-hours foothold
    actor_ip = f"198.51.100.{r.randint(2,254)}"                        # TEST-NET-2
    victim = r.choice(PEOPLE)
    n = sidx * 100000

    def m(dmin, dataset, category, action, host, message, extra):
        nonlocal n
        te = t0 + _dt.timedelta(minutes=dmin)
        ti = te + clock.arrival_delay()
        uid = _ev(events, candidate_id, board, seed, te, ti, dataset, category, action,
                  host, message, extra, f"incident{sidx}", n, malicious=True)
        uids.append(uid); n += 1
        return uid

    tech = []
    if family == "privileged-identity-compromise":
        m(0, "cloud.signin", "authentication", "cloud_login", "vpn-gw",
          f"Risky sign-in for {victim['user']} from {actor_ip} (impossible travel)",
          {"user.name": victim["user"], "source.ip": actor_ip, "event.outcome": "success"})
        m(12, "windows.security", "iam", "group_member_added", "dc01",
          f"Member added to Domain Admins: {victim['user']}",
          {"user.name": victim["user"], "winlog.event_id": 4728})
        m(20, "edr.process", "process", "process_start", "app-core",
          "powershell.exe -enc <base64> (spawned by services.exe)",
          {"process.name": "powershell.exe", "process.command_line": "-enc"})
        m(35, "database.audit", "database", "query", "db-core",
          f"{victim['user']} read customer_pii from core-banking",
          {"user.name": victim["user"], "ranger_app": "core-banking"})
        tech = ["T1078", "T1098", "T1059.001", "T1213"]
        verdict = "true_positive"
    elif family == "data-exfiltration":
        m(0, "windows.security", "authentication", "logon", "ws-corp-03",
          f"Account logged on: {victim['user']}", {"user.name": victim["user"], "winlog.event_id": 4624, "winlog.logon_type": 3})
        m(18, "network.http", "network", "http_request", "web-portal",
          "GET /api/export?all=true 200 (bytes=84211233)",
          {"http.request.method": "GET", "http.response.status_code": 200, "url.original": "/api/export"})
        c2 = EXTERNAL_SUS[0]
        for i in range(4):
            m(25 + i * 9, "network.dns", "network", "dns_query", "ws-corp-03",
              f"query {hashlib.md5(str(i).encode(), usedforsecurity=False).hexdigest()[:10]}.{c2} TXT",
              {"dns.question.name": f"x{i}.{c2}", "destination.ip": actor_ip})
        m(60, "network.firewall", "network", "firewall_allow", "fw-edge",
          f"ALLOW ws-corp-03 -> {actor_ip}:443 (bytes=84000000)",
          {"destination.ip": actor_ip, "destination.port": 443, "network.action": "allowed"})
        tech = ["T1078", "T1530", "T1048", "T1071.004"]
        verdict = "true_positive"
    elif family == "compromised-service-identity":
        s = r.choice(SERVICE_ACCOUNTS)
        wrong = r.choice([h for h in HOSTS if h not in s["normal_hosts"] and h.startswith("ws-corp")])
        m(0, "windows.security", "authentication", "logon", wrong,
          f"Interactive logon by service account {s['user']} on {wrong}",
          {"user.name": s["user"], "winlog.event_id": 4624, "winlog.logon_type": 2})
        m(10, "linux.sudo", "process", "sudo", "db-trading",
          f"{s['user']} escalated to root outside automation window",
          {"user.name": s["user"], "user.target": "root"})
        m(22, "database.audit", "database", "query", "db-trading",
          f"{s['user']} ran ad-hoc SELECT on trading.positions",
          {"user.name": s["user"], "ranger_app": "trading-platform"})
        tech = ["T1078.003", "T1548", "T1005"]
        verdict = "true_positive"
    elif family == "endpoint-lateral-movement":
        src = "ws-corp-05"
        m(0, "edr.process", "process", "process_start", src,
          "cmd.exe /c whoami (parent: winword.exe)",
          {"process.name": "cmd.exe", "process.command_line": "whoami"})
        for i, dst in enumerate(["ws-corp-06", "app-core", "db-core"]):
            m(10 + i * 8, "windows.security", "authentication", "logon", dst,
              f"Network logon from {src} using {victim['user']}",
              {"user.name": victim["user"], "winlog.event_id": 4624, "winlog.logon_type": 3,
               "source.ip": "10.0.0.5"})
        m(40, "edr.process", "process", "process_start", "app-core",
          "psexesvc.exe installed (remote admin)", {"process.name": "psexesvc.exe"})
        tech = ["T1059", "T1021.002", "T1570", "T1569.002"]
        verdict = "true_positive"
    else:   # detection-failure (false negative): malicious behavior present, detector gapped
        # Same shape as an exfil, but over a channel the (gapped) rule does not cover.
        m(0, "windows.security", "authentication", "logon", "ws-corp-07",
          f"Account logged on: {victim['user']}", {"user.name": victim["user"], "winlog.event_id": 4624})
        m(30, "network.dns", "network", "dns_query", "ws-corp-07",
          f"query {EXTERNAL_SUS[4]} TXT (long label DNS tunneling)",
          {"dns.question.name": EXTERNAL_SUS[4], "destination.ip": actor_ip})
        tech = ["T1071.004", "T1048.003"]
        verdict = "true_positive_missed_by_detector"

    return {"family": family, "event_uids": uids, "techniques": tech, "verdict": verdict,
            "actor_ip": actor_ip, "primary_identity": victim["user"]}


SCENARIO_FAMILIES = ["privileged-identity-compromise", "data-exfiltration",
                     "compromised-service-identity", "endpoint-lateral-movement",
                     "detection-failure"]


def generate(candidate_id: str, board: int, seed: str, profile: str = "B",
             families=None):
    """Return (events, truth). `events` go to the candidate's index with no labels;
    `truth` stays in the Ranger backend for grading. Pure function of the seed.

    `families` (optional): an explicit, ordered list of incident families to inject,
    so a ScenarioSpec can drive composition deterministically instead of the default
    random sample. Each must be a known SCENARIO_FAMILIES value; unknown -> ValueError.
    Default (None) preserves the original seed-driven random selection."""
    cfg = PROFILES[profile]
    r = _random.Random(f"ent:{board}:{seed}:{profile}")
    r._benign_target = cfg["benign"]
    start = _dt.datetime(2026, 3, 1, tzinfo=_dt.timezone.utc)
    clock = _Clock(r, start, cfg["days"])

    events: list[dict] = []
    # incidents first (so benign fills around them to the target benign count)
    if families is not None:
        bad = [f for f in families if f not in SCENARIO_FAMILIES]
        if bad:
            raise ValueError(f"unknown scenario families: {bad}")
        chosen = list(families)[:cfg["incidents"]]
    else:
        chosen = r.sample(SCENARIO_FAMILIES, min(cfg["incidents"], len(SCENARIO_FAMILIES)))
    truth = []
    for i, fam in enumerate(chosen):
        truth.append(_scenario(events, r, clock, candidate_id, board, seed, fam, i))
    _benign(events, r, clock, candidate_id, board, seed)

    # out-of-order: shuffle so index order != time order (candidates must sort)
    r.shuffle(events)
    # strip the internal _malicious flag from what gets indexed
    indexed = [{"_id": e["_id"], "_source": e["_source"]} for e in events]
    return indexed, {"profile": profile, "incidents": truth,
                     "counts": {"total": len(events),
                                "malicious": sum(1 for e in events if e["_malicious"]),
                                "benign": sum(1 for e in events if not e["_malicious"])}}
