"""Reproducible telemetry generation.

`generate(candidate_id, board, seed)` returns normalized events for one candidate:
a coherent multi-event incident (malicious activity the candidate must piece
together) interleaved with benign background noise, spanning Linux, Windows/identity,
and network sources. It is a pure function of the seed, so it reseeds identically.

Nothing in an event labels it malicious or names the technique the candidate must
identify: that would reveal the answer. Events carry raw fields and a scenario-family
tag only. Every event is synthetic, carries provenance, and has a deterministic
event_uid so ingestion is idempotent.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import random as _random

from . import GENERATOR_VERSION
from .schema import normalized

SCENARIO_FAMILIES = ("credential-misuse", "unauthorized-access", "privilege-abuse",
                     "host-persistence", "abnormal-network")

_HOSTS = ["kingslanding", "winterfell", "castelblack", "meereen", "braavos"]
_USERS = ["arya.stark", "jon.snow", "tyrion.lannister", "sansa.stark", "davos.seaworth"]
_SVC = ["nginx", "sshd", "cron", "systemd-logind", "postgres"]
_DOMAINS_BENIGN = ["updates.debian.org", "github.com", "api.internal.corp", "ntp.pool.org"]
_DOMAINS_SUS = ["a8f3k2.duckdns.org", "cdn-telemetry.xyz", "pastebin.com", "rawcdn.link"]


def _uid(candidate_id: str, seed: str, n: int) -> str:
    return hashlib.sha256(f"{candidate_id}:{seed}:{n}".encode()).hexdigest()[:20]


def generate(candidate_id: str, board: int, seed: str) -> list[dict]:
    r = _random.Random(f"siem:{board}:{seed}")
    family = r.choice(SCENARIO_FAMILIES)
    base = _dt.datetime(2026, 3, r.randint(1, 20), r.randint(0, 6), r.randint(0, 59),
                        tzinfo=_dt.timezone.utc)
    attacker_ip = f"203.0.113.{r.randint(2, 254)}"      # TEST-NET-3, non-routable
    victim_user = r.choice(_USERS)
    target = r.choice(_HOSTS)
    events = []
    n = 0

    def emit(delta_min, category, action, host, message, extra):
        nonlocal n
        ts = (base + _dt.timedelta(minutes=delta_min)).isoformat()
        doc = normalized(candidate_id, board, seed, extra.pop("_dataset"),
                         category, action, host, message, ts, extra)
        doc["ranger"]["scenario"] = family
        doc["ranger"]["event_uid"] = _uid(candidate_id, seed, n)
        events.append({"_id": doc["ranger"]["event_uid"], "_source": doc})
        n += 1

    # --- benign background noise across sources (the haystack) ----------
    for i in range(r.randint(18, 26)):
        host = r.choice(_HOSTS)
        kind = r.choice(["linux-auth", "network-dns", "network-http", "linux-process", "windows-auth"])
        t = r.randint(0, 600)
        if kind == "linux-auth":
            u = r.choice(_USERS)
            emit(t, "authentication", "ssh_login", host,
                 f"Accepted publickey for {u} from 10.0.{r.randint(0,5)}.{r.randint(2,254)} port {r.randint(30000,60000)} ssh2",
                 {"_dataset": "linux.auth", "user.name": u, "source.ip": f"10.0.{r.randint(0,5)}.{r.randint(2,254)}",
                  "event.outcome": "success"})
        elif kind == "network-dns":
            emit(t, "network", "dns_query", host,
                 f"query {r.choice(_DOMAINS_BENIGN)} A",
                 {"_dataset": "network.dns", "dns.question.name": r.choice(_DOMAINS_BENIGN)})
        elif kind == "network-http":
            emit(t, "network", "http_request", host,
                 "GET /health 200",
                 {"_dataset": "network.http", "http.request.method": "GET",
                  "http.response.status_code": 200, "url.original": "/health"})
        elif kind == "linux-process":
            p = r.choice(["ls", "cat", "python3", "systemctl", "apt-get"])
            emit(t, "process", "process_start", host, f"{p} executed",
                 {"_dataset": "linux.process", "process.name": p, "process.pid": r.randint(1000, 40000)})
        else:
            u = r.choice(_USERS)
            emit(t, "authentication", "windows_logon", host,
                 f"An account was successfully logged on. Account: {u}",
                 {"_dataset": "windows.security", "user.name": u, "winlog.event_id": 4624,
                  "winlog.logon_type": r.choice([2, 3, 7]), "event.outcome": "success"})

    # --- the incident: a coherent chain the candidate must reconstruct ---
    # 1. brute force: a burst of failed SSH from one external IP
    for i in range(r.randint(8, 15)):
        emit(620 + i, "authentication", "ssh_login_failed", target,
             f"Failed password for {victim_user} from {attacker_ip} port {r.randint(30000,60000)} ssh2",
             {"_dataset": "linux.auth", "user.name": victim_user, "source.ip": attacker_ip,
              "event.outcome": "failure"})
    # 2. successful login from the same IP
    emit(640, "authentication", "ssh_login", target,
         f"Accepted password for {victim_user} from {attacker_ip} port {r.randint(30000,60000)} ssh2",
         {"_dataset": "linux.auth", "user.name": victim_user, "source.ip": attacker_ip,
          "event.outcome": "success"})
    # 3. privilege escalation via sudo
    emit(643, "process", "sudo", target,
         f"{victim_user} : TTY=pts/0 ; PWD=/home/{victim_user} ; USER=root ; COMMAND=/bin/bash",
         {"_dataset": "linux.sudo", "user.name": victim_user, "user.target": "root"})
    # 4. persistence: a new service / cron (board-dependent flavor)
    if family in ("host-persistence", "privilege-abuse"):
        emit(648, "process", "service_install", target,
             "A new cron job was installed: * * * * * /tmp/.cache/beacon.sh",
             {"_dataset": "linux.process", "process.name": "cron", "process.command_line": "/tmp/.cache/beacon.sh"})
    # 5. file permission change on a sensitive path
    emit(650, "file", "permission_change", target,
         "mode of '/etc/sudoers.d/90-cloud' changed to 0777",
         {"_dataset": "linux.file", "file.path": "/etc/sudoers.d/90-cloud"})
    # 6. C2 beacon: periodic DNS to a suspicious domain + firewall allow
    c2 = _random.Random(seed).choice(_DOMAINS_SUS)
    for i in range(r.randint(3, 6)):
        emit(655 + i * 7, "network", "dns_query", target, f"query {c2} A",
             {"_dataset": "network.dns", "dns.question.name": c2, "destination.ip": attacker_ip})
    emit(658, "network", "firewall_allow", target,
         f"ALLOW TCP {target} -> {attacker_ip}:443",
         {"_dataset": "network.firewall", "destination.ip": attacker_ip,
          "destination.port": 443, "network.transport": "tcp", "network.action": "allowed"})
    # 7. identity: privileged group change (Windows/identity surface)
    emit(662, "iam", "group_member_added", "kingslanding",
         f"A member was added to a security-enabled global group. Member: {victim_user}; Group: Domain Admins",
         {"_dataset": "windows.security", "user.name": victim_user, "winlog.event_id": 4728})

    r.shuffle(events)  # candidates get events out of order, as in a real SIEM
    return events


def summary(events: list[dict]) -> dict:
    """Provenance summary for the ingestion record (counts by dataset, family)."""
    by_ds, families = {}, set()
    for e in events:
        src = e["_source"]
        ds = src["event"]["dataset"]
        by_ds[ds] = by_ds.get(ds, 0) + 1
        families.add(src["ranger"].get("scenario"))
    return {"total": len(events), "by_dataset": by_ds,
            "scenario_families": sorted(f for f in families if f),
            "generator_version": GENERATOR_VERSION}
