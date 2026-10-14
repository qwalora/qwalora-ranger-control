"""Scenario generators + graders, keyed by each ranger's scenario seed.

The generator is a pure function of the seed, so the same seed reproduces the
same world and the same answer key. The key is produced here, on the server,
and never leaves it: candidates get the dataset with the key stripped, submit
their analysis, and the server re-derives the key from the seed to score them.
That is what keeps grading answer-free and un-gameable, and what makes a
returning ranger's different seed a genuinely different exercise.

Only board 1 (SOC triage) is implemented here. Boards 2-6 follow the same
shape: generate(seed) -> scenario, public_view(scenario), score(scenario, sub).
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


# --- dispatch ---------------------------------------------------------------
_GENERATORS = {1: (generate_board1, public_board1, score_board1)}


def has_board(n):
    return n in _GENERATORS


def dataset(n, seed):
    gen, pub, _ = _GENERATORS[n]
    return pub(gen(seed))


def grade(n, seed, submission):
    gen, _, scorer = _GENERATORS[n]
    return scorer(gen(seed), submission)
