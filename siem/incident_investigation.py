"""STRATA Board-1 ADVANCED layer: multi-step incident investigation.

This is ADDITIVE to the existing Board-1 SOC triage (scenarios.generate_board1 / score_board1 are
untouched, and the 95% qualification gate is unchanged). Where triage asks "is each alert a true
positive, and what technique", the incident investigation asks the harder, self-directed question a
real SOC analyst faces: given a field of alerts, which ones belong to the SAME intrusion, how did the
attacker move, and can you defend that correlation with evidence that is actually in the telemetry.

Design principles (per the assessment's rigor requirements):
  * Coherent telemetry, real relationships. A campaign is an ORDERED chain of techniques by ONE actor
    account from ONE origin, pivoting host->host; each step's raw log carries the real linking facts
    (the actor account, the origin, and - for lateral steps - the previous host as the source). The
    correlation is reconstructible from the logs alone; nothing in the public dataset hints at the
    grouping.
  * Separation matters. The field contains a second, distinct campaign (different actor/origin) plus
    isolated true positives and benign noise, so lumping everything into one incident is wrong.
  * The grader rewards DEFENSIBLE correlation, not label guessing: grouping F1, the entry point, the
    affected host/account sets, the ORDERED technique chain, and cited evidence that genuinely appears
    across the grouped alerts. A correct grouping with no real evidence scores materially lower; a
    single giant incident is penalized on precision, entry, chain and benign contamination.
  * Answer-free and un-gameable: the key is derived from the seed on the server and never leaves it;
    the public view is alerts only.
"""
from __future__ import annotations

import datetime as _dt
import random as _random

# Attack-chain building blocks. Each step is (role, technique_id, technique_name, raw_template).
# Templates expose the actor account {user}, the origin/source {src}, the target {dst}, and small
# numeric jitter {d}; lateral/credential steps read "from {src}" so the host pivot is determinable.
_ENTRY = [
    ("entry", "T1078", "Valid Accounts",
     "Interactive logon for {user} on {dst} from {src} at 0{d}:14 (first-ever auth from this source)"),
    ("entry", "T1110.003", "Password Spraying",
     "{d}0 failed NTLM logons across 12 accounts from {src}, then one success as {user} on {dst}"),
    ("entry", "T1566.001", "Spearphishing Attachment",
     "{user} opened invoice_{d}.docm on {dst}; macro spawned powershell beaconing to {src}"),
]
_LATERAL = [
    ("lateral", "T1021.002", "SMB / Admin Shares",
     "ADMIN$ on {dst} accessed by {user} from {src}, then a service was created"),
    ("lateral", "T1021.006", "WinRM",
     "WinRM (5985) session to {dst} as {user} originating from {src}"),
    ("lateral", "T1570", "Lateral Tool Transfer",
     "psexec-style binary copied to {dst}\\C$ by {user} from {src}"),
]
_CRED = [
    ("credential", "T1003.001", "LSASS Memory",
     "Handle to lsass.exe opened by a non-system process on {dst} as {user} (sekurlsa-style) from {src}"),
    ("credential", "T1558.003", "Kerberoasting",
     "{user} on {src} requested {d}3 RC4 service tickets, then authenticated to {dst}"),
]
_PERSIST = [
    ("persistence", "T1053.005", "Scheduled Task",
     "Scheduled task 'Updater' created on {dst} by {user} from {src} running a base64 payload"),
    ("persistence", "T1543.003", "Windows Service",
     "Service 'WinDefendSvc' installed on {dst} by {user} from {src} pointing at a temp binary"),
]
_EXFIL = [
    ("exfil", "T1048", "Exfiltration Over Alternative Protocol",
     "{d}20 MB DNS-tunneled to {src} from {dst} by {user} over 11 minutes"),
    ("exfil", "T1041", "Exfiltration Over C2 Channel",
     "Sustained HTTPS upload from {dst} to {src} ({d}80 MB) by {user} outside business hours"),
]
_BENIGN = [
    "Password change for {user} via the self-service portal",
    "New device enrollment for {user} (MDM)",
    "VPN login for {user} from a known corporate IP",
    "Windows Update installed KB50{d}321 on {dst}",
    "Scheduled backup job completed on {dst}",
    "Account {user} added to distribution group 'allstaff'",
]
_ISOLATED_TP = [
    ("T1136.001", "Create Account",
     "Local account 'svc_{d}' created on {dst} by {user} (no approval ticket)"),
    ("T1562.001", "Impair Defenses",
     "Defender real-time protection disabled on {dst} by {user}"),
]
_HOSTS = ["kingslanding", "winterfell", "castelblack", "meereen", "braavos", "dragonstone", "highgarden"]
_ACCOUNTS = ["jon.snow", "arya.stark", "tyrion.lannister", "jaime.lannister",
             "cersei.lannister", "samwell.tarly", "sansa.stark", "davos.seaworth"]
_ORIGINS = ["45.77.{d}.{e}", "185.220.{d}.{e}", "91.219.{d}.{e}", "VPN-GW-{d}"]
_SEVERITIES = ["medium", "high", "critical"]


def _origin(r):
    t = r.choice(_ORIGINS)
    return t.format(d=r.randint(2, 250), e=r.randint(2, 250))


def _acct(login):
    return "sevenkingdoms\\" + login.split(".")[0]


def _build_chain(r, steps_spec, actor, origin, host_pool, base_ts, aid_start):
    """Build one campaign: an ordered list of alert dicts with per-alert keys, sharing actor+origin
    and pivoting host->host. Returns (alerts, incident_key)."""
    user = _acct(actor)
    alerts = []
    chain = []
    hosts_used = []
    accounts_used = {user}
    src = origin
    ts = base_ts
    first_host = r.choice(host_pool)
    cur_host = first_host
    for idx, pool in enumerate(steps_spec):
        role, tid, tname, tmpl = r.choice(pool)
        if idx == 0:
            dst = first_host
        else:
            dst = r.choice([h for h in host_pool if h not in hosts_used]) if len(hosts_used) < len(host_pool) else r.choice(host_pool)
        ts = ts + _dt.timedelta(minutes=r.randint(3, 40))
        raw = tmpl.format(user=user, src=src, dst=dst, d=r.randint(1, 9))
        aid = "ALRT-%04d" % aid_start
        aid_start += 1
        sev = "critical" if role in ("credential", "exfil") else r.choice(_SEVERITIES)
        iocs = sorted({src, user, dst})
        alerts.append({"id": aid, "timestamp": ts.isoformat(), "host": dst, "signal": tname,
                       "raw": raw, "_key": {"verdict": "true_positive", "severity": sev,
                                            "technique": tid, "iocs": iocs}})
        chain.append(tid)
        if dst not in hosts_used:
            hosts_used.append(dst)
        # pivot: the host just compromised becomes the source of the next step
        src = cur_host if idx == 0 else dst
        cur_host = dst
    incident_key = {
        "alert_ids": sorted(a["id"] for a in alerts),
        "entry_alert_id": alerts[0]["id"],
        "entry_technique": chain[0],
        "technique_chain": chain,
        "affected_hosts": sorted(set(hosts_used)),
        "affected_accounts": sorted(accounts_used),
        "actor_src": origin,
        "actor_account": user,
    }
    return alerts, incident_key, aid_start


def generate_incident(seed, variant=None):
    """Seed-deterministic incident-investigation scenario: a primary multi-step campaign, a distinct
    secondary campaign, isolated true positives, and benign noise. variant may tune difficulty via
    'incident_min_steps'/'incident_distractors' but defaults produce a rigorous field."""
    v = variant or {}
    r = _random.Random("incident-board1:%s:%s" % (v.get("id", ""), seed))
    base = _dt.datetime(2026, 3, r.randint(1, 20), r.randint(0, 5), r.randint(0, 59))
    aid = 2000
    alerts = []
    incidents = []

    # Primary campaign: entry -> lateral -> credential -> (persistence|exfil), length 3-4.
    steps = [_ENTRY, _LATERAL, _CRED]
    if r.random() < 0.7:
        steps.append(r.choice([_PERSIST, _EXFIL]))
    a1_actor = r.choice(_ACCOUNTS)
    a1_origin = _origin(r)
    c1, k1, aid = _build_chain(r, steps, a1_actor, a1_origin, _HOSTS, base, aid)
    alerts += c1
    incidents.append(dict(k1, incident_id="INC-1"))

    # Secondary campaign: a DIFFERENT actor + origin, length 2 (entry -> lateral|credential).
    steps2 = [_ENTRY, r.choice([_LATERAL, _CRED])]
    a2_actor = r.choice([a for a in _ACCOUNTS if a != a1_actor])
    a2_origin = _origin(r)
    while a2_origin == a1_origin:
        a2_origin = _origin(r)
    base2 = base + _dt.timedelta(hours=r.randint(2, 20))
    c2, k2, aid = _build_chain(r, steps2, a2_actor, a2_origin, _HOSTS, base2, aid)
    alerts += c2
    incidents.append(dict(k2, incident_id="INC-2"))

    # Isolated true positives (real TPs that are NOT part of a multi-step campaign -> must NOT be
    # grouped into a campaign). 1-2 of them.
    for _ in range(r.randint(1, 2)):
        tid, tname, tmpl = r.choice(_ISOLATED_TP)
        dst = r.choice(_HOSTS); who = _acct(r.choice(_ACCOUNTS))
        ts = (base + _dt.timedelta(minutes=r.randint(0, 900)))
        alerts.append({"id": "ALRT-%04d" % aid, "timestamp": ts.isoformat(), "host": dst,
                       "signal": tname, "raw": tmpl.format(user=who, dst=dst, d=r.randint(1, 9)),
                       "_key": {"verdict": "true_positive", "severity": r.choice(_SEVERITIES),
                                "technique": tid, "iocs": sorted({who, dst})}})
        aid += 1

    # Benign noise.
    for _ in range(r.randint(5, 8)):
        who = _acct(r.choice(_ACCOUNTS)); dst = r.choice(_HOSTS)
        ts = (base + _dt.timedelta(minutes=r.randint(0, 1200)))
        alerts.append({"id": "ALRT-%04d" % aid, "timestamp": ts.isoformat(), "host": dst,
                       "signal": "Routine activity",
                       "raw": r.choice(_BENIGN).format(user=who, dst=dst, d=r.randint(1, 9)),
                       "_key": {"verdict": "false_positive", "severity": "low",
                                "technique": None, "iocs": []}})
        aid += 1

    r.shuffle(alerts)
    return {"board": 1, "layer": "incident", "cohort_theme": "sevenkingdoms.local",
            "variant": v.get("id"), "alerts": alerts, "_incidents": incidents}


def public_incident(scenario):
    """Investigation surface: alerts only, no keys, no incident grouping, no actor labels."""
    return {"board": 1, "layer": "incident", "theme": scenario["cohort_theme"],
            "alerts": [{"id": a["id"], "timestamp": a["timestamp"], "host": a["host"],
                        "signal": a["signal"], "raw": a["raw"]} for a in scenario["alerts"]]}


def _norm(s):
    return str(s or "").strip().lower()


def _f1(sub_set, key_set):
    sub_set = {_norm(x) for x in (sub_set or [])}
    key_set = {_norm(x) for x in (key_set or [])}
    if not key_set and not sub_set:
        return 1.0
    if not sub_set or not key_set:
        return 0.0
    inter = len(sub_set & key_set)
    if inter == 0:
        return 0.0
    prec = inter / len(sub_set)
    rec = inter / len(key_set)
    return 2 * prec * rec / (prec + rec)


def _ordered_chain_score(sub_chain, key_chain):
    """Longest-common-subsequence ratio over the ORDERED technique chain (order matters)."""
    a = [_norm(x) for x in (sub_chain or [])]
    b = [_norm(x) for x in (key_chain or [])]
    if not b:
        return 1.0 if not a else 0.0
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            dp[i][j] = dp[i - 1][j - 1] + 1 if a[i - 1] == b[j - 1] else max(dp[i - 1][j], dp[i][j - 1])
    lcs = dp[m][n]
    rec = lcs / len(b)
    extra_pen = 0.1 * max(0, len(a) - len(b))  # discourage padding the chain
    return max(0.0, rec - extra_pen)


def _evidence_support(sub_incident, grouped_alerts):
    """Fraction of the submitted evidence items that are DEFENSIBLE: a linking fact that actually
    appears in at least two of the grouped alerts' telemetry (raw text or IOCs). This is what makes
    the score reward real correlation rather than label guessing."""
    ev = [_norm(x) for x in (sub_incident.get("evidence") or []) if _norm(x)]
    if not ev:
        return 0.0
    # Build the corpus of linking facts actually present, per alert.
    per_alert_text = []
    for a in grouped_alerts:
        toks = _norm(a.get("raw"))
        iocs = " ".join(_norm(x) for x in (a.get("_key", {}).get("iocs") or []))
        per_alert_text.append(toks + " " + iocs)
    supported = 0
    for item in ev:
        hits = sum(1 for t in per_alert_text if item in t)
        if hits >= 2:  # a real shared linking fact across the incident
            supported += 1
    return supported / len(ev)


def score_incident(scenario, submission):
    """Score an incident-investigation submission against the hidden key. Returns
    (score_0_100, per_incident_flags). Reveals correctness flags only, never the key.

    Weighting per matched incident: grouping F1 0.35, entry point 0.15, affected hosts 0.10,
    affected accounts 0.10, ordered technique chain 0.15, evidence defensibility 0.15. Overall score
    multiplies the matched-incident quality by a precision factor over submitted incidents, so
    spurious/over-merged incidents are penalized."""
    true_incidents = scenario.get("_incidents") or []
    alerts_by_id = {a["id"]: a for a in scenario["alerts"]}
    subs = [s for s in (submission.get("incidents") or []) if isinstance(s, dict)]

    # Greedy best-match each true incident to the submitted incident with max alert-id overlap.
    used = set()
    per_incident = []
    quality_sum = 0.0
    for key in true_incidents:
        key_ids = set(key["alert_ids"])
        best_j, best_ov = None, -1.0
        for j, s in enumerate(subs):
            if j in used:
                continue
            sid = {str(x).strip() for x in (s.get("alert_ids") or [])}
            ov = _f1(sid, key_ids)
            if ov > best_ov:
                best_ov, best_j = ov, j
        if best_j is None or best_ov <= 0.0:
            per_incident.append({"incident": key["incident_id"], "matched": False})
            continue
        used.add(best_j)
        s = subs[best_j]
        grouped = [alerts_by_id[i] for i in {str(x).strip() for x in (s.get("alert_ids") or [])}
                   if i in alerts_by_id]
        grp = _f1({str(x).strip() for x in (s.get("alert_ids") or [])}, key_ids)
        entry = 1.0 if _norm(s.get("entry_alert_id")) == _norm(key["entry_alert_id"]) else 0.0
        hosts = _f1(s.get("affected_hosts"), key["affected_hosts"])
        accts = _f1(s.get("affected_accounts"), key["affected_accounts"])
        chain = _ordered_chain_score(s.get("technique_chain"), key["technique_chain"])
        evid = _evidence_support(s, grouped)
        q = (0.35 * grp + 0.15 * entry + 0.10 * hosts + 0.10 * accts + 0.15 * chain + 0.15 * evid)
        quality_sum += q
        per_incident.append({"incident": key["incident_id"], "matched": True,
                             "grouping_ok": grp >= 0.8, "entry_ok": bool(entry),
                             "chain_ok": chain >= 0.8, "evidence_ok": evid >= 0.5})

    denom = len(true_incidents) or 1
    matched_quality = quality_sum / denom  # 0..1, recall-weighted over true incidents
    # precision over submitted incidents: spurious incidents (matched to nothing) drag the score down
    n_sub = len(subs)
    precision = (len(used) / n_sub) if n_sub else (1.0 if not true_incidents else 0.0)
    score = round(100.0 * matched_quality * (0.5 + 0.5 * precision), 1)
    return score, per_incident
