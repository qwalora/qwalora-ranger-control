"""Sigma-style detection rules, a cross-source correlation config, and an offline
evaluator.

The rules are field-based selections (the shape OpenSearch Security Analytics /
Sigma use). The evaluator runs them against generated telemetry so we can prove,
offline and before any cluster exists, that findings come from detection LOGIC (not
hardcoded objects): rules fire on the incident events and not on benign noise, and
the deliberately gapped DNS rule MISSES the detection-failure scenario, giving a
genuine false negative for the candidate to find.

On the real cluster these map to Security Analytics detectors + Sigma rules;
correlation maps to correlation rules. Feature availability is verified against the
deployed OpenSearch version (documented, not faked, if unavailable).
"""
from __future__ import annotations


def _get(doc, dotted):
    cur = doc
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def _match_pred(value, pred):
    if value is None:
        return False
    if isinstance(pred, dict):
        if "contains" in pred:
            return str(pred["contains"]).lower() in str(value).lower()
        if "startswith" in pred:
            return str(value).startswith(pred["startswith"])
        if "in" in pred:
            return value in pred["in"]
        if "not_startswith_any" in pred:
            return not any(str(value).startswith(p) for p in pred["not_startswith_any"])
    return value == pred


# Each rule: a dataset filter plus a selection (all fields must match). Severity and
# ATT&CK technique are carried for findings. These are intentionally realistic and,
# in one case (dns-c2), intentionally NARROW to leave a detectable gap.
RULES = [
    {"id": "win-domain-admin-add", "title": "Member added to Domain Admins",
     "dataset": "windows.security", "severity": "critical", "technique": "T1098",
     "select": {"winlog.event_id": 4728}},
    {"id": "cloud-risky-signin", "title": "Risky cloud sign-in from external address",
     "dataset": "cloud.signin", "severity": "high", "technique": "T1078",
     "select": {"event.action": "cloud_login",
                "source.ip": {"not_startswith_any": ["10.", "192.168.", "172.16."]}}},
    {"id": "svc-interactive-logon", "title": "Service account interactive logon",
     "dataset": "windows.security", "severity": "high", "technique": "T1078.003",
     "select": {"winlog.logon_type": 2, "user.name": {"startswith": "svc-"}}},
    {"id": "encoded-powershell", "title": "Encoded PowerShell execution",
     "dataset": "edr.process", "severity": "high", "technique": "T1059.001",
     "select": {"process.name": "powershell.exe", "process.command_line": {"contains": "-enc"}}},
    {"id": "mass-data-export", "title": "Bulk data export via web API",
     "dataset": "network.http", "severity": "high", "technique": "T1530",
     "select": {"url.original": {"contains": "/api/export"}}},
    {"id": "remote-exec-psexec", "title": "PsExec service installed (remote execution)",
     "dataset": "edr.process", "severity": "high", "technique": "T1569.002",
     "select": {"process.name": "psexesvc.exe"}},
    # DELIBERATELY NARROW: only flags one known-bad domain, so DNS tunneling to a
    # different domain is NOT detected. This is the gap behind the detection-failure
    # scenario; it is a realistic rule weakness, not a scripted miss.
    {"id": "dns-c2-known-domain", "title": "DNS to known C2 domain (narrow allowlist)",
     "dataset": "network.dns", "severity": "medium", "technique": "T1071.004",
     "select": {"dns.question.name": {"contains": "cdn-metrics.ru"}}},
]

# Cross-source correlation: findings for the same primary identity within a window
# escalate to a high-severity correlated incident.
CORRELATION = {"group_by": "user.name", "window_minutes": 120, "min_findings": 2,
               "escalate_to": "critical"}


def run_rules(events: list[dict]) -> list[dict]:
    """Return findings: one per (rule, matching event)."""
    findings = []
    for e in events:
        src = e["_source"]
        ds = _get(src, "event.dataset")
        for rule in RULES:
            if rule["dataset"] != ds:
                continue
            if all(_match_pred(_get(src, f), pred) for f, pred in rule["select"].items()):
                findings.append({"rule_id": rule["id"], "technique": rule["technique"],
                                 "severity": rule["severity"], "event_uid": e["_id"],
                                 "user": _get(src, "user.name"), "host": _get(src, "host.name")})
    return findings


def correlate(findings: list[dict]) -> list[dict]:
    """Group findings by identity; emit a correlated incident when >= min_findings."""
    by_user = {}
    for f in findings:
        by_user.setdefault(f.get("user") or "_none", []).append(f)
    incidents = []
    for user, fs in by_user.items():
        if len(fs) >= CORRELATION["min_findings"]:
            incidents.append({"user": user, "finding_count": len(fs),
                              "techniques": sorted({f["technique"] for f in fs}),
                              "severity": CORRELATION["escalate_to"]})
    return incidents


def validate(events: list[dict], truth: dict) -> dict:
    """Prove the detections derive from logic: measure, against the hidden truth,
    which incidents are detected, which are missed, and the false positives on
    benign events."""
    findings = run_rules(events)
    fired_uids = {f["event_uid"] for f in findings}
    malicious_uids = {u for inc in truth["incidents"] for u in inc["event_uids"]}

    per_incident = []
    for inc in truth["incidents"]:
        hit = bool(set(inc["event_uids"]) & fired_uids)
        per_incident.append({"family": inc["family"], "detected": hit,
                             "expected_missed": inc["verdict"].endswith("missed_by_detector")})
    # false positives: findings on events that are not in any incident
    fp = [f for f in findings if f["event_uid"] not in malicious_uids]
    tp = [f for f in findings if f["event_uid"] in malicious_uids]
    detected = sum(1 for p in per_incident if p["detected"])
    missed = [p for p in per_incident if not p["detected"]]
    return {
        "findings": len(findings), "true_positive_findings": len(tp),
        "false_positive_findings": len(fp),
        "incidents_total": len(per_incident), "incidents_detected": detected,
        "incidents_missed": [m["family"] for m in missed],
        "per_incident": per_incident,
        "correlated_incidents": correlate(findings),
    }
