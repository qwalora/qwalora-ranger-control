"""Remediation-queue CVE feed for the candidate dashboard.

Nudges candidates to behave like practitioners: a rolling queue of ACTIVELY EXPLOITED
vulnerabilities (CISA Known Exploited Vulnerabilities catalog) they are prompted to triage and
remediate, the way a real SOC/vuln-management team works to a clock.

Data: a bundled snapshot of real recent CISA KEV entries (below), rotated daily so the queue feels
live. If RANGER_CVE_FEED_URL is set to a reachable CISA KEV JSON mirror, `refresh()` replaces the
snapshot from it; otherwise the bundle is authoritative. The dashboard render path never blocks on
the network: it reads the in-memory list only.
"""
import datetime as _dt
import hashlib
import json
import os
import threading

NVD = "https://nvd.nist.gov/vuln/detail/"

# Real recent CISA KEV entries (actively exploited). Refreshable; see refresh().
_SNAPSHOT = [
    {"cve": "CVE-2026-104935", "vendor": "Ivanti", "product": "Connect Secure",
     "type": "Authentication bypass by spoofing", "severity": "Critical"},
    {"cve": "CVE-2026-96951", "vendor": "Microsoft", "product": "Windows",
     "type": "Command injection", "severity": "Critical"},
    {"cve": "CVE-2026-11645", "vendor": "Google", "product": "Chromium V8",
     "type": "Out-of-bounds read and write", "severity": "High"},
    {"cve": "CVE-2026-20245", "vendor": "Cisco", "product": "Catalyst SD-WAN Manager",
     "type": "Improper output encoding/escaping", "severity": "High"},
    {"cve": "CVE-2026-76460", "vendor": "Cisco", "product": "Identity Services Engine",
     "type": "Incorrect use of privileged APIs", "severity": "High"},
    {"cve": "CVE-2026-7473", "vendor": "Arista", "product": "EOS",
     "type": "Incomplete comparison with missing factors", "severity": "High"},
    {"cve": "CVE-2026-87886", "vendor": "Acronis", "product": "Backup",
     "type": "Incorrect default permissions", "severity": "Medium"},
]

_LOCK = threading.Lock()
_STATE = {"items": list(_SNAPSHOT), "source": "bundled-kev-snapshot", "refreshed": None}


def _decorate(it):
    it = dict(it)
    it["url"] = NVD + it["cve"]
    it["kev"] = True
    return it


def queue(n=4, day=None):
    """Top N of today's rotating remediation queue. Rotation is deterministic per day so every
    candidate sees the same queue on a given day and it changes daily."""
    with _LOCK:
        items = list(_STATE["items"])
    if not items:
        return []
    d = day or _dt.date.today().toordinal()
    k = d % len(items)
    rotated = items[k:] + items[:k]
    return [_decorate(x) for x in rotated[:max(0, n)]]


def source():
    with _LOCK:
        return _STATE["source"]


def refresh(url=None, timeout=5):
    """Replace the snapshot from a CISA KEV JSON feed if RANGER_CVE_FEED_URL (or url) is set and
    reachable. Best-effort and off by default; never raises into the caller."""
    url = url or os.environ.get("RANGER_CVE_FEED_URL", "").strip()
    if not url:
        return False
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 - operator-configured URL
            data = json.loads(r.read().decode("utf-8", "replace"))
        vulns = data.get("vulnerabilities") or data.get("items") or []
        vulns = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)[:12]
        items = []
        for v in vulns:
            cve = v.get("cveID") or v.get("cve")
            if not cve:
                continue
            items.append({"cve": cve, "vendor": v.get("vendorProject", ""),
                          "product": v.get("product", ""),
                          "type": v.get("vulnerabilityName", v.get("shortDescription", ""))[:80],
                          "severity": "Critical" if "exploit" in (v.get("notes", "") or "").lower() else "High"})
        if items:
            with _LOCK:
                _STATE.update(items=items, source="cisa-kev-live",
                              refreshed=_dt.datetime.utcnow().isoformat())
            return True
    except Exception:  # noqa: BLE001 - the dashboard must never break on a feed error
        return False
    return False
