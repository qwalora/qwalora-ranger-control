#!/usr/bin/env python3
"""Backup freshness / failure detection for the parallax-nonprod encrypted backups.

A dead-man's-switch the scheduler (or an external monitor) runs to decide whether backups are
actually healthy. It is read-only: it inspects the backup manifests + ciphertext in a destination
directory and never touches the database. Exit code drives alerting.

Checks (newest backup):
  - at least one backup manifest exists                      -> else MISSING
  - newest backup age <= max-age window (RPO + slack)        -> else STALE
  - newest ciphertext still matches its recorded SHA-256     -> else CORRUPT
  - (optional) expected minimum byte size                    -> else SUSPECT

Configuration (environment or flags)
  RANGER_BACKUP_DEST            directory holding *.manifest.json + *.dump.age (default ./backups)
  RANGER_BACKUP_MAX_AGE_HOURS   freshness window in hours (default 26; daily cadence + slack)
  RANGER_BACKUP_MIN_BYTES       minimum plausible ciphertext size (default 0 = off)

Exit codes: 0 healthy, 2 missing (no backup at all), 3 stale, 4 corrupt/suspect. A NON-ZERO exit is
the alert signal: wire it to a Railway cron-failure webhook, or run it as a scheduled monitor whose
failure pages an on-call channel. Emits one structured JSON summary line on stdout.
"""
from __future__ import annotations

import datetime as _dt
import glob
import hashlib
import json
import os
import sys


def _log(level, event, **f):
    rec = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), "level": level, "event": event}
    rec.update(f)
    sys.stdout.write(json.dumps(rec, sort_keys=True) + "\n"); sys.stdout.flush()


def _parse_ts(s):
    # manifest created_utc is "%Y%m%dT%H%M%SZ"
    return _dt.datetime.strptime(s, "%Y%m%dT%H%M%SZ").replace(tzinfo=_dt.timezone.utc)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check(dest, max_age_hours=26.0, min_bytes=0, now=None):
    """Return (exit_code, summary_dict). Pure function over the filesystem; no DB access."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    manifests = sorted(glob.glob(os.path.join(dest, "*.manifest.json")))
    if not manifests:
        _log("error", "healthcheck.missing", dest=dest, reason="no backup manifests found")
        return 2, {"status": "missing", "dest": dest}

    newest = None
    for m in manifests:
        try:
            with open(m, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            ts = _parse_ts(data["created_utc"])
        except Exception as e:  # noqa: BLE001
            _log("info", "healthcheck.manifest_unreadable", manifest=os.path.basename(m), note=str(e)[:160])
            continue
        if newest is None or ts > newest[0]:
            newest = (ts, m, data)
    if newest is None:
        _log("error", "healthcheck.missing", dest=dest, reason="no readable manifest")
        return 2, {"status": "missing", "dest": dest}

    ts, mpath, data = newest
    age_h = (now - ts).total_seconds() / 3600.0
    artifact = os.path.join(dest, data.get("artifact", ""))
    summary = {"status": "ok", "newest": data.get("artifact"), "age_hours": round(age_h, 2),
               "max_age_hours": max_age_hours, "database": data.get("database"),
               "bytes": data.get("bytes"), "backups_total": len(manifests)}

    if age_h > max_age_hours:
        summary["status"] = "stale"
        _log("error", "healthcheck.stale", **summary)
        return 3, summary

    # ciphertext integrity of the newest artifact (recorded sha256 must still match)
    if os.path.exists(artifact) and data.get("sha256"):
        actual = _sha256_file(artifact)
        if actual != data["sha256"]:
            summary["status"] = "corrupt"; summary["sha256_expected"] = data["sha256"]; summary["sha256_actual"] = actual
            _log("error", "healthcheck.corrupt", **summary)
            return 4, summary
    elif not os.path.exists(artifact):
        summary["status"] = "corrupt"; summary["reason"] = "artifact missing for newest manifest"
        _log("error", "healthcheck.corrupt", **summary)
        return 4, summary

    if min_bytes and (data.get("bytes") or 0) < min_bytes:
        summary["status"] = "suspect"; summary["min_bytes"] = min_bytes
        _log("error", "healthcheck.suspect", **summary)
        return 4, summary

    _log("info", "healthcheck.ok", **summary)
    return 0, summary


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    dest = (argv[0] if argv else None) or os.environ.get("RANGER_BACKUP_DEST") or os.path.join(os.getcwd(), "backups")
    max_age = float(os.environ.get("RANGER_BACKUP_MAX_AGE_HOURS", "26"))
    min_bytes = int(os.environ.get("RANGER_BACKUP_MIN_BYTES", "0"))
    code, _ = check(dest, max_age_hours=max_age, min_bytes=min_bytes)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
