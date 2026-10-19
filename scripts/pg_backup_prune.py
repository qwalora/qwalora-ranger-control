#!/usr/bin/env python3
"""Grandfather-father-son retention pruning for the encrypted backup destination.

Keeps the newest N daily, M weekly, and K monthly backups and removes the rest (each backup is its
`*.dump.age` artifact plus the `.sha256` and `.manifest.json` sidecars). Dry-run by DEFAULT: it only
reports what it would delete unless `--apply` (or RANGER_BACKUP_PRUNE_APPLY=1) is given, so a
misconfiguration can never silently destroy backups. It never deletes the single newest backup, and
if the retention math would remove everything it refuses (fail-safe).

This operates on a filesystem-style destination (a mounted volume, or a local mirror of the bucket).
For an object store, prefer the bucket's own lifecycle/expiry rules as the primary retention and use
this as a secondary, auditable pass.

Config (env or flags): RANGER_BACKUP_DEST (dir), RANGER_BACKUP_KEEP_DAILY (7),
RANGER_BACKUP_KEEP_WEEKLY (4), RANGER_BACKUP_KEEP_MONTHLY (3), RANGER_BACKUP_PRUNE_APPLY (0/1).
Exit: 0 ok (reported or applied), 2 misconfig, 3 refused (would delete everything).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import json
import os
import sys


def _log(level, event, **f):
    rec = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), "level": level, "event": event}
    rec.update(f)
    sys.stdout.write(json.dumps(rec, sort_keys=True) + "\n"); sys.stdout.flush()


def _parse_ts(s):
    return _dt.datetime.strptime(s, "%Y%m%dT%H%M%SZ").replace(tzinfo=_dt.timezone.utc)


def _load(dest):
    """Return [(ts, basename, manifest_path)] sorted newest-first for readable manifests."""
    out = []
    for m in glob.glob(os.path.join(dest, "*.manifest.json")):
        try:
            with open(m, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            out.append((_parse_ts(data["created_utc"]), data.get("artifact"), m))
        except Exception as e:  # noqa: BLE001
            _log("info", "prune.manifest_unreadable", manifest=os.path.basename(m), note=str(e)[:160])
    out.sort(key=lambda t: t[0], reverse=True)
    return out


def select_keep(entries, keep_daily, keep_weekly, keep_monthly):
    """Return the set of basenames to KEEP under GFS. entries are (ts, basename, mpath) newest-first."""
    keep = set()
    seen_day, seen_week, seen_month = set(), set(), set()
    # daily: newest backup per distinct UTC day, up to keep_daily days
    for ts, art, _ in entries:
        d = ts.strftime("%Y-%m-%d")
        if d not in seen_day and len(seen_day) < keep_daily:
            seen_day.add(d); keep.add(art)
    for ts, art, _ in entries:
        iso = ts.isocalendar(); w = "%04d-W%02d" % (iso[0], iso[1])
        if w not in seen_week and len(seen_week) < keep_weekly:
            seen_week.add(w); keep.add(art)
    for ts, art, _ in entries:
        mo = ts.strftime("%Y-%m")
        if mo not in seen_month and len(seen_month) < keep_monthly:
            seen_month.add(mo); keep.add(art)
    if entries:
        keep.add(entries[0][1])  # never drop the newest
    return keep


def prune(dest, keep_daily=7, keep_weekly=4, keep_monthly=3, apply=False):
    entries = _load(dest)
    if not entries:
        _log("error", "prune.nothing", dest=dest, reason="no readable manifests")
        return 2, {"kept": [], "deleted": []}
    keep = select_keep(entries, keep_daily, keep_weekly, keep_monthly)
    to_delete = [(ts, art, m) for (ts, art, m) in entries if art not in keep]
    if to_delete and len(to_delete) == len(entries):
        _log("error", "prune.refused", reason="retention would remove every backup")
        return 3, {"kept": [], "deleted": []}
    deleted = []
    for ts, art, mpath in to_delete:
        targets = [os.path.join(dest, art), os.path.join(dest, art + ".sha256"), mpath]
        if apply:
            for t in targets:
                try:
                    if os.path.exists(t):
                        os.unlink(t)
                except OSError as e:
                    _log("info", "prune.unlink_note", target=os.path.basename(t), note=str(e)[:120])
        deleted.append(art)
    _log("info", "prune.apply" if apply else "prune.dryrun",
         dest=dest, total=len(entries), kept=len(keep), deleted=len(deleted),
         keep_daily=keep_daily, keep_weekly=keep_weekly, keep_monthly=keep_monthly,
         deleted_artifacts=deleted)
    return 0, {"kept": sorted(keep), "deleted": deleted}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("dest", nargs="?", default=os.environ.get("RANGER_BACKUP_DEST") or os.path.join(os.getcwd(), "backups"))
    ap.add_argument("--keep-daily", type=int, default=int(os.environ.get("RANGER_BACKUP_KEEP_DAILY", "7")))
    ap.add_argument("--keep-weekly", type=int, default=int(os.environ.get("RANGER_BACKUP_KEEP_WEEKLY", "4")))
    ap.add_argument("--keep-monthly", type=int, default=int(os.environ.get("RANGER_BACKUP_KEEP_MONTHLY", "3")))
    ap.add_argument("--apply", action="store_true",
                    default=os.environ.get("RANGER_BACKUP_PRUNE_APPLY", "").strip().lower() in ("1", "true", "yes", "on"))
    args = ap.parse_args(argv)
    code, _ = prune(args.dest, args.keep_daily, args.keep_weekly, args.keep_monthly, args.apply)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
