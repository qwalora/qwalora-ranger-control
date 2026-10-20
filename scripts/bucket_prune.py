#!/usr/bin/env python3
"""Grandfather-father-son retention pruning for a Railway Storage Bucket (or any S3 bucket WITHOUT
lifecycle rules).

Railway Buckets do not support bucket lifecycle configuration or Object Lock, so offsite retention
cannot be delegated to the provider: this prunes the bucket directly, reusing the exact GFS keep
logic from pg_backup_prune (newest N daily, M weekly, K monthly). Dry-run by DEFAULT (reports only
unless --apply / RANGER_BACKUP_PRUNE_APPLY), never deletes the single newest backup, and refuses if
retention would remove everything (fail-safe). Because the bucket is not immutable (no Object Lock),
this is the only retention mechanism, so its safety guards matter: deletes require an explicit apply.

The S3 calls are injected (list_fn/delete_fn) so the logic is provider-agnostic and unit-testable
without any network. The CLI path drives them via the AWS CLI against RANGER_BACKUP_S3_URL.

Exit: 0 ok (reported or applied), 2 misconfig (no objects / no target), 3 refused (would delete all).
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pg_backup_prune import select_keep, _parse_ts  # reuse the proven GFS logic  # noqa: E402

_TS = re.compile(r"-(\d{8}T\d{6}Z)\.dump\.age$")


def _log(level, event, **f):
    rec = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), "level": level, "event": event}
    rec.update(f)
    sys.stdout.write(json.dumps(rec, sort_keys=True) + "\n"); sys.stdout.flush()


def entries_from_keys(keys):
    """Build [(ts, basename, None)] newest-first from the .dump.age object keys (basenames)."""
    out = []
    for k in keys:
        base = k.rsplit("/", 1)[-1]
        m = _TS.search(base)
        if base.endswith(".dump.age") and m:
            out.append((_parse_ts(m.group(1)), base, None))
    out.sort(key=lambda t: t[0], reverse=True)
    return out


def prune_bucket(list_fn, delete_fn, keep_daily=7, keep_weekly=4, keep_monthly=3, apply=False):
    """list_fn() -> iterable of object keys/basenames; delete_fn(basename) -> None. Deletes each
    non-kept backup's artifact plus its .sha256 and .manifest.json sidecars."""
    keys = list(list_fn())
    entries = entries_from_keys(keys)
    if not entries:
        _log("error", "bucket_prune.nothing", reason="no .dump.age objects found")
        return 2, {"kept": [], "deleted": []}
    keep = select_keep(entries, keep_daily, keep_weekly, keep_monthly)
    to_delete = [art for (_, art, _) in entries if art not in keep]
    if to_delete and len(to_delete) == len(entries):
        _log("error", "bucket_prune.refused", reason="retention would remove every backup")
        return 3, {"kept": [], "deleted": []}
    present = set(k.rsplit("/", 1)[-1] for k in keys)
    deleted = []
    for art in to_delete:
        for name in (art, art + ".sha256", art + ".manifest.json"):
            if name in present and apply:
                try:
                    delete_fn(name)
                except Exception as e:  # noqa: BLE001
                    _log("info", "bucket_prune.delete_note", target=name, note=str(e)[:120])
        deleted.append(art)
    _log("info", "bucket_prune.apply" if apply else "bucket_prune.dryrun",
         total=len(entries), kept=len(keep), deleted=len(deleted), deleted_artifacts=deleted)
    return 0, {"kept": sorted(keep), "deleted": deleted}


def _aws_fns(s3_url):
    import subprocess
    base = s3_url.rstrip("/")
    endpoint = os.environ.get("AWS_ENDPOINT_URL_S3")
    args = (["--endpoint-url", endpoint] if endpoint else [])

    def list_fn():
        p = subprocess.run(["aws"] + args + ["s3", "ls", base + "/"], capture_output=True, text=True)
        if p.returncode != 0:
            return []
        return [ln.split()[-1] for ln in p.stdout.splitlines() if ln.strip()]

    def delete_fn(name):
        subprocess.run(["aws"] + args + ["s3", "rm", base + "/" + name], capture_output=True, text=True,
                       check=True)
    return list_fn, delete_fn


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    s3_url = argv[0] if argv else os.environ.get("RANGER_BACKUP_S3_URL")
    if not s3_url:
        _log("error", "bucket_prune.misconfigured", reason="no RANGER_BACKUP_S3_URL / target")
        return 2
    apply = os.environ.get("RANGER_BACKUP_PRUNE_APPLY", "").strip().lower() in ("1", "true", "yes", "on")
    lf, df = _aws_fns(s3_url)
    code, _ = prune_bucket(lf, df,
                           int(os.environ.get("RANGER_BACKUP_KEEP_DAILY", "7")),
                           int(os.environ.get("RANGER_BACKUP_KEEP_WEEKLY", "4")),
                           int(os.environ.get("RANGER_BACKUP_KEEP_MONTHLY", "3")), apply)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
