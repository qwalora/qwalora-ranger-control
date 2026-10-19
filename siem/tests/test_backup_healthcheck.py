"""Backup freshness / failure-detection probe (scripts/backup_healthcheck.py).

Pure filesystem checks (no DB), so these run without the _pgtest gate. They validate the alert
signal the scheduler would act on: healthy -> exit 0; missing/stale/corrupt -> non-zero.
"""
import datetime as dt
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import backup_healthcheck as hc  # noqa: E402


def _write_backup(dest, when, *, body=b"age-encryption.org/v1\nciphertext-bytes", good_sha=True,
                  artifact_present=True, name=None):
    os.makedirs(dest, exist_ok=True)
    ts = when.strftime("%Y%m%dT%H%M%SZ")
    art = name or ("ranger-db-%s.dump.age" % ts)
    apath = os.path.join(dest, art)
    if artifact_present:
        with open(apath, "wb") as fh:
            fh.write(body)
    sha = hashlib.sha256(body).hexdigest() if good_sha else ("0" * 64)
    manifest = {"artifact": art, "created_utc": ts, "database": "ranger", "bytes": len(body),
                "sha256": sha}
    with open(apath + ".manifest.json", "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    return apath


def test_healthy_recent_backup_exits_zero(tmp_path):
    dest = str(tmp_path)
    _write_backup(dest, dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2))
    code, summary = hc.check(dest, max_age_hours=26)
    assert code == 0 and summary["status"] == "ok"


def test_missing_backup_is_detected(tmp_path):
    code, summary = hc.check(str(tmp_path), max_age_hours=26)
    assert code == 2 and summary["status"] == "missing"


def test_stale_backup_is_detected(tmp_path):
    dest = str(tmp_path)
    _write_backup(dest, dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=50))
    code, summary = hc.check(dest, max_age_hours=26)
    assert code == 3 and summary["status"] == "stale"


def test_corrupt_ciphertext_is_detected(tmp_path):
    dest = str(tmp_path)
    _write_backup(dest, dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1), good_sha=False)
    code, summary = hc.check(dest, max_age_hours=26)
    assert code == 4 and summary["status"] == "corrupt"


def test_missing_artifact_for_manifest_is_detected(tmp_path):
    dest = str(tmp_path)
    _write_backup(dest, dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1), artifact_present=False)
    code, summary = hc.check(dest, max_age_hours=26)
    assert code == 4 and summary["status"] == "corrupt"


def test_newest_backup_is_the_one_evaluated(tmp_path):
    dest = str(tmp_path)
    # an old stale one plus a fresh one -> healthy (newest wins)
    _write_backup(dest, dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=100))
    _write_backup(dest, dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1))
    code, summary = hc.check(dest, max_age_hours=26)
    assert code == 0 and summary["status"] == "ok" and summary["backups_total"] == 2
