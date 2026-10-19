"""GFS retention pruning (scripts/pg_backup_prune.py). Pure filesystem; no DB, no _pgtest gate."""
import datetime as dt
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import pg_backup_prune as pr  # noqa: E402


def _mk(dest, when):
    os.makedirs(dest, exist_ok=True)
    ts = when.strftime("%Y%m%dT%H%M%SZ")
    art = "ranger-db-%s.dump.age" % ts
    for suffix, body in ((art, b"cipher"), (art + ".sha256", b"abc  " + art.encode())):
        with open(os.path.join(dest, suffix), "wb") as fh:
            fh.write(body)
    with open(os.path.join(dest, art + ".manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"artifact": art, "created_utc": ts, "bytes": 6, "sha256": "abc"}, fh)
    return art


def test_dryrun_default_deletes_nothing(tmp_path):
    dest = str(tmp_path)
    base = dt.datetime.now(dt.timezone.utc)
    for i in range(40):  # 40 daily backups
        _mk(dest, base - dt.timedelta(days=i))
    code, res = pr.prune(dest, keep_daily=7, keep_weekly=4, keep_monthly=3, apply=False)
    assert code == 0 and len(res["deleted"]) > 0
    # dry-run: every artifact + sidecar still present
    remaining = [f for f in os.listdir(dest) if f.endswith(".dump.age")]
    assert len(remaining) == 40


def test_apply_keeps_gfs_window(tmp_path):
    dest = str(tmp_path)
    base = dt.datetime.now(dt.timezone.utc)
    for i in range(40):
        _mk(dest, base - dt.timedelta(days=i))
    code, res = pr.prune(dest, keep_daily=7, keep_weekly=4, keep_monthly=3, apply=True)
    assert code == 0
    kept_files = sorted(f for f in os.listdir(dest) if f.endswith(".dump.age"))
    # 7 distinct days + up to 4 distinct weeks + up to 3 distinct months, de-duplicated
    assert len(kept_files) == len(res["kept"])
    assert 7 <= len(kept_files) <= 14
    # each kept backup retains all three files
    for art in res["kept"]:
        assert os.path.exists(os.path.join(dest, art))
        assert os.path.exists(os.path.join(dest, art + ".sha256"))
        assert os.path.exists(os.path.join(dest, art + ".manifest.json"))
    # deleted backups removed entirely
    for art in res["deleted"]:
        assert not os.path.exists(os.path.join(dest, art))
        assert not os.path.exists(os.path.join(dest, art + ".manifest.json"))


def test_never_deletes_the_only_backup(tmp_path):
    dest = str(tmp_path)
    _mk(dest, dt.datetime.now(dt.timezone.utc))
    code, res = pr.prune(dest, keep_daily=0, keep_weekly=0, keep_monthly=0, apply=True)
    # fail-safe: refuses to delete everything OR keeps the newest; either way the backup survives
    assert os.path.exists(os.path.join(dest, res["kept"][0])) if res["kept"] else code == 3
    assert any(f.endswith(".dump.age") for f in os.listdir(dest))


def test_empty_dest_is_misconfig(tmp_path):
    code, _ = pr.prune(str(tmp_path), apply=True)
    assert code == 2


def test_newest_always_kept(tmp_path):
    dest = str(tmp_path)
    base = dt.datetime.now(dt.timezone.utc)
    newest = _mk(dest, base)
    for i in range(1, 20):
        _mk(dest, base - dt.timedelta(days=i * 3))
    code, res = pr.prune(dest, keep_daily=1, keep_weekly=1, keep_monthly=1, apply=True)
    assert code == 0 and newest in res["kept"]
    assert os.path.exists(os.path.join(dest, newest))
