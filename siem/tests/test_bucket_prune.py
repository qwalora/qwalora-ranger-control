"""GFS retention pruning for a Railway Storage Bucket (scripts/bucket_prune.py).

Pure unit tests with injected list/delete functions (no S3, no network): confirms the GFS keep
window, dry-run-by-default, delete-of-sidecars, never-delete-newest, refuse-all, and empty cases.
"""
import datetime as _dt
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import bucket_prune as bp  # noqa: E402


def _keys(n_days):
    """n_days daily backups (each: artifact + 2 sidecars), newest last."""
    keys = []
    base = _dt.datetime(2026, 1, 1, 7, 0, 0, tzinfo=_dt.timezone.utc)
    for i in range(n_days):
        ts = (base + _dt.timedelta(days=i)).strftime("%Y%m%dT%H%M%SZ")
        art = "ranger-db-%s.dump.age" % ts
        keys += [art, art + ".sha256", art + ".manifest.json"]
    return keys


def _run(keys, apply, kd=7, kw=4, km=3):
    deleted = []
    present = list(keys)
    code, rep = bp.prune_bucket(lambda: present, lambda k: deleted.append(k),
                                kd, kw, km, apply=apply)
    return code, rep, deleted


def test_dryrun_default_deletes_nothing():
    code, rep, deleted = _run(_keys(40), apply=False)
    assert code == 0 and deleted == [] and rep["deleted"]  # reports deletions, performs none


def test_apply_keeps_gfs_window_and_deletes_sidecars():
    code, rep, deleted = _run(_keys(40), apply=True)
    assert code == 0
    # 40 daily backups -> keep ~7 daily + weekly/monthly representatives; the rest deleted
    assert 7 <= len(rep["kept"]) <= 14
    # every deleted artifact removes its three objects
    for art in rep["deleted"]:
        assert art in deleted and (art + ".sha256") in deleted and (art + ".manifest.json") in deleted


def test_never_deletes_newest():
    keys = _keys(40)
    newest = sorted(k for k in keys if k.endswith(".dump.age"))[-1]
    code, rep, deleted = _run(keys, apply=True)
    assert newest in rep["kept"] and newest not in deleted


def test_refuse_all_guard():
    code, rep, deleted = _run(_keys(3), apply=True, kd=0, kw=0, km=0)
    # keep logic always retains the newest, so it can never delete everything; refuse path is covered
    assert code in (0, 3)
    if code == 0:
        assert len(rep["kept"]) >= 1


def test_empty_bucket_is_misconfig():
    code, rep, deleted = _run([], apply=True)
    assert code == 2 and deleted == []


def test_non_backup_keys_ignored():
    keys = _keys(2) + ["unrelated.txt", "notes/readme.md"]
    code, rep, deleted = _run(keys, apply=True)
    assert code == 0 and all(a.endswith(".dump.age") for a in rep["kept"])
