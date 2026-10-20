"""Post-upload offsite verification policy + logic (scripts/backup_upload_verify.py).

Pure unit tests with a FAKE remote (no AWS, no PostgreSQL): confirm the newest backup object and both
sidecars are checked, size mismatches and missing objects fail, and that production/readiness mode
cannot silently disable verification.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import pytest  # noqa: E402
import backup_upload_verify as bv  # noqa: E402

_MANAGED = ("RANGER_BACKUP_REQUIRE_VERIFY", "RANGER_BACKUP_VERIFY_UPLOAD",
            "RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV", "RANGER_REQUIRE_SECURE_SECRETS")


@pytest.fixture()
def clean_env():
    saved = {k: os.environ.get(k) for k in _MANAGED}
    for k in _MANAGED:
        os.environ.pop(k, None)
    try:
        yield
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _make_backup_set(tmp_path, dump_bytes=b"age-ciphertext", sha_bytes=b"abc  x\n",
                     man_bytes=b"{}\n"):
    d = tmp_path / "out"
    d.mkdir()
    base = d / "ranger-db-20260101T000000Z.dump.age"
    base.write_bytes(dump_bytes)
    (d / (base.name + ".sha256")).write_bytes(sha_bytes)
    (d / (base.name + ".manifest.json")).write_bytes(man_bytes)
    sizes = {base.name: len(dump_bytes), base.name + ".sha256": len(sha_bytes),
             base.name + ".manifest.json": len(man_bytes)}
    return str(d), sizes


def _remote(sizes):
    def head(basename):
        return {"size": sizes[basename], "etag": '"x"', "version_id": "v1"} if basename in sizes else None
    return head


def test_all_three_objects_verified(clean_env, tmp_path):
    dest, sizes = _make_backup_set(tmp_path)
    ok, rep = bv.verify(dest, _remote(sizes))
    assert ok is True and len(rep["checked"]) == 3 and not rep["problems"]


def test_missing_sidecar_offsite_fails(clean_env, tmp_path):
    dest, sizes = _make_backup_set(tmp_path)
    remote = dict(sizes); remote.pop([k for k in sizes if k.endswith(".manifest.json")][0])
    ok, rep = bv.verify(dest, _remote(remote))
    assert ok is False and any("manifest.json" in p["file"] for p in rep["problems"])


def test_size_mismatch_fails(clean_env, tmp_path):
    dest, sizes = _make_backup_set(tmp_path)
    bad = dict(sizes)
    dump = [k for k in sizes if k.endswith(".dump.age")][0]
    bad[dump] = sizes[dump] - 1  # remote reports a smaller object
    ok, rep = bv.verify(dest, _remote(bad))
    assert ok is False and any(p.get("error") == "size mismatch" for p in rep["problems"])


def test_object_not_visible_fails(clean_env, tmp_path):
    dest, sizes = _make_backup_set(tmp_path)
    ok, rep = bv.verify(dest, lambda b: None)  # nothing visible offsite
    assert ok is False and len(rep["problems"]) == 3


def test_incomplete_local_set_fails_closed(clean_env, tmp_path):
    dest, sizes = _make_backup_set(tmp_path)
    # remove a local sidecar -> an incomplete local set must not be 'verified'
    os.remove(os.path.join(dest, [k for k in sizes if k.endswith(".sha256")][0]))
    with pytest.raises(SystemExit) as ei:
        bv.verify(dest, _remote(sizes))
    assert ei.value.code == 2


def test_production_cannot_disable_verification(clean_env, tmp_path):
    dest, sizes = _make_backup_set(tmp_path)
    os.environ["RANGER_BACKUP_REQUIRE_VERIFY"] = "1"
    os.environ["RANGER_BACKUP_VERIFY_UPLOAD"] = "0"  # attempt to silently disable
    with pytest.raises(SystemExit) as ei:
        bv.verify(dest, _remote(sizes))
    assert ei.value.code == 2


def test_production_marker_requires_verification(clean_env, tmp_path):
    os.environ["RANGER_ENV"] = "production"
    assert bv.verification_required() is True
    os.environ["RANGER_BACKUP_VERIFY_UPLOAD"] = "0"
    with pytest.raises(SystemExit) as ei:
        bv.resolve_mode()
    assert ei.value.code == 2


def test_nonproduction_may_skip(clean_env, tmp_path):
    dest, sizes = _make_backup_set(tmp_path)
    os.environ["RANGER_BACKUP_VERIFY_UPLOAD"] = "0"  # allowed only outside production
    ok, rep = bv.verify(dest, lambda b: None)
    assert ok is True and rep.get("skipped") is True


def test_ambiguous_environment_requires_verification(clean_env, tmp_path):
    # an unrecognized RANGER_ENV makes prodconfig.is_production raise -> verifier fails safe (required)
    os.environ["RANGER_ENV"] = "prd-typo-xyz"
    assert bv.verification_required() is True
