#!/usr/bin/env python3
"""Post-upload offsite verification for the encrypted backup runner.

Before a backup job may report success, this confirms the newest backup OBJECT and BOTH of its
integrity sidecars (`.sha256`, `.manifest.json`) are visible offsite at the expected byte sizes
(and records any checksum/version metadata the provider returns). Upload-command success alone is
NOT accepted as delivery.

Production enforcement
----------------------
For a production or production-readiness job (declared by `RANGER_BACKUP_REQUIRE_VERIFY=1`, or by a
production environment marker via prodconfig), verification is MANDATORY and CANNOT be disabled:
setting `RANGER_BACKUP_VERIFY_UPLOAD=0` in that mode fails closed (exit 2) rather than silently
skipping. Outside production, `RANGER_BACKUP_VERIFY_UPLOAD=0` may skip verification.

Remote visibility is not provider durability: a successful HeadObject proves the object is visible
and the right size, not that the provider has durably/redundantly stored it. Durability is the
provider's SLA; this check catches absent, truncated, or partially-uploaded (one-of-three-missing)
backup sets. Exit codes: 0 verified (or legitimately skipped), 2 misconfiguration / disabled-in-
production (fail closed), 4 verification failed.
"""
from __future__ import annotations

import datetime as _dt
import glob
import json
import os
import sys

_TRUTHY = {"1", "true", "yes", "on"}
# Self-contained environment-marker detection (no cross-sprint dependency). Recognized production and
# development tokens; an unrecognized, non-empty RANGER_ENV is treated as ambiguous and fails safe
# (verification required) rather than silently optional.
_PROD_VALUES = {"prod", "production", "prd", "live"}
_DEV_VALUES = {"dev", "development", "local", "localhost", "test", "testing", "ci",
               "staging", "stage", "qa", "sandbox", "preview", "nonprod", "nonproduction",
               "non-production"}


def _log(level, event, **f):
    rec = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), "level": level, "event": event}
    rec.update(f)
    sys.stdout.write(json.dumps(rec, sort_keys=True) + "\n"); sys.stdout.flush()


def verification_required(env=None) -> bool:
    """True when verification must not be skippable: an explicit backup flag, a secure-secrets force
    flag, a production marker, or an ambiguous (unrecognized) RANGER_ENV (fail safe)."""
    env = env if env is not None else os.environ
    if (env.get("RANGER_BACKUP_REQUIRE_VERIFY") or "").strip().lower() in _TRUTHY:
        return True
    if (env.get("RANGER_REQUIRE_SECURE_SECRETS") or "").strip().lower() in _TRUTHY:
        return True
    ranger_env = (env.get("RANGER_ENV") or "").strip().lower()
    if ranger_env:
        if ranger_env in _PROD_VALUES:
            return True
        if ranger_env not in _DEV_VALUES:
            return True  # ambiguous marker -> fail safe
    for m in ("APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
        if (env.get(m) or "").strip().lower() in _PROD_VALUES:
            return True
    return False


def resolve_mode(env=None):
    """Return 'enabled' | 'skipped', or raise SystemExit(2) if verification is disabled where it is
    required. 'skipped' only outside production with RANGER_BACKUP_VERIFY_UPLOAD=0."""
    env = env if env is not None else os.environ
    disabled = (env.get("RANGER_BACKUP_VERIFY_UPLOAD") or "").strip() == "0"
    if verification_required(env):
        if disabled:
            _log("error", "upload.verify_disabled_in_production",
                 reason="RANGER_BACKUP_VERIFY_UPLOAD=0 is not allowed for a production/readiness job")
            raise SystemExit(2)
        return "enabled"
    return "skipped" if disabled else "enabled"


def newest_backup_set(dest):
    """Return [(basename, local_size)] for the newest .dump.age and its two sidecars, or raise
    SystemExit(2) if the local trio is incomplete (an incomplete local set must not be 'verified')."""
    ages = sorted(glob.glob(os.path.join(dest, "*.dump.age")), key=os.path.getmtime, reverse=True)
    if not ages:
        _log("error", "upload.verify_no_local_artifact", dest=dest)
        raise SystemExit(2)
    base = ages[0]
    files = [base, base + ".sha256", base + ".manifest.json"]
    out = []
    for f in files:
        if not os.path.exists(f):
            _log("error", "upload.verify_incomplete_local_set", missing=os.path.basename(f))
            raise SystemExit(2)
        out.append((os.path.basename(f), os.path.getsize(f)))
    return out


def verify(dest, head_fn, env=None):
    """Confirm each file of the newest backup set is visible offsite at the expected size.

    head_fn(basename) -> dict with at least {"size": int} (and optionally etag/version_id/checksum),
    or None if the object is not visible. Returns (ok, report). Never raises for a verification miss
    (returns ok=False); raises SystemExit(2) only for a disabled-in-production misconfiguration or an
    incomplete local set."""
    env = env if env is not None else os.environ
    mode = resolve_mode(env)
    if mode == "skipped":
        _log("info", "upload.verify_skipped", reason="disabled and not required (non-production)")
        return True, {"skipped": True}
    expected = newest_backup_set(dest)
    checked, problems = [], []
    for basename, size in expected:
        meta = None
        try:
            meta = head_fn(basename)
        except Exception as e:  # noqa: BLE001
            problems.append({"file": basename, "error": str(e)[:160]})
            continue
        if not meta:
            problems.append({"file": basename, "error": "not visible offsite"})
            continue
        rsize = meta.get("size")
        if rsize != size:
            problems.append({"file": basename, "error": "size mismatch",
                             "local": size, "remote": rsize})
            continue
        checked.append({"file": basename, "size": size,
                        "etag": meta.get("etag"), "version_id": meta.get("version_id"),
                        "checksum": meta.get("checksum")})
    ok = (not problems and len(checked) == len(expected))
    _log("info" if ok else "error", "upload.verify_result",
         ok=ok, files_expected=len(expected), files_verified=len(checked), problems=problems,
         note="remote visibility confirmed; durability is the provider SLA, not proven here")
    return ok, {"checked": checked, "problems": problems}


def _aws_head_fn(s3_url):
    """Build a head_fn backed by `aws s3api head-object` (used by the runner). Keys live directly
    under the given s3:// prefix. Returns None when the object is not visible."""
    import re
    import subprocess
    base = s3_url.rstrip("/")
    m = re.match(r"^s3://([^/]+)/?(.*)$", base)
    if not m:
        raise SystemExit(2)
    bucket, prefix = m.group(1), m.group(2)
    endpoint = os.environ.get("AWS_ENDPOINT_URL_S3")

    def head(basename):
        key = (prefix + "/" + basename) if prefix else basename
        cmd = ["aws"]
        if endpoint:
            cmd += ["--endpoint-url", endpoint]
        cmd += ["s3api", "head-object", "--bucket", bucket, "--key", key, "--output", "json"]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            return None  # not visible (404) or access/transport error -> treated as unverified
        d = json.loads(p.stdout or "{}")
        return {"size": d.get("ContentLength"), "etag": d.get("ETag"),
                "version_id": d.get("VersionId"), "checksum": d.get("ChecksumSHA256")}
    return head


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) < 2:
        _log("error", "upload.verify_usage", usage="backup_upload_verify.py <dest_dir> <s3_url>")
        return 2
    dest, s3_url = argv[0], argv[1]
    try:
        ok, _ = verify(dest, _aws_head_fn(s3_url))
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 2
    return 0 if ok else 4


if __name__ == "__main__":
    raise SystemExit(main())
