#!/usr/bin/env python3
"""Encrypted logical PostgreSQL backup for parallax-nonprod.

A COMPLEMENT to Railway's platform backups (scheduled volume snapshots and PITR), not a
replacement: this produces a portable `pg_dump -Fc` logical dump, encrypted with age using a
PUBLIC recipient key, so the running service can create backups it cannot itself decrypt. The
private age identity is held separately (a secret store or offline), so a compromise of the
portal or inference service does not grant the ability to read historical backups.

Security properties
--------------------
- The database password is NEVER passed on argv (visible in `ps`/`/proc`). It is written to a
  temporary PGPASSFILE with 0600 perms and removed in a finally block.
- The dump is NEVER written in plaintext. If no age recipient is configured the run fails closed
  before pg_dump is invoked; the pipeline streams pg_dump -> age and only ciphertext touches disk.
- Logs are structured JSON on stdout with the DB URL redacted to user-masked host:port/db. No
  secret, token, password, or evidence payload is ever logged.
- A SHA-256 of the ciphertext and a non-secret JSON manifest are written beside the artifact so
  integrity can be checked before any restore.

Configuration (environment)
---------------------------
  RANGER_BACKUP_SOURCE_URL   source DB SQLAlchemy/libpq URL (falls back to DATABASE_URL)
  RANGER_BACKUP_AGE_RECIPIENT  age PUBLIC recipient (age1...) OR
  RANGER_BACKUP_AGE_RECIPIENTS_FILE  path to a file of recipients (one per line)
  RANGER_BACKUP_DEST         output directory (default ./backups); the durable off-box target
                             (object store / dedicated volume) is an approval-gated deployment
                             decision, not chosen here.
  RANGER_PG_BIN              directory holding pg_dump (auto-discovered if unset)
  RANGER_AGE_BIN             path to the `age` binary (default: age on PATH)

Exit codes: 0 success, 2 misconfiguration (fail-closed), 3 tool/subprocess failure.
"""
from __future__ import annotations

import datetime as _dt
import glob
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile

try:
    from sqlalchemy.engine import make_url
except Exception:  # noqa: BLE001 - sqlalchemy is a portal dependency; fail clearly if missing
    make_url = None


def _log(level: str, event: str, **fields) -> None:
    rec = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), "level": level, "event": event}
    rec.update(fields)
    sys.stdout.write(json.dumps(rec, sort_keys=True) + "\n")
    sys.stdout.flush()


def redact_url(url: str) -> str:
    """A safe-to-log identifier for a DB URL: user is masked, password is dropped entirely."""
    try:
        u = make_url(url)
        user = (u.username or "")
        user_masked = (user[0] + "***") if user else "-"
        return "%s@%s:%s/%s" % (user_masked, u.host or "-", u.port or "-", u.database or "-")
    except Exception:  # noqa: BLE001
        return "<unparseable-url>"


def _discover_pg_bin() -> str:
    env = os.environ.get("RANGER_PG_BIN")
    if env and os.path.isdir(env):
        return env
    for cand in sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True):
        if os.path.exists(os.path.join(cand, "pg_dump")):
            return cand
    return ""  # rely on PATH


def _pg_dump_path() -> str:
    d = _discover_pg_bin()
    return os.path.join(d, "pg_dump") if d else "pg_dump"


def _recipients() -> list:
    rf = os.environ.get("RANGER_BACKUP_AGE_RECIPIENTS_FILE")
    if rf and os.path.exists(rf):
        with open(rf, "r", encoding="utf-8") as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
    one = os.environ.get("RANGER_BACKUP_AGE_RECIPIENT", "").strip()
    return [one] if one else []


def _write_pgpass(u) -> str:
    """Write a 0600 PGPASSFILE so the password is never on argv. Returns the file path."""
    fd, path = tempfile.mkstemp(prefix="ranger-pgpass-")
    os.close(fd)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 before writing the secret
    host = u.host or "localhost"
    port = str(u.port or 5432)
    db = u.database or "*"
    user = u.username or "*"
    pw = u.password or ""
    # pgpass format: host:port:database:user:password  (escape : and \)
    esc = lambda s: s.replace("\\", "\\\\").replace(":", "\\:")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("%s:%s:%s:%s:%s\n" % (esc(host), port, esc(db), esc(user), esc(pw)))
    return path


def run_backup(source_url: str, dest_dir: str, recipients: list, *, age_bin: str = None,
               label: str = None) -> dict:
    """Create one encrypted backup artifact. Returns a manifest dict. Raises on failure."""
    if make_url is None:
        raise SystemExit(2)
    if not source_url:
        _log("error", "backup.misconfigured", reason="no source URL (RANGER_BACKUP_SOURCE_URL/DATABASE_URL)")
        raise SystemExit(2)
    if not recipients:
        # Fail closed: never write an unencrypted dump.
        _log("error", "backup.misconfigured", reason="no age recipient configured; refusing to write plaintext")
        raise SystemExit(2)

    u = make_url(source_url)
    age_bin = age_bin or os.environ.get("RANGER_AGE_BIN") or "age"
    os.makedirs(dest_dir, exist_ok=True)
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = "ranger-%s-%s" % (u.database or "db", ts)
    out_path = os.path.join(dest_dir, base + ".dump.age")

    _log("info", "backup.start", source=redact_url(source_url), dest=out_path,
         recipients=len(recipients), pg_dump=_pg_dump_path())

    pgpass = _write_pgpass(u)
    env = dict(os.environ)
    env["PGPASSFILE"] = pgpass
    # Password comes only from PGPASSFILE; host/port/user/db are non-secret args.
    dump_cmd = [_pg_dump_path(), "-h", u.host or "localhost", "-p", str(u.port or 5432),
                "-U", u.username or "postgres", "-d", u.database or "postgres",
                "-Fc", "--no-owner", "--no-privileges", "--no-password"]
    age_cmd = [age_bin]
    for r in recipients:
        age_cmd += ["-r", r]
    age_cmd += ["-o", out_path]

    try:
        dump = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        enc = subprocess.Popen(age_cmd, stdin=dump.stdout, stderr=subprocess.PIPE)
        dump.stdout.close()  # allow dump to get SIGPIPE if enc exits
        enc_err = enc.communicate()[1]
        dump_err = dump.stderr.read(); dump.stderr.close(); dump.wait()
        if dump.returncode != 0:
            _log("error", "backup.pg_dump_failed", code=dump.returncode,
                 stderr=(dump_err or b"").decode("utf-8", "replace")[:500])
            _safe_unlink(out_path)
            raise SystemExit(3)
        if enc.returncode != 0:
            _log("error", "backup.encrypt_failed", code=enc.returncode,
                 stderr=(enc_err or b"").decode("utf-8", "replace")[:500])
            _safe_unlink(out_path)
            raise SystemExit(3)
    finally:
        _safe_unlink(pgpass)

    size = os.path.getsize(out_path)
    sha = _sha256_file(out_path)
    with open(out_path + ".sha256", "w", encoding="utf-8") as fh:
        fh.write("%s  %s\n" % (sha, os.path.basename(out_path)))
    manifest = {
        "artifact": os.path.basename(out_path),
        "created_utc": ts,
        "label": label or os.environ.get("RANGER_BACKUP_LABEL") or "manual",
        "source": redact_url(source_url),
        "database": u.database,
        "bytes": size,
        "sha256": sha,
        "format": "pg_dump -Fc (custom, compressed)",
        "encryption": "age (X25519 public-key); decryption key held separately",
        "recipients": len(recipients),
        "pg_dump_version": _tool_version(_pg_dump_path()),
    }
    with open(out_path + ".manifest.json", "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    _log("info", "backup.ok", **{k: manifest[k] for k in ("artifact", "bytes", "sha256", "database")})
    return manifest


def _safe_unlink(path: str) -> None:
    try:
        if path and os.path.exists(path):
            os.unlink(path)
    except OSError:
        pass


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _tool_version(binpath: str) -> str:
    try:
        out = subprocess.run([binpath, "--version"], capture_output=True, text=True, timeout=10)
        return (out.stdout or "").strip().splitlines()[0] if out.stdout else ""
    except Exception:  # noqa: BLE001
        return ""


def main(argv=None) -> int:
    source = os.environ.get("RANGER_BACKUP_SOURCE_URL") or os.environ.get("DATABASE_URL") or ""
    dest = os.environ.get("RANGER_BACKUP_DEST") or os.path.join(os.getcwd(), "backups")
    run_backup(source, dest, _recipients())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
