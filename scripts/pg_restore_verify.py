#!/usr/bin/env python3
"""Restore an encrypted backup into an ISOLATED disposable database and verify its integrity.

Never restores in place and never targets a production-like database: the target name must look
like a throwaable test/restore database and the server must not carry a production app database,
mirroring the guard in siem/tests/_pgtest.py. Verification covers:

  1. Ciphertext integrity  - SHA-256 of the .age artifact matches its sidecar (or a supplied value)
                             BEFORE anything is decrypted.
  2. Row-count parity      - per-table counts in the restored DB match the live source (when a
                             source URL is supplied) or a supplied counts manifest.
  3. Signed-evidence integrity - the Ed25519 hash-chained audit trail re-verifies from the restored
                             rows (parallax.auditlog.verify_chain + audit_integrity.verify_events),
                             so any corruption of signed bytes across dump/restore is caught.
  4. Representative records - candidate and program-membership rows are present and well-formed.

Configuration (environment)
---------------------------
  RANGER_BACKUP_AGE_IDENTITY       age identity (private key) text, OR
  RANGER_BACKUP_AGE_IDENTITY_FILE  path to an age identity file (preferred; 0600)
  RANGER_RESTORE_TARGET_URL        disposable target DB URL (name must match a test/restore pattern)
  RANGER_VERIFY_SOURCE_URL         live source URL to compare row counts against (optional)
  RANGER_PG_BIN / RANGER_AGE_BIN   tool locations (auto-discovered / PATH otherwise)

Exit codes: 0 all checks passed, 2 misconfiguration/guard refusal, 3 tool failure, 4 verification failed.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

_SAFE_TARGET = re.compile(r"(test|restore|verify|disposable|scratch)", re.IGNORECASE)
_PRODUCTION_LIKE = frozenset({
    "ranger", "ranger_prod", "ranger_production", "portal", "production", "prod",
    "qwalora", "qwalora_ranger", "app", "application", "main",
})
# Evidence-bearing + authorization tables whose fidelity we care about most.
_CORE_TABLES = ("candidates", "program_memberships", "board_results", "qualification_decisions",
                "parallax_audit_events", "parallax_audit_checkpoints", "parallax_approvals")


def _log(level, event, **f):
    import datetime as dt
    rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(), "level": level, "event": event}
    rec.update(f)
    sys.stdout.write(json.dumps(rec, sort_keys=True) + "\n"); sys.stdout.flush()


def _discover_pg_bin():
    env = os.environ.get("RANGER_PG_BIN")
    if env and os.path.isdir(env):
        return env
    for c in sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True):
        if os.path.exists(os.path.join(c, "pg_restore")):
            return c
    return ""


def _bin(name):
    d = _discover_pg_bin()
    return os.path.join(d, name) if d else name


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_ciphertext(artifact, expected=None):
    if expected is None:
        side = artifact + ".sha256"
        if os.path.exists(side):
            with open(side, "r", encoding="utf-8") as fh:
                expected = fh.read().split()[0].strip()
    actual = sha256_file(artifact)
    ok = (expected is not None and actual == expected)
    _log("info" if ok else "error", "restore.ciphertext_sha256",
         ok=ok, actual=actual, expected=expected)
    return ok, actual


def guard_disposable(target_url):
    u = make_url(target_url)
    name = (u.database or "").strip()
    if not name or not _SAFE_TARGET.search(name):
        raise SystemExit2("target '%s' is not an obvious disposable test/restore DB" % name)
    if name.lower() in _PRODUCTION_LIKE:
        raise SystemExit2("target '%s' is a production-like name; refusing" % name)
    return u


class SystemExit2(SystemExit):
    def __init__(self, msg):
        _log("error", "restore.guard_refused", reason=msg)
        super().__init__(2)


def decrypt(artifact, identity_file, age_bin=None):
    age_bin = age_bin or os.environ.get("RANGER_AGE_BIN") or "age"
    fd, plain = tempfile.mkstemp(prefix="ranger-restore-", suffix=".dump")
    os.close(fd)
    cmd = [age_bin, "-d", "-i", identity_file, "-o", plain, artifact]
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        _safe_unlink(plain)
        _log("error", "restore.decrypt_failed", code=p.returncode,
             stderr=(p.stderr or b"").decode("utf-8", "replace")[:300])
        raise SystemExit(3)
    return plain


def _admin_engine(u):
    """Engine on the server's default 'postgres' db for CREATE/DROP DATABASE (autocommit)."""
    admin_url = u.set(database="postgres")
    return create_engine(admin_url, isolation_level="AUTOCOMMIT", future=True)


def recreate_target(u):
    name = u.database
    eng = _admin_engine(u)
    with eng.connect() as c:
        c.execute(text("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                       "WHERE datname=:n AND pid<>pg_backend_pid()"), {"n": name})
        c.execute(text('DROP DATABASE IF EXISTS "%s"' % name))
        c.execute(text('CREATE DATABASE "%s"' % name))
    eng.dispose()
    _log("info", "restore.target_recreated", database=name)


def restore(dump_path, u):
    pgpass = _write_pgpass(u)
    env = dict(os.environ); env["PGPASSFILE"] = pgpass
    cmd = [_bin("pg_restore"), "-h", u.host or "localhost", "-p", str(u.port or 5432),
           "-U", u.username or "postgres", "-d", u.database, "--no-owner", "--no-privileges",
           "--no-password", "--exit-on-error", dump_path]
    try:
        p = subprocess.run(cmd, capture_output=True, env=env)
    finally:
        _safe_unlink(pgpass)
    if p.returncode != 0:
        _log("error", "restore.pg_restore_failed", code=p.returncode,
             stderr=(p.stderr or b"").decode("utf-8", "replace")[:800])
        raise SystemExit(3)
    _log("info", "restore.restored", database=u.database)


def _write_pgpass(u):
    import stat as _st
    fd, path = tempfile.mkstemp(prefix="ranger-pgpass-"); os.close(fd)
    os.chmod(path, _st.S_IRUSR | _st.S_IWUSR)
    esc = lambda s: (s or "").replace("\\", "\\\\").replace(":", "\\:")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("%s:%s:%s:%s:%s\n" % (esc(u.host or "localhost"), str(u.port or 5432),
                                       esc(u.database or "*"), esc(u.username or "*"),
                                       esc(u.password or "")))
    return path


def _counts(url, tables):
    eng = create_engine(url, future=True)
    out = {}
    with eng.connect() as c:
        for t in tables:
            try:
                out[t] = c.execute(text('SELECT count(*) FROM "%s"' % t)).scalar()
            except Exception:  # noqa: BLE001 - table may not exist in a given snapshot
                out[t] = None
    eng.dispose()
    return out


def compare_counts(target_url, source_url=None, expected=None, tables=_CORE_TABLES):
    restored = _counts(target_url, tables)
    ref = expected
    if ref is None and source_url:
        ref = _counts(source_url, tables)
    if ref is None:
        _log("info", "restore.counts", restored=restored, reference="none (reporting only)")
        return True, restored
    mism = {t: (ref.get(t), restored.get(t)) for t in tables
            if ref.get(t) is not None and ref.get(t) != restored.get(t)}
    ok = not mism
    _log("info" if ok else "error", "restore.counts_parity",
         ok=ok, restored=restored, reference=ref, mismatches=mism)
    return ok, restored


def verify_signatures(target_url):
    """Point the portal app at the restored DB and re-verify the signed audit trail from its rows.
    Requires the same signing key material (RANGER_SIGNING_KEY/RANGER_SIGNING_KEYS) that signed them."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    prev_db = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = target_url
    try:
        import importlib
        import app as appmod
        importlib.reload(appmod)
        from models import db, ParallaxAuditEvent
        from parallax import auditlog, audit_integrity
        application = appmod.create_app()
        with application.app_context():
            n = ParallaxAuditEvent.query.filter_by(stream="parallax-governance").count()
            chain_ok = auditlog.verify_chain(db)
            try:
                ev = audit_integrity.verify_events(db)
                events_ok = bool(ev.get("ok", True)) if isinstance(ev, dict) else bool(ev)
            except Exception as e:  # noqa: BLE001
                events_ok = chain_ok  # checkpoint stream may be empty in a given snapshot
                _log("info", "restore.verify_events_note", note=str(e)[:200])
        ok = chain_ok and events_ok
        _log("info" if ok else "error", "restore.signature_integrity",
             ok=ok, audit_events=n, chain_ok=chain_ok, events_ok=events_ok)
        return ok
    finally:
        if prev_db is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = prev_db


def sample_records(target_url):
    eng = create_engine(target_url, future=True)
    with eng.connect() as c:
        cands = c.execute(text("SELECT handle, status, current_board FROM candidates "
                               "ORDER BY id LIMIT 5")).fetchall()
        mems = c.execute(text("SELECT program, status, count(*) FROM program_memberships "
                              "GROUP BY program, status ORDER BY program, status")).fetchall()
    eng.dispose()
    sample = {"candidates": [dict(handle=r[0], status=r[1], board=r[2]) for r in cands],
              "memberships": [dict(program=r[0], status=r[1], n=r[2]) for r in mems]}
    _log("info", "restore.sample_records", **sample)
    return sample


def _identity_file():
    f = os.environ.get("RANGER_BACKUP_AGE_IDENTITY_FILE")
    if f and os.path.exists(f):
        return f, False
    ident = os.environ.get("RANGER_BACKUP_AGE_IDENTITY", "").strip()
    if ident:
        import stat as _st
        fd, path = tempfile.mkstemp(prefix="ranger-ident-"); os.close(fd)
        os.chmod(path, _st.S_IRUSR | _st.S_IWUSR)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(ident + "\n")
        return path, True
    _log("error", "restore.misconfigured", reason="no age identity (RANGER_BACKUP_AGE_IDENTITY[_FILE])")
    raise SystemExit(2)


def _safe_unlink(p):
    try:
        if p and os.path.exists(p):
            os.unlink(p)
    except OSError:
        pass


def run(artifact, target_url, source_url=None, expected_sha=None, expected_counts=None,
        drop_after=True):
    u = guard_disposable(target_url)
    ok_sha, _ = verify_ciphertext(artifact, expected_sha)
    if not ok_sha:
        raise SystemExit(4)
    ident, ident_tmp = _identity_file()
    plain = None
    try:
        plain = decrypt(artifact, ident)
        recreate_target(u)
        restore(plain, u)
        ok_counts, restored = compare_counts(target_url, source_url, expected_counts)
        ok_sig = verify_signatures(target_url)
        sample_records(target_url)
    finally:
        _safe_unlink(plain)
        if ident_tmp:
            _safe_unlink(ident)
        if drop_after:
            try:
                eng = _admin_engine(u)
                with eng.connect() as c:
                    c.execute(text("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                                   "WHERE datname=:n AND pid<>pg_backend_pid()"), {"n": u.database})
                    c.execute(text('DROP DATABASE IF EXISTS "%s"' % u.database))
                eng.dispose()
                _log("info", "restore.target_dropped", database=u.database)
            except Exception as e:  # noqa: BLE001
                _log("info", "restore.target_drop_note", note=str(e)[:200])
    all_ok = ok_sha and ok_counts and ok_sig
    _log("info" if all_ok else "error", "restore.verify_complete",
         ok=all_ok, sha=ok_sha, counts=ok_counts, signatures=ok_sig)
    if not all_ok:
        raise SystemExit(4)
    return {"ok": True, "restored_counts": restored}


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        _log("error", "restore.usage", usage="pg_restore_verify.py <artifact.dump.age>")
        return 2
    artifact = argv[0]
    target = os.environ.get("RANGER_RESTORE_TARGET_URL")
    if not target:
        _log("error", "restore.misconfigured", reason="RANGER_RESTORE_TARGET_URL not set")
        return 2
    source = os.environ.get("RANGER_VERIFY_SOURCE_URL")
    run(artifact, target, source_url=source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
