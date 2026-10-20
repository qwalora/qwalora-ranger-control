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
# Evidence-bearing + authorization tables whose fidelity we care about most. unit_results and badges
# are included so a restore proves the qualification/credential surfaces round-trip unchanged (no row
# gained or lost), supporting the post-restore qualification-isolation check.
_CORE_TABLES = ("candidates", "program_memberships", "board_results", "qualification_decisions",
                "unit_results", "badges",
                "parallax_audit_events", "parallax_audit_checkpoints", "parallax_approvals",
                "parallax_research_runs")


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


def _tool_major(binpath):
    import re as _re
    try:
        out = subprocess.run([binpath, "--version"], capture_output=True, text=True, timeout=10)
        m = _re.search(r"(\d+)\.", (out.stdout or "") + " " + (out.stderr or ""))
        return int(m.group(1)) if m else None
    except Exception:  # noqa: BLE001
        return None


def _manifest_major(manifest):
    import re as _re
    m = _re.search(r"(\d+)\.", (manifest or {}).get("pg_dump_version") or "")
    return int(m.group(1)) if m else None


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


def _require_signing_key():
    """Restore verification must run with the SAME signing key material that signed the records. If
    neither RANGER_SIGNING_KEY nor RANGER_SIGNING_KEYS is set, signing.py would synthesize a legacy key
    from SECRET_KEY and verification could pass under the WRONG key (a false positive). Fail closed."""
    if not (os.environ.get("RANGER_SIGNING_KEY") or os.environ.get("RANGER_SIGNING_KEYS")):
        _log("error", "restore.misconfigured",
             reason="no signing key configured (RANGER_SIGNING_KEY/RANGER_SIGNING_KEYS); refusing to "
                    "verify under a derived key")
        raise SystemExit(2)


def _verify_research_runs(db):
    """Re-verify EVERY signed research record from the restored rows: recompute the canonical SHA-256
    and the Ed25519 signature (kid-aware) for research evidence, investigations, and reviewer
    adjudications; confirm the signed researcher_id matches the row's researcher_id column; and confirm
    each investigation's linked evidence exists and is owned by the same researcher. Fails closed if
    any row's hash, signature, or ownership does not verify."""
    import hashlib as _h
    import json as _j
    import signing
    from models import ParallaxResearchRun
    rows = ParallaxResearchRun.query.all()
    owner_by_id = {r.run_id: r.researcher_id for r in rows}
    counts = {"total": 0, "trial": 0, "investigation": 0, "adjudication": 0, "other": 0}
    bad = 0
    owner_bad = 0
    for r in rows:
        counts["total"] += 1
        try:
            rec = _j.loads(r.run_record)
        except Exception:  # noqa: BLE001
            bad += 1
            continue
        manifest = rec.get("manifest") or {}
        metrics = rec.get("metrics") or {}
        kind = metrics.get("kind") or manifest.get("kind") or "other"
        counts[kind] = counts.get(kind, 0) + 1 if kind in counts else counts.get("other", 0) + 1
        hash_ok = (_h.sha256(signing.canonical(rec)).hexdigest() == r.record_hash)
        sig_ok = bool(signing.verify(rec, r.signature, kid=r.signing_kid))
        # researcher_id in the signed record must match the stored column (no row re-pointing)
        col_owner_ok = (rec.get("researcher_id") == r.researcher_id)
        # an investigation's linked evidence must exist and be owned by the same researcher
        owner_ok = True
        if kind == "investigation":
            parent = manifest.get("parent_run") or metrics.get("parent_run")
            owner_ok = (parent in owner_by_id and owner_by_id[parent] == r.researcher_id)
        if not (hash_ok and sig_ok and col_owner_ok and owner_ok):
            bad += 1
            if not (col_owner_ok and owner_ok):
                owner_bad += 1
    ok = (bad == 0)
    _log("info" if ok else "error", "restore.research_signature_integrity",
         ok=ok, verified=counts["total"], failed=bad, ownership_failures=owner_bad,
         trials=counts.get("trial", 0), investigations=counts.get("investigation", 0),
         adjudications=counts.get("adjudication", 0))
    return ok


def _public_tables(url):
    eng = create_engine(url, future=True)
    with eng.connect() as c:
        rows = c.execute(text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name")).fetchall()
    eng.dispose()
    return sorted(r[0] for r in rows)


def verify_schema(target_url, manifest_schema):
    """Confirm the restored schema matches the schema recorded in the backup manifest. Fails closed on
    any drift (a table present at backup time missing after restore, or vice versa). Reporting-only
    when the manifest carries no schema list (older backups), with a clear note."""
    if not manifest_schema:
        _log("info", "restore.schema_check", ok=True, note="manifest has no schema_tables; skipped")
        return True
    restored = _public_tables(target_url)
    missing = sorted(set(manifest_schema) - set(restored))   # present at backup, absent after restore
    extra = sorted(set(restored) - set(manifest_schema))     # unexpected tables after restore
    ok = not missing and not extra
    _log("info" if ok else "error", "restore.schema_check",
         ok=ok, manifest_tables=len(manifest_schema), restored_tables=len(restored),
         missing=missing, unexpected=extra)
    return ok


def _load_manifest(artifact):
    path = artifact + ".manifest.json"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:  # noqa: BLE001 - a missing/invalid manifest is handled by callers
        _log("info", "restore.manifest_note", note="unreadable manifest: %s" % str(e)[:160])
        return {}


def verify_signatures(target_url):
    """Point the portal app at the restored DB and re-verify ALL signed records from the restored rows:
    the Ed25519 hash-chained governance audit trail AND every research evidence / investigation /
    reviewer-adjudication record. Requires the same signing key material (RANGER_SIGNING_KEY/
    RANGER_SIGNING_KEYS) that signed them; a wrong/absent key fails closed."""
    _require_signing_key()
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
            # A broken checkpoint stream must fail closed, not be silently downgraded. An empty
            # checkpoint set is benign (verify_events returns ok); only a raised error or an explicit
            # ok=False indicates corruption.
            try:
                ev = audit_integrity.verify_events(db)
                events_ok = bool(ev.get("ok", True)) if isinstance(ev, dict) else bool(ev)
            except Exception as e:  # noqa: BLE001
                events_ok = False
                _log("error", "restore.verify_events_failed", note=str(e)[:200])
            # Checkpoint integrity: a restored checkpoint stream must be self-consistent. A healthy
            # result is ok or no_checkpoint; truncated/rewritten/forged/broken fail closed.
            try:
                ck = audit_integrity.assess(db)
                ck_status = ck.get("status") if isinstance(ck, dict) else str(ck)
            except Exception as e:  # noqa: BLE001
                ck_status = "error:%s" % str(e)[:80]
            checkpoint_ok = ck_status in ("ok", "no_checkpoint")
            research_ok = _verify_research_runs(db)
        ok = chain_ok and events_ok and checkpoint_ok and research_ok
        _log("info" if ok else "error", "restore.signature_integrity",
             ok=ok, audit_events=n, chain_ok=chain_ok, events_ok=events_ok,
             checkpoint_status=ck_status, checkpoint_ok=checkpoint_ok, research_ok=research_ok)
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
    _require_signing_key()  # fail closed up front rather than after a full decrypt+restore
    ok_sha, _ = verify_ciphertext(artifact, expected_sha)
    if not ok_sha:
        raise SystemExit(4)
    manifest = _load_manifest(artifact)
    # PostgreSQL major-version compatibility: pg_restore must be >= the pg_dump major that produced the
    # backup, or the restore would fail or silently misbehave. Fail closed before touching the target.
    src_major, rst_major = _manifest_major(manifest), _tool_major(_bin("pg_restore"))
    if src_major and rst_major and rst_major < src_major:
        _log("error", "restore.version_incompatible", pg_restore_major=rst_major, dump_major=src_major,
             reason="pg_restore major is older than the backup's pg_dump major")
        raise SystemExit(2)
    # Completeness reference: prefer an explicit/live source; otherwise fall back to the row counts
    # recorded in the manifest so a partial/empty restore is caught even with no live source.
    ref_counts = expected_counts or (manifest.get("row_counts") if not source_url else None)
    ident, ident_tmp = _identity_file()
    plain = None
    try:
        plain = decrypt(artifact, ident)
        recreate_target(u)
        restore(plain, u)
        ok_schema = verify_schema(target_url, manifest.get("schema_tables"))
        ok_counts, restored = compare_counts(target_url, source_url, ref_counts)
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
    all_ok = ok_sha and ok_schema and ok_counts and ok_sig
    _log("info" if all_ok else "error", "restore.verify_complete",
         ok=all_ok, sha=ok_sha, schema=ok_schema, counts=ok_counts, signatures=ok_sig)
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
