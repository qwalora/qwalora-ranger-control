"""Encrypted PostgreSQL backup + restore-verify workflow (scripts/pg_backup.py,
scripts/pg_restore_verify.py) on GENUINE PostgreSQL.

Gated by _pgtest (skips fail-closed when a disposable PG is not authorized). Proves:
- a real pg_dump is age-encrypted (public-key), checksummed, and restores into an isolated DB
  with row-count parity and intact Ed25519 signed-evidence (audit chain re-verifies from the rows);
- the workflow fails closed with no recipient (never writes plaintext);
- a tampered ciphertext is rejected by the SHA-256 gate before any decrypt/restore;
- a production-like restore target is refused;
- verification actually checks signatures: a wrong signing key fails the integrity check.
"""
import importlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

os.environ.setdefault("SECRET_KEY", "backup-restore-test")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import base64  # noqa: E402
import pytest  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402

import _pgtest  # noqa: E402
import pg_backup  # noqa: E402
import pg_restore_verify as rv  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)
_PGBIN = "/usr/lib/postgresql/16/bin"
_SIGNKEY = base64.b64encode(b"\x11" * 32).decode()  # fixed test signing seed
_ENV_KEYS = ("DATABASE_URL", "RANGER_SIGNING_KEY", "RANGER_SIGNING_KEYS", "RANGER_PG_BIN",
             "RANGER_BACKUP_AGE_RECIPIENT", "RANGER_BACKUP_AGE_IDENTITY_FILE")


def _seed(source_url):
    os.environ["DATABASE_URL"] = source_url
    os.environ["RANGER_SIGNING_KEY"] = _SIGNKEY
    import signing
    signing._reset_registry()  # pick up this suite's key regardless of prior suites
    import app as appmod
    importlib.reload(appmod)
    from models import db, Candidate, Cohort, ProgramMembership, ParallaxAuditEvent
    from parallax import auditlog
    application = appmod.create_app()
    with application.app_context():
        db.drop_all(); db.create_all()
        db.session.add(Cohort(name="2026-A", sequence=1, status="active", pathway="strata"))
        db.session.add(Cohort(name="2026-PX", sequence=2, status="active", pathway="parallax"))
        db.session.commit()
        spec = [("c_strata", "strata"), ("c_px", "parallax"), ("c_dual", "strata"), ("c_pend", None)]
        made = []
        for h, prog in spec:
            c = Candidate(handle=h, name=h.upper(), email=h + "@e", cohort="2026-A", github_id=h,
                          status=("pending" if h == "c_pend" else "active"), current_board=1,
                          token="tok-" + h)
            db.session.add(c); db.session.commit(); made.append(c)
            if prog:
                db.session.add(ProgramMembership(candidate_id=c.id, program=prog, status="active",
                                                 cohort="2026-A"))
            if h == "c_dual":
                db.session.add(ProgramMembership(candidate_id=c.id, program="parallax",
                                                 status="active", cohort="2026-A"))
        db.session.commit()
        for c in made:
            auditlog.append(db, action="candidate.enrolled", actor_id="admin",
                            subject_kind="candidate", subject_ref=str(c.id), detail={"cohort": "2026-A"})
        db.session.commit()
        assert auditlog.verify_chain(db) is True
        return {"candidates": Candidate.query.count(),
                "program_memberships": ProgramMembership.query.count(),
                "parallax_audit_events": ParallaxAuditEvent.query.count()}


@pytest.fixture()
def bk(tmp_path):
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    os.environ["RANGER_PG_BIN"] = _PGBIN
    base = make_url(_pgtest.resolve_test_url())
    src_name = _pgtest._create_disposable(base)
    src_url = str(base.set(database=src_name))
    # ephemeral age keypair (never written to the repo)
    ident = os.path.join(str(tmp_path), "id.txt")
    pub = subprocess.run(["age-keygen", "-o", ident], capture_output=True, text=True)
    os.chmod(ident, 0o600)
    import re as _re
    m = _re.search(r"age1[0-9a-z]+", pub.stderr + "\n" + pub.stdout)
    recipient = m.group(0) if m else None
    assert recipient, "could not parse age recipient from age-keygen output"
    counts = _seed(src_url)
    ctx = dict(base=base, src_url=src_url, src_name=src_name, ident=ident,
               recipient=recipient, counts=counts, dest=str(tmp_path / "out"))
    try:
        yield ctx
    finally:
        _pgtest._drop_disposable(base, src_name)
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        try:
            import signing
            signing._reset_registry()
        except Exception:  # noqa: BLE001
            pass


def test_backup_restore_roundtrip_verifies_counts_and_signatures(bk):
    manifest = pg_backup.run_backup(bk["src_url"], bk["dest"], [bk["recipient"]])
    assert manifest["bytes"] > 0 and len(manifest["sha256"]) == 64
    artifact = os.path.join(bk["dest"], manifest["artifact"])
    assert os.path.exists(artifact)
    # ciphertext is real age output, not a plaintext dump
    with open(artifact, "rb") as fh:
        head = fh.read(40)
    assert head.startswith(b"age-encryption.org/v")
    assert b"PGDMP" not in head  # pg_dump custom-format magic must not be in the clear

    os.environ["RANGER_BACKUP_AGE_IDENTITY_FILE"] = bk["ident"]
    restore_url = str(bk["base"].set(database="ranger_test_restore_" + bk["src_name"][-8:]))
    result = rv.run(artifact, restore_url, source_url=bk["src_url"], drop_after=True)
    assert result["ok"] is True
    assert result["restored_counts"]["candidates"] == bk["counts"]["candidates"]
    assert result["restored_counts"]["program_memberships"] == bk["counts"]["program_memberships"]
    assert result["restored_counts"]["parallax_audit_events"] == bk["counts"]["parallax_audit_events"]


def test_backup_fails_closed_without_recipient(bk):
    with pytest.raises(SystemExit) as ei:
        pg_backup.run_backup(bk["src_url"], bk["dest"], [])
    assert ei.value.code == 2
    # no artifact written
    assert not (os.path.isdir(bk["dest"]) and any(f.endswith(".age") for f in os.listdir(bk["dest"])))


def test_tampered_ciphertext_rejected_before_restore(bk):
    manifest = pg_backup.run_backup(bk["src_url"], bk["dest"], [bk["recipient"]])
    artifact = os.path.join(bk["dest"], manifest["artifact"])
    data = bytearray(open(artifact, "rb").read())
    data[100] ^= 0xFF  # flip a byte
    open(artifact, "wb").write(bytes(data))
    os.environ["RANGER_BACKUP_AGE_IDENTITY_FILE"] = bk["ident"]
    restore_url = str(bk["base"].set(database="ranger_test_restore_" + bk["src_name"][-8:]))
    with pytest.raises(SystemExit) as ei:
        rv.run(artifact, restore_url, source_url=bk["src_url"])
    assert ei.value.code == 4  # SHA-256 gate


def test_production_like_target_is_refused(bk):
    for bad in ("ranger", "production", "qwalora_ranger", "portal"):
        url = str(bk["base"].set(database=bad))
        with pytest.raises(SystemExit) as ei:
            rv.guard_disposable(url)
        assert ei.value.code == 2


def test_verification_detects_wrong_signing_key(bk):
    """Restore-verify with a DIFFERENT signing key must fail the signature check (exit 4), proving
    the verifier really checks Ed25519 signatures. Run as a subprocess for a clean key environment."""
    manifest = pg_backup.run_backup(bk["src_url"], bk["dest"], [bk["recipient"]])
    artifact = os.path.join(bk["dest"], manifest["artifact"])
    restore_url = str(bk["base"].set(database="ranger_test_restore_" + bk["src_name"][-8:]))
    env = dict(os.environ)
    env["RANGER_SIGNING_KEY"] = base64.b64encode(b"\x99" * 32).decode()  # wrong key
    env["SECRET_KEY"] = "unrelated-secret"
    env["RANGER_PG_BIN"] = _PGBIN
    env["RANGER_BACKUP_AGE_IDENTITY_FILE"] = bk["ident"]
    env["RANGER_RESTORE_TARGET_URL"] = restore_url
    env.pop("RANGER_SIGNING_KEYS", None)
    p = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "pg_restore_verify.py"), artifact],
                       capture_output=True, text=True, env=env)
    assert p.returncode == 4, p.stdout + p.stderr
    assert "restore.signature_integrity" in p.stdout and '"signatures": false' in p.stdout
