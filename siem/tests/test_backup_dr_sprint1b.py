"""Sprint 1B backup & disaster-recovery gap scenarios on GENUINE PostgreSQL (scripts/pg_backup.py,
scripts/pg_restore_verify.py). Gated by _pgtest (skips fail-closed without an authorized disposable
PG). Synthetic data only; never touches a live database.

Covers the scenarios not already exercised by test_backup_restore.py:
- truncated/incomplete ciphertext (age AEAD auth failure after the SHA gate is satisfied),
- invalid backup manifest (healthcheck fails closed),
- encryption/authentication failure (wrong age identity on restore),
- schema incompatibility (restored schema diverges from the manifest's recorded schema),
- missing signing-key dependency (restore-verify refuses to verify under a derived key),
- research-evidence and reviewer-adjudication signature re-verification after restore,
- qualification isolation after restore (PARALLAX research introduces no qualification artifacts),
- restore idempotency (re-running the verify is safe and deterministic).
"""
import base64
import importlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

os.environ.setdefault("SECRET_KEY", "backup-dr-sprint1b-test")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402

import _pgtest  # noqa: E402
import pg_backup  # noqa: E402
import pg_restore_verify as rv  # noqa: E402

_OK, _REASON = _pgtest.authorization_status()
pytestmark = pytest.mark.skipif(not _OK, reason="disposable PostgreSQL not authorized: %s" % _REASON)
_PGBIN = "/usr/lib/postgresql/16/bin"
_SIGNKEY = base64.b64encode(b"\x22" * 32).decode()  # fixed test signing seed
_ENV_KEYS = ("DATABASE_URL", "RANGER_SIGNING_KEY", "RANGER_SIGNING_KEYS", "RANGER_PG_BIN",
             "RANGER_BACKUP_AGE_RECIPIENT", "RANGER_BACKUP_AGE_IDENTITY_FILE", "RANGER_VERIFY_SOURCE_URL")


def _seed(source_url):
    os.environ["DATABASE_URL"] = source_url
    os.environ["RANGER_SIGNING_KEY"] = _SIGNKEY
    import signing
    signing._reset_registry()
    import app as appmod
    importlib.reload(appmod)
    from models import db, Candidate, Cohort, ProgramMembership
    from parallax import auditlog
    from parallax.research import store as rstore
    application = appmod.create_app()
    with application.app_context():
        db.drop_all(); db.create_all()
        db.session.add(Cohort(name="2026-A", sequence=1, status="active", pathway="parallax"))
        db.session.commit()
        researcher = "gh-researcher-1"
        c = Candidate(handle="px_res", name="PX", email="px@e", cohort="2026-A",
                      github_id=researcher, status="active", current_board=1, token="tok-px")
        db.session.add(c); db.session.commit()
        db.session.add(ProgramMembership(candidate_id=c.id, program="parallax", status="active",
                                         cohort="2026-A"))
        db.session.commit()
        # a signed PARALLAX trial (evidence), investigation, and reviewer adjudication
        ev = rstore.persist_run(db, researcher_id=researcher, campaign={
            "manifest": {"kind": "trial", "backend": {"is_real": False, "model_id": "stub"},
                         "n_records": 1},
            "metrics": {"kind": "trial", "record": {"condition": "experimental_attack",
                        "observed_behavior": "INJECTION-OK",
                        "evaluation": {"canary": True, "task_ok": False},
                        "outcome": "successful_unauthorized_behavior"}, "findings_available": False}})
        db.session.commit()
        inv = rstore.persist_run(db, researcher_id=researcher, campaign={
            "manifest": {"kind": "investigation", "backend": {"is_real": False, "model_id": "n/a"},
                         "n_records": 0, "parent_run": ev.run_id},
            "metrics": {"kind": "investigation", "parent_run": ev.run_id,
                        "analysis": "SIMULATED self-test analysis for DR."}})
        db.session.commit()
        rstore.adjudicate_investigation(db, investigation_id=inv.run_id, reviewer_id="gh-reviewer-9",
                                        decision="inconclusive", comment="DR test adjudication")
        db.session.commit()
        auditlog.append(db, action="candidate.enrolled", actor_id="admin", subject_kind="candidate",
                        subject_ref=str(c.id), detail={"cohort": "2026-A"})
        db.session.commit()
        assert auditlog.verify_chain(db) is True
        from models import ParallaxResearchRun
        return {"evidence_id": ev.run_id, "investigation_id": inv.run_id,
                "research_runs": ParallaxResearchRun.query.count()}


@pytest.fixture()
def bk(tmp_path):
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    os.environ["RANGER_PG_BIN"] = _PGBIN
    base = make_url(_pgtest.resolve_test_url())
    src_name = _pgtest._create_disposable(base)
    src_url = str(base.set(database=src_name))
    ident = os.path.join(str(tmp_path), "id.txt")
    kg = subprocess.run(["age-keygen", "-o", ident], capture_output=True, text=True)
    os.chmod(ident, 0o600)
    import re as _re
    recipient = _re.search(r"age1[0-9a-z]+", kg.stderr + "\n" + kg.stdout).group(0)
    info = _seed(src_url)
    restore_url = str(base.set(database="ranger_test_restore_" + src_name[-8:]))
    ctx = dict(base=base, src_url=src_url, src_name=src_name, ident=ident, recipient=recipient,
               dest=str(tmp_path / "out"), restore_url=restore_url, info=info, tmp=str(tmp_path))
    try:
        yield ctx
    finally:
        _pgtest._drop_disposable(base, src_name)
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        try:
            import signing
            signing._reset_registry()
        except Exception:  # noqa: BLE001
            pass


def _backup(bk):
    m = pg_backup.run_backup(bk["src_url"], bk["dest"], [bk["recipient"]])
    return os.path.join(bk["dest"], m["artifact"]), m


# (a) positive round trip also re-verifies research + adjudication signatures now
def test_roundtrip_reverifies_research_and_adjudication_signatures(bk):
    artifact, m = _backup(bk)
    assert m["schema_tables"] and "parallax_research_runs" in m["schema_tables"]
    os.environ["RANGER_BACKUP_AGE_IDENTITY_FILE"] = bk["ident"]
    res = rv.run(artifact, bk["restore_url"], source_url=bk["src_url"], drop_after=True)
    assert res["ok"] is True
    assert res["restored_counts"]["parallax_research_runs"] == bk["info"]["research_runs"]


# (c)+(e) truncated ciphertext with a recomputed SHA passes the hash gate but fails age AEAD auth
def test_truncated_ciphertext_fails_closed_on_decrypt(bk):
    artifact, _ = _backup(bk)
    raw = bytearray(open(artifact, "rb").read())
    del raw[len(raw) // 2:]              # truncate the second half
    open(artifact, "wb").write(bytes(raw))
    import hashlib
    newsha = hashlib.sha256(bytes(raw)).hexdigest()
    with open(artifact + ".sha256", "w") as fh:  # recompute so the SHA gate is satisfied
        fh.write("%s  %s\n" % (newsha, os.path.basename(artifact)))
    os.environ["RANGER_BACKUP_AGE_IDENTITY_FILE"] = bk["ident"]
    with pytest.raises(SystemExit) as ei:
        rv.run(artifact, bk["restore_url"], source_url=bk["src_url"])
    assert ei.value.code == 3  # age decrypt/auth failure, not a silent pass


# (e) wrong age identity cannot decrypt
def test_wrong_age_identity_fails_closed(bk):
    artifact, _ = _backup(bk)
    other = os.path.join(bk["tmp"], "other_id.txt")
    subprocess.run(["age-keygen", "-o", other], capture_output=True, text=True)
    os.chmod(other, 0o600)
    os.environ["RANGER_BACKUP_AGE_IDENTITY_FILE"] = other  # not the recipient's key
    with pytest.raises(SystemExit) as ei:
        rv.run(artifact, bk["restore_url"], source_url=bk["src_url"])
    assert ei.value.code == 3


# (d) invalid manifest is detected by the healthcheck (fails closed)
def test_invalid_manifest_detected_by_healthcheck(bk):
    import backup_healthcheck as hc
    artifact, _ = _backup(bk)
    with open(artifact + ".manifest.json", "w") as fh:
        fh.write("{ this is not valid json ")
    code, summary = hc.check(bk["dest"], max_age_hours=99999, min_bytes=0)
    assert code == 2 and summary["status"] == "missing"  # unreadable manifest -> fails closed


# (f) schema incompatibility: manifest records a table that is absent after restore
def test_schema_incompatibility_fails_closed(bk):
    artifact, _ = _backup(bk)
    mpath = artifact + ".manifest.json"
    man = json.load(open(mpath))
    man["schema_tables"] = sorted(man["schema_tables"] + ["a_table_not_in_the_dump"])
    json.dump(man, open(mpath, "w"))
    os.environ["RANGER_BACKUP_AGE_IDENTITY_FILE"] = bk["ident"]
    with pytest.raises(SystemExit) as ei:
        rv.run(artifact, bk["restore_url"], source_url=bk["src_url"])
    assert ei.value.code == 4  # schema drift


# (g) missing signing-key dependency: refuse to verify under a derived key
def test_missing_signing_key_fails_closed(bk):
    artifact, _ = _backup(bk)
    env = dict(os.environ)
    env.pop("RANGER_SIGNING_KEY", None)
    env.pop("RANGER_SIGNING_KEYS", None)
    env["SECRET_KEY"] = "some-unrelated-secret"
    env["RANGER_PG_BIN"] = _PGBIN
    env["RANGER_BACKUP_AGE_IDENTITY_FILE"] = bk["ident"]
    env["RANGER_RESTORE_TARGET_URL"] = bk["restore_url"]
    p = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "pg_restore_verify.py"), artifact],
                       capture_output=True, text=True, env=env)
    assert p.returncode == 2, p.stdout + p.stderr
    assert "no signing key configured" in p.stdout


# research-signature gate detects a tampered research record (tampered in the source before backup)
def test_tampered_research_record_fails_verification(bk):
    eng = create_engine(bk["src_url"], future=True)
    with eng.begin() as c:
        row = c.execute(text("SELECT run_id, run_record FROM parallax_research_runs "
                             "WHERE run_record LIKE '%\"kind\":\"investigation\"%' LIMIT 1")).fetchone()
        rec = json.loads(row[1])
        rec["metrics"]["analysis"] = rec["metrics"]["analysis"] + " [TAMPERED]"
        c.execute(text("UPDATE parallax_research_runs SET run_record=:r WHERE run_id=:i"),
                  {"r": json.dumps(rec, separators=(",", ":")), "i": row[0]})
    eng.dispose()
    artifact, _ = _backup(bk)
    os.environ["RANGER_BACKUP_AGE_IDENTITY_FILE"] = bk["ident"]
    with pytest.raises(SystemExit) as ei:
        rv.run(artifact, bk["restore_url"], source_url=bk["src_url"])
    assert ei.value.code == 4  # research signature/hash mismatch


# (i) qualification isolation after restore: PARALLAX research introduces no qualification artifacts
def test_qualification_isolation_after_restore(bk):
    artifact, _ = _backup(bk)
    os.environ["RANGER_BACKUP_AGE_IDENTITY_FILE"] = bk["ident"]
    rv.run(artifact, bk["restore_url"], source_url=bk["src_url"], drop_after=False)
    try:
        eng = create_engine(bk["restore_url"], future=True)
        with eng.connect() as c:
            qual = c.execute(text("SELECT count(*) FROM qualification_decisions")).scalar()
            units = c.execute(text("SELECT count(*) FROM unit_results "
                                   "WHERE kind='qualification_decision'")).scalar()
            badges = c.execute(text("SELECT count(*) FROM badges")).scalar()
            boards = c.execute(text("SELECT count(*) FROM board_results")).scalar()
            runs = c.execute(text("SELECT count(*) FROM parallax_research_runs")).scalar()
        eng.dispose()
        assert qual == 0 and units == 0 and badges == 0 and boards == 0  # no qualification issued
        assert runs == bk["info"]["research_runs"]                        # research evidence intact
    finally:
        eng2 = rv._admin_engine(make_url(bk["restore_url"]))
        with eng2.connect() as c:
            c.execute(text("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                           "WHERE datname=:n AND pid<>pg_backend_pid()"),
                      {"n": make_url(bk["restore_url"]).database})
            c.execute(text('DROP DATABASE IF EXISTS "%s"' % make_url(bk["restore_url"]).database))
        eng2.dispose()


# (j) restore idempotency: re-running the verify on the same artifact is safe and deterministic
def test_restore_verify_is_idempotent(bk):
    artifact, _ = _backup(bk)
    os.environ["RANGER_BACKUP_AGE_IDENTITY_FILE"] = bk["ident"]
    r1 = rv.run(artifact, bk["restore_url"], source_url=bk["src_url"], drop_after=True)
    r2 = rv.run(artifact, bk["restore_url"], source_url=bk["src_url"], drop_after=True)
    assert r1["ok"] is True and r2["ok"] is True
    assert r1["restored_counts"] == r2["restored_counts"]
