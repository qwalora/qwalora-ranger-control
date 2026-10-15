"""Pathway migration — PRODUCTION compatibility validation against REAL PostgreSQL.

SQLite tests do not establish PostgreSQL compatibility, so this module runs the same
migration logic against a real Postgres server. It SKIPS (exit 0) unless DATABASE_URL
points at postgresql, so the ordinary offline suite is unaffected; CI/operators run it
by exporting a Postgres DATABASE_URL (see the bring-up in the F1 report).

Validates on real Postgres: legacy-value detection (read-only), transaction atomicity +
rollback (all-or-none, no partial writes), idempotency, detection-only startup (no
uncontrolled writes), authorized startup migration, and startup-failure handling
(never crash-loops).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


def run():
    url = os.environ.get("DATABASE_URL", "")
    if not url.startswith("postgresql"):
        print("SKIP: DATABASE_URL is not PostgreSQL (%r); offline suite unaffected." % url)
        return True

    os.environ.setdefault("SECRET_KEY", "pg-test-secret")
    os.environ.setdefault("DEFAULT_COHORT", "2026-A")
    # ensure startup is detection-only unless a test opts in
    os.environ.pop("RANGER_PATHWAY_MIGRATE", None)

    import app as appmod
    from models import (db, Cohort, ScenarioCatalogEntry,
                        detect_legacy_pathways, normalize_persisted_pathways,
                        startup_pathway_check)

    application = appmod.create_app()        # create_all + ensure_schema on real Postgres
    ctx = application.app_context(); ctx.push()
    check("Postgres backend confirmed", db.engine.dialect.name == "postgresql")

    # clean slate for our fixture names
    db.session.execute(db.text("DELETE FROM cohorts WHERE name LIKE 'PGMIG-%'")); db.session.commit()

    base_strata = db.session.execute(db.text("SELECT COUNT(*) FROM cohorts WHERE pathway='strata'")).scalar()

    c_ops = Cohort(name="PGMIG-OPS", sequence=81); c_ops.pathway = "strata"
    c_ai = Cohort(name="PGMIG-AI", sequence=82); c_ai.pathway = "strata"
    db.session.add_all([c_ops, c_ai]); db.session.commit()
    db.session.execute(db.text("UPDATE cohorts SET pathway='cyber-ops' WHERE name='PGMIG-OPS'"))
    db.session.execute(db.text("UPDATE cohorts SET pathway='cyber-ai'  WHERE name='PGMIG-AI'"))
    db.session.commit()

    # --- read-only detection on real Postgres ---------------------------------------
    det = detect_legacy_pathways(db)
    check("PG legacy detection counts both interim rows (read-only)", det.get("cohorts", 0) >= 2)

    # --- detection-only startup performs NO writes ----------------------------------
    res = startup_pathway_check(db)
    still_legacy = db.session.execute(
        db.text("SELECT COUNT(*) FROM cohorts WHERE pathway IN ('cyber-ops','cyber-ai')")).scalar()
    check("PG unauthorized startup is detection-only (no writes, rows untouched)",
          res["migrated"] is None and still_legacy >= 2)

    # --- transaction atomicity + rollback: force failure on the 2nd UPDATE ----------
    orig = db.session.execute
    state = {"updates": 0}
    def flaky(statement, *a, **k):
        s = str(statement)
        if s.strip().upper().startswith("UPDATE"):
            state["updates"] += 1
            if state["updates"] == 2:               # fail the 2nd remap in the same txn
                raise RuntimeError("injected failure mid-migration")
        return orig(statement, *a, **k)
    db.session.execute = flaky
    try:
        normalize_persisted_pathways(db)            # should roll back the whole cohorts txn
    finally:
        db.session.execute = orig
    after_fail = db.session.execute(
        db.text("SELECT COUNT(*) FROM cohorts WHERE pathway IN ('cyber-ops','cyber-ai')")).scalar()
    check("PG transaction atomicity: a mid-migration failure rolls back ALL remaps (no partial writes)",
          after_fail >= 2)

    # --- real authorized migration + idempotency ------------------------------------
    first = normalize_persisted_pathways(db)
    second = normalize_persisted_pathways(db)
    now_strata = db.session.execute(db.text("SELECT COUNT(*) FROM cohorts WHERE pathway='strata'")).scalar()
    now_par = db.session.execute(db.text("SELECT COUNT(*) FROM cohorts WHERE pathway='parallax'")).scalar()
    now_legacy = db.session.execute(
        db.text("SELECT COUNT(*) FROM cohorts WHERE pathway IN ('cyber-ops','cyber-ai')")).scalar()
    check("PG migration remaps legacy rows (cohorts>0 on first run)", first.get("cohorts", 0) >= 2)
    check("PG idempotent: second run remaps 0", second.get("cohorts", 0) == 0)
    check("PG post-migration: canonical values only, no interim ids remain",
          now_legacy == 0 and now_strata == base_strata + 1 and now_par >= 1)

    # --- authorized startup path migrates on boot -----------------------------------
    db.session.execute(db.text("UPDATE cohorts SET pathway='cyber-ops' WHERE name='PGMIG-OPS'"))
    db.session.commit()
    os.environ["RANGER_PATHWAY_MIGRATE"] = "1"
    try:
        res2 = startup_pathway_check(db)
    finally:
        os.environ.pop("RANGER_PATHWAY_MIGRATE", None)
    boot_legacy = db.session.execute(
        db.text("SELECT COUNT(*) FROM cohorts WHERE pathway IN ('cyber-ops','cyber-ai')")).scalar()
    check("PG authorized startup migration applies (RANGER_PATHWAY_MIGRATE=1)",
          res2["migrated"] and boot_legacy == 0)

    # --- startup-failure handling: never raises even if a table is missing ----------
    try:
        _ = detect_legacy_pathways(db, existing_tables=set())   # no tables -> empty, no raise
        safe = startup_pathway_check(db, existing_tables=set()) is not None
    except Exception:
        safe = False
    check("PG startup-failure handling: detection/startup never crash-loops", safe)

    # cleanup
    db.session.execute(db.text("DELETE FROM cohorts WHERE name LIKE 'PGMIG-%'")); db.session.commit()
    ctx.pop()
    print(f"\n{P} passed, {F} failed")
    return F == 0


def test_pathway_migration_pg():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
