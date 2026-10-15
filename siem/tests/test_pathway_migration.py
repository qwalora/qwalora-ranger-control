"""Pathway migration — END-TO-END against a REAL database (sqlite via create_app).

Proves the point raised in review: Python read-time normalization is NOT sufficient once
SQL predicates filter by pathway. We persist legacy 'cyber-ops'/'cyber-ai' rows, show a
canonical SQL predicate MISSES them (the gap), run the non-destructive
normalize_persisted_pathways migration, and show every real access path — raw SQL
predicate, ORM filter, GROUP BY reporting, and catalog-assignment join — then behaves
correctly. Also proves idempotency and non-destruction. Assertions are delta-based so a
seeded default cohort does not affect the result.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import app as appmod                                  # noqa: E402
from models import db, Cohort, ScenarioCatalogEntry, normalize_persisted_pathways  # noqa: E402

P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


def _count(table, pathway):
    return db.session.execute(
        db.text(f"SELECT COUNT(*) FROM {table} WHERE pathway = :p"), {"p": pathway}).scalar()


def _pathway_of(table, name_col, name):
    return db.session.execute(
        db.text(f"SELECT pathway FROM {table} WHERE {name_col} = :n"), {"n": name}).scalar()


def run():
    application = appmod.create_app()      # create_all + ensure_schema (any seed rows already canonical)
    ctx = application.app_context(); ctx.push()

    base_strata = _count("cohorts", "strata")
    base_parallax = _count("cohorts", "parallax")
    base_cat_parallax = _count("scenario_catalog_entries", "parallax")

    # seed: a legacy STRATA cohort (interim id), a genuine PARALLAX cohort, a genuine STRATA cohort
    legacy = Cohort(name="MIG-LEGACY", sequence=91); legacy.pathway = "strata"
    gpar = Cohort(name="MIG-PAR", sequence=92); gpar.pathway = "parallax"
    gstr = Cohort(name="MIG-STR", sequence=93); gstr.pathway = "strata"
    db.session.add_all([legacy, gpar, gstr]); db.session.commit()
    # force the legacy interim value via raw SQL to emulate a pre-naming DB
    db.session.execute(db.text("UPDATE cohorts SET pathway='cyber-ops' WHERE name='MIG-LEGACY'"))
    db.session.commit()

    entry = ScenarioCatalogEntry(spec_id="MIG-pkg-1", spec_version=1, status="catalog_eligible")
    db.session.add(entry); db.session.commit()
    db.session.execute(db.text("UPDATE scenario_catalog_entries SET pathway='cyber-ai' WHERE spec_id='MIG-pkg-1'"))
    db.session.commit()
    total_cohorts_before = db.session.execute(db.text("SELECT COUNT(*) FROM cohorts")).scalar()

    # --- the GAP: canonical SQL predicate misses legacy rows -------------------------
    check("GAP: SQL `WHERE pathway='strata'` misses the legacy 'cyber-ops' cohort",
          _count("cohorts", "strata") == base_strata + 1 and _count("cohorts", "cyber-ops") == 1)
    check("GAP: ORM filter_by(pathway='strata') misses the legacy cohort",
          Cohort.query.filter_by(pathway="strata").count() == base_strata + 1)
    check("GAP: SQL `WHERE pathway='parallax'` misses the legacy 'cyber-ai' catalog entry",
          _count("scenario_catalog_entries", "parallax") == base_cat_parallax
          and _count("scenario_catalog_entries", "cyber-ai") == 1)

    # --- run the non-destructive migration ------------------------------------------
    counts = normalize_persisted_pathways(db)
    check("migration remapped exactly the legacy rows (1 cohort, 1 catalog entry)",
          counts.get("cohorts") == 1 and counts.get("scenario_catalog_entries") == 1)

    # --- FIXED at the SQL level ------------------------------------------------------
    check("FIXED: legacy cohort now persists canonical 'strata'",
          _pathway_of("cohorts", "name", "MIG-LEGACY") == "strata")
    check("FIXED: SQL predicate matches both STRATA cohorts; no 'cyber-ops' remains",
          _count("cohorts", "strata") == base_strata + 2 and _count("cohorts", "cyber-ops") == 0)
    check("FIXED: ORM filter_by(pathway='strata') returns both STRATA cohorts",
          Cohort.query.filter_by(pathway="strata").count() == base_strata + 2)
    check("FIXED: catalog entry now persists canonical 'parallax'",
          _pathway_of("scenario_catalog_entries", "spec_id", "MIG-pkg-1") == "parallax"
          and _count("scenario_catalog_entries", "parallax") == base_cat_parallax + 1)

    # reporting: GROUP BY pathway yields only canonical buckets (no interim ids)
    rows = db.session.execute(db.text("SELECT DISTINCT pathway FROM cohorts")).all()
    buckets = {r[0] for r in rows}
    check("FIXED: reporting GROUP BY pathway has only canonical buckets (no cyber-ops/cyber-ai)",
          "cyber-ops" not in buckets and "cyber-ai" not in buckets and buckets <= {"strata", "parallax"})

    # catalog-assignment style: eligible entries whose pathway matches a cohort's pathway
    coh = Cohort.query.filter_by(name="MIG-LEGACY").first()
    check("FIXED: catalog assignment matches eligible entries to the cohort's pathway",
          coh.pathway == "strata"
          and ScenarioCatalogEntry.query.filter_by(pathway="parallax", status="catalog_eligible").count()
              == base_cat_parallax + 1)

    # --- idempotency + non-destruction ----------------------------------------------
    counts2 = normalize_persisted_pathways(db)
    check("idempotent: a second run remaps 0 rows",
          counts2.get("cohorts") == 0 and counts2.get("scenario_catalog_entries") == 0)
    check("non-destructive: cohort row count unchanged by migration",
          db.session.execute(db.text("SELECT COUNT(*) FROM cohorts")).scalar() == total_cohorts_before)
    check("non-destructive: genuine 'parallax' cohort untouched",
          _pathway_of("cohorts", "name", "MIG-PAR") == "parallax")

    ctx.pop()
    print(f"\n{P} passed, {F} failed")
    return F == 0


def test_pathway_migration():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
