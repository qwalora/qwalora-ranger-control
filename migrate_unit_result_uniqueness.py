"""Versioned, explicitly-authorized migration: add UNIQUE(candidate_id, unit_ref, kind, record_hash)
to `unit_results` on a database that predates it (PARALLAX Phase 1C Workstream B).

Run by an operator, never on ordinary startup. Non-destructive: it adds a constraint and never deletes
or merges rows. If conflicting duplicate rows exist it ABORTS with a diagnostic and makes no change -
an operator resolves the duplicates and re-runs. Idempotent (a second run is a no-op) and serialized
by a PostgreSQL advisory lock.

Usage:
    python migrate_unit_result_uniqueness.py            # preflight (dry run): report state, no writes
    python migrate_unit_result_uniqueness.py --apply    # perform the migration (explicit authorization)

NOTE: do NOT run this against Railway production in this phase. Target a disposable/staging database.
"""
import sys

from app import create_app
from models import db
from parallax import evidence_migration as M


def main(argv):
    apply = "--apply" in argv
    app = create_app()
    with app.app_context():
        pre = M.preflight(db)
        print("dialect:            %s" % pre["dialect"])
        print("constraint present: %s" % pre["constraint_present"])
        print("duplicate groups:   %d (rows=%d)" % (len(pre["duplicate_groups"]), pre["duplicate_rows"]))
        print("decision:           %s" % pre["decision"])
        for d in pre["duplicate_groups"]:
            print("  DUP candidate_id=%s unit_ref=%s kind=%s record_hash=%s count=%d"
                  % (d["candidate_id"], d["unit_ref"], d["kind"], d["record_hash"], d["count"]))
        if not apply:
            print("dry run: no writes performed. Re-run with --apply to migrate.")
            return 0
        if pre["decision"] == "blocked":
            print("ABORT: conflicting duplicate rows present; resolve them manually and re-run.",
                  file=sys.stderr)
            return 1
        res = M.apply_migration(db)
        print("result: %s" % res)
        if res["status"] in ("applied", "noop"):
            return 0
        if res["status"] == "unsupported":
            print("NOTE: this engine creates the constraint with the table (create_all); nothing to do.")
            return 0
        print("ERROR: migration did not complete", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
