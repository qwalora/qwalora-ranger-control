"""Versioned, explicitly-authorized pathway migration (run by an operator, never on
ordinary startup).

Remaps legacy interim pathway ids ('cyber-ops'->'strata', 'cyber-ai'->'parallax') to the
canonical ids in every table that persists a `pathway` column. Non-destructive (value
remap only), transactional (rollback on error), and idempotent (a second run migrates 0).

Usage:
    python migrate_pathways.py            # detect only (dry run): report legacy counts, no writes
    python migrate_pathways.py --apply    # perform the migration (explicit authorization)

The --apply path is the controlled, reviewable alternative to writing on every boot. It
prints before/after counts for an audit trail and exits non-zero on failure.
"""
import sys

from app import create_app
from models import db, detect_legacy_pathways, normalize_persisted_pathways


def main(argv):
    apply = "--apply" in argv
    app = create_app()
    with app.app_context():
        before = detect_legacy_pathways(db)
        total = sum(before.values())
        print(f"legacy pathway rows detected: {before} (total={total})")
        if not apply:
            print("dry run: no writes performed. Re-run with --apply to migrate.")
            return 0
        if not total:
            print("nothing to migrate.")
            return 0
        migrated = normalize_persisted_pathways(db)
        after = detect_legacy_pathways(db)
        print(f"migrated: {migrated}")
        print(f"legacy pathway rows remaining: {after} (total={sum(after.values())})")
        if sum(after.values()) != 0:
            print("ERROR: legacy rows remain after migration", file=sys.stderr)
            return 1
        print("migration complete; all pathway values canonical.")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
