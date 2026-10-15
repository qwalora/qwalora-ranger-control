"""Idempotent telemetry ingestion pipeline.

Implements the required steps: identify the authorized candidate and board; select
the approved scenario; load the telemetry; normalize; bind to the candidate's
permitted index; record status; validate counts and mappings; prevent cross-candidate
ingestion; record provenance and version; and support controlled reset and reseed.

The broker admin identity is the only writer. A dry-run mode validates and reports
without writing, so the pipeline can be exercised with no cluster.
"""
from __future__ import annotations

import datetime as _dt

from . import schema, telemetry
from .authz import CredentialBroker, decide_access, index_name
from .client import AuthorizationError


class IngestionError(Exception):
    pass


class Seeder:
    def __init__(self, client, admin_user=None):
        self.client = client
        self.admin = admin_user or getattr(client, "ADMIN", "_broker_admin")
        self.broker = CredentialBroker(client, self.admin)

    def seed(self, cohort: str, candidate_id: str, status: str, current_board: int,
             seed: str, dry_run: bool = False, reset: bool = False) -> dict:
        """Seed one candidate-board. Returns an ingestion record (provenance +
        status). Idempotent: re-seeding the same seed upserts by event_uid, so
        counts do not inflate. `reset=True` drops and recreates the index first."""
        # 1. identify + authorize candidate/board (server-side gate)
        decision = decide_access(status, current_board)
        if not decision.allowed:
            return {"status": "denied", "reason": decision.reason,
                    "candidate_id": candidate_id, "board": current_board}

        idx = index_name(cohort, candidate_id, current_board)

        # 2 + 3 + 4. select scenario, load dataset, normalize (telemetry does 3+4)
        events = telemetry.generate(candidate_id, current_board, seed)

        # 7a. validate schema + 8. prevent cross-candidate ingestion
        problems = []
        for e in events:
            src = e["_source"]
            v = schema.validate(src)
            if v:
                problems.append({"_id": e["_id"], "problems": v})
            if src["ranger"]["candidate_id"] != candidate_id:
                # Hard stop: an event not owned by this candidate must never enter
                # this candidate's index.
                raise IngestionError(
                    f"cross-candidate event {e['_id']}: "
                    f"{src['ranger']['candidate_id']} != {candidate_id}")
        if problems:
            raise IngestionError(f"{len(problems)} invalid events: {problems[:3]}")

        prov = telemetry.summary(events)
        record = {
            "status": "dry-run" if dry_run else "pending",
            "candidate_id": candidate_id, "board": current_board, "cohort": cohort,
            "index": idx, "seed": seed, "provenance": prov,
            "expected_count": len(events),
            "started_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        }
        if dry_run:
            record["validated"] = True
            return record

        # 10. controlled reset
        if reset and self.client.index_exists(idx):
            self.client.delete_index(self.admin, idx)

        # 5. bind to the candidate's permitted index (create if missing, with mapping)
        if not self.client.index_exists(idx):
            self.client.create_index(self.admin, idx, schema.INDEX_MAPPING)

        # write (idempotent upsert by _id)
        try:
            added = self.client.bulk_index(self.admin, idx, events)
        except AuthorizationError as e:
            raise IngestionError(f"ingest not authorized: {e}")

        # 6 + 7b. record status + validate indexed count matches expected
        indexed = self.client.count(self.admin, idx)
        record.update({
            "status": "ok" if indexed == len(events) else "count-mismatch",
            "newly_added": added,
            "indexed_count": indexed,
            "idempotent_ok": indexed == len(events),  # re-seed does not inflate
            "completed_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        })
        if indexed != len(events):
            raise IngestionError(
                f"count mismatch for {idx}: indexed {indexed} != expected {len(events)}")
        return record

    def reset(self, cohort: str, candidate_id: str, board: int) -> dict:
        """Drop a candidate-board index."""
        idx = index_name(cohort, candidate_id, board)
        existed = self.client.index_exists(idx)
        if existed:
            self.client.delete_index(self.admin, idx)
        return {"status": "reset", "index": idx, "existed": existed}

    def reseed(self, cohort, candidate_id, status, current_board, seed) -> dict:
        """Reset then seed fresh."""
        return self.seed(cohort, candidate_id, status, current_board, seed, reset=True)
