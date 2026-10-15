"""Normalized event schema (ECS-aligned) and the OpenSearch index mapping.

One normalized shape spans Linux, Windows/identity, and network telemetry so a
single query language works across sources. The schema is deliberately a small,
documented subset of the Elastic Common Schema.

Every event carries provenance: a documented origin, schema version, scenario
association, synthetic flag, and generator version. The answer key is never part
of a normalized event.
"""
from __future__ import annotations

from . import SCHEMA_VERSION, GENERATOR_VERSION

# Event categories this SIEM carries, and the ECS-style category/type they map to.
SOURCES = ("linux-auth", "linux-sudo", "linux-process", "linux-file",
           "windows-auth", "windows-privilege", "windows-group", "windows-process",
           "network-dns", "network-http", "network-firewall", "network-conn")

# The fields a normalized event must carry.
REQUIRED = ("@timestamp", "event.kind", "event.category", "event.action",
            "event.dataset", "host.name", "message",
            "ranger.candidate_id", "ranger.board", "ranger.scenario_seed",
            "ranger.schema_version", "ranger.generator_version", "data.synthetic")


def normalized(candidate_id: str, board: int, seed: str, dataset: str,
               category: str, action: str, host: str, message: str,
               ts: str, extra: dict | None = None, kind: str = "event") -> dict:
    """Build one normalized event. `extra` carries source-specific fields under
    their ECS paths (e.g. {'source.ip': ..., 'user.name': ...})."""
    doc = {
        "@timestamp": ts,
        "event": {"kind": kind, "category": category, "action": action,
                  "dataset": dataset, "module": "ranger"},
        "host": {"name": host},
        "message": message,
        "ranger": {
            # candidate_id is the isolation key: it is both the index owner and the
            # document-level-security filter value.
            "candidate_id": candidate_id,
            "board": board,
            "scenario_seed": seed,
            "schema_version": SCHEMA_VERSION,
            "generator_version": GENERATOR_VERSION,
        },
        # Synthetic is always true and always explicit: these events are generated,
        # never observed on a live production system.
        "data": {"synthetic": True},
    }
    for k, v in (extra or {}).items():
        _set_path(doc, k, v)
    return doc


def _set_path(doc: dict, dotted: str, value):
    cur = doc
    parts = dotted.split(".")
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def _get_path(doc: dict, dotted: str):
    cur = doc
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def validate(doc: dict) -> list[str]:
    """Return a list of problems with a normalized event (empty if valid)."""
    problems = []
    for field in REQUIRED:
        if _get_path(doc, field) is None:
            problems.append(f"missing:{field}")
    if _get_path(doc, "data.synthetic") is not True:
        problems.append("synthetic-flag-must-be-true")
    if _get_path(doc, "ranger.schema_version") != SCHEMA_VERSION:
        problems.append("schema-version-mismatch")
    return problems


# OpenSearch index mapping for a candidate index. Keyword for exact-match fields,
# date for the timestamp, text for the free-text message.
INDEX_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "message": {"type": "text"},
            "event": {"properties": {
                "kind": {"type": "keyword"}, "category": {"type": "keyword"},
                "action": {"type": "keyword"}, "dataset": {"type": "keyword"},
                "module": {"type": "keyword"}}},
            "host": {"properties": {"name": {"type": "keyword"}}},
            "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
            "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
            "user": {"properties": {"name": {"type": "keyword"}, "target": {"type": "keyword"}}},
            "process": {"properties": {"name": {"type": "keyword"},
                                       "command_line": {"type": "text"},
                                       "pid": {"type": "long"}}},
            "dns": {"properties": {"question": {"properties": {"name": {"type": "keyword"}}}}},
            "url": {"properties": {"original": {"type": "keyword"}}},
            "http": {"properties": {"request": {"properties": {"method": {"type": "keyword"}}},
                                    "response": {"properties": {"status_code": {"type": "integer"}}}}},
            "network": {"properties": {"transport": {"type": "keyword"},
                                       "action": {"type": "keyword"}}},
            "winlog": {"properties": {"event_id": {"type": "long"},
                                      "logon_type": {"type": "integer"}}},
            "ranger": {"properties": {
                "candidate_id": {"type": "keyword"}, "board": {"type": "integer"},
                "scenario_seed": {"type": "keyword"}, "schema_version": {"type": "keyword"},
                "generator_version": {"type": "keyword"},
                "scenario": {"type": "keyword"}, "event_uid": {"type": "keyword"}}},
            "data": {"properties": {"synthetic": {"type": "boolean"}}},
        }
    },
}
