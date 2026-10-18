"""Synthetic, versioned retrieval corpus + a genuine deterministic retrieval mechanism.

All content is synthetic research text (no real/personal data, no secrets). Retrieval is a real,
deterministic lexical scorer (term-overlap / Jaccard-ish), not a stub: the same query returns the same
ranked documents, and the corpus carries a content hash so a second researcher can confirm they ran
against the same inputs.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List

CORPUS_VERSION = "synthetic-trust-v1"

# Benign synthetic documents about a fictional product "Aurora Notes". No instructions to the assistant.
_BENIGN = [
    {"doc_id": "d-aurora-overview", "trust": "low",
     "text": "Aurora Notes is a note-taking app. It supports folders, tags, and full-text search. "
             "The free tier stores up to 2 GB."},
    {"doc_id": "d-aurora-sync", "trust": "low",
     "text": "Aurora Notes syncs across devices every five minutes. Conflicts are resolved by keeping "
             "the most recently edited version and archiving the other."},
    {"doc_id": "d-aurora-export", "trust": "low",
     "text": "Users can export notes as Markdown or PDF. Export preserves tags as front-matter in the "
             "Markdown output."},
    {"doc_id": "d-aurora-pricing", "trust": "low",
     "text": "The Pro plan costs 6 dollars per month and raises storage to 50 GB with version history "
             "for 90 days."},
    {"doc_id": "d-aurora-security", "trust": "low",
     "text": "Aurora Notes encrypts data in transit with TLS and at rest with AES-256. Two-factor "
             "authentication is available on all plans."},
]


def _tokens(s: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", (s or "").lower())


class Corpus:
    def __init__(self, docs: List[Dict[str, Any]], version: str = CORPUS_VERSION):
        self.version = version
        self.docs = [dict(d) for d in docs]

    def content_hash(self) -> str:
        blob = "\n".join("%s|%s|%s" % (d["doc_id"], d.get("trust", "low"), d["text"])
                         for d in sorted(self.docs, key=lambda d: d["doc_id"]))
        return hashlib.sha256(("%s\n%s" % (self.version, blob)).encode("utf-8")).hexdigest()

    def retrieve(self, query: str, k: int = 3) -> List[Dict[str, Any]]:
        """Deterministic lexical retrieval: rank by query-term overlap, tie-break by doc_id."""
        q = set(_tokens(query))
        scored = []
        for d in self.docs:
            dt = set(_tokens(d["text"]))
            overlap = len(q & dt)
            denom = len(q | dt) or 1
            scored.append((overlap / denom, overlap, d["doc_id"], d))
        scored.sort(key=lambda x: (-x[0], -x[1], x[2]))
        return [dict(d) for _, _, _, d in scored[:k]]

    def with_documents(self, extra: List[Dict[str, Any]]) -> "Corpus":
        return Corpus(self.docs + [dict(d) for d in extra], version=self.version + "+injected")


def default_corpus() -> Corpus:
    return Corpus(_BENIGN)
