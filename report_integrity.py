"""Written-channel integrity: near-duplicate detection across candidates' reports.

Per-candidate seeds make the objective channel collusion-proof: two candidates get
different instances, so a shared objective answer is simply wrong. The written report is
the one place collusion can still work, because prose is not seed-bound. This module
fingerprints a report as a set of normalized word-shingles and flags a new submission that
overlaps heavily with another candidate's report for the same board. It never auto-rejects;
it raises a flag for the assessor, who adjudicates. Flagging is advisory and one-directional
(the newer submission is flagged), so an honest candidate is never penalized for a later
copier.
"""
from __future__ import annotations

import hashlib
import json
import re

SHINGLE_K = 5           # words per shingle
FLAG_THRESHOLD = 0.55   # Jaccard over shingle sets above which to flag for review

_WORD = re.compile(r"[a-z0-9]+")
# Evidence tokens (ids, hosts, hashes) legitimately recur across reports of the SAME board
# instance is impossible (seeds differ), but generic security vocabulary recurs everywhere;
# shingles of 5 words make incidental overlap vanishingly unlikely while copied paragraphs
# light up. We do not strip domain terms - a copied *analysis* is exactly what we want to catch.


def _tokens(text):
    return _WORD.findall((text or "").lower())


def shingles(text, k=SHINGLE_K):
    """Set of stable 12-hex hashes of k-word windows. Order-preserving, dedup via the set."""
    toks = _tokens(text)
    if len(toks) < k:
        # short texts: hash the whole thing as one shingle so near-identical short reports match
        return {hashlib.sha1((" ".join(toks)).encode()).hexdigest()[:12]} if toks else set()
    out = set()
    for i in range(len(toks) - k + 1):
        out.add(hashlib.sha1((" ".join(toks[i:i + k])).encode()).hexdigest()[:12])
    return out


def dump_shingles(text):
    """JSON list of a report's shingle hashes, for storage on the Report row."""
    return json.dumps(sorted(shingles(text)))


def load_shingles(blob):
    try:
        return set(json.loads(blob)) if blob else set()
    except (ValueError, TypeError):
        return set()


def jaccard(a, b):
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def check(body, others):
    """Fingerprint `body` and compare to other candidates' reports for the same board.

    `others` is an iterable of (label, shingles_set). Returns
    (flag: bool, note: str|None, shingles_json: str) where note names the closest match and
    its overlap when the flag threshold is crossed.
    """
    mine = shingles(body)
    best_label, best = None, 0.0
    for label, sh in others:
        j = jaccard(mine, sh)
        if j > best:
            best, best_label = j, label
    blob = json.dumps(sorted(mine))
    if best >= FLAG_THRESHOLD and best_label is not None:
        note = "%.0f%% text overlap with %s's report for this board" % (best * 100, best_label)
        return True, note, blob
    return False, None, blob
