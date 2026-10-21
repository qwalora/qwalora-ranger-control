"""Resumable research campaigns with durable checkpoints and failure accounting.

A campaign is a deterministic, ordered plan of trial units; this module runs it so it can be stopped
and resumed without losing, duplicating, or silently skipping work, and without ever marking a partial
campaign complete.

Durability and safety:
- Each completed trial is appended to a JSON-lines file (records.jsonl) and fsync'd; a crash mid-append
  can only leave a truncated LAST line, which load() detects (JSON parse failure or a failed evidence
  hash) and discards, re-running that unit.
- state.json is written atomically (temp file + os.replace) so the state/progress/chain head is never
  half-written.
- Resume is idempotent: completed units are keyed by (repetition, condition, task, variant) and never
  re-run, so a duplicate submission is a no-op.
- Resume validates the current campaign spec fingerprint against the one stored at creation; a changed
  material configuration refuses to resume (no silent cross-config mixing).
- Each persisted record's evidence hash is re-verified on load, and an evidence CHAIN head links the
  records in order so reordering or tampering is detectable.

Failure accounting: every attempt that does not complete is written to a structured ledger. Excluded
(infra/eval failure) trials are RECORDED, never dropped, so an exclusion can never silently raise the
reported attack-success or task-completion rate.

Pure Python, file-based; no database, no network, no new infrastructure. It drives harness.run_trial.
"""
from __future__ import annotations

import json
import os
import time
import hashlib
from typing import Any, Dict, List, Optional, Tuple

import signing
from . import protocol as P
from . import harness, commitments, provenance

# explicit campaign states
PENDING = "pending"
RUNNING = "running"
INTERRUPTED = "interrupted"     # stopped by deadline/signal with work remaining
INCOMPLETE = "incomplete"       # finished scheduling but some units could not complete
COMPLETED = "completed"         # every planned unit has a verified record
FAILED = "failed"               # campaign-level failure (e.g. spec mismatch, unusable checkpoint)

# failure categories
CAT_INFRA = "infrastructure_failure"
CAT_MODEL = "model_backend_error"
CAT_EVAL = "evaluator_failure"
CAT_TIMEOUT = "timeout"
CAT_CORRUPT = "corrupted_evidence"
CAT_AUTH = "authorization_failure"
CAT_HARNESS = "harness_error"


def _hash_record(record: Dict[str, Any]) -> str:
    return hashlib.sha256(signing.canonical(
        {k: v for k, v in record.items() if k != "evidence_hash"})).hexdigest()


def _atomic_write(path: str, data: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)   # atomic on POSIX


def _append_line(path: str, obj: Any) -> None:
    line = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _unit_key(u: Dict[str, Any]) -> Tuple:
    return (u["repetition"], u["condition"], u["task_id"], u["variant_id"])


def _classify(outcome: Optional[str], infra_error: Optional[str]) -> str:
    if infra_error and "model_backend_error" in infra_error:
        return CAT_MODEL
    if infra_error and ("timed out" in infra_error.lower() or "timeout" in infra_error.lower()):
        return CAT_TIMEOUT
    if outcome == "evaluation_error":
        return CAT_EVAL
    if outcome == "infrastructure_failure":
        return CAT_INFRA
    if infra_error:
        return CAT_HARNESS
    return CAT_HARNESS


def _sanitize_error(msg: Optional[str]) -> Optional[str]:
    if not msg:
        return None
    return provenance.redact(str(msg))[:300]


class StoppedForDeadline(Exception):
    pass


class ResumeSpecMismatch(Exception):
    pass


class CampaignRunner:
    def __init__(self, checkpoint_dir: str, *, backend, corpus, repetitions: int = 1,
                 tasks: Optional[List[Dict[str, Any]]] = None,
                 variants: Optional[List[Dict[str, Any]]] = None,
                 protocol_version: str = P.PROTOCOL_VERSION,
                 deadline_s: Optional[float] = None, max_retries: int = 2,
                 max_trials: int = harness.MAX_TRIALS_PER_CAMPAIGN):
        self.dir = checkpoint_dir
        self.backend = backend
        self.corpus = corpus
        self.repetitions = repetitions
        self.tasks = tasks if tasks is not None else P.LEGIT_TASKS
        self.variants = variants if variants is not None else P.ATTACK_VARIANTS
        self.protocol_version = protocol_version
        self.deadline_s = deadline_s
        self.max_retries = max_retries
        self.max_trials = max_trials
        os.makedirs(self.dir, exist_ok=True)
        self.records_path = os.path.join(self.dir, "records.jsonl")
        self.ledger_path = os.path.join(self.dir, "ledger.jsonl")
        self.manifest_path = os.path.join(self.dir, "manifest.json")
        self.state_path = os.path.join(self.dir, "state.json")

    # ---- planning / spec ----
    def plan(self) -> List[Dict[str, Any]]:
        units: List[Dict[str, Any]] = []
        for rep in range(1, self.repetitions + 1):
            for task in self.tasks:
                units.append({"repetition": rep, "condition": P.CONDITION_BASELINE,
                              "task_id": task["task_id"], "variant_id": "none"})
            for task in self.tasks:
                for v in self.variants:
                    units.append({"repetition": rep, "condition": P.CONDITION_EXPERIMENTAL,
                                  "task_id": task["task_id"], "variant_id": v["attack_id"]})
        if len(units) > self.max_trials:
            raise RuntimeError("campaign plan exceeds trial cap (%d > %d)" % (len(units), self.max_trials))
        return units

    def spec_fingerprint(self) -> str:
        spec = {
            "protocol_version": self.protocol_version,
            "repetitions": self.repetitions,
            "corpus_version": self.corpus.version, "corpus_hash": self.corpus.content_hash(),
            "backend": self.backend.identity(),
            "tasks": [t["task_id"] for t in self.tasks],
            "variants": [v["attack_id"] for v in self.variants],
            "prompt_template_version": harness.PROMPT_TEMPLATE_VERSION,
            "harness_version": harness.HARNESS_VERSION,
        }
        return hashlib.sha256(signing.canonical(spec)).hexdigest()

    # ---- load / recovery ----
    def load_records(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Return (verified_records, problems). Skips a truncated/corrupt trailing line and any record
        whose evidence hash does not verify; such lines are reported as problems, never counted done."""
        records: List[Dict[str, Any]] = []
        problems: List[str] = []
        if not os.path.exists(self.records_path):
            return records, problems
        with open(self.records_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        for i, raw in enumerate(lines):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except Exception:
                problems.append("line %d: unparseable (truncated/corrupt), discarded" % (i + 1))
                continue
            if _hash_record(rec) != rec.get("evidence_hash"):
                problems.append("line %d: evidence_hash mismatch, discarded" % (i + 1))
                continue
            records.append(rec)
        return records, problems

    def _chain_head(self, records: List[Dict[str, Any]]) -> str:
        head = ""
        for r in records:
            head = hashlib.sha256((head + r.get("evidence_hash", "")).encode("utf-8")).hexdigest()
        return head

    def _write_state(self, state: str, done: int, total: int, chain_head: str,
                     extra: Optional[Dict[str, Any]] = None) -> None:
        obj = {"campaign_state": state, "progress": {"completed": done, "total": total,
               "remaining": total - done, "fraction": (done / total if total else 1.0)},
               "chain_head": chain_head, "spec_fingerprint": self.spec_fingerprint(),
               "updated_at": time.time()}
        if extra:
            obj.update(extra)
        _atomic_write(self.state_path, json.dumps(obj, sort_keys=True, indent=2))

    def _ledger(self, unit: Dict[str, Any], category: str, retry_count: int, recoverable: bool,
                status: str, error: Optional[str], started: float) -> None:
        _append_line(self.ledger_path, {
            "campaign_id": os.path.basename(self.dir.rstrip("/")),
            "trial_key": "|".join(str(x) for x in _unit_key(unit)),
            "repetition": unit["repetition"], "condition": unit["condition"],
            "task_id": unit["task_id"], "variant_id": unit["variant_id"],
            "failure_category": category, "retry_count": retry_count, "recoverable": recoverable,
            "status": status, "attempted_at": started, "resolved_at": time.time(),
            "error": _sanitize_error(error)})

    def read_ledger(self) -> List[Dict[str, Any]]:
        out = []
        if os.path.exists(self.ledger_path):
            for raw in open(self.ledger_path, encoding="utf-8"):
                raw = raw.strip()
                if raw:
                    try:
                        out.append(json.loads(raw))
                    except Exception:
                        pass
        return out

    # ---- run / resume ----
    def run(self) -> Dict[str, Any]:
        units = self.plan()
        total = len(units)
        # create or validate the manifest
        if os.path.exists(self.manifest_path):
            man = json.load(open(self.manifest_path, encoding="utf-8"))
            if man.get("spec_fingerprint") != self.spec_fingerprint():
                self._write_state(FAILED, 0, total, "", {"reason": "spec_fingerprint_mismatch"})
                raise ResumeSpecMismatch("resume refused: campaign spec changed since creation")
        else:
            man = {"campaign_id": os.path.basename(self.dir.rstrip("/")),
                   "spec_fingerprint": self.spec_fingerprint(), "created_at": time.time(),
                   "total_units": total}
            _atomic_write(self.manifest_path, json.dumps(man, sort_keys=True, indent=2))

        records, problems = self.load_records()
        for p in problems:
            # a corrupt/truncated persisted record is a corrupted-evidence event, not a completed unit
            _append_line(self.ledger_path, {"campaign_id": man["campaign_id"], "failure_category": CAT_CORRUPT,
                                            "recoverable": True, "status": "attempted", "detail": p,
                                            "resolved_at": time.time()})
        done_keys = {_unit_key({"repetition": r["repetition"], "condition": r["condition"],
                                "task_id": r.get("legitimate_task_id"),
                                "variant_id": r.get("adversarial_input_id") or "none"}) for r in records}
        chain_head = self._chain_head(records)
        done = len(records)
        self._write_state(RUNNING, done, total, chain_head)

        variants_by_id = {v["attack_id"]: v for v in self.variants}
        tasks_by_id = {t["task_id"]: t for t in self.tasks}
        start_wall = time.time()
        stopped = False

        for unit in units:
            if _unit_key(unit) in done_keys:
                continue    # idempotent: already completed, never re-run or duplicate
            if self.deadline_s is not None and (time.time() - start_wall) >= self.deadline_s:
                stopped = True
                break
            task = tasks_by_id[unit["task_id"]]
            variant = None if unit["condition"] == P.CONDITION_BASELINE else variants_by_id[unit["variant_id"]]
            attempt = 0
            persisted = False
            while attempt <= self.max_retries:
                started = time.time()
                try:
                    rec = harness.run_trial(self.backend, self.corpus, task=task, variant=variant,
                                            condition=unit["condition"], repetition=unit["repetition"],
                                            protocol_version=self.protocol_version)
                except Exception as e:   # noqa: BLE001 - a harness bug is accounted, never silently dropped
                    attempt += 1
                    self._ledger(unit, CAT_HARNESS, attempt, True, "attempted",
                                 "%s: %s" % (type(e).__name__, e), started)
                    continue
                outcome = rec.get("outcome")
                infra_error = rec.get("infra_error")
                if outcome in ("infrastructure_failure", "evaluation_error"):
                    # a recoverable failure OUTCOME: retry; if retries exhausted, PERSIST the failure
                    # record (so it is accounted and excluded by metrics, never silently skipped).
                    attempt += 1
                    cat = _classify(outcome, infra_error)
                    if attempt > self.max_retries:
                        _append_line(self.records_path, rec)
                        records.append(rec)
                        done_keys.add(_unit_key(unit))
                        done += 1
                        chain_head = hashlib.sha256((chain_head + rec["evidence_hash"]).encode()).hexdigest()
                        self._ledger(unit, cat, attempt, True, "excluded", infra_error, started)
                        self._write_state(RUNNING, done, total, chain_head)
                        persisted = True
                        break
                    self._ledger(unit, cat, attempt, True, "attempted", infra_error, started)
                    continue
                # success-class outcome (success/boundary/inconclusive): persist durably
                _append_line(self.records_path, rec)
                records.append(rec)
                done_keys.add(_unit_key(unit))
                done += 1
                chain_head = hashlib.sha256((chain_head + rec["evidence_hash"]).encode()).hexdigest()
                self._write_state(RUNNING, done, total, chain_head)
                persisted = True
                break
            if not persisted:
                # exhausted retries on a harness exception: a non-recoverable unit; do NOT fabricate a result
                self._ledger(unit, CAT_HARNESS, attempt, False, "excluded", "retries exhausted", start_wall)

        # final state: never 'completed' unless every planned unit has a verified persisted record
        persisted_keys = {_unit_key({"repetition": r["repetition"], "condition": r["condition"],
                                     "task_id": r.get("legitimate_task_id"),
                                     "variant_id": r.get("adversarial_input_id") or "none"}) for r in records}
        all_done = all(_unit_key(u) in persisted_keys for u in units)
        if stopped:
            state = INTERRUPTED
        elif all_done:
            state = COMPLETED
        else:
            state = INCOMPLETE
        self._write_state(state, len(records), total, chain_head,
                          {"ledger_entries": len(self.read_ledger())})
        return {"state": state, "completed": len(records), "total": total,
                "remaining": total - len(records), "chain_head": chain_head,
                "spec_fingerprint": self.spec_fingerprint(),
                "problems_recovered": len(problems), "ledger_entries": len(self.read_ledger())}

    def status(self) -> Dict[str, Any]:
        if os.path.exists(self.state_path):
            return json.load(open(self.state_path, encoding="utf-8"))
        return {"campaign_state": PENDING}

    def verify_chain(self) -> bool:
        """Recompute the evidence chain over persisted records and compare to the stored head."""
        records, problems = self.load_records()
        if problems:
            return False
        return self._chain_head(records) == self.status().get("chain_head")
