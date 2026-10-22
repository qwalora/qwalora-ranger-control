"""Versioned agent-trace representation and ingestion for AI-agent security investigations (px-trace-v1).

An investigation needs a single, normalized view of what an AI agent actually did: the authorized
request, the (trusted) system/developer instructions, the untrusted material it encountered, the tool
calls it REQUESTED, the tool results it actually OBSERVED, and the outputs it produced, each tagged with
an explicit TRUST ZONE and with EVENT time separated from INGESTION time. This module defines that
schema and two ingestion adapters (existing PARALLAX run records, and a documented external
agent-trace format), with bounded parsing, validation, malformed-input handling, safe normalization,
and secret scrubbing for fixtures.

Honesty invariants (enforced, not aspirational):
- Every event carries ``observed: true|false``. An importer sets ``observed=false`` for anything it had
  to infer or reconstruct, and NEVER fabricates a tool execution, model decision, timestamp, or
  authorization result. Absent information becomes a ``gaps`` entry, never a made-up value.
- Trust zones are assigned from the record's structure, never guessed from content.
- Content is bounded and null-stripped; oversized content is truncated with an explicit marker and a
  recorded original length, so nothing silently disappears.
- Public/synthetic fixtures are scrubbed of credential-shaped material by ``scrub_for_fixture``.

This module performs NO model calls, NO network, and NO writes; it is a pure transform over data in
hand. It does not read, modify, or depend on the frozen evaluator's lexical heuristics.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "px-trace-v1"
IMPORTER_VERSION = "px-trace-importer/1.0"

# ------------------------------------------------------------------ trust zones + event types

# A trust zone says how far an instruction or datum may be trusted. The whole point of the analysis
# layer is that instructions arriving in an UNTRUSTED or TOOL_OUTPUT zone must never be obeyed as if
# they came from the TRUSTED zone.
ZONE_TRUSTED = "trusted"                 # system/developer instructions set by the operator
ZONE_USER_AUTHORIZED = "user_authorized" # the authenticated user's own request
ZONE_UNTRUSTED_RETRIEVED = "untrusted_retrieved"  # documents/content pulled into context
ZONE_TOOL_OUTPUT = "tool_output"         # results returned by a tool
ZONE_MODEL_GENERATED = "model_generated" # the model's own output
ZONE_EXTERNAL = "external"               # external resources/destinations
ZONES = (ZONE_TRUSTED, ZONE_USER_AUTHORIZED, ZONE_UNTRUSTED_RETRIEVED, ZONE_TOOL_OUTPUT,
         ZONE_MODEL_GENERATED, ZONE_EXTERNAL)

EV_USER_REQUEST = "user_request"
EV_SYSTEM_INSTRUCTION = "system_instruction"
EV_DEVELOPER_INSTRUCTION = "developer_instruction"
EV_RETRIEVED_DOCUMENT = "retrieved_document"
EV_TOOL_CALL_REQUEST = "tool_call_request"
EV_TOOL_RESULT = "tool_result"
EV_MODEL_OUTPUT = "model_output"
EV_SECURITY_OBSERVATION = "security_observation"
EV_HUMAN_REVIEW = "human_review"
EVENT_TYPES = (EV_USER_REQUEST, EV_SYSTEM_INSTRUCTION, EV_DEVELOPER_INSTRUCTION, EV_RETRIEVED_DOCUMENT,
               EV_TOOL_CALL_REQUEST, EV_TOOL_RESULT, EV_MODEL_OUTPUT, EV_SECURITY_OBSERVATION,
               EV_HUMAN_REVIEW)

_DEFAULT_ZONE = {
    EV_USER_REQUEST: ZONE_USER_AUTHORIZED,
    EV_SYSTEM_INSTRUCTION: ZONE_TRUSTED,
    EV_DEVELOPER_INSTRUCTION: ZONE_TRUSTED,
    EV_RETRIEVED_DOCUMENT: ZONE_UNTRUSTED_RETRIEVED,
    EV_TOOL_CALL_REQUEST: ZONE_MODEL_GENERATED,   # the MODEL requests a tool call
    EV_TOOL_RESULT: ZONE_TOOL_OUTPUT,
    EV_MODEL_OUTPUT: ZONE_MODEL_GENERATED,
    EV_SECURITY_OBSERVATION: ZONE_TRUSTED,
    EV_HUMAN_REVIEW: ZONE_TRUSTED,
}

# ------------------------------------------------------------------ bounds (resource-exhaustion safety)

MAX_EVENTS = 5000
MAX_CONTENT_CHARS = 20000
MAX_FIELD_CHARS = 4000
MAX_TOTAL_INPUT_BYTES = 8 * 1024 * 1024    # 8 MB cap on a single imported trace document


class TraceValidationError(Exception):
    """Raised when input is not a well-formed trace document or exceeds safe bounds."""


# ------------------------------------------------------------------ safe normalization + scrubbing

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# credential-shaped material that must not land in public/synthetic fixtures
_SECRET_RE = [
    ("github_token", re.compile(r"\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{10,}\b")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{12,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("basic_auth_url", re.compile(r"\b[a-z]+://[^/\s:@]+:[^/\s@]+@")),
]


def _norm_text(s: Any, limit: int = MAX_CONTENT_CHARS) -> Tuple[Optional[str], Optional[int]]:
    """Return (normalized_text, original_len_if_truncated). NFKC, strip control chars, bound length.
    Returns (None, None) for non-strings so absence stays absent (no fabricated empty string)."""
    if s is None:
        return None, None
    if not isinstance(s, str):
        s = str(s)
    s = unicodedata.normalize("NFKC", s)
    s = _CTRL_RE.sub("", s)
    if len(s) > limit:
        return s[:limit] + "…[truncated]", len(s)
    return s, None


def scrub_for_fixture(obj: Any) -> Any:
    """Recursively replace credential-shaped substrings with a labelled placeholder, for synthetic
    fixtures that may be shared. Structure-preserving; never removes non-secret content."""
    if isinstance(obj, dict):
        return {k: scrub_for_fixture(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_for_fixture(v) for v in obj]
    if isinstance(obj, str):
        out = obj
        for label, pat in _SECRET_RE:
            out = pat.sub("[SCRUBBED:%s]" % label, out)
        return out
    return obj


def _sha(s: Optional[str]) -> Optional[str]:
    return hashlib.sha256(s.encode("utf-8")).hexdigest() if isinstance(s, str) else None


# ------------------------------------------------------------------ event + trace construction

def make_event(*, event_id: str, etype: str, content: Any = None, zone: Optional[str] = None,
               observed: bool = True, source_ref: Optional[str] = None,
               event_time: Optional[str] = None, ingestion_time: Optional[str] = None,
               review_time: Optional[str] = None, attrs: Optional[Dict[str, Any]] = None,
               seq: Optional[int] = None) -> Dict[str, Any]:
    """Construct one normalized event. Unknown etype raises; zone defaults by type but may be set
    explicitly. Content is normalized+bounded; the original length is recorded when truncated."""
    if etype not in EVENT_TYPES:
        raise TraceValidationError("unknown event type: %r" % etype)
    z = zone or _DEFAULT_ZONE.get(etype)
    if z not in ZONES:
        raise TraceValidationError("invalid trust zone: %r" % z)
    norm, orig_len = _norm_text(content)
    ev: Dict[str, Any] = {
        "event_id": str(event_id),
        "seq": seq,
        "type": etype,
        "trust_zone": z,
        "observed": bool(observed),
        "content": norm,
        "content_sha256": _sha(norm),
        "content_truncated_from": orig_len,
        "source_ref": source_ref,
        "timestamps": {"event_time": event_time, "ingestion_time": ingestion_time,
                       "review_time": review_time},
        "attrs": {k: (_norm_text(v, MAX_FIELD_CHARS)[0] if isinstance(v, str) else v)
                  for k, v in (attrs or {}).items()},
    }
    return ev


def build_trace(*, trace_id: str, source_format: str, model: Optional[Dict[str, Any]],
                authorization: Dict[str, Any], events: List[Dict[str, Any]],
                integrity: Optional[Dict[str, Any]] = None,
                gaps: Optional[List[str]] = None) -> Dict[str, Any]:
    """Assemble a normalized trace. Events are renumbered deterministically; a stable trace hash is
    computed over (event_id, type, zone, content_sha256) tuples so two identical traces hash alike."""
    if len(events) > MAX_EVENTS:
        raise TraceValidationError("trace exceeds MAX_EVENTS (%d)" % MAX_EVENTS)
    ordered = list(events)
    for i, e in enumerate(ordered):
        e["seq"] = i
    spine = [(e["event_id"], e["type"], e["trust_zone"], e.get("content_sha256")) for e in ordered]
    trace_hash = hashlib.sha256(repr(spine).encode("utf-8")).hexdigest()
    return {
        "schema_version": SCHEMA_VERSION,
        "trace_id": str(trace_id),
        "source": {"format": source_format, "importer_version": IMPORTER_VERSION},
        "model": model or {"id": None, "revision": None, "observed": False},
        "authorization": authorization,
        "events": ordered,
        "event_count": len(ordered),
        "integrity": integrity or {},
        "trace_hash": trace_hash,
        "gaps": sorted(set(gaps or [])),
    }


def validate_trace(trace: Dict[str, Any]) -> List[str]:
    """Return a list of validation problems (empty means valid). Never raises; used by tests and the
    ingestion path to fail safe on malformed data."""
    problems: List[str] = []
    if not isinstance(trace, dict):
        return ["trace is not an object"]
    if trace.get("schema_version") != SCHEMA_VERSION:
        problems.append("schema_version != %s" % SCHEMA_VERSION)
    if not trace.get("trace_id"):
        problems.append("missing trace_id")
    evs = trace.get("events")
    if not isinstance(evs, list):
        problems.append("events is not a list")
        return problems
    seen_ids = set()
    for i, e in enumerate(evs):
        if not isinstance(e, dict):
            problems.append("event %d is not an object" % i); continue
        if e.get("type") not in EVENT_TYPES:
            problems.append("event %d has invalid type %r" % (i, e.get("type")))
        if e.get("trust_zone") not in ZONES:
            problems.append("event %d has invalid trust_zone %r" % (i, e.get("trust_zone")))
        eid = e.get("event_id")
        if not eid:
            problems.append("event %d missing event_id" % i)
        elif eid in seen_ids:
            problems.append("duplicate event_id %r" % eid)
        else:
            seen_ids.add(eid)
        if not isinstance(e.get("observed"), bool):
            problems.append("event %d missing boolean observed flag" % i)
    return problems


# ------------------------------------------------------------------ adapter: PARALLAX run record

def from_parallax_record(record: Dict[str, Any], *, trace_id: Optional[str] = None,
                         ingestion_time: Optional[str] = None) -> Dict[str, Any]:
    """Normalize an existing PARALLAX trial record (harness.run_trial shape, or a stored run's
    metrics.record) into a px-trace-v1 trace. Only fields actually present become observed events;
    anything absent is recorded in gaps, never invented."""
    if not isinstance(record, dict):
        raise TraceValidationError("record is not an object")
    tr = record
    # accept either a raw trial record or a stored run wrapper {record:{metrics:{record:...}}}
    if "metrics" in tr and isinstance(tr.get("metrics"), dict):
        tr = (tr.get("metrics") or {}).get("record") or tr
    tid = trace_id or tr.get("experiment_id") or tr.get("evidence_hash") or "trace-unknown"
    gaps: List[str] = []
    events: List[Dict[str, Any]] = []
    n = 0

    def eid(tag):
        nonlocal n
        n += 1
        return "%s:%s:%d" % (tid, tag, n)

    prov_ts = ((tr.get("provenance") or {}).get("timestamps") or {})
    timing = tr.get("timing") or {}
    etime = None
    try:
        import datetime
        start = prov_ts.get("started") or timing.get("started")
        if start is not None:
            etime = (datetime.datetime.fromtimestamp(float(start), datetime.timezone.utc)
                     .replace(tzinfo=None).isoformat() + "Z")
    except Exception:  # noqa: BLE001
        etime = None

    task = tr.get("legitimate_task") or tr.get("legitimate_task_id")
    if task:
        events.append(make_event(event_id=eid("user_request"), etype=EV_USER_REQUEST, content=task,
                                 observed=True, event_time=etime, ingestion_time=ingestion_time))
    else:
        gaps.append("no authorized user request recorded")

    # untrusted retrieved content: the attack variant + retrieved doc ids
    adv = tr.get("adversarial_input_id")
    docs = tr.get("retrieved_doc_ids") or []
    if adv or docs:
        events.append(make_event(
            event_id=eid("retrieved"), etype=EV_RETRIEVED_DOCUMENT,
            content=("injected variant: %s" % adv) if adv else "retrieved documents",
            zone=ZONE_UNTRUSTED_RETRIEVED, observed=True, source_ref=adv,
            event_time=etime, ingestion_time=ingestion_time,
            attrs={"retrieved_doc_ids": docs, "attack_category": tr.get("attack_category"),
                   "attempts_injection": bool(tr.get("attempts_injection"))}))
    else:
        gaps.append("no retrieved/untrusted content recorded")

    # PARALLAX trials do not record tool calls; do NOT fabricate them.
    for tc in (tr.get("tool_calls") or []):
        req = tc.get("request") if isinstance(tc, dict) else tc
        events.append(make_event(event_id=eid("toolcall"), etype=EV_TOOL_CALL_REQUEST, content=req,
                                 observed=True, event_time=etime, ingestion_time=ingestion_time))
        if isinstance(tc, dict) and "result" in tc:
            events.append(make_event(event_id=eid("toolresult"), etype=EV_TOOL_RESULT,
                                     content=tc.get("result"), observed=True, event_time=etime,
                                     ingestion_time=ingestion_time))
    if not (tr.get("tool_calls")):
        gaps.append("no tool-call events in this trace (PARALLAX trials record none)")

    obs = tr.get("observed_behavior")
    if obs is not None:
        events.append(make_event(event_id=eid("output"), etype=EV_MODEL_OUTPUT, content=obs,
                                 observed=True, event_time=etime, ingestion_time=ingestion_time,
                                 attrs={"outcome": tr.get("outcome"),
                                        "canary": (tr.get("evaluation") or {}).get("canary")}))
    else:
        gaps.append("no observed model output recorded")

    # the evaluator's deterministic outcome is a SECURITY OBSERVATION (heuristic, not a confirmed
    # finding); it is included with observed=true (it was computed) but marked heuristic in attrs.
    if tr.get("outcome"):
        events.append(make_event(
            event_id=eid("secobs"), etype=EV_SECURITY_OBSERVATION,
            content="automated outcome: %s" % tr.get("outcome"), observed=True,
            event_time=etime, ingestion_time=ingestion_time,
            attrs={"heuristic": True, "outcome": tr.get("outcome"),
                   "note": "automated candidate detection, not a confirmed compromise"}))

    model = {"id": (tr.get("model") or {}).get("id"),
             "revision": (tr.get("model") or {}).get("revision"),
             "digest": (tr.get("model") or {}).get("digest"),
             "observed": bool(tr.get("model"))}
    authorization = {
        "user_request": (_norm_text(task, MAX_FIELD_CHARS)[0] if task else None),
        "authorized_scope": "PARALLAX prompt-injection study: answer the task; never emit the canary",
        "system_instructions_available": False,     # not recorded in PARALLAX trials -> honest false
        "condition": tr.get("condition"),
    }
    integrity = {"evidence_hash": tr.get("evidence_hash"),
                 "corpus_hash": tr.get("corpus_hash"),
                 "protocol_version": tr.get("protocol_version")}
    return build_trace(trace_id=tid, source_format="parallax-run-record", model=model,
                       authorization=authorization, events=events, integrity=integrity, gaps=gaps)


# ------------------------------------------------------------------ adapter: external "Open Agent Trace"

# A documented, realistic external format this importer supports. See docs/research/AGENT_TRACE_SCHEMA.md
# for the full specification. Shape (all fields optional except messages):
#   {
#     "trace_id": str, "model": {"id","revision"},
#     "request": str,                      # the user's authorized request
#     "system": str,                       # trusted system instruction
#     "messages": [ {"role": "user|assistant|tool|system", "content": str,
#                    "tool_call": {"id","name","arguments"}?, "tool_result": str?, "ts": iso?} ],
#     "retrieved": [ {"id","content","source"} ],
#   }
def from_open_agent_trace(obj: Dict[str, Any], *, ingestion_time: Optional[str] = None) -> Dict[str, Any]:
    """Import a documented external agent-trace JSON object. Bounded + validated. Roles map to event
    types and trust zones; a tool_result present on a message is an OBSERVED execution result, while a
    tool_call without a result leaves the result ABSENT (a gap), never invented."""
    if not isinstance(obj, dict):
        raise TraceValidationError("open-agent-trace must be a JSON object")
    msgs = obj.get("messages")
    if not isinstance(msgs, list):
        raise TraceValidationError("open-agent-trace requires a 'messages' list")
    if len(msgs) > MAX_EVENTS:
        raise TraceValidationError("messages exceed MAX_EVENTS")
    tid = str(obj.get("trace_id") or "oat-" + hashlib.sha256(repr(sorted(obj.keys())).encode()).hexdigest()[:12])
    gaps: List[str] = []
    events: List[Dict[str, Any]] = []
    n = 0

    def eid(tag):
        nonlocal n
        n += 1
        return "%s:%s:%d" % (tid, tag, n)

    if obj.get("system"):
        events.append(make_event(event_id=eid("sys"), etype=EV_SYSTEM_INSTRUCTION,
                                 content=obj.get("system"), observed=True, ingestion_time=ingestion_time))
    else:
        gaps.append("no system instruction provided")
    if obj.get("request"):
        events.append(make_event(event_id=eid("req"), etype=EV_USER_REQUEST, content=obj.get("request"),
                                 observed=True, ingestion_time=ingestion_time))
    for d in (obj.get("retrieved") or []):
        if not isinstance(d, dict):
            continue
        events.append(make_event(event_id=eid("doc"), etype=EV_RETRIEVED_DOCUMENT,
                                 content=d.get("content"), zone=ZONE_UNTRUSTED_RETRIEVED, observed=True,
                                 source_ref=str(d.get("source") or d.get("id") or ""),
                                 ingestion_time=ingestion_time, attrs={"doc_id": d.get("id")}))

    for m in msgs:
        if not isinstance(m, dict):
            gaps.append("a message was not an object (skipped)"); continue
        role = m.get("role")
        ts = m.get("ts") if isinstance(m.get("ts"), str) else None
        if role in ("system",):
            events.append(make_event(event_id=eid("sys"), etype=EV_SYSTEM_INSTRUCTION,
                                     content=m.get("content"), observed=True, event_time=ts,
                                     ingestion_time=ingestion_time))
        elif role in ("user",):
            events.append(make_event(event_id=eid("user"), etype=EV_USER_REQUEST,
                                     content=m.get("content"), observed=True, event_time=ts,
                                     ingestion_time=ingestion_time))
        elif role in ("assistant", None):
            if isinstance(m.get("tool_call"), dict):
                tc = m["tool_call"]
                events.append(make_event(
                    event_id=eid("toolcall"), etype=EV_TOOL_CALL_REQUEST,
                    content="%s(%s)" % (tc.get("name"), tc.get("arguments")), observed=True,
                    event_time=ts, ingestion_time=ingestion_time,
                    attrs={"tool_name": tc.get("name"), "tool_call_id": tc.get("id")}))
            if m.get("content") is not None:
                events.append(make_event(event_id=eid("out"), etype=EV_MODEL_OUTPUT,
                                         content=m.get("content"), observed=True, event_time=ts,
                                         ingestion_time=ingestion_time))
        elif role in ("tool",):
            # a tool message is an OBSERVED execution result
            events.append(make_event(event_id=eid("toolresult"), etype=EV_TOOL_RESULT,
                                     content=m.get("content") if m.get("content") is not None
                                     else m.get("tool_result"), zone=ZONE_TOOL_OUTPUT, observed=True,
                                     event_time=ts, ingestion_time=ingestion_time,
                                     attrs={"tool_call_id": m.get("tool_call_id")}))
        else:
            gaps.append("unknown message role %r (skipped)" % role)

    # if a tool_call has no following tool result, record the gap (never invent an execution result)
    calls = [e for e in events if e["type"] == EV_TOOL_CALL_REQUEST]
    results = [e for e in events if e["type"] == EV_TOOL_RESULT]
    if len(calls) > len(results):
        gaps.append("%d tool-call(s) have no observed execution result" % (len(calls) - len(results)))

    model = {"id": (obj.get("model") or {}).get("id"), "revision": (obj.get("model") or {}).get("revision"),
             "observed": bool(obj.get("model"))}
    authorization = {"user_request": _norm_text(obj.get("request"), MAX_FIELD_CHARS)[0],
                     "system_instructions_available": bool(obj.get("system")),
                     "authorized_scope": _norm_text(obj.get("authorized_scope"), MAX_FIELD_CHARS)[0]}
    if not authorization["authorized_scope"]:
        gaps.append("no explicit authorized_scope provided")
    return build_trace(trace_id=tid, source_format="open-agent-trace-v0", model=model,
                       authorization=authorization, events=events, gaps=gaps)


def ingest(obj: Any, *, source_format: Optional[str] = None,
           ingestion_time: Optional[str] = None) -> Dict[str, Any]:
    """Front door: dispatch to the right adapter and validate the result. Fails safe on malformed or
    oversized input with TraceValidationError (never a partial/garbage trace)."""
    import json
    if isinstance(obj, (bytes, str)):
        raw = obj.encode("utf-8") if isinstance(obj, str) else obj
        if len(raw) > MAX_TOTAL_INPUT_BYTES:
            raise TraceValidationError("input exceeds MAX_TOTAL_INPUT_BYTES")
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            raise TraceValidationError("input is not valid JSON: %s" % type(e).__name__)
    fmt = source_format
    if fmt is None:
        fmt = "open-agent-trace-v0" if (isinstance(obj, dict) and "messages" in obj) else "parallax-run-record"
    if fmt == "open-agent-trace-v0":
        trace = from_open_agent_trace(obj, ingestion_time=ingestion_time)
    elif fmt == "parallax-run-record":
        trace = from_parallax_record(obj, ingestion_time=ingestion_time)
    else:
        raise TraceValidationError("unknown source_format: %r" % fmt)
    problems = validate_trace(trace)
    if problems:
        raise TraceValidationError("normalized trace failed validation: %s" % "; ".join(problems[:5]))
    return trace
