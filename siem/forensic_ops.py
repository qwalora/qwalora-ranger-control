"""F4 - versioned, provider-neutral forensic operations (the ForensicProcessor).

Each operation takes an AUTHORIZED source artifact (bytes already preserved via F3), runs a
pinned open-source tool inside the OS-enforced sandbox (siem/forensic_sandbox), and returns an
`OpResult` that strictly separates three levels of result (section 8 of the F4 spec):

  observed_facts     - directly extracted, deterministic metadata / hashes / measurable props
  interpretations    - hypotheses with EXPLICIT uncertainty and supporting basis (never verdicts)
  derived            - new evidence bytes (frames, spectrograms, thumbnails) with sha256 + lineage

No operation decodes untrusted media in this process: media ops (audio/video/image) shell out to
ffprobe/ffmpeg INSIDE the sandbox. Provenance uses a bounded, memory-safe byte-marker scan plus
c2patool if present (missing manifest != fake; valid signature != truth). Agent-trace inspection
is strict bounded JSON parsing with schema validation and NEVER executes embedded code, tool calls,
model instructions, or deserialized objects.

Reproducibility is best-effort and documented: exact input hash, tool+version, environment
version and parameters are recorded so an authorized verifier can repeat the operation; byte-for-
byte identical derived outputs are NOT guaranteed across codec/tool/platform builds (so derived
hashes are recorded as observed-at-this-environment, not as a determinism claim).
"""
from __future__ import annotations

import hashlib
import json

from . import forensic_sandbox as sb

FORENSIC_CONTRACT_VERSION = 1
PROCESSOR_VERSION = "f4-forensic-processor/1"

MB = 1024 * 1024

# category -> evidence_type of the SOURCE it accepts (for authorization/routing)
CATEGORIES = ("audio", "video", "image", "provenance", "agent_trace")

# hard caps enforced before expensive work
MAX_IMAGE_PIXELS = 64_000_000           # 64 MP decompression guard
MAX_FRAMES = 16                         # bounded frame extraction
MAX_TRACE_BYTES = 16 * MB
MAX_TRACE_EVENTS = 5000
MAX_TRACE_DEPTH = 32
MAX_TRACE_FIELD = 64 * 1024
MAX_PROV_SCAN_BYTES = 8 * MB


class OpError(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class OpResult:
    def __init__(self, operation, category):
        self.operation = operation
        self.category = category
        self.ok = False
        self.observed_facts = {}
        self.interpretations = []          # list of {claim, basis, uncertainty}
        self.derived = []                  # list of {name, bytes, media_type, kind, sha256}
        self.limitations = []
        self.errors = []
        self.tool = None
        self.tool_params = {}
        self.sandbox = {}
        self.source_sha256 = None

    def manifest(self):
        """The reproducible result manifest (without the raw derived bytes)."""
        return {
            "forensic_contract_version": FORENSIC_CONTRACT_VERSION,
            "processor_version": PROCESSOR_VERSION,
            "operation": self.operation, "category": self.category, "ok": self.ok,
            "source_sha256": self.source_sha256,
            "tool": self.tool, "tool_params": self.tool_params,
            "sandbox": self.sandbox,
            "observed_facts": self.observed_facts,
            "interpretations": self.interpretations,
            "derived": [{"name": d["name"], "media_type": d["media_type"], "kind": d["kind"],
                         "sha256": d["sha256"], "bytes": len(d["bytes"])} for d in self.derived],
            "limitations": self.limitations, "errors": self.errors,
        }


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _sandbox_meta(res):
    return {"runtime_version": sb.SANDBOX_RUNTIME_VERSION, "rc": res.rc, "wall_ms": res.wall_ms,
            "timed_out": res.timed_out, "killed": res.killed,
            "out_bytes": res.out_bytes, "files": sorted(res.files.keys())}


# --- ffprobe helper (runs INSIDE the sandbox) --------------------------------
def _ffprobe_json(source_path, *, wall_sec=30):
    res = sb.run_sandboxed(
        "ffprobe",
        ["-v", "error", "-show_format", "-show_streams", "-show_error",
         "-print_format", "json", "/input"],
        source_path=source_path, limits={"cpu_sec": 20, "out_bytes": 8 * MB}, wall_sec=wall_sec)
    if res.error:
        raise OpError(res.error.get("code", "SANDBOX_ERROR"), res.error.get("message", ""))
    if res.timed_out:
        raise OpError("TIMEOUT", "ffprobe timed out in the sandbox")
    try:
        data = json.loads(res.stdout.decode() or "{}")
    except Exception as e:
        raise OpError("PARSE_ERROR", f"ffprobe output not JSON: {e}")
    return data, res


# =============================== AUDIO =======================================
def op_audio_inspect(source_path, params):
    r = OpResult("audio.inspect", "audio")
    r.tool = sb.tool_version("ffprobe")
    data, res = _ffprobe_json(source_path)
    r.sandbox = _sandbox_meta(res)
    fmt = data.get("format", {}) or {}
    astreams = [s for s in data.get("streams", []) if s.get("codec_type") == "audio"]
    r.observed_facts = {
        "container_format": fmt.get("format_name"),
        "container_long_name": fmt.get("format_long_name"),
        "reported_duration_s": _as_float(fmt.get("duration")),
        "reported_bitrate": _as_int(fmt.get("bit_rate")),
        "nb_streams": _as_int(fmt.get("nb_streams")),
        "audio_streams": [{
            "index": s.get("index"), "codec": s.get("codec_name"),
            "codec_long": s.get("codec_long_name"), "sample_rate": _as_int(s.get("sample_rate")),
            "channels": _as_int(s.get("channels")), "channel_layout": s.get("channel_layout"),
            "bitrate": _as_int(s.get("bit_rate")), "sample_fmt": s.get("sample_fmt"),
            "reported_duration_s": _as_float(s.get("duration")),
            "tags": _safe_tags(s.get("tags")),
        } for s in astreams],
        "format_tags": _safe_tags(fmt.get("tags")),
        "ffprobe_error": data.get("error"),
    }
    if not astreams:
        r.limitations.append("no audio stream detected by the decoder")
    r.limitations.append("container 'reported_*' values are self-declared metadata, not an "
                         "independent decode of every sample")
    r.ok = res.ok
    return r


def op_audio_spectrogram(source_path, params):
    r = OpResult("audio.spectrogram", "audio")
    r.tool = sb.tool_version("ffmpeg")
    r.tool_params = {"size": "1024x512", "legend": True}
    res = sb.run_sandboxed(
        "ffmpeg",
        ["-v", "error", "-nostdin", "-i", "/input",
         "-lavfi", "showspectrumpic=s=1024x512:legend=1", "-frames:v", "1", "/work/spectrogram.png"],
        source_path=source_path, limits={"cpu_sec": 25, "out_bytes": 32 * MB})
    r.sandbox = _sandbox_meta(res)
    _attach_derived(r, res, media_type="image/png", kind="audio_spectrogram")
    r.interpretations.append({
        "claim": "a reproducible frequency-domain (STFT) rendering of the audio",
        "basis": "ffmpeg showspectrumpic over the full stream",
        "uncertainty": "a spectrogram visualises energy per frequency bin; it is NOT evidence of "
                       "synthetic speech or speaker identity and must not be read as such"})
    r.ok = res.ok and bool(r.derived)
    return r


# =============================== VIDEO =======================================
def op_video_inspect(source_path, params):
    r = OpResult("video.inspect", "video")
    r.tool = sb.tool_version("ffprobe")
    data, res = _ffprobe_json(source_path)
    r.sandbox = _sandbox_meta(res)
    fmt = data.get("format", {}) or {}
    vs = [s for s in data.get("streams", []) if s.get("codec_type") == "video"]
    aus = [s for s in data.get("streams", []) if s.get("codec_type") == "audio"]
    r.observed_facts = {
        "container_format": fmt.get("format_name"),
        "reported_duration_s": _as_float(fmt.get("duration")),
        "reported_bitrate": _as_int(fmt.get("bit_rate")),
        "nb_streams": _as_int(fmt.get("nb_streams")),
        "video_streams": [{
            "index": s.get("index"), "codec": s.get("codec_name"),
            "profile": s.get("profile"), "width": _as_int(s.get("width")),
            "height": _as_int(s.get("height")), "pix_fmt": s.get("pix_fmt"),
            "reported_avg_frame_rate": s.get("avg_frame_rate"),
            "reported_r_frame_rate": s.get("r_frame_rate"),
            "reported_nb_frames": _as_int(s.get("nb_frames")),
            "reported_duration_s": _as_float(s.get("duration")),
            "bitrate": _as_int(s.get("bit_rate")), "tags": _safe_tags(s.get("tags")),
        } for s in vs],
        "audio_streams": [{"index": s.get("index"), "codec": s.get("codec_name"),
                           "sample_rate": _as_int(s.get("sample_rate")),
                           "channels": _as_int(s.get("channels"))} for s in aus],
        "format_tags": _safe_tags(fmt.get("tags")),
        "ffprobe_error": data.get("error"),
    }
    r.limitations.append("reported frame counts, durations and timestamps are container metadata; "
                         "they may be incomplete or inconsistent with an actual full decode")
    r.ok = res.ok and bool(vs)
    if not vs:
        r.errors.append({"code": "NO_VIDEO_STREAM", "message": "no video stream detected"})
    return r


def op_video_frames(source_path, params):
    r = OpResult("video.frames", "video")
    r.tool = sb.tool_version("ffmpeg")
    n = min(int(params.get("count", 4) or 4), MAX_FRAMES)
    fps = params.get("fps")
    width = min(int(params.get("width", 640) or 640), 1920)
    # bound dimensions first via a cheap probe (decompression guard)
    try:
        data, _ = _ffprobe_json(source_path)
        vs = next((s for s in data.get("streams", []) if s.get("codec_type") == "video"), {})
        w, h = _as_int(vs.get("width")) or 0, _as_int(vs.get("height")) or 0
        if w and h and w * h > MAX_IMAGE_PIXELS:
            raise OpError("PIXELS_TOO_LARGE", f"{w}x{h} exceeds the {MAX_IMAGE_PIXELS}px decode cap")
    except OpError:
        raise
    except Exception:
        pass
    vf = f"fps={fps}" if fps else "thumbnail"
    scale = f",scale={width}:-2"
    r.tool_params = {"count": n, "fps": fps, "width": width, "select": vf}
    res = sb.run_sandboxed(
        "ffmpeg",
        ["-v", "error", "-nostdin", "-i", "/input", "-vf", vf + scale,
         "-frames:v", str(n), "-vsync", "vfr", "/work/frame_%03d.png"],
        source_path=source_path, limits={"cpu_sec": 30, "out_bytes": 96 * MB})
    r.sandbox = _sandbox_meta(res)
    _attach_derived(r, res, media_type="image/png", kind="video_frame")
    r.observed_facts = {
        "frames_extracted": len(r.derived),
        "requested_count": n,
        "frame_hashes": [{"name": d["name"], "sha256": d["sha256"], "bytes": len(d["bytes"])}
                         for d in r.derived],
        "source_to_frame_provenance": "each frame is derived_from the source artifact (see custody)",
    }
    r.limitations.append("derived PNG bytes are environment-dependent (codec/ffmpeg build); the "
                         "recorded frame sha256 is observed-at-this-environment, not a determinism claim")
    r.ok = res.ok and bool(r.derived)
    return r


# =============================== IMAGE =======================================
def op_image_inspect(source_path, params):
    r = OpResult("image.inspect", "image")
    r.tool = sb.tool_version("ffprobe")
    data, res = _ffprobe_json(source_path)
    r.sandbox = _sandbox_meta(res)
    vs = next((s for s in data.get("streams", []) if s.get("codec_type") == "video"), {}) or {}
    fmt = data.get("format", {}) or {}
    w, h = _as_int(vs.get("width")), _as_int(vs.get("height"))
    r.observed_facts = {
        "container_format": fmt.get("format_name"),
        "codec": vs.get("codec_name"),
        "pixel_format": vs.get("pix_fmt"),
        "width": w, "height": h,
        "pixels": (w * h) if (w and h) else None,
        "format_tags": _safe_tags(fmt.get("tags")),
        "stream_tags": _safe_tags(vs.get("tags")),
        "decoder_integrity_ok": res.ok and data.get("error") is None,
        "ffprobe_error": data.get("error"),
    }
    if w and h and w * h > MAX_IMAGE_PIXELS:
        r.interpretations.append({
            "claim": "image exceeds the configured decompression guard",
            "basis": f"{w}x{h} > {MAX_IMAGE_PIXELS}px",
            "uncertainty": "a large image is not itself suspicious; derived rasterisation is skipped"})
    # exiftool is the richer metadata tool; report honestly when unavailable
    if "exiftool" not in sb.TOOLS:
        r.limitations.append("exiftool not installed: only container/decoder metadata is available; "
                             "full EXIF/XMP/ICC extraction is unsupported in this environment")
    r.limitations.append("ordinary compression artifacts are NOT evidence of manipulation")
    r.ok = res.ok
    return r


def op_image_thumbnail(source_path, params):
    r = OpResult("image.thumbnail", "image")
    r.tool = sb.tool_version("ffmpeg")
    width = min(int(params.get("width", 512) or 512), 1024)
    # decompression guard first
    try:
        data, _ = _ffprobe_json(source_path)
        vs = next((s for s in data.get("streams", []) if s.get("codec_type") == "video"), {})
        w, h = _as_int(vs.get("width")) or 0, _as_int(vs.get("height")) or 0
        if w and h and w * h > MAX_IMAGE_PIXELS:
            raise OpError("PIXELS_TOO_LARGE", f"{w}x{h} exceeds the {MAX_IMAGE_PIXELS}px decode cap")
    except OpError:
        raise
    except Exception:
        pass
    r.tool_params = {"width": width}
    res = sb.run_sandboxed(
        "ffmpeg", ["-v", "error", "-nostdin", "-i", "/input",
                   "-vf", f"scale={width}:-2", "-frames:v", "1", "/work/thumbnail.png"],
        source_path=source_path, limits={"cpu_sec": 20, "out_bytes": 32 * MB})
    r.sandbox = _sandbox_meta(res)
    _attach_derived(r, res, media_type="image/png", kind="image_thumbnail")
    r.ok = res.ok and bool(r.derived)
    return r


# =============================== PROVENANCE ==================================
# C2PA / provenance states (section "DIGITAL PROVENANCE")
PROV_VERIFIED = "verified"
PROV_INVALID = "invalid_signature"
PROV_MISSING = "missing_manifest"
PROV_UNSUPPORTED = "unsupported_tooling"
PROV_ERROR = "processing_error"
PROV_INDETERMINATE = "indeterminate"


def op_provenance_c2pa(source_path, params):
    """Inspect C2PA/content-credentials. A MISSING manifest is NOT evidence of fakery; a VALID
    signature does NOT prove depicted events are true. Uses c2patool if present, else a bounded,
    memory-safe byte-marker scan to distinguish 'missing' from 'present-but-unverifiable'."""
    r = OpResult("provenance.c2pa", "provenance")
    manifest_present = _scan_c2pa_marker(source_path)
    if "c2patool" in sb.TOOLS:
        r.tool = sb.tool_version("c2patool")
        res = sb.run_sandboxed("c2patool", ["/input"], source_path=source_path,
                               limits={"cpu_sec": 20, "out_bytes": 8 * MB})
        r.sandbox = _sandbox_meta(res)
        if res.ok:
            try:
                report = json.loads(res.stdout.decode() or "{}")
            except Exception:
                report = {"raw": res.stdout.decode("utf-8", "replace")[:4000]}
            state = PROV_VERIFIED if report.get("validation_status") in (None, [], "valid") else PROV_INVALID
            r.observed_facts = {"provenance_state": state, "c2pa_report": report,
                                "manifest_present": True}
        else:
            r.observed_facts = {"provenance_state": PROV_MISSING if not manifest_present else PROV_ERROR,
                                "manifest_present": manifest_present,
                                "tool_stderr": res.stderr.decode("utf-8", "replace")[:1000]}
    else:
        r.tool = "c2pa-marker-scan/1 (c2patool unavailable)"
        state = PROV_INDETERMINATE if manifest_present else PROV_MISSING
        r.observed_facts = {"provenance_state": state, "manifest_present": manifest_present}
        r.limitations.append("c2patool not installed: a present manifest cannot be cryptographically "
                             "verified here (state 'indeterminate'); signature validity is not asserted")
        r.ok = True
    r.interpretations.append({
        "claim": "provenance state as defined by C2PA validation levels",
        "basis": "content-credentials manifest inspection",
        "uncertainty": "a missing manifest is NOT evidence the media is fake; a valid provenance "
                       "signature proves integrity relative to its signer, NOT that depicted events occurred"})
    if r.observed_facts.get("provenance_state") in (PROV_VERIFIED, PROV_MISSING, PROV_INVALID,
                                                    PROV_INDETERMINATE, PROV_UNSUPPORTED):
        r.ok = True
    return r


def _scan_c2pa_marker(source_path):
    """Bounded, memory-safe substring scan (NOT a decode) for a C2PA/JUMBF marker."""
    try:
        with open(source_path, "rb") as f:
            blob = f.read(MAX_PROV_SCAN_BYTES)
        return (b"c2pa" in blob) or (b"jumbf" in blob) or (b"jumb" in blob) or (b"urn:uuid:" in blob and b"c2pa" in blob)
    except OSError:
        return False


# =============================== AGENT TRACE =================================
def op_agent_trace_inspect(source_path, params):
    """Strict, bounded, schema-validated parsing of a structured AI-agent/model execution trace.
    NEVER executes embedded code, tool calls, model instructions, or deserialized objects - it
    only reads declared, supported fields as data."""
    r = OpResult("agent_trace.inspect", "agent_trace")
    r.tool = "ranger-trace-parser/1"
    try:
        size = _file_size(source_path)
        if size > MAX_TRACE_BYTES:
            raise OpError("TOO_LARGE", f"trace {size} bytes exceeds {MAX_TRACE_BYTES}")
        with open(source_path, "rb") as f:
            raw = f.read(MAX_TRACE_BYTES + 1)
        if len(raw) > MAX_TRACE_BYTES:
            raise OpError("TOO_LARGE", "trace exceeds byte bound")
        _check_depth(raw.decode("utf-8", "strict"))
        doc = json.loads(raw.decode("utf-8"))
    except OpError:
        raise
    except Exception as e:
        raise OpError("BAD_TRACE", f"not a valid bounded JSON trace: {e}")

    events = doc.get("events") if isinstance(doc, dict) else (doc if isinstance(doc, list) else None)
    if not isinstance(events, list):
        raise OpError("BAD_SCHEMA", "trace must be a JSON object with an 'events' array (or a top-level array)")
    if len(events) > MAX_TRACE_EVENTS:
        raise OpError("TOO_MANY_EVENTS", f"{len(events)} events exceeds {MAX_TRACE_EVENTS}")

    SUPPORTED = {"model_request", "model_response", "tool_call", "tool_result",
                 "api_authorization", "retrieval", "data_access", "security_event"}
    counts, tool_calls, authz_decisions, denials, retrievals, boundaries = {}, [], [], [], [], []
    unsupported = set()
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            continue
        kind = _bounded_str(ev.get("type"))
        counts[kind] = counts.get(kind, 0) + 1
        if kind not in SUPPORTED:
            unsupported.add(kind)
            continue
        ref = {"index": i, "ts": _bounded_str(ev.get("ts"))}
        if kind == "tool_call":
            tool_calls.append({**ref, "tool": _bounded_str(ev.get("tool")),
                               "action": _bounded_str(ev.get("action"))})
        elif kind == "api_authorization":
            decision = _bounded_str(ev.get("decision"))
            rec = {**ref, "principal": _bounded_str(ev.get("principal")),
                   "resource": _bounded_str(ev.get("resource")), "decision": decision}
            authz_decisions.append(rec)
            if decision in ("deny", "denied", "forbidden"):
                denials.append(rec)
        elif kind == "retrieval":
            retrievals.append({**ref, "source": _bounded_str(ev.get("source")),
                               "n_results": _as_int(ev.get("n_results"))})
        elif kind == "data_access":
            boundaries.append({**ref, "boundary": _bounded_str(ev.get("boundary")),
                               "crossed": bool(ev.get("crossed"))})
    r.observed_facts = {
        "event_count": len(events), "event_type_counts": counts,
        "tool_calls": tool_calls[:500], "api_authorization_decisions": authz_decisions[:500],
        "authorization_denials": denials[:500], "retrievals": retrievals[:500],
        "data_access_boundaries": boundaries[:500],
        "unsupported_event_types": sorted(unsupported),
        "source_event_refs": "every observation above cites its 0-based source event index",
    }
    crossed = [b for b in boundaries if b.get("crossed")]
    if crossed:
        r.interpretations.append({
            "claim": f"{len(crossed)} data-access boundary crossing(s) are recorded in the trace",
            "basis": "data_access events with crossed=true (see source_event_refs)",
            "uncertainty": "this reports what the trace asserts; it is an observation of the trace, "
                           "not an authoritative finding that a real violation occurred"})
    r.limitations.append("only explicitly supported, schema-validated fields are read; embedded "
                         "code, tool calls, model instructions and objects are never executed or deserialized")
    r.ok = True
    return r


# --- registry ----------------------------------------------------------------
OPS = {
    "audio.inspect": {"fn": op_audio_inspect, "category": "audio", "tool": "ffprobe", "produces_derived": False},
    "audio.spectrogram": {"fn": op_audio_spectrogram, "category": "audio", "tool": "ffmpeg", "produces_derived": True},
    "video.inspect": {"fn": op_video_inspect, "category": "video", "tool": "ffprobe", "produces_derived": False},
    "video.frames": {"fn": op_video_frames, "category": "video", "tool": "ffmpeg", "produces_derived": True},
    "image.inspect": {"fn": op_image_inspect, "category": "image", "tool": "ffprobe", "produces_derived": False},
    "image.thumbnail": {"fn": op_image_thumbnail, "category": "image", "tool": "ffmpeg", "produces_derived": True},
    "provenance.c2pa": {"fn": op_provenance_c2pa, "category": "provenance", "tool": "c2patool", "produces_derived": False},
    "agent_trace.inspect": {"fn": op_agent_trace_inspect, "category": "agent_trace", "tool": "ranger-trace-parser", "produces_derived": False},
}


def supported_operations():
    out = {}
    for op_id, spec in OPS.items():
        tool = spec["tool"]
        out[op_id] = {"category": spec["category"], "tool": tool,
                      "tool_available": (tool in sb.TOOLS) or tool == "ranger-trace-parser",
                      "produces_derived": spec["produces_derived"]}
    return out


class ForensicProcessor:
    """The versioned, provider-neutral processing interface. `run` executes exactly one authorized
    operation over one source file path (already retrieved + authorized by the job layer)."""

    version = PROCESSOR_VERSION

    def __init__(self):
        self.sandbox_probe = None

    def ensure_sandbox(self):
        if self.sandbox_probe is None:
            self.sandbox_probe = sb.probe_sandbox()
        return self.sandbox_probe

    def run(self, op_id, source_path, *, params=None, require_sandbox=True, trusted_fixture=False):
        spec = OPS.get(op_id)
        if spec is None:
            raise OpError("UNKNOWN_OPERATION", f"operation {op_id!r} is not supported")
        tool = spec["tool"]
        media_op = spec["category"] in ("audio", "video", "image") or (
            spec["category"] == "provenance" and tool in sb.TOOLS)
        if media_op:
            if tool not in sb.TOOLS:
                raise OpError("TOOL_UNAVAILABLE", f"{tool} not installed; operation cannot run")
            if require_sandbox:
                probe = self.ensure_sandbox()
                if not probe.required_ok and not trusted_fixture:
                    # fail closed: do not decode untrusted media without verified isolation
                    raise OpError("SANDBOX_UNVERIFIED",
                                  "required sandbox controls are not verified; untrusted media is "
                                  "blocked. Use an explicitly trusted synthetic fixture for demos.")
        with open(source_path, "rb") as f:
            src = f.read()
        result = spec["fn"](source_path, params or {})
        result.source_sha256 = _sha(src)
        return result


# --- small safe helpers ------------------------------------------------------
def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _as_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _bounded_str(v, n=512):
    if v is None:
        return None
    s = str(v)
    return s[:n]


def _safe_tags(tags):
    if not isinstance(tags, dict):
        return {}
    return {str(k)[:64]: str(v)[:512] for k, v in list(tags.items())[:64]}


def _file_size(path):
    import os
    return os.path.getsize(path)


def _check_depth(text, limit=MAX_TRACE_DEPTH):
    depth = 0
    for ch in text:
        if ch in "[{":
            depth += 1
            if depth > limit:
                raise OpError("TOO_DEEP", f"JSON nesting exceeds {limit}")
        elif ch in "]}":
            depth -= 1


def _attach_derived(result, res, *, media_type, kind):
    if res.error:
        result.errors.append(res.error)
        return
    if res.timed_out:
        result.errors.append({"code": "TIMEOUT", "message": "operation timed out in the sandbox"})
        return
    for name in sorted(res.files.keys()):
        data = res.files[name]
        result.derived.append({"name": name, "bytes": data, "media_type": media_type,
                               "kind": kind, "sha256": _sha(data)})
