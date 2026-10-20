#!/usr/bin/env python3
"""Isolated PARALLAX inference worker - a SEPARATE process from the Ranger web application.

Researcher-controlled workloads (prompts built from attacker-controlled low-trust documents) execute
HERE, never in the Flask web process. The web app reaches this worker only over loopback via
model_backend.HTTPBackend. Hardening in this process:

  * resource limits: RLIMIT_AS (address-space/memory cap) and RLIMIT_CPU (CPU-seconds) via setrlimit,
    so a runaway generation cannot exhaust the host.
  * execution timeout: each generation runs in a worker thread with a wall-clock cap; a timeout
    returns 504 and is recorded as a failure, never a faked output.
  * concurrency limit: a bounded semaphore caps simultaneous generations; over-limit returns 429.
  * controlled network: binds 127.0.0.1 ONLY; the worker itself makes no outbound calls.
  * model-version tracking: /api/version reports model id + weights SHA-256 + config + the active
    limits; /api/generate echoes the weights digest so every evidence record is pinned to exact weights.

Endpoints (Ollama-compatible generate):
  POST /api/generate {prompt, options:{temperature,num_predict}} -> {response, model, weights_sha256, ...}
  GET  /api/health   -> {ok, model_id, busy, ...}
  GET  /api/version  -> {model_id, weights_sha256, config, limits}

Config via env: MODEL_DIR, WORKER_PORT (5099), WORKER_MEM_LIMIT_MB (4096), WORKER_MAX_CONCURRENCY (1),
WORKER_GEN_TIMEOUT_S (30), WORKER_MODEL_KIND (auto|char-gpt|transformers).

Supports the in-repo char-GPT proof-of-concept now and a HuggingFace-format transformers model dir
(the production path) when capable weights are available locally - no code change needed to switch.
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL_DIR = os.environ.get("MODEL_DIR", "/tmp/qwalora-tiny-model")
PORT = int(os.environ.get("WORKER_PORT", "5099"))
MEM_LIMIT_MB = int(os.environ.get("WORKER_MEM_LIMIT_MB", "4096"))
CPU_LIMIT_S = int(os.environ.get("WORKER_CPU_LIMIT_S", "0"))  # 0 = unlimited
MAX_CONCURRENCY = int(os.environ.get("WORKER_MAX_CONCURRENCY", "1"))
GEN_TIMEOUT_S = float(os.environ.get("WORKER_GEN_TIMEOUT_S", "30"))
MODEL_KIND = os.environ.get("WORKER_MODEL_KIND", "auto")


def _apply_limits():
    import resource
    applied = {}
    if MEM_LIMIT_MB > 0:
        soft = MEM_LIMIT_MB * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_AS, (soft, soft))
            applied["RLIMIT_AS_mb"] = MEM_LIMIT_MB
        except (ValueError, OSError) as e:
            applied["RLIMIT_AS_error"] = str(e)
    if CPU_LIMIT_S > 0:
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_S, CPU_LIMIT_S + 5))
            applied["RLIMIT_CPU_s"] = CPU_LIMIT_S
        except (ValueError, OSError) as e:
            applied["RLIMIT_CPU_error"] = str(e)
    return applied


def _detect_kind():
    if MODEL_KIND != "auto":
        return MODEL_KIND
    if os.path.exists(os.path.join(MODEL_DIR, "model.pt")):
        return "char-gpt"
    if os.path.exists(os.path.join(MODEL_DIR, "config.json")):
        return "transformers"
    raise SystemExit("cannot detect model kind in %s" % MODEL_DIR)


class _Model:
    def __init__(self):
        self.kind = _detect_kind()
        self.weights_sha256 = ""
        p = os.path.join(MODEL_DIR, "weights_sha256.txt")
        if os.path.exists(p):
            self.weights_sha256 = open(p).read().strip()
        if self.kind == "char-gpt":
            import torch
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                            "local_runtime"))
            from train_tiny_model import TinyGPT
            self.cfg = json.load(open(os.path.join(MODEL_DIR, "model_config.json")))
            self.model_id = self.cfg.get("model_id", "qwalora-charGPT-tiny")
            self._torch = torch
            self._itos = {i: c for i, c in enumerate(self.cfg["chars"])}
            self._stoi = {c: i for i, c in enumerate(self.cfg["chars"])}
            self._block = self.cfg["block_size"]
            m = TinyGPT(self.cfg["vocab"], n_embd=self.cfg["n_embd"], n_head=self.cfg["n_head"],
                        n_layer=self.cfg["n_layer"], block_size=self._block)
            m.load_state_dict(torch.load(os.path.join(MODEL_DIR, "model.pt"), map_location="cpu"))
            m.eval()
            self._m = m
        else:  # transformers (production path for a capable local model)
            from transformers import pipeline, AutoConfig
            cfg = AutoConfig.from_pretrained(MODEL_DIR)
            self.model_id = os.environ.get("RANGER_RESEARCH_MODEL_ID") or getattr(cfg, "name_or_path", MODEL_DIR)
            if not self.weights_sha256:
                self.weights_sha256 = _dir_weights_digest(MODEL_DIR)
            self._pipe = pipeline("text-generation", model=MODEL_DIR)

    def generate(self, prompt, max_new_tokens, temperature):
        if self.kind == "char-gpt":
            torch = self._torch
            with torch.no_grad():
                ids = [self._stoi[c] for c in prompt if c in self._stoi] or [0]
                idx = torch.tensor([ids], dtype=torch.long)
                out = []
                import torch.nn.functional as F
                for _ in range(max_new_tokens):
                    logits, _ = self._m(idx[:, -self._block:])
                    logits = logits[:, -1, :] / max(temperature, 1e-6)
                    nxt = torch.multinomial(F.softmax(logits, dim=-1), 1)
                    idx = torch.cat([idx, nxt], 1)
                    out.append(self._itos[int(nxt.item())])
                    if "".join(out).endswith("\nTASK:"):
                        break
                return "".join(out)
        res = self._pipe(prompt, max_new_tokens=max_new_tokens,
                         temperature=max(temperature, 1e-6), do_sample=temperature > 0)
        return res[0]["generated_text"][len(prompt):]


def _dir_weights_digest(d):
    import hashlib
    h = hashlib.sha256()
    for root, _, files in os.walk(d):
        for fn in sorted(files):
            if fn.endswith((".safetensors", ".bin", ".pt")):
                with open(os.path.join(root, fn), "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
    return h.hexdigest()


_MODEL = None
_SEM = threading.BoundedSemaphore(MAX_CONCURRENCY)
_LIMITS = {}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.rstrip("/")
        if path == "/api/health":
            self._send(200, {"ok": True, "model_id": _MODEL.model_id, "kind": _MODEL.kind,
                             "busy": _SEM._value < MAX_CONCURRENCY})
        elif path == "/api/version":
            cfg = _MODEL.cfg if _MODEL.kind == "char-gpt" else {"format": "transformers"}
            self._send(200, {"model_id": _MODEL.model_id, "weights_sha256": _MODEL.weights_sha256,
                             "kind": _MODEL.kind, "config": cfg, "limits": _LIMITS})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/api/generate":
            self._send(404, {"error": "not found"}); return
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self._send(400, {"error": "bad json"}); return
        opts = body.get("options") or {}
        prompt = body.get("prompt", "")
        max_new = int(opts.get("num_predict") or 96)
        temp = float(opts.get("temperature", 0.8))
        if not _SEM.acquire(blocking=False):
            self._send(429, {"error": "worker at max concurrency"}); return
        result = {}

        def _run():
            t0 = time.time()
            try:
                result["text"] = _MODEL.generate(prompt, max_new, temp)
                result["latency_s"] = round(time.time() - t0, 3)
            except Exception as e:  # noqa: BLE001 - surfaced, never faked
                result["error"] = "generation failed: %s" % type(e).__name__
        try:
            th = threading.Thread(target=_run, daemon=True)
            th.start()
            th.join(GEN_TIMEOUT_S)
            if th.is_alive():
                self._send(504, {"error": "generation exceeded %ss timeout" % GEN_TIMEOUT_S}); return
            if "error" in result:
                self._send(502, {"error": result["error"]}); return
            self._send(200, {"response": result["text"], "model": _MODEL.model_id, "done": True,
                             "weights_sha256": _MODEL.weights_sha256,
                             "latency_s": result.get("latency_s")})
        finally:
            _SEM.release()


def main():
    global _MODEL, _LIMITS
    _LIMITS = _apply_limits()
    _LIMITS.update({"max_concurrency": MAX_CONCURRENCY, "gen_timeout_s": GEN_TIMEOUT_S})
    _MODEL = _Model()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)  # loopback ONLY
    print("inference worker: model=%s kind=%s weights=%s limits=%s on http://127.0.0.1:%d"
          % (_MODEL.model_id, _MODEL.kind, _MODEL.weights_sha256[:16], _LIMITS, PORT), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
