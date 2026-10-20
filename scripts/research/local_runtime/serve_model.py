#!/usr/bin/env python3
"""Serve the locally-trained tiny model over a loopback Ollama-compatible endpoint.

Exposes POST /api/generate {prompt, options:{temperature,num_predict}} -> {"response": "<text>", ...},
which is exactly what parallax.research.model_backend.HTTPBackend calls. Binds 127.0.0.1 ONLY, so it
passes the backend's _host_authorized loopback check and cannot be reached off-host.

Real autoregressive generation from real trained weights (no fabrication, no canned responses). This
is a nonprod local runtime that exists only because capable model weights are egress-blocked here.

Usage: python serve_model.py <model_dir> <port>
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

import torch
import torch.nn.functional as F

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from train_tiny_model import TinyGPT  # reuse the exact architecture  # noqa: E402

MODEL_DIR = sys.argv[1] if len(sys.argv) > 1 else "/tmp/qwalora-tiny-model"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5099

_cfg = json.load(open(os.path.join(MODEL_DIR, "model_config.json")))
_chars = _cfg["chars"]
_stoi = {c: i for i, c in enumerate(_chars)}
_itos = {i: c for i, c in enumerate(_chars)}
_block = _cfg["block_size"]
_model = TinyGPT(_cfg["vocab"], n_embd=_cfg["n_embd"], n_head=_cfg["n_head"],
                 n_layer=_cfg["n_layer"], block_size=_block)
_model.load_state_dict(torch.load(os.path.join(MODEL_DIR, "model.pt"), map_location="cpu"))
_model.eval()
_MODEL_ID = _cfg.get("model_id", "qwalora-charGPT-tiny")
_WEIGHTS_SHA = open(os.path.join(MODEL_DIR, "weights_sha256.txt")).read().strip()


@torch.no_grad()
def generate(prompt, max_new_tokens=96, temperature=0.8):
    # encode only characters the model knows; unknown chars are dropped (char-level vocab from corpus)
    ids = [_stoi[c] for c in prompt if c in _stoi]
    if not ids:
        ids = [0]
    idx = torch.tensor([ids], dtype=torch.long)
    out = []
    for _ in range(max_new_tokens):
        cond = idx[:, -_block:]
        logits, _ = _model(cond)
        logits = logits[:, -1, :] / max(temperature, 1e-6)
        probs = F.softmax(logits, dim=-1)
        nxt = torch.multinomial(probs, num_samples=1)
        idx = torch.cat([idx, nxt], dim=1)
        ch = _itos[int(nxt.item())]
        out.append(ch)
        if "".join(out).endswith("\nTASK:"):  # stop at the next turn boundary
            break
    return "".join(out)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_POST(self):
        if self.path.rstrip("/") != "/api/generate":
            self.send_response(404); self.end_headers(); return
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        opts = body.get("options") or {}
        text = generate(body.get("prompt", ""),
                        max_new_tokens=int(opts.get("num_predict") or 96),
                        temperature=float(opts.get("temperature", 0.8)))
        resp = {"response": text, "model": _MODEL_ID, "done": True,
                "weights_sha256": _WEIGHTS_SHA}
        payload = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", PORT), H)  # loopback ONLY
    print("serving %s (weights %s) on http://127.0.0.1:%d/api/generate" % (_MODEL_ID, _WEIGHTS_SHA[:16], PORT), flush=True)
    srv.serve_forever()
