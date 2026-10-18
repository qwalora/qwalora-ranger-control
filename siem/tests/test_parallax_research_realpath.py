"""PARALLAX Phase 2B - genuine model-backend conformance (NO findings, NO campaign).

These tests exercise the REAL code path of HTTPBackend against an actual loopback HTTP server, and the
REAL TransformersBackend against an actual local transformers model when torch+transformers are
installed. They verify the harness can correctly drive, time out, fail, and attribute a genuine model
response - the §4 requirement that the backend "correctly handles real-model responses, timeouts,
failures, and provenance".

CRITICAL honesty scope: nothing here is an empirical AI-security finding.
  * The loopback HTTP server is a protocol conformance fixture, not a language model and not the
    DeterministicStubBackend; it is NEVER run as an experimental campaign and produces NO metrics.
  * The TransformersBackend test, when it runs, loads a tiny RANDOMLY-INITIALIZED (untrained) model
    built locally from a config with a locally-trained byte tokenizer. It proves the inference engine
    executes a real torch forward pass on this CPU. Its output is gibberish by construction and is
    never evaluated, scored, persisted as evidence, or reported as a result.
A genuine, trained, instruction-tuned model remains OPEN in this environment (see the Phase 2B
engineering report); these tests do not stand in for it.
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

import pytest  # noqa: E402

from parallax.research import model_backend as mb  # noqa: E402


# ------------------------------- loopback HTTP model endpoint fixture -------------------------------
class _Handler(BaseHTTPRequestHandler):
    mode = "ok"

    def log_message(self, *a):  # silence
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n)
        req = json.loads(raw.decode("utf-8")) if raw else {}
        if type(self).mode == "slow":
            time.sleep(2.0)
        if type(self).mode == "error":
            self.send_response(500); self.end_headers(); self.wfile.write(b"boom"); return
        # echo back the received prompt so the test can assert the real request was transmitted
        body = {"response": "ENDPOINT_OK prompt_chars=%d model=%s"
                % (len(req.get("prompt", "")), req.get("model", "?"))}
        payload = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def endpoint():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield "http://127.0.0.1:%d" % port
    finally:
        srv.shutdown()


def _req():
    return mb.GenRequest(system="S", developer="D", task="How much free storage?",
                         context=[{"doc_id": "d1", "trust": "low", "text": "Free storage is 2 GB."}])


def test_httpbackend_real_network_path_and_provenance(endpoint):
    _Handler.mode = "ok"
    be = mb.HTTPBackend(endpoint, model_id="conformance-fixture")
    res = be.generate(_req())
    # the backend actually transmitted the assembled trust-fenced prompt and parsed a real HTTP response
    assert res.text.startswith("ENDPOINT_OK prompt_chars=")
    assert "model=conformance-fixture" in res.text
    assert res.is_real is True and res.provenance == "infrastructure_backed"
    assert "latency_s" in res.meta


def test_httpbackend_server_error_is_backend_error(endpoint):
    _Handler.mode = "error"
    be = mb.HTTPBackend(endpoint, model_id="x")
    with pytest.raises(mb.ModelBackendError):
        be.generate(_req())   # a 5xx becomes a ModelBackendError -> recorded infrastructure_failure, never faked
    _Handler.mode = "ok"


def test_httpbackend_timeout_is_backend_error(endpoint):
    _Handler.mode = "slow"
    be = mb.HTTPBackend(endpoint, model_id="x", timeout=0.3)
    with pytest.raises(mb.ModelBackendError):
        be.generate(_req())
    _Handler.mode = "ok"


def test_httpbackend_refuses_non_loopback_host():
    # host-authorization is enforced at construction; an external endpoint is refused before any call
    with pytest.raises(mb.ModelBackendError):
        mb.HTTPBackend("https://api.openai.com/v1", model_id="x")
    # an explicitly allow-listed host is accepted (operator opt-in via RANGER_RESEARCH_MODEL_HOSTS)
    os.environ["RANGER_RESEARCH_MODEL_HOSTS"] = "model.internal.test"
    try:
        be = mb.HTTPBackend("http://model.internal.test:11434", model_id="x")
        assert be.is_real is True
    finally:
        os.environ.pop("RANGER_RESEARCH_MODEL_HOSTS", None)


def test_from_config_selects_http_for_loopback_url(endpoint):
    be = mb.from_config({"RANGER_RESEARCH_MODEL_URL": endpoint, "RANGER_RESEARCH_MODEL_ID": "m"})
    assert isinstance(be, mb.HTTPBackend) and be.is_real is True


# ------------------------------- real transformers engine execution (untrained) -------------------
def _have_transformers():
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _have_transformers(), reason="torch+transformers not installed")
def test_transformersbackend_executes_real_forward_pass(tmp_path):
    """Builds a tiny UNTRAINED GPT-2-style model + a locally-trained byte tokenizer, saves them, and
    drives the REAL TransformersBackend. Proves a genuine torch forward pass executes on this CPU and
    that the backend reports is_real/provenance correctly. Output is random gibberish and is NOT a
    finding - never evaluated, scored, or persisted."""
    import torch  # noqa: F401
    from transformers import GPT2Config, GPT2LMHeadModel, PreTrainedTokenizerFast
    from tokenizers import Tokenizer, models, pre_tokenizers, trainers

    # a minimal byte-level tokenizer trained locally on synthetic text (no external download)
    tok = Tokenizer(models.BPE(unk_token="<unk>"))
    tok.pre_tokenizer = pre_tokenizers.ByteLevel()
    tr = trainers.BpeTrainer(vocab_size=300, special_tokens=["<unk>", "<pad>", "<eos>"])
    tok.train_from_iterator(["the free storage is 2 gb and the export format is markdown or pdf"] * 50, tr)
    fast = PreTrainedTokenizerFast(tokenizer_object=tok, unk_token="<unk>", pad_token="<pad>",
                                   eos_token="<eos>")
    d = str(tmp_path / "tiny")
    os.makedirs(d, exist_ok=True)
    fast.save_pretrained(d)
    cfg = GPT2Config(vocab_size=fast.vocab_size, n_positions=64, n_embd=32, n_layer=2, n_head=2)
    GPT2LMHeadModel(cfg).save_pretrained(d)

    be = mb.TransformersBackend(d, model_id="untrained-gpt2-tiny")
    res = be.generate(mb.GenRequest(system="S", developer="D", task="hello",
                                    context=[{"doc_id": "d1", "trust": "low", "text": "hi"}],
                                    max_tokens=8))
    assert isinstance(res.text, str)          # a real generation call completed on CPU
    assert res.is_real is True and res.provenance == "infrastructure_backed"
    assert res.runtime == "transformers"
