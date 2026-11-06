"""Sandbox for PX-D2: run a candidate's DEFENSE CODE as the system-under-test's guard.

A PX-D2 candidate submits defense.py exposing any of:
    SYSTEM: str                      # optional hardened system prompt
    def sanitize(doc: str) -> str    # transform each low-trust retrieved document (input defense)
    def screen(answer: str) -> str   # transform the model output (output defense)

Security posture (be honest): this is a LAYERED, meaningful sandbox, not a bulletproof jail.
  1. Static AST allowlist (static_check): rejects imports, any underscore-leading attribute access,
     dunder names, dangerous builtins, and '__'-bearing string literals BEFORE the code ever runs -
     this blocks the classic `().__class__...__subclasses__()` / `.__globals__` escapes, the
     `"{0.__class__}".format(x)` read vector, and `import os`, while still allowing ordinary method
     calls (`doc.lower()`, `re.sub(...)`) so a real defense can be written.
  2. Isolated child process: `python -I -S` (no site, no env, no user site-packages), a restricted
     __builtins__ (no __import__/open/eval/exec/compile/getattr/...), only re/string/json/math/random
     pre-injected.
  3. OS resource limits in the child: CPU seconds, address space, zero file size (no writes), few file
     descriptors, no core.
  4. Parent wall-clock watchdog per request; any timeout/crash/limit/protocol error FAILS CLOSED (the
     submission is a critical sandbox failure, never a silent pass).
  5. The grader that runs this holds NO signing key and NO org token and sits on a private network, so
     the blast radius of a hypothetical escape is contained.

True isolation (defense against a determined escape) needs an OS-level jail (gVisor/Firecracker) or a
WASM runtime, which this container does not provide. Treat PX-D2 as OPT-IN and review before enabling in
production. Candidate code is DATA to the platform: it is only ever executed inside this sandbox.
"""
from __future__ import annotations

import ast
import json
import os
import select
import signal
import subprocess
import sys
from typing import Any, Dict, List, Optional

MAX_CODE_BYTES = 20_000
DEFAULT_CPU_S = 5
DEFAULT_MEM_MB = 256
DEFAULT_REQ_TIMEOUT_S = 3.0
INTERFACE = ("SYSTEM", "sanitize", "screen")

# Builtins the candidate code may call. No __import__/open/eval/exec/compile/getattr/setattr/delattr/
# globals/locals/vars/input/breakpoint/memoryview/help/compile - the escape-enabling set is excluded.
_SAFE_BUILTINS = ("abs", "all", "any", "bool", "bytes", "chr", "dict", "divmod", "enumerate", "filter",
                  "float", "format", "frozenset", "hex", "int", "isinstance", "issubclass", "len",
                  "list", "map", "max", "min", "oct", "ord", "pow", "range", "repr", "reversed",
                  "round", "set", "slice", "sorted", "str", "sum", "tuple", "zip", "True", "False",
                  "None")
_FORBIDDEN_CALLS = {"eval", "exec", "compile", "open", "__import__", "globals", "locals", "vars",
                    "getattr", "setattr", "delattr", "input", "breakpoint", "memoryview", "help",
                    "exit", "quit", "object"}


def static_check(code: str) -> List[str]:
    """AST allowlist screen. Returns [] if the code is acceptable, else a list of reasons. This is the
    primary safety layer: it blocks imports, any attribute access and any dunder name (which together
    prevent the usual pure-Python sandbox escapes), and dangerous builtin calls."""
    errs: List[str] = []
    if not isinstance(code, str) or not code.strip():
        return ["defense.py is empty"]
    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        return ["defense.py too large (max %d bytes)" % MAX_CODE_BYTES]
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return ["syntax error: %s" % e]
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            errs.append("imports are not allowed")
        elif isinstance(node, ast.Attribute):
            # Ordinary method access is allowed (so `re.sub(...)`, `doc.lower()` work), but any
            # underscore-leading attribute is rejected: that closes the `().__class__.__bases__.
            # __subclasses__()` / `.__globals__` traversal escapes while keeping the board usable.
            if node.attr.startswith("_"):
                errs.append("underscore/dunder attribute access is not allowed: %r" % node.attr)
        elif isinstance(node, ast.Name) and node.id.startswith("__"):
            errs.append("dunder name not allowed: %s" % node.id)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            errs.append("global/nonlocal not allowed")
        elif isinstance(node, (ast.Lambda,)):
            pass
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_CALLS:
            errs.append("call to %s() not allowed" % node.func.id)
        # Block the literal-format-string attribute-traversal vector ("{0.__class__}".format(x)),
        # which reads attributes at runtime without an AST Attribute node. Only dunder-bearing
        # literals are rejected, so a defense may still match plain text.
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and "__" in node.value:
            errs.append("string literal contains '__' (blocked: format-string escape vector)")
    syms = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    syms |= {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign)
             for t in n.targets if isinstance(t, ast.Name)}
    if not (set(INTERFACE) & syms):
        errs.append("defense.py must define at least one of: SYSTEM, sanitize(doc), screen(answer)")
    # de-dup, keep order
    seen, out = set(), []
    for e in errs:
        if e not in seen:
            seen.add(e); out.append(e)
    return out[:20]


# The child program: sets rlimits, builds a restricted namespace, execs the (already static-checked)
# candidate code, then serves one JSON request per line on stdin. It never imports anything the
# candidate asked for; only re/string/json/math/random are pre-provided.
_CHILD = r'''
import sys, json, resource, re, string, math, random
cpu, mem = int(sys.argv[1]), int(sys.argv[2]) * 1024 * 1024
for res, lim in ((resource.RLIMIT_CPU,(cpu,cpu)),(resource.RLIMIT_AS,(mem,mem)),
                 (resource.RLIMIT_FSIZE,(0,0)),(resource.RLIMIT_NOFILE,(32,32)),
                 (resource.RLIMIT_CORE,(0,0))):
    try: resource.setrlimit(res,lim)
    except Exception: pass
SAFE=%r
import builtins as _b
SB={n:getattr(_b,n) for n in SAFE if hasattr(_b,n)}
code=sys.stdin.readline()
code=json.loads(code)["code"]
ns={"__builtins__":SB,"re":re,"string":string,"json":json,"math":math,"random":random}
try:
    exec(compile(code,"<defense>","exec"), ns)
    sys.stdout.write(json.dumps({"ready":True})+"\n"); sys.stdout.flush()
except Exception as e:
    sys.stdout.write(json.dumps({"ready":False,"error":"load:"+type(e).__name__})+"\n"); sys.stdout.flush()
    sys.exit(0)
def call(op,payload):
    if op=="system":
        v=ns.get("SYSTEM"); return v if isinstance(v,str) else None
    f=ns.get(op)
    if not callable(f): return payload
    r=f(payload)
    return r if isinstance(r,str) else payload
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try:
        req=json.loads(line); out=call(req["op"], req.get("payload"))
        sys.stdout.write(json.dumps({"ok":True,"result":out})+"\n")
    except Exception as e:
        sys.stdout.write(json.dumps({"ok":False,"error":type(e).__name__})+"\n")
    sys.stdout.flush()
''' % (list(_SAFE_BUILTINS),)


class SandboxError(Exception):
    pass


class SandboxSession:
    """A persistent sandboxed child serving sanitize/screen/system requests for one campaign."""

    def __init__(self, code: str, *, cpu_s: int = DEFAULT_CPU_S, mem_mb: int = DEFAULT_MEM_MB,
                 req_timeout_s: float = DEFAULT_REQ_TIMEOUT_S):
        errs = static_check(code)
        if errs:
            raise SandboxError("static_check: " + "; ".join(errs))
        self.req_timeout_s = req_timeout_s
        self.failed: Optional[str] = None
        self.proc = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", _CHILD, str(cpu_s), str(mem_mb)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1, env={"PATH": "/usr/bin:/bin"},
            start_new_session=True)
        self._send({"code": code})
        ready = self._recv()
        if not ready or not ready.get("ready"):
            self.close(); raise SandboxError("defense load failed: %s" % (ready or {}).get("error"))

    def _send(self, obj: Dict[str, Any]) -> None:
        try:
            self.proc.stdin.write(json.dumps(obj) + "\n"); self.proc.stdin.flush()
        except Exception as e:  # noqa: BLE001
            raise SandboxError("send: %s" % type(e).__name__)

    def _recv(self) -> Optional[Dict[str, Any]]:
        r, _, _ = select.select([self.proc.stdout], [], [], self.req_timeout_s)
        if not r:
            self._kill("timeout"); raise SandboxError("sandbox request timed out")
        line = self.proc.stdout.readline()
        if not line:
            self._kill("eof"); raise SandboxError("sandbox exited")
        try:
            return json.loads(line)
        except Exception:  # noqa: BLE001
            self._kill("protocol"); raise SandboxError("sandbox protocol error")

    def _kill(self, why: str) -> None:
        self.failed = why
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except Exception:  # noqa: BLE001
            pass

    def _op(self, op: str, payload: Optional[str]) -> Optional[str]:
        if self.failed:
            raise SandboxError("sandbox already failed: %s" % self.failed)
        self._send({"op": op, "payload": payload})
        resp = self._recv()
        if not resp or not resp.get("ok"):
            raise SandboxError("op %s failed: %s" % (op, (resp or {}).get("error")))
        return resp.get("result")

    def system(self) -> Optional[str]:
        return self._op("system", None)

    def sanitize(self, doc: str) -> str:
        out = self._op("sanitize", doc)
        return out if isinstance(out, str) else doc

    def screen(self, answer: str) -> str:
        out = self._op("screen", answer)
        return out if isinstance(out, str) else answer

    def close(self) -> None:
        try:
            if self.proc.poll() is None:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except Exception:  # noqa: BLE001
            pass


class CodeDefense:
    """Harness-facing wrapper: exposes the same shape the declarative defense does, backed by sandboxed
    candidate code. Built once per campaign; fail-closed (a sandbox error aborts the grade, never passes)."""

    def __init__(self, session: SandboxSession):
        self.s = session
        self._system = session.system()   # computed once
        self.active = True

    def system_prompt(self, default: str) -> str:
        return self._system if isinstance(self._system, str) and self._system.strip() else default

    def sanitize_docs(self, docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for d in docs:
            nd = dict(d); nd["text"] = self.s.sanitize(d.get("text", "") or ""); out.append(nd)
        return out

    def screen_output(self, text: Optional[str]) -> Optional[str]:
        return self.s.screen(text) if isinstance(text, str) else text

    def close(self) -> None:
        self.s.close()


def build_code_defense(code: str, **kw) -> CodeDefense:
    return CodeDefense(SandboxSession(code, **kw))
