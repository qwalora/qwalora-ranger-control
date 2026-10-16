"""F4 - host-side driver for the bounded, OS-enforced forensic sandbox.

Untrusted media is never decoded in the privileged Ranger web process. Every forensic tool
runs inside a throwaway set of Linux namespaces (user + mount + pid + net + ipc + uts) created
with `unshare`, pivoting into a minimal root where:

  - there is NO network (empty net namespace; verified by the probe),
  - the host filesystem is detached (pivot_root + MNT_DETACH of the old root),
  - system dirs are bind-mounted READ-ONLY (the tool + its libraries, nothing writable),
  - the single source artifact is bind-mounted READ-ONLY at /input,
  - the ONLY writable space is a size-limited tmpfs at /work (+ a tiny /tmp),
  - rlimits (address space, CPU seconds, file size, process count, open files, core=0)
    are applied, PR_SET_NO_NEW_PRIVS is set, and a wall-clock timeout kills the whole
    process group,
  - only a pinned allowlisted executable is run, with a STRUCTURED argv (never a shell),
  - candidate-provided code/scripts are never executed (python3 may run ONLY our own
    pinned package scripts, enforced here).

Honest limitations (reported by `probe_sandbox`): this host has no Docker daemon and no
delegated cgroup v2 controllers, so memory/CPU are bounded by POSIX rlimits + wall-clock
timeout rather than cgroups (RLIMIT_AS caps virtual address space, not RSS; RLIMIT_CPU is
CPU-seconds). seccomp syscall filtering is not applied. The processor FAILS CLOSED: if the
probe cannot confirm the required controls, untrusted media is not processed - only
explicitly trusted synthetic fixtures are, for development demonstrations.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import struct
import subprocess
import threading
import time

PKG_DIR = os.path.dirname(os.path.realpath(__file__))
APP_DIR = os.path.dirname(PKG_DIR)
INIT_PATH = os.path.join(PKG_DIR, "_sandbox_init.py")
PROBE_PATH = os.path.join(PKG_DIR, "_sandbox_probe.py")

SANDBOX_RUNTIME_VERSION = "f4-ns-sandbox/1"

_UNSHARE = shutil.which("unshare")


def _resolve(name):
    p = shutil.which(name)
    return os.path.realpath(p) if p else None


# Pinned executable allowlist (absolute real paths). Nothing else may ever be exec'd.
TOOLS = {k: v for k, v in {
    "ffprobe": _resolve("ffprobe"),
    "ffmpeg": _resolve("ffmpeg"),
    "exiftool": _resolve("exiftool"),
    "python3": _resolve("python3") or _resolve("python"),
}.items() if v}


def tool_version(tool_id):
    """Pinned tool identity+version string (for reproducible manifests)."""
    path = TOOLS.get(tool_id)
    if not path:
        return None
    flag = {"ffprobe": "-version", "ffmpeg": "-version", "exiftool": "-ver",
            "python3": "--version"}.get(tool_id, "--version")
    try:
        out = subprocess.run([path, flag], capture_output=True, text=True, timeout=10)
        line = (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else ""
        return f"{tool_id} {line}".strip()
    except Exception:
        return tool_id


DEFAULT_LIMITS = {
    "as_bytes": 1024 * 1024 * 1024,   # 1 GiB virtual address space
    "cpu_sec": 30,                    # CPU seconds
    "fsize_bytes": 256 * 1024 * 1024, # max single-file write
    "nproc": 64,
    "nofile": 256,
    "out_bytes": 256 * 1024 * 1024,   # total /work tmpfs budget
}
DEFAULT_WALL_SEC = 60


class SandboxUnavailable(Exception):
    pass


class SandboxResult:
    def __init__(self):
        self.ok = False
        self.rc = None
        self.killed = False
        self.timed_out = False
        self.wall_ms = 0
        self.stdout = b""
        self.stderr = b""
        self.files = {}          # name -> bytes (contents of /work, excluding .stdout/.stderr)
        self.out_bytes = 0
        self.error = None        # {code, message} on setup/driver failure
        self.launcher_stderr = b""

    def as_dict(self):
        return {"ok": self.ok, "rc": self.rc, "killed": self.killed, "timed_out": self.timed_out,
                "wall_ms": self.wall_ms, "out_bytes": self.out_bytes,
                "files": sorted(self.files.keys()), "error": self.error,
                "stdout_bytes": len(self.stdout), "stderr_bytes": len(self.stderr)}


def available():
    return bool(_UNSHARE and TOOLS.get("python3") and os.path.exists(INIT_PATH))


def _is_trusted_script(path):
    rp = os.path.realpath(path)
    return rp.startswith(PKG_DIR + os.sep) and rp.endswith(".py") and os.path.isfile(rp)


def _read_exact(fd, n):
    buf = b""
    while len(buf) < n:
        chunk = os.read(fd, n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _drain(fd, result):
    """Read length-prefixed frames from the sandbox init until EOF."""
    try:
        while True:
            hdr_len_raw = _read_exact(fd, 4)
            if len(hdr_len_raw) < 4:
                break
            (hlen,) = struct.unpack(">I", hdr_len_raw)
            if hlen <= 0 or hlen > 1 << 20:
                break
            hdr = _read_exact(fd, hlen)
            if len(hdr) < hlen:
                break
            try:
                obj = json.loads(hdr.decode())
            except Exception:
                break
            t = obj.get("type")
            if t == "file":
                data = _read_exact(fd, int(obj.get("size", 0)))
                name = obj.get("name", "")
                if name == ".stdout":
                    result.stdout = data
                elif name == ".stderr":
                    result.stderr = data
                else:
                    result.files[name] = data
            elif t == "eof":
                result.rc = obj.get("rc")
                result.out_bytes = obj.get("out_bytes", 0)
                break
            elif t == "error":
                result.error = {"code": obj.get("code"), "message": obj.get("message")}
                break
    except OSError:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def run_sandboxed(tool_id, argv, *, source_path=None, script_path=None,
                  limits=None, wall_sec=DEFAULT_WALL_SEC):
    """Execute a pinned tool inside the namespace sandbox. Returns a SandboxResult.
    Never raises for tool failure; raises SandboxUnavailable only if the runtime is missing."""
    res = SandboxResult()
    if not available():
        raise SandboxUnavailable("namespace sandbox runtime unavailable (unshare/python3/init)")
    tpath = TOOLS.get(tool_id)
    if not tpath:
        res.error = {"code": "TOOL_NOT_ALLOWED", "message": f"tool {tool_id!r} not in allowlist"}
        return res
    if tool_id == "python3":
        if not script_path or not _is_trusted_script(script_path):
            res.error = {"code": "UNTRUSTED_SCRIPT",
                         "message": "python3 may only run pinned package scripts, never candidate input"}
            return res
    if not isinstance(argv, (list, tuple)) or any(not isinstance(a, str) or "\x00" in a for a in argv):
        res.error = {"code": "BAD_ARGV", "message": "argv must be a list of NUL-free strings (structured, never a shell)"}
        return res
    lim = dict(DEFAULT_LIMITS)
    lim.update(limits or {})

    spec = {"tool_path": tpath, "argv": list(argv), "source_path": source_path,
            "script_path": os.path.realpath(script_path) if script_path else None, "limits": lim}

    r_fd, w_fd = os.pipe()
    env = {"SBX_SPEC": json.dumps(spec), "SBX_OUTFD": str(w_fd),
           "PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    cmd = [_UNSHARE, "--user", "--map-root-user", "--mount", "--net", "--pid", "--ipc",
           "--uts", "--fork", TOOLS["python3"], "-I", INIT_PATH]

    start = time.time()
    try:
        proc = subprocess.Popen(cmd, pass_fds=(w_fd,), env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                start_new_session=True, cwd="/")
    except Exception as e:
        os.close(r_fd); os.close(w_fd)
        res.error = {"code": "SPAWN_FAILED", "message": str(e)}
        return res
    os.close(w_fd)

    reader = threading.Thread(target=_drain, args=(r_fd, res), daemon=True)
    reader.start()
    try:
        _, launcher_err = proc.communicate(timeout=wall_sec)
        res.launcher_stderr = launcher_err or b""
    except subprocess.TimeoutExpired:
        res.timed_out = True
        res.killed = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            _, launcher_err = proc.communicate(timeout=10)
            res.launcher_stderr = launcher_err or b""
        except Exception:
            pass
    reader.join(timeout=10)
    res.wall_ms = int((time.time() - start) * 1000)
    if res.rc is None and not res.error and not res.timed_out:
        rc = proc.returncode
        res.error = {"code": "NO_RESULT",
                     "message": f"sandbox produced no result frame (launcher rc={rc})"}
    res.ok = bool(res.error is None and not res.timed_out and (res.rc == 0))
    return res


# --- required-control probe --------------------------------------------------
REQUIRED_CONTROLS = ("network_isolated", "root_readonly", "system_readonly",
                     "work_writable", "no_new_privs", "host_root_detached", "pid_isolated")


class SandboxProbe:
    def __init__(self):
        self.backend = "linux-namespaces"
        self.runtime_available = available()
        self.controls = {}
        self.required_ok = False
        self.limitations = [
            "no container runtime (docker daemon unavailable): namespaces via unshare only",
            "no delegated cgroup v2 controllers: memory/CPU bounded by POSIX rlimits + "
            "wall-clock timeout, not cgroups (RLIMIT_AS caps virtual address space, not RSS)",
            "no seccomp syscall allowlist applied",
            "rlimit_as enforcement is advisory in the probe (allocation test)",
        ]
        self.error = None
        self.raw = None

    def as_dict(self):
        return {"backend": self.backend, "runtime_available": self.runtime_available,
                "required_controls": list(REQUIRED_CONTROLS), "controls": self.controls,
                "required_ok": self.required_ok, "limitations": self.limitations,
                "error": self.error, "runtime_version": SANDBOX_RUNTIME_VERSION}


def probe_sandbox(*, wall_sec=30):
    """Run the trusted in-sandbox self-test and return a SandboxProbe with REAL results.
    `required_ok` is True only if every control in REQUIRED_CONTROLS is enforced."""
    pr = SandboxProbe()
    if not pr.runtime_available:
        pr.error = "sandbox runtime unavailable"
        return pr
    # tighter limits so the rlimit_as allocation test is meaningful and quick
    res = run_sandboxed("python3", ["/op.py"], script_path=PROBE_PATH,
                        limits={"as_bytes": 512 * 1024 * 1024, "cpu_sec": 15,
                                "out_bytes": 8 * 1024 * 1024}, wall_sec=wall_sec)
    if res.error:
        pr.error = f"{res.error.get('code')}: {res.error.get('message')}"
        if res.launcher_stderr:
            pr.error += " | launcher: " + res.launcher_stderr.decode("utf-8", "replace")[:400]
        return pr
    try:
        pr.raw = json.loads(res.stdout.decode().strip().splitlines()[-1])
    except Exception as e:
        pr.error = f"could not parse probe output: {e}; stdout={res.stdout[:200]!r}"
        return pr
    pr.controls = pr.raw
    pr.required_ok = all(bool(pr.raw.get(c)) for c in REQUIRED_CONTROLS)
    return pr


if __name__ == "__main__":  # quick manual probe
    import pprint
    pprint.pprint(probe_sandbox().as_dict())
