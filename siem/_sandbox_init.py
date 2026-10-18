"""F4 - in-namespace sandbox init (runs INSIDE the unshared namespaces).

This process is launched by siem/forensic_sandbox.py as:

    unshare --user --map-root-user --mount --net --pid --ipc --uts --fork \
        python3 -I siem/_sandbox_init.py

It is the pid-1 init of a fresh PID namespace, root inside a fresh USER namespace
(mapped to the caller's unprivileged uid on the host), with its own MOUNT, NET, IPC
and UTS namespaces. It:

  1. makes the mount tree private,
  2. builds a minimal new root on a size-limited tmpfs:
       - read-only binds of the host system dirs the pinned tool needs (/usr,/bin,...),
       - a read-only bind of the single source file at /input,
       - a writable tmpfs work dir at /work (the ONLY writable location),
       - a minimal /dev (null, zero, urandom, random) and a private /proc,
  3. pivot_root into it and detaches the old root (the host filesystem disappears),
  4. forks a child that applies rlimits + PR_SET_NO_NEW_PRIVS, chdir /work, and
     execs the pinned tool with a structured argv (never a shell),
  5. streams the child's stdout/stderr and every file written under /work back to the
     host over an inherited pipe (fd given in SBX_OUTFD), then exits with the child rc.

There is NO network (empty net namespace), NO writable host mount (old root detached),
and NO candidate code execution (the host only ever passes a pinned tool path + argv).
On any setup failure it emits a structured error frame and exits non-zero (fail closed).
"""
import ctypes
import ctypes.util
import json
import os
import platform
import resource
import struct
import sys

# --- mount(2) flags ----------------------------------------------------------
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MNT_DETACH = 2
PR_SET_NO_NEW_PRIVS = 38

_SYS_pivot_root = {"x86_64": 155, "aarch64": 41, "armv7l": 218, "ppc64le": 203, "s390x": 217}

_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def _b(s):
    return s.encode() if isinstance(s, str) else s


def _mount(src, tgt, fstype, flags, data):
    r = _libc.mount(_b(src) if src is not None else None,
                    _b(tgt),
                    _b(fstype) if fstype is not None else None,
                    ctypes.c_ulong(flags),
                    _b(data) if data is not None else None)
    if r != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"mount({src!r},{tgt!r},{fstype!r},{flags:#x}): {os.strerror(e)}")


def _umount2(tgt, flags):
    if _libc.umount2(_b(tgt), ctypes.c_int(flags)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"umount2({tgt!r}): {os.strerror(e)}")


def _pivot_root(new_root, put_old):
    nr = _SYS_pivot_root.get(platform.machine())
    if nr is None:
        raise OSError("pivot_root syscall number unknown for arch " + platform.machine())
    if _libc.syscall(ctypes.c_long(nr), _b(new_root), _b(put_old)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"pivot_root({new_root!r},{put_old!r}): {os.strerror(e)}")


def _no_new_privs():
    if _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"prctl(NO_NEW_PRIVS): {os.strerror(e)}")


def _frame(outfd, obj, blob=b""):
    """Write one length-prefixed frame: [4-byte header len][json header][raw blob]."""
    hdr = json.dumps(obj).encode()
    os.write(outfd, struct.pack(">I", len(hdr)))
    os.write(outfd, hdr)
    if blob:
        # header carries the blob length; write the bytes straight after
        off = 0
        while off < len(blob):
            off += os.write(outfd, blob[off:off + 1 << 20] if False else blob[off:off + (1 << 20)])


def _fail(outfd, code, msg):
    try:
        _frame(outfd, {"type": "error", "code": code, "message": msg})
    except Exception:
        pass
    os._exit(70)


SYS_RO_DIRS = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/etc"]
DEV_NODES = ["null", "zero", "full", "random", "urandom", "tty"]


def main():
    try:
        outfd = int(os.environ["SBX_OUTFD"])
        spec = json.loads(os.environ["SBX_SPEC"])
    except Exception as e:  # noqa
        # last-resort: nothing to stream to
        sys.stderr.write(f"sandbox init bad spec: {e}\n")
        os._exit(71)

    try:
        _run(spec, outfd)
    except OSError as e:
        _fail(outfd, "SETUP_FAILED", f"{e}")
    except Exception as e:  # noqa
        _fail(outfd, "SETUP_ERROR", f"{type(e).__name__}: {e}")


def _run(spec, outfd):
    tool = spec["tool_path"]
    argv = spec["argv"]
    source = spec.get("source_path")
    lim = spec["limits"]
    work_bytes = int(lim.get("out_bytes", 64 * 1024 * 1024))
    tmpfs_bytes = work_bytes + 16 * 1024 * 1024

    # 1) private mount tree
    _mount("none", "/", None, MS_REC | MS_PRIVATE, None)

    # 2) new root on a size-limited tmpfs
    NR = "/tmp/.sbxroot"
    os.makedirs(NR, exist_ok=True)
    _mount("tmpfs", NR, "tmpfs", MS_NOSUID | MS_NODEV,
           f"size={tmpfs_bytes},nr_inodes=20000,mode=0755")
    for d in ("work", "proc", "dev", "oldroot", "tmp"):
        os.makedirs(os.path.join(NR, d), exist_ok=True)
    os.chmod(os.path.join(NR, "work"), 0o700)
    os.chmod(os.path.join(NR, "tmp"), 0o1777)

    # read-only binds of the system dirs the pinned tool needs
    present_ro = []
    for sd in SYS_RO_DIRS:
        if os.path.isdir(sd) and not os.path.islink(sd):
            tgt = NR + sd
            os.makedirs(tgt, exist_ok=True)
            _mount(sd, tgt, None, MS_BIND | MS_REC, None)
            _mount("", tgt, None,
                   MS_BIND | MS_REC | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, None)
            present_ro.append(sd)
    # symlinked top dirs (e.g. /lib -> /usr/lib on merged-usr): recreate as symlinks
    for sd in SYS_RO_DIRS:
        if os.path.islink(sd):
            link = os.readlink(sd)
            try:
                os.symlink(link, NR + sd)
            except FileExistsError:
                pass

    # minimal /dev
    for node in DEV_NODES:
        hostdev = "/dev/" + node
        if os.path.exists(hostdev):
            tnode = NR + "/dev/" + node
            open(tnode, "w").close()
            try:
                _mount(hostdev, tnode, None, MS_BIND, None)
            except OSError:
                os.remove(tnode)

    # read-only bind of the single source file at /input
    if source:
        tgt = NR + "/input"
        open(tgt, "w").close()
        _mount(source, tgt, None, MS_BIND, None)
        _mount("", tgt, None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, None)

    # read-only bind of a single TRUSTED script at /op.py (our own probe/op code; never
    # candidate input - the host enforces the script lives inside the Ranger package).
    script = spec.get("script_path")
    if script:
        tgt = NR + "/op.py"
        open(tgt, "w").close()
        _mount(script, tgt, None, MS_BIND, None)
        _mount("", tgt, None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, None)

    # private /proc (needs the pid namespace we are in)
    _mount("proc", NR + "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, None)

    # the ONLY writable locations: a size-limited /work (outputs) and a tiny /tmp, each a
    # separate tmpfs mounted over the (about-to-be-read-only) root.
    _mount("tmpfs", NR + "/work", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
           f"size={work_bytes},nr_inodes=10000,mode=0700")
    _mount("tmpfs", NR + "/tmp", "tmpfs", MS_NOSUID | MS_NODEV,
           "size=8388608,nr_inodes=2000,mode=1777")

    # 3) pivot_root; detach the old (host) root so the host fs disappears
    os.chdir(NR)
    _pivot_root(".", "oldroot")
    os.chroot(".")
    _umount2("/oldroot", MNT_DETACH)
    try:
        os.rmdir("/oldroot")
    except OSError:
        pass
    # make the root read-only; only /work and /tmp (separate tmpfs) stay writable
    try:
        _mount("", "/", None, MS_REMOUNT | MS_RDONLY, None)
    except OSError:
        pass  # best-effort; the probe reports whether "/" is actually writable

    # 4) fork the child that execs the pinned tool under rlimits + no_new_privs
    pid = os.fork()
    if pid == 0:
        try:
            os.close(outfd)
        except OSError:
            pass
        # redirect stdio: no stdin; stdout/stderr -> files in /work
        devnull = os.open("/dev/null", os.O_RDONLY)
        os.dup2(devnull, 0)
        so = os.open("/work/.stdout", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        se = os.open("/work/.stderr", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.dup2(so, 1)
        os.dup2(se, 2)
        os.chdir("/work")
        # rlimits (kernel-enforced; see forensic_sandbox for documented limitations)
        def setl(r, v):
            try:
                resource.setrlimit(r, (v, v))
            except (ValueError, OSError):
                pass
        if lim.get("as_bytes"):
            setl(resource.RLIMIT_AS, int(lim["as_bytes"]))
        if lim.get("cpu_sec"):
            setl(resource.RLIMIT_CPU, int(lim["cpu_sec"]))
        if lim.get("fsize_bytes"):
            setl(resource.RLIMIT_FSIZE, int(lim["fsize_bytes"]))
        if lim.get("nproc"):
            setl(resource.RLIMIT_NPROC, int(lim["nproc"]))
        if lim.get("nofile"):
            setl(resource.RLIMIT_NOFILE, int(lim["nofile"]))
        setl(resource.RLIMIT_CORE, 0)
        try:
            _no_new_privs()
        except OSError:
            os._exit(72)
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/work", "TMPDIR": "/tmp",
               "LD_LIBRARY_PATH": ""}
        try:
            os.execve(tool, [tool] + list(argv), env)
        except OSError as e:
            os._exit(73 if e.errno == 13 else 74)
    # 5) parent: wait, then stream outputs back over outfd
    _, status = os.waitpid(pid, 0)
    rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
    _stream_outputs(outfd, rc, work_bytes)


def _stream_outputs(outfd, rc, work_bytes):
    total = 0
    names = []
    for root, _dirs, files in os.walk("/work"):
        for fn in files:
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, "/work")
            try:
                data = open(p, "rb").read()
            except OSError:
                continue
            total += len(data)
            if total > work_bytes + (16 << 20):
                _frame(outfd, {"type": "error", "code": "OUTPUT_TOO_LARGE",
                               "message": "output exceeded the sandbox tmpfs budget"})
                os._exit(75)
            names.append(rel)
            _frame(outfd, {"type": "file", "name": rel, "size": len(data)}, data)
    _frame(outfd, {"type": "eof", "rc": rc, "files": names, "out_bytes": total})
    os._exit(0 if rc == 0 else (rc if 0 < rc < 126 else 76))


if __name__ == "__main__":
    main()
