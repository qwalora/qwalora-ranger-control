"""F4 - trusted sandbox self-test (runs INSIDE the sandbox via python3 /op.py).

Empirically exercises each required isolation control from inside the sandbox and prints a
single JSON object on stdout. This is OUR code (bound read-only at /op.py by the host); it is
never candidate input. The host (forensic_sandbox.probe_sandbox) reads the result and decides
whether the sandbox may process untrusted media (fail closed otherwise).
"""
import json
import os
import socket


def _no_new_privs():
    try:
        for line in open("/proc/self/status"):
            if line.startswith("NoNewPrivs:"):
                return line.split()[1] == "1"
    except OSError:
        pass
    return False


def _cannot_write(path):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        try:
            os.remove(path)
        except OSError:
            pass
        return False  # write SUCCEEDED -> control NOT enforced
    except OSError:
        return True   # write blocked -> good


def _network_isolated():
    for addr in (("1.1.1.1", 53), ("8.8.8.8", 53)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect(addr)
            s.close()
            return False  # reached the network -> NOT isolated
        except OSError:
            continue
    return True


def _source_readonly():
    if not os.path.exists("/input"):
        return None
    try:
        fd = os.open("/input", os.O_WRONLY)
        os.close(fd)
        return False  # could open source for write -> NOT read-only
    except OSError:
        return True


def _rlimit_as_enforced():
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_AS)
        if soft in (resource.RLIM_INFINITY, -1):
            return False
        try:
            _ = bytearray(soft + (256 << 20))  # exceed the address-space cap
            return False  # allocation succeeded past the cap -> NOT enforced
        except (MemoryError, OverflowError):
            return True
    except Exception:
        return False


def main():
    work_ok = False
    try:
        with open("/work/.probe_w", "w") as f:
            f.write("ok")
        with open("/work/.probe_w") as f:
            work_ok = f.read() == "ok"
        os.remove("/work/.probe_w")
    except OSError:
        work_ok = False

    try:
        proc_entries = [e for e in os.listdir("/proc") if e.isdigit()]
    except OSError:
        proc_entries = []

    result = {
        "no_new_privs": _no_new_privs(),
        "network_isolated": _network_isolated(),
        "root_readonly": _cannot_write("/.probe_root"),
        "system_readonly": _cannot_write("/etc/.probe_sys"),
        "source_readonly": _source_readonly(),
        "work_writable": work_ok,
        "pid_isolated": (os.getpid() <= 5 and len(proc_entries) <= 5),
        "rlimit_as_enforced": _rlimit_as_enforced(),
        "host_root_detached": not os.path.exists("/oldroot"),
        "uid": os.getuid(),
        "visible_root": sorted(os.listdir("/")),
        "visible_pids": len(proc_entries),
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
