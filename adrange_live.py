"""Portal-side adapter for the live-execution AD range (the Samba AD DC on Railway).

This is the Railway-native counterpart to broker.py (which drives Ludus/GOAD on a Proxmox host).
Railway cannot run Windows VMs or nested virtualization, so the live range is a real Samba Active
Directory Domain Controller; this module is how the portal talks to it:

  enabled()              is the live range configured for this environment?
  connection_details(c)  the candidate-facing briefing: host, ports, realm, foothold creds, objective
  validate_live()        a REAL technical-validation probe of the DC over Railway's private network
                         (the token-gated /validate proof endpoint): is it live and is the attack path
                         actually planted? Fail-closed if unreachable - never a fabricated pass.
  verify_compromise(s)   verify a candidate's DCSync proof (the Administrator NT hash) against the
                         expected hash derived from the shared admin secret. Unfakeable: the only way
                         to obtain the hash is to really compromise the domain.
  attest(...)/verify_*   build and verify an Ed25519-signed live-compromise attestation that credits
                         the isolated-board (5/6) live objective under governance.

HONESTY
-------
A live compromise is credited ONLY when (a) the proof-of-compromise hash matches AND (b) the live
technical-validation probe passes AND (c) the operator has confirmed the live range by setting
ADRANGE_ADAPTER_VERIFIED=1 (mirrors broker.adapter_verified()). Any of these missing -> not creditable.
Nothing here derives credit from a configured URL alone.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import struct
import urllib.error
import urllib.request

import signing

ATTEST_KIND = "adrange_compromise"
ATTEST_VERSION = 1


# --- NT hash (MD4 of UTF-16LE); modern OpenSSL disables md4, so inline it ------
def _md4(data: bytes) -> bytes:
    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    msg = bytearray(data)
    bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bits)
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d
        for i in (0, 4, 8, 12):
            a = lrot(a + ((b & c) | (~b & d)) + X[i], 3)
            d = lrot(d + ((a & b) | (~a & c)) + X[i + 1], 7)
            c = lrot(c + ((d & a) | (~d & b)) + X[i + 2], 11)
            b = lrot(b + ((c & d) | (~c & a)) + X[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = lrot(a + ((b & c) | (b & d) | (c & d)) + X[i] + 0x5A827999, 3)
            d = lrot(d + ((a & b) | (a & c) | (b & c)) + X[i + 4] + 0x5A827999, 5)
            c = lrot(c + ((d & a) | (d & b) | (a & b)) + X[i + 8] + 0x5A827999, 9)
            b = lrot(b + ((c & d) | (c & a) | (d & a)) + X[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = lrot(a + (b ^ c ^ d) + X[i] + 0x6ED9EBA1, 3)
            d = lrot(d + (a ^ b ^ c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = lrot(c + (d ^ a ^ b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = lrot(b + (c ^ d ^ a) + X[i + 12] + 0x6ED9EBA1, 15)
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


def nt_hash(password: str) -> str:
    return _md4(password.encode("utf-16-le")).hex()


# --- config ------------------------------------------------------------------
def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def enabled() -> bool:
    """The live range is offered when it is switched on AND a candidate-facing host is configured."""
    return _truthy(os.environ.get("ADRANGE_ENABLED")) and bool(os.environ.get("ADRANGE_HOST"))


def adapter_verified() -> bool:
    """An operator has confirmed the live range is really up (mirrors broker.adapter_verified)."""
    return _truthy(os.environ.get("ADRANGE_ADAPTER_VERIFIED"))


def realm() -> str:
    return os.environ.get("ADRANGE_REALM", "QWALORA.RANGE")


def netbios() -> str:
    return os.environ.get("ADRANGE_NETBIOS", (realm().split(".")[0] or "QWALORA")).upper()


def _ports() -> dict:
    """Parse ADRANGE_PORTS='ldap=12345,kerberos=23456,...' into {service: int}."""
    out = {}
    for pair in (os.environ.get("ADRANGE_PORTS", "") or "").split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            try:
                out[k.strip().lower()] = int(v.strip())
            except ValueError:
                pass
    return out


def foothold() -> dict:
    return {"username": os.environ.get("ADRANGE_FOOTHOLD_USER", "ranger"),
            "password": os.environ.get("ADRANGE_FOOTHOLD_PASSWORD", "")}


def socks() -> dict:
    """The SOCKS5 pivot the candidate tunnels through. Railway exposes one TCP proxy per service, so
    a SOCKS pivot gives access to every AD port at its standard number. ADRANGE_HOST/ADRANGE_SOCKS_PORT
    are the public proxy endpoint; the creds gate the proxy (shown to the candidate, not secret)."""
    return {"host": os.environ.get("ADRANGE_HOST", ""),
            "port": int(os.environ.get("ADRANGE_SOCKS_PORT", "0") or 0),
            "username": os.environ.get("ADRANGE_SOCKS_USER", "ranger"),
            "password": os.environ.get("ADRANGE_SOCKS_PASSWORD", "")}


def expected_admin_nt_hash() -> str | None:
    pw = os.environ.get("ADRANGE_ADMIN_PASSWORD")
    return nt_hash(pw) if pw else None


# --- per-candidate trophy flag -----------------------------------------------
# Proof of compromise is a WRITE the candidate performs with the domain dominance they win through the
# planted path: they create CN=<flag>,OU=Trophies over LDAP. The flag is derived by HMAC over the
# candidate's identity with a portal-only key (the proof token), so (a) each candidate's flag is
# unique - concurrent candidates never collide and one cannot forge another's - and (b) writing it
# proves both domain dominance and identity. The portal verifies it by reading the DC directly.
def _proof_key() -> bytes:
    return (os.environ.get("ADRANGE_PROOF_TOKEN", "") or "").encode()


def trophy_flag(handle, board, attempt: int = 1) -> str:
    """Deterministic, per-candidate, per-board, per-attempt trophy name. CN-safe (matches the DC's
    flag charset). Stable for a given (handle, board, attempt) so the candidate can be shown it and
    the portal can re-derive it to verify."""
    import hashlib
    import hmac as _hmac
    msg = ("trophy|%s|%d|%d" % (handle or "", int(board), int(attempt or 1))).encode()
    dig = _hmac.new(_proof_key(), msg, hashlib.sha256).hexdigest()[:16]
    return "pwn-%s" % dig


# The DC is reached THROUGH the scoped SOCKS pivot, which ignores the requested host and always lands
# on the DC's loopback. Candidates therefore target a placeholder range IP (not 127.0.0.1), which also
# avoids proxychains' default localnet bypass of loopback addresses.
_TARGET = "10.10.10.10"


def connection_details(candidate=None, board=None) -> dict:
    """Everything a candidate needs to attack the range. Never includes the admin password or proof
    material - only the foothold they are legitimately given, the SOCKS pivot they tunnel through, and
    their own per-candidate trophy flag (an assigned nonce, not a secret: proof comes from writing it
    into the directory, which requires real compromise)."""
    sk = socks()
    fh = foothold()
    r = realm()
    proxychains_conf = ("[ProxyList]\nsocks5 %s %s %s %s"
                        % (sk["host"], sk["port"], sk["username"], sk["password"]))
    flag = None
    if candidate is not None and board is not None:
        flag = trophy_flag(getattr(candidate, "handle", None), board,
                           getattr(candidate, "attempt", 1) or 1)
    trophy_dn = "CN=%s,OU=Trophies,%s" % (flag or "<your-flag>",
                                          ",".join("DC=%s" % p for p in r.lower().split(".")))
    return {
        "enabled": enabled(),
        "realm": r,
        "domain": netbios(),
        "socks": sk,
        "proxychains_conf": proxychains_conf,
        "target": _TARGET,
        "foothold": fh,
        "trophy_flag": flag,
        "trophy_dn": trophy_dn,
        "objective": ("Pivot in through the SOCKS proxy and compromise the domain via the planted path "
                      "(foothold -> ForceChangePassword -> Kerberoastable service account -> a group "
                      "with domain-dominant rights). Prove it by using that control to create your "
                      "trophy object %s over LDAP, then submit it for verification." % trophy_dn),
        "hints": [
            "Add the SOCKS pivot to /etc/proxychains4.conf:  socks5 %s %s %s %s"
            % (sk["host"], sk["port"], sk["username"], sk["password"]),
            "Collect the graph:  proxychains bloodhound-python -d %s -u %s -p '<pw>' -ns %s "
            "--dns-tcp -c all" % (r, fh["username"], _TARGET),
            "Kerberoast:  proxychains GetUserSPNs.py %s/%s:'<pw>' -dc-ip %s -request"
            % (r, fh["username"], _TARGET),
            "Abuse the ACL to seize svc_mssql:  proxychains bloodyAD -u %s -p '<pw>' -d %s --host %s "
            "set password svc_mssql '<newpw>'" % (fh["username"], r, _TARGET),
            "svc_mssql is in the group that holds domain-dominant rights (see the BloodHound graph).",
            "Plant your trophy as svc_mssql:  proxychains bloodyAD -u svc_mssql -p '<newpw>' -d %s "
            "--host %s add computer %s  (or add a contact/OU child named %s under OU=Trophies)"
            % (r, _TARGET, flag or "<your-flag>", flag or "<your-flag>"),
            "ldap alternative:  proxychains ldapadd -H ldap://%s -D 'svc_mssql@%s' -w '<newpw>' -x, "
            "with an LDIF creating %s" % (_TARGET, r, trophy_dn),
        ],
    }


# --- live technical-validation probe ------------------------------------------
# Two transports to the DC's token-gated /validate proof endpoint:
#   * PRIVATE (nonprod): the DC shares the portal's Railway environment, so it is reached directly
#     over private networking at ADRANGE_INTERNAL_URL (.railway.internal:9443).
#   * PIVOT (isolated prod): the DC lives in its OWN project, off the portal's private network, so the
#     portal reaches the proof server THROUGH the authenticated scoped SOCKS pivot, using a portal-only
#     validator credential that the pivot scopes to port 9443 alone. This keeps an attacker-owned range
#     DC entirely off the production segment while still allowing a real, fail-closed validation probe.
# The proof response carries structural checks only (never the Administrator hash), so no secret
# transits either transport.
def _internal_url() -> str:
    return (os.environ.get("ADRANGE_INTERNAL_URL") or "").rstrip("/")


def _validator_socks() -> dict:
    """The portal's own pivot credential, scoped by the DC's SOCKS to the proof server (9443) only.
    Host/port are the public pivot endpoint; the validator cred is portal-only, never shown to
    candidates (who hold the AD-ports cred instead)."""
    return {"host": os.environ.get("ADRANGE_HOST", ""),
            "port": int(os.environ.get("ADRANGE_SOCKS_PORT", "0") or 0),
            "username": os.environ.get("ADRANGE_VALIDATOR_USER", ""),
            "password": os.environ.get("ADRANGE_VALIDATOR_PASSWORD", "")}


def _shape_validation(data: dict) -> dict:
    checks = data.get("checks") or {}
    ok = bool(data.get("ok")) and all(v is True for k, v in checks.items() if k != "error")
    return {"ok": ok, "reachable": True, "checks": checks,
            "reason": "live technical validation passed" if ok
            else "live range reachable but attack path not fully validated"}


def _socks5_connect(host, port, user, password, dst_port, timeout):
    """Open an authenticated SOCKS5 CONNECT tunnel to the DC's dst_port. The scoped pivot ignores the
    requested destination host and lands on the DC loopback, so a placeholder IP is sent. Returns a
    connected socket, or raises OSError."""
    import socket as _s
    sk = _s.create_connection((host, port), timeout=timeout)
    try:
        sk.settimeout(timeout)
        sk.sendall(struct.pack("!BBB", 5, 1, 2))                     # SOCKS5; 1 method: user/pass
        if sk.recv(2) != b"\x05\x02":
            raise OSError("user/pass auth not negotiated")
        u, p = user.encode(), password.encode()
        sk.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)     # RFC 1929
        if sk.recv(2) != b"\x01\x00":
            raise OSError("auth rejected")
        sk.sendall(struct.pack("!BBBB", 5, 1, 0, 1)
                   + _s.inet_aton("10.10.10.10") + struct.pack("!H", dst_port))
        rep = sk.recv(4)
        if len(rep) < 2 or rep[1] != 0x00:
            raise OSError("connect refused by pivot (rep=%s)" % (rep[1] if len(rep) > 1 else "?"))
        atyp = rep[3] if len(rep) >= 4 else 1
        sk.recv(6 if atyp == 1 else 18 if atyp == 4 else 0)          # drain BND.ADDR/PORT
        return sk
    except Exception:
        sk.close()
        raise


def _validate_via_pivot(token: str, timeout: float):
    """Fetch /validate from the proof server through the authenticated SOCKS pivot. Returns a shaped
    validation dict, or None when pivot validation is not configured."""
    sk = _validator_socks()
    if not (sk["host"] and sk["port"] and sk["username"] and sk["password"]):
        return None
    try:
        conn = _socks5_connect(sk["host"], sk["port"], sk["username"], sk["password"], 9443, timeout)
    except OSError as e:
        return {"ok": False, "reachable": False, "checks": {},
                "reason": "proof pivot unreachable: %s" % e}
    try:
        conn.settimeout(timeout)
        conn.sendall(("GET /validate HTTP/1.1\r\nHost: adrange\r\nX-Proof-Token: %s\r\n"
                      "Connection: close\r\n\r\n" % token).encode())
        buf = b""
        while len(buf) <= 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
    except OSError as e:
        return {"ok": False, "reachable": False, "checks": {},
                "reason": "proof pivot read failed: %s" % e}
    finally:
        try:
            conn.close()
        except OSError:
            pass
    if b"\r\n\r\n" not in buf:
        return {"ok": False, "reachable": True, "checks": {},
                "reason": "proof pivot returned no HTTP body"}
    try:
        data = json.loads(buf.split(b"\r\n\r\n", 1)[1].decode() or "{}")
    except ValueError:
        return {"ok": False, "reachable": True, "checks": {},
                "reason": "proof pivot returned unparseable response"}
    return _shape_validation(data)


def validate_live(timeout: float = 6.0) -> dict:
    """A REAL technical-validation probe of the DC's token-gated /validate endpoint, over whichever
    transport is configured (private same-env URL, else the authenticated pivot). Returns
    {ok, reachable, checks, reason}. Fail-closed: any gap or error -> ok False, reachable False."""
    token = os.environ.get("ADRANGE_PROOF_TOKEN", "")
    if not token:
        return {"ok": False, "reachable": False, "checks": {},
                "reason": "live-range proof token not configured"}
    base = _internal_url()
    if base:
        req = urllib.request.Request(base + "/validate", headers={"X-Proof-Token": token})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read().decode() or "{}")
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
            return {"ok": False, "reachable": False, "checks": {},
                    "reason": "proof endpoint unreachable: %s" % e}
        return _shape_validation(data)
    pivot = _validate_via_pivot(token, timeout)
    if pivot is None:
        return {"ok": False, "reachable": False, "checks": {},
                "reason": "live-range validation not configured (no internal URL or validator pivot)"}
    return pivot


def _proof_http_get(path: str, timeout: float):
    """GET an arbitrary proof-server path over whichever transport is configured (private same-env URL,
    else the authenticated SOCKS pivot scoped to 9443). Returns (data_dict|None, reachable_bool,
    reason). Mirrors validate_live's transport selection; used for the /trophy proof check."""
    token = os.environ.get("ADRANGE_PROOF_TOKEN", "")
    if not token:
        return None, False, "live-range proof token not configured"
    base = _internal_url()
    if base:
        req = urllib.request.Request(base + path, headers={"X-Proof-Token": token})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode() or "{}"), True, "ok"
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
            return None, False, "proof endpoint unreachable: %s" % e
    sk = _validator_socks()
    if not (sk["host"] and sk["port"] and sk["username"] and sk["password"]):
        return None, False, "live-range validation not configured (no internal URL or validator pivot)"
    try:
        conn = _socks5_connect(sk["host"], sk["port"], sk["username"], sk["password"], 9443, timeout)
    except OSError as e:
        return None, False, "proof pivot unreachable: %s" % e
    try:
        conn.settimeout(timeout)
        conn.sendall(("GET %s HTTP/1.1\r\nHost: adrange\r\nX-Proof-Token: %s\r\n"
                      "Connection: close\r\n\r\n" % (path, token)).encode())
        buf = b""
        while len(buf) <= 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
    except OSError as e:
        return None, False, "proof pivot read failed: %s" % e
    finally:
        try:
            conn.close()
        except OSError:
            pass
    if b"\r\n\r\n" not in buf:
        return None, True, "proof pivot returned no HTTP body"
    try:
        return json.loads(buf.split(b"\r\n\r\n", 1)[1].decode() or "{}"), True, "ok"
    except ValueError:
        return None, True, "proof pivot returned unparseable response"


def read_trophy(flag: str, timeout: float = 6.0) -> dict:
    """Ask the proof server whether CN=<flag>,OU=Trophies exists on the live DC. Returns
    {ok, reachable, present, reason}. Fail-closed: unreachable/unparseable -> ok False."""
    import urllib.parse
    data, reachable, reason = _proof_http_get("/trophy?flag=%s" % urllib.parse.quote(flag), timeout)
    if data is None:
        return {"ok": False, "reachable": bool(reachable), "present": False, "reason": reason}
    present = bool(data.get("present"))
    return {"ok": present, "reachable": True, "present": present,
            "reason": "trophy object present - real domain compromise"
            if present else "trophy object not found yet - compromise not proven"}


def verify_trophy(candidate, board, attempt: int = 1, timeout: float = 6.0) -> dict:
    """Verify a candidate's proof of compromise: re-derive their trophy flag and confirm they created
    CN=<flag>,OU=Trophies on the live DC. Returns {ok, reachable, present, reason, flag}."""
    handle = getattr(candidate, "handle", None) if candidate is not None else None
    flag = trophy_flag(handle, board, attempt)
    r = read_trophy(flag, timeout)
    r["flag"] = flag
    return r


# --- proof of compromise -----------------------------------------------------
def parse_submitted_hash(text: str) -> str | None:
    """Pull an NT hash out of whatever the candidate pastes: a bare 32-hex NT hash, an
    'LM:NT' pair, or a full secretsdump line 'user:rid:lm:nt:::'. Returns the lowercase NT hash."""
    if not text:
        return None
    t = text.strip().strip("'\"").strip()
    # secretsdump line: name:rid:lm:nt:::
    parts = t.split(":")
    cand = None
    if len(parts) >= 4 and all(len(parts[i]) == 32 for i in (2, 3)):
        cand = parts[3]
    elif len(parts) == 2 and len(parts[1]) == 32:
        cand = parts[1]
    elif len(parts) == 1 and len(parts[0]) == 32:
        cand = parts[0]
    if cand and all(ch in "0123456789abcdefABCDEF" for ch in cand):
        return cand.lower()
    return None


def verify_compromise(submission: str) -> dict:
    """Verify a DCSync proof. Returns {ok, reason, submitted_nt}. ok only when the parsed NT hash
    exactly equals the expected Administrator NT hash (constant-time compare)."""
    expected = expected_admin_nt_hash()
    got = parse_submitted_hash(submission)
    if not expected:
        return {"ok": False, "reason": "range admin secret not configured", "submitted_nt": got}
    if not got:
        return {"ok": False, "reason": "no NT hash found in submission", "submitted_nt": None}
    import hmac
    ok = hmac.compare_digest(got, expected.lower())
    return {"ok": ok,
            "reason": "administrator hash verified - real domain compromise"
            if ok else "hash does not match the domain Administrator",
            "submitted_nt": got}


# --- creditability + attestation ---------------------------------------------
def creditable(validation: dict, proof: dict) -> bool:
    """A live compromise backs objective credit ONLY with a confirmed adapter AND a passing live
    technical-validation AND a verified proof of compromise. Fail-closed on any gap."""
    return bool(adapter_verified() and validation.get("ok") and proof.get("ok"))


def _now():
    return _dt.datetime.now(_dt.timezone.utc)


def attest(candidate, board, *, cohort=None, attempt=1, validation=None, proof=None,
           scenario=None):
    """Build and Ed25519-sign a live-compromise attestation. Returns (creditable, record).

    Binds candidate identity + board/attempt + the real validation checks + the verified proof. It
    never contains the admin password or the full proof hash (only a short fingerprint), so the
    record is safe to store and show."""
    validation = validation or validate_live()
    proof = proof or {"ok": False, "reason": "no proof supplied"}
    now = _now()
    cred = creditable(validation, proof)
    nt = proof.get("submitted_nt") or ""
    flag = proof.get("flag") or ""
    claim = {
        "kind": ATTEST_KIND,
        "attestation_version": ATTEST_VERSION,
        "handle": getattr(candidate, "handle", None),
        "candidate_github_id": getattr(candidate, "github_id", None),
        "cohort": cohort if cohort is not None else getattr(candidate, "cohort", None),
        "board": int(board),
        "attempt": int(attempt or 1),
        "realm": realm(),
        "range": "samba-ad-dc (railway live-execution)",
        "technical_validation": {"passed": bool(validation.get("ok")),
                                 "reachable": bool(validation.get("reachable")),
                                 "checks": validation.get("checks") or {},
                                 "reason": validation.get("reason")},
        "proof_of_compromise": {"verified": bool(proof.get("ok")),
                                "method": "trophy-write" if flag else "dcsync",
                                "target": "OU=Trophies" if flag else "Administrator",
                                "trophy": (flag or None),
                                "nt_fingerprint": (nt[:8] + "..." if nt else None),
                                "reason": proof.get("reason")},
        "adapter_verified": adapter_verified(),
        "mode": "real" if cred else "unavailable",
        "real": bool(cred),
        "scenario_ref": (scenario or {}).get("scenario_ref"),
        "at": now.isoformat(),
    }
    record = dict(claim)
    record["signature"] = signing.sign(claim)
    return cred, record


def verify_attestation(record, *, handle=None, board=None, cohort=None, attempt=None, now=None):
    """Verify a stored live-compromise attestation: signature authentic, identity matches (when
    supplied), and the record is a real creditable compromise. Returns (ok, reason)."""
    if not isinstance(record, dict) or not record.get("signature"):
        return False, "no attestation / unsigned"
    claim = {k: record[k] for k in record if k != "signature"}
    try:
        if not signing.verify(claim, record["signature"]):
            return False, "signature invalid (forged or altered)"
    except Exception:  # noqa: BLE001
        return False, "signature could not be verified"
    if record.get("kind") != ATTEST_KIND:
        return False, "wrong attestation kind"
    for field, want in (("handle", handle), ("board", board),
                        ("cohort", cohort), ("attempt", attempt)):
        if want is not None and record.get(field) != want:
            return False, "attestation %s mismatch (foreign/superseded)" % field
    if not (record.get("real") is True and record.get("mode") == "real"):
        return False, "attestation is not a creditable real compromise"
    tv = record.get("technical_validation") or {}
    poc = record.get("proof_of_compromise") or {}
    if not tv.get("passed") or not poc.get("verified"):
        return False, "attestation lacks verified validation/proof"
    return True, "ok"
