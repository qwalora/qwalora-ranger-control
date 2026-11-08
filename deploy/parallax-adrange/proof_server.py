#!/usr/bin/env python3
"""Private-network proof + validation server for the live AD range.

Binds to [::]:9443 on the Railway PRIVATE network only (never publicly proxied). The portal reads it
to (a) confirm the range is genuinely live and the attack path is actually planted - a real
technical-validation probe, not a fabricated pass - and (b) obtain the expected proof-of-compromise
material (the Administrator NT hash) so it can verify a candidate's DCSync submission.

All endpoints except /healthz require the shared ADRANGE_PROOF_TOKEN (X-Proof-Token header or
?token=). The Administrator NT hash is served only over this private, token-gated endpoint; it is the
grader's truth, never exposed on the candidate-facing proxy.
"""
import json
import os
import socket
import struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import re

PROOF_TOKEN = os.environ.get("ADRANGE_PROOF_TOKEN", "")
ADMIN_PASS = os.environ.get("ADRANGE_ADMIN_PASSWORD", "")
REALM = os.environ.get("ADRANGE_REALM", "QWALORA.RANGE")
FOOTHOLD_USER = os.environ.get("ADRANGE_FOOTHOLD_USER", "ranger")
SMB_CONF = "/etc/samba/smb.conf"
SAMDB_PATH = "/var/lib/samba/private/sam.ldb"

GUID_FORCE_CHANGE_PW = "00299570-246d-11d0-a768-00aa006e0529"
GUID_DS_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"

# A candidate's trophy flag is an HMAC-derived token the portal issues; restrict to this charset so
# the value is always safe to splice into an LDAP filter / RDN (defence-in-depth; the portal already
# produces hex-ish tokens).
_FLAG_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# --- MD4 (modern OpenSSL disables it, so ship a compact implementation) -------
def _md4(data: bytes) -> bytes:
    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    msg = bytearray(data)
    orig_len_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len_bits)
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


# --- live attack-path validation (read the real directory) --------------------
def validate_directory():
    """Return a dict of real checks against the live sam.ldb. Every check is a genuine query; a
    missing object or ACE yields False, never a fabricated pass."""
    checks = {
        "provisioned": False, "foothold_present": False, "kerberoastable_spn": False,
        "asrep_decoy": False, "tier_group": False,
        "forcechangepw_ace": False, "dcsync_ace": False,
        "trophy_ou": False, "trophy_create_ace": False,
    }
    try:
        from samba.auth import system_session
        from samba.param import LoadParm
        from samba.samdb import SamDB
        lp = LoadParm()
        lp.load(SMB_CONF)
        db = SamDB(url=SAMDB_PATH, session_info=system_session(), lp=lp)
        base = db.domain_dn()
        checks["provisioned"] = True

        def one(expr, attrs):
            r = db.search(base=base, expression=expr, attrs=attrs)
            return r[0] if r else None

        checks["foothold_present"] = one("(sAMAccountName=%s)" % FOOTHOLD_USER, ["dn"]) is not None
        svc = one("(sAMAccountName=svc_mssql)", ["servicePrincipalName"])
        checks["kerberoastable_spn"] = bool(svc and svc.get("servicePrincipalName"))
        leg = one("(sAMAccountName=svc_legacy)", ["userAccountControl"])
        checks["asrep_decoy"] = bool(leg and (int(leg["userAccountControl"][0]) & 0x400000))
        checks["tier_group"] = one("(sAMAccountName=TierAdmins)", ["dn"]) is not None
        # ACE presence: read the SDs and look for the planted extended rights. Match on the SDDL
        # string (robust across samba structure versions) rather than walking the ACE union.
        try:
            dom_sid = db.get_domain_sid()
        except Exception:  # noqa: BLE001
            dom_sid = None
        svc_sd = one("(sAMAccountName=svc_mssql)", ["nTSecurityDescriptor"])
        dom_sd = db.search(base=base, scope=0, attrs=["nTSecurityDescriptor"])[0]
        checks["forcechangepw_ace"] = _sd_has_right(svc_sd, GUID_FORCE_CHANGE_PW, dom_sid)
        checks["dcsync_ace"] = _sd_has_right(dom_sd, GUID_DS_GET_CHANGES, dom_sid)
        # Trophy container + the Create-Child grant to TierAdmins that lets a compromised candidate
        # write their per-candidate proof object.
        tier = one("(sAMAccountName=TierAdmins)", ["objectSid"])
        tier_sid = None
        if tier and tier.get("objectSid"):
            from samba.dcerpc import security as _sec
            from samba.ndr import ndr_unpack as _unpack
            tier_sid = str(_unpack(_sec.dom_sid, tier["objectSid"][0]))
        ou = db.search(base=base, expression="(ou=Trophies)", attrs=["nTSecurityDescriptor"])
        checks["trophy_ou"] = bool(ou)
        checks["trophy_create_ace"] = bool(ou) and _sd_has_createchild(ou[0], tier_sid, dom_sid)
    except Exception as e:  # noqa: BLE001
        checks["error"] = str(e)
    return checks


def _sd_has_createchild(entry, trustee_sid, dom_sid=None):
    """True when the object's DACL grants Create-Child (SDDL right 'CC') to trustee_sid."""
    if not entry or "nTSecurityDescriptor" not in entry or not trustee_sid:
        return False
    try:
        from samba.dcerpc import security
        from samba.ndr import ndr_unpack
        sd = ndr_unpack(security.descriptor, entry["nTSecurityDescriptor"][0])
        try:
            sddl = sd.as_sddl(dom_sid) if dom_sid is not None else sd.as_sddl()
        except Exception:  # noqa: BLE001
            sddl = sd.as_sddl()
        sddl = sddl or ""
        # Match an allow ACE that both carries the Create-Child right and ends with the trustee SID.
        for ace in re.findall(r"\(([^)]*)\)", sddl):
            f = ace.split(";")
            if len(f) >= 6 and f[0].startswith("A") and "CC" in f[2] and f[5].rstrip(")") == trustee_sid:
                return True
        return False
    except Exception:  # noqa: BLE001
        return False


def trophy_present(flag):
    """True when CN=<flag>,OU=Trophies exists in the directory. flag is validated against _FLAG_RE
    before use so it is safe to place in the LDAP filter."""
    if not flag or not _FLAG_RE.match(flag):
        return False
    try:
        from samba.auth import system_session
        from samba.param import LoadParm
        from samba.samdb import SamDB
        lp = LoadParm()
        lp.load(SMB_CONF)
        db = SamDB(url=SAMDB_PATH, session_info=system_session(), lp=lp)
        base = db.domain_dn()
        res = db.search(base="OU=Trophies,%s" % base,
                        expression="(cn=%s)" % flag, attrs=["dn"])
        return len(res) >= 1
    except Exception:  # noqa: BLE001
        return False


def _sd_has_right(entry, guid_str, dom_sid=None):
    if not entry or "nTSecurityDescriptor" not in entry:
        return False
    try:
        from samba.dcerpc import security
        from samba.ndr import ndr_unpack
        sd = ndr_unpack(security.descriptor, entry["nTSecurityDescriptor"][0])
        try:
            sddl = sd.as_sddl(dom_sid) if dom_sid is not None else sd.as_sddl()
        except Exception:  # noqa: BLE001
            sddl = sd.as_sddl()
        return guid_str.lower() in (sddl or "").lower()
    except Exception:  # noqa: BLE001
        return False


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self, q):
        tok = self.headers.get("X-Proof-Token") or (q.get("token", [""])[0])
        return bool(PROOF_TOKEN) and tok == PROOF_TOKEN

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/healthz":
            return self._send(200, {"status": "ok", "realm": REALM})
        if not self._authed(q):
            return self._send(403, {"error": "forbidden"})
        if u.path == "/validate":
            checks = validate_directory()
            ok = all(v is True for k, v in checks.items() if k != "error")
            # Structural validation only - confirms the range is live and the attack path (including
            # the trophy container + its Create-Child grant) is genuinely planted. No secret is
            # returned; proof of a specific candidate's compromise is the /trophy check below.
            return self._send(200, {"ok": ok, "realm": REALM, "checks": checks})
        if u.path == "/trophy":
            # Proof of compromise: did the candidate create their per-candidate trophy object? The
            # portal passes the flag it issued that candidate; only a candidate who won domain
            # dominance could have written CN=<flag>,OU=Trophies over LDAP.
            flag = (q.get("flag", [""])[0] or "").strip()
            return self._send(200, {"present": trophy_present(flag), "realm": REALM})
        return self._send(404, {"error": "not found"})

    def log_message(self, *a):  # quiet
        pass


class _V6Server(ThreadingHTTPServer):
    # Railway private networking is IPv6 (<service>.railway.internal resolves AAAA), so bind IPv6.
    # On Linux a "::" bind with IPV6_V6ONLY off also accepts IPv4-mapped connections.
    address_family = socket.AF_INET6

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except (AttributeError, OSError):
            pass
        super().server_bind()


def main():
    srv = _V6Server(("::", 9443), Handler)
    srv.serve_forever()


if __name__ == "__main__":
    main()
