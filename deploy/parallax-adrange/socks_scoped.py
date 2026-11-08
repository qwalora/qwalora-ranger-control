#!/usr/bin/env python3
"""Scoped SOCKS5 pivot for the live AD range.

A deliberately-vulnerable, internet-reachable DC must not double as an open relay. microsocks forwards
anywhere; this does not. It is a minimal SOCKS5 proxy that:

  * REQUIRES username/password auth (RFC 1929) - no anonymous access;
  * IGNORES the client's requested destination host and ALWAYS connects to the DC on loopback
    (127.0.0.1), so the proxy can never reach any host but the range itself; and
  * scopes each credential to a disjoint set of ports: the candidate cred reaches only the AD
    service ports the attack chain needs, and a separate validator cred (used only by the portal)
    reaches only the token-gated proof server (9443). Every other port is refused. This lets the
    portal validate the compromise through the authenticated pivot without the DC ever sitting on
    the portal's private network, and without a candidate being able to reach the proof endpoint.

So a candidate tunnels in with proxychains, targets any placeholder IP (e.g. 10.10.10.10) on a standard
AD port, and lands on the DC; they cannot use the pivot to reach the portal, the internet, or anything
else. Because the destination host is ignored, there is also no proxychains loopback-bypass gotcha:
the client never has to target 127.0.0.1.

Binds dual-stack (IPv6 with V6ONLY off) so Railway's TCP-proxy edge reaches it the same way the proof
server is reached over private networking.
"""
import hmac
import os
import select
import socket
import struct
import threading

LISTEN_PORT = int(os.environ.get("ADRANGE_SOCKS_PORT", "1080") or 1080)
DC = "127.0.0.1"  # the DC runs in this same container; only loopback is ever dialed.

# Two credentials, each scoped to a disjoint set of ports on the DC loopback, so the candidate
# channel and the portal's validation channel never overlap:
#   - the CANDIDATE cred reaches only the AD service ports needed for the attack chain
#     (DNS, Kerberos, EPM, LDAP, SMB, kpasswd, LDAPS, Global Catalog);
#   - the VALIDATOR cred (used only by the portal) reaches only the token-gated proof server (9443),
#     so a candidate holding the attack cred cannot reach the proof endpoint at all.
# AD service ports, plus the DC's DCE/RPC ephemeral range. Samba's AD DC serves DRSUAPI (the
# replication interface DCSync uses) and other RPC services over dynamic endpoints registered with the
# endpoint mapper (135) in the standard Windows ephemeral range 49152-65535. We allow that whole range
# rather than constraining Samba's RPC (which conflicted its endpoint registration and corrupted the
# GetNCChanges reply). Everything here is still dialed only on the DC's loopback, so no other host or
# service is reachable through the pivot.
AD_PORTS = frozenset({53, 88, 135, 389, 445, 464, 636, 3268, 3269} | set(range(49152, 65536)))
VALIDATOR_PORTS = frozenset({9443})

CAND_USER = os.environ.get("ADRANGE_SOCKS_USER", "ranger").encode()
CAND_PASSWORD = os.environ.get("ADRANGE_SOCKS_PASSWORD", "").encode()
VAL_USER = os.environ.get("ADRANGE_VALIDATOR_USER", "").encode()
VAL_PASSWORD = os.environ.get("ADRANGE_VALIDATOR_PASSWORD", "").encode()


def _scope_for(uname: bytes, passwd: bytes):
    """Return the allowed-port set for these credentials, or None if they authenticate nothing.
    Both comparisons run so a bad username costs the same as a bad password."""
    cand_ok = bool(CAND_PASSWORD) and hmac.compare_digest(uname, CAND_USER) and \
        hmac.compare_digest(passwd, CAND_PASSWORD)
    val_ok = bool(VAL_PASSWORD) and hmac.compare_digest(uname, VAL_USER) and \
        hmac.compare_digest(passwd, VAL_PASSWORD)
    if cand_ok:
        return AD_PORTS
    if val_ok:
        return VALIDATOR_PORTS
    return None

_VER = 0x05
_M_USERPASS = 0x02
_M_NONE_ACCEPTABLE = 0xFF
_CMD_CONNECT = 0x01
_REP_OK = 0x00
_REP_RULESET = 0x02      # connection not allowed by ruleset
_REP_CMD_UNSUP = 0x07


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


def _reply(sock, rep):
    # BND.ADDR/PORT are not meaningful here; send a well-formed zero IPv4 reply.
    sock.sendall(struct.pack("!BBBB", _VER, rep, 0x00, 0x01) + b"\x00\x00\x00\x00\x00\x00")


def _handle(client):
    try:
        client.settimeout(30)
        ver, nmethods = struct.unpack("!BB", _recvn(client, 2))
        methods = _recvn(client, nmethods)
        if ver != _VER or _M_USERPASS not in methods:
            client.sendall(struct.pack("!BB", _VER, _M_NONE_ACCEPTABLE))
            return
        client.sendall(struct.pack("!BB", _VER, _M_USERPASS))
        # RFC 1929 username/password auth
        avr = _recvn(client, 1)[0]
        ulen = _recvn(client, 1)[0]
        uname = _recvn(client, ulen)
        plen = _recvn(client, 1)[0]
        passwd = _recvn(client, plen)
        scope = _scope_for(uname, passwd) if avr == 0x01 else None
        client.sendall(struct.pack("!BB", 0x01, 0x00 if scope is not None else 0x01))
        if scope is None:
            return
        # request
        ver, cmd, _rsv, atyp = struct.unpack("!BBBB", _recvn(client, 4))
        if atyp == 0x01:
            _recvn(client, 4)
        elif atyp == 0x03:
            dlen = _recvn(client, 1)[0]
            _recvn(client, dlen)
        elif atyp == 0x04:
            _recvn(client, 16)
        else:
            _reply(client, _REP_CMD_UNSUP)
            return
        port = struct.unpack("!H", _recvn(client, 2))[0]
        if cmd != _CMD_CONNECT:
            _reply(client, _REP_CMD_UNSUP)
            return
        if port not in scope:
            _reply(client, _REP_RULESET)   # scope: this credential may not reach this port
            return
        try:
            upstream = socket.create_connection((DC, port), timeout=15)
        except OSError:
            _reply(client, _REP_RULESET)
            return
        _reply(client, _REP_OK)
        _splice(client, upstream)
    except (OSError, ConnectionError, struct.error):
        return
    finally:
        try:
            client.close()
        except OSError:
            pass


def _splice(a, b):
    a.settimeout(None)
    b.settimeout(None)
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 300)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        return
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


def main():
    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # accept IPv4-mapped too
    except OSError:
        pass
    srv.bind(("::", LISTEN_PORT))
    srv.listen(128)
    print("[adrange] scoped SOCKS5 listening on :%d (DC loopback; candidate=AD ports, validator=9443)"
          % LISTEN_PORT)
    while True:
        try:
            client, _ = srv.accept()
        except OSError:
            continue
        threading.Thread(target=_handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
