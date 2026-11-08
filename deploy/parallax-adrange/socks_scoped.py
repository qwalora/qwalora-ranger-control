#!/usr/bin/env python3
"""Scoped SOCKS5 pivot for the live AD range.

A deliberately-vulnerable, internet-reachable DC must not double as an open relay. microsocks forwards
anywhere; this does not. It is a minimal SOCKS5 proxy that:

  * REQUIRES username/password auth (RFC 1929) - no anonymous access;
  * IGNORES the client's requested destination host and ALWAYS connects to the DC on loopback
    (127.0.0.1), so the proxy can never reach any host but the range itself; and
  * only allows the AD service ports the attack chain needs - every other port is refused.

So a candidate tunnels in with proxychains, targets any placeholder IP (e.g. 10.10.10.10) on a standard
AD port, and lands on the DC; they cannot use the pivot to reach the portal, the internet, or anything
else. Because the destination host is ignored, there is also no proxychains loopback-bypass gotcha:
the client never has to target 127.0.0.1.

Binds dual-stack (IPv6 with V6ONLY off) so Railway's TCP-proxy edge reaches it the same way the proof
server is reached over private networking.
"""
import os
import select
import socket
import struct
import threading

USER = os.environ.get("ADRANGE_SOCKS_USER", "ranger").encode()
PASSWORD = os.environ.get("ADRANGE_SOCKS_PASSWORD", "").encode()
LISTEN_PORT = int(os.environ.get("ADRANGE_SOCKS_PORT", "1080") or 1080)
DC = "127.0.0.1"  # the DC runs in this same container; only loopback is ever dialed.
# AD service ports the chain needs: DNS, Kerberos, EPM, LDAP, SMB, kpasswd, LDAPS, Global Catalog.
ALLOWED_PORTS = frozenset({53, 88, 135, 389, 445, 464, 636, 3268, 3269})

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
        import hmac
        ok = (avr == 0x01 and hmac.compare_digest(uname, USER)
              and PASSWORD and hmac.compare_digest(passwd, PASSWORD))
        client.sendall(struct.pack("!BB", 0x01, 0x00 if ok else 0x01))
        if not ok:
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
        if port not in ALLOWED_PORTS:
            _reply(client, _REP_RULESET)   # scope: only AD ports on the DC are reachable
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
    print("[adrange] scoped SOCKS5 listening on :%d (DC loopback, AD ports only)" % LISTEN_PORT)
    while True:
        try:
            client, _ = srv.accept()
        except OSError:
            continue
        threading.Thread(target=_handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
