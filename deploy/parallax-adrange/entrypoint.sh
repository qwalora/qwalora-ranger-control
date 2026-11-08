#!/usr/bin/env bash
# Live AD range entrypoint: provision a fresh Samba AD Domain Controller, plant the attack path,
# start the private proof server, then run the DC in the foreground.
#
# The domain is provisioned fresh on every boot (ephemeral range). The Administrator password comes
# from ADRANGE_ADMIN_PASSWORD, so the proof target (its NT hash) is STABLE across restarts as long as
# that secret is stable; krbtgt and machine keys are random per provision.
set -euo pipefail

# Samba's ldb modules (samba_secrets, etc.) are not always on ldb's default search path in a slim
# image; without them `samba-tool domain provision` fails at secrets.ldb. Point LDB_MODULES_PATH at
# whichever directory actually holds the samba ldb modules.
if [ -z "${LDB_MODULES_PATH:-}" ]; then
  for d in /usr/lib/*/samba/ldb /usr/lib/samba/ldb /usr/lib/*/ldb/modules/ldb; do
    if [ -d "$d" ]; then export LDB_MODULES_PATH="$d"; break; fi
  done
fi
echo "[adrange] LDB_MODULES_PATH=${LDB_MODULES_PATH:-<unset>}"
if [ -n "${ADRANGE_DIAG:-}" ]; then
  echo "[adrange][diag] secrets modules:"; find /usr/lib /usr/local/lib -name 'secrets*' 2>/dev/null | head -20
  echo "[adrange][diag] ldb .so modules:"; find /usr/lib /usr/local/lib -name '*.so' -path '*ldb*' 2>/dev/null | head -60
fi

REALM="${ADRANGE_REALM:-QWALORA.RANGE}"
DOMAIN="${ADRANGE_NETBIOS:-QWALORA}"
ADMINPASS="${ADRANGE_ADMIN_PASSWORD:?ADRANGE_ADMIN_PASSWORD must be set}"
FOOTHOLD_USER="${ADRANGE_FOOTHOLD_USER:-ranger}"
FOOTHOLD_PASS="${ADRANGE_FOOTHOLD_PASSWORD:?ADRANGE_FOOTHOLD_PASSWORD must be set}"
FORWARDER="${ADRANGE_DNS_FORWARDER:-1.1.1.1}"

# A completion sentinel, written only after a FULLY successful provision. A bare sam.ldb is not
# enough: provisioning can create sam.ldb and then fail later (e.g. at the sysvol ACL step), leaving a
# half-provisioned domain that must NOT be reused. On any boot without the sentinel we wipe and
# provision cleanly.
SENTINEL=/var/lib/samba/.adrange_provisioned

provision() {
  echo "[adrange] provisioning AD DC: realm=$REALM domain=$DOMAIN"
  rm -rf /etc/samba/smb.conf /var/lib/samba/private/* /var/lib/samba/sysvol/* 2>/dev/null || true
  # posix:eadb routes extended attributes (including the NT ACLs Samba sets on SYSVOL) into a TDB
  # file instead of privileged security.* filesystem xattrs, which the container's overlay fs cannot
  # store (provisioning otherwise aborts at setsysvolacl with NT_STATUS_ACCESS_DENIED).
  samba-tool domain provision \
    --use-rfc2307 \
    --realm="$REALM" \
    --domain="$DOMAIN" \
    --server-role=dc \
    --host-name="${ADRANGE_DC_HOSTNAME:-DC01}" \
    --adminpass="$ADMINPASS" \
    --option="dns forwarder=$FORWARDER" \
    --option="posix:eadb = /var/lib/samba/eadb.tdb" \
    >/tmp/provision.log 2>&1 || { echo "[adrange] provision FAILED"; cat /tmp/provision.log; exit 1; }
  touch "$SENTINEL"
}

if [ ! -f "$SENTINEL" ]; then
  provision
else
  echo "[adrange] existing domain found; reusing"
fi

# Plant (idempotently) the GOAD-style attack path.
echo "[adrange] seeding attack path"
ADRANGE_REALM="$REALM" ADRANGE_NETBIOS="$DOMAIN" \
ADRANGE_FOOTHOLD_USER="$FOOTHOLD_USER" ADRANGE_FOOTHOLD_PASSWORD="$FOOTHOLD_PASS" \
python3 /opt/adrange/seed.py || { echo "[adrange] seed FAILED"; exit 1; }

# Private-network proof server (portal reads expected proof material here). Never publicly proxied.
echo "[adrange] starting private proof server on :9443"
ADRANGE_ADMIN_PASSWORD="$ADMINPASS" ADRANGE_REALM="$REALM" \
python3 /opt/adrange/proof_server.py &

# SOCKS5 pivot: the ONE publicly-proxied port. Candidates point proxychains here (authenticated) and
# then reach the DC's AD services, exactly as a red-teamer pivots through a foothold. We run a SCOPED
# SOCKS (socks_scoped.py) rather than microsocks: an internet-reachable, deliberately-vulnerable DC
# must not double as an open relay, so the pivot requires auth, ALWAYS connects to the DC loopback
# (ignoring the client's requested host), and only permits AD service ports. It also binds dual-stack
# (IPv6, V6ONLY off) so the Railway TCP-proxy edge reaches it the same way the proof server is reached.
SOCKS_PORT="${ADRANGE_SOCKS_PORT:-1080}"
SOCKS_USER="${ADRANGE_SOCKS_USER:-ranger}"
SOCKS_PASS="${ADRANGE_SOCKS_PASSWORD:?ADRANGE_SOCKS_PASSWORD must be set}"
echo "[adrange] starting scoped SOCKS5 pivot on :$SOCKS_PORT (user $SOCKS_USER, DC loopback, AD ports only)"
ADRANGE_SOCKS_PORT="$SOCKS_PORT" ADRANGE_SOCKS_USER="$SOCKS_USER" ADRANGE_SOCKS_PASSWORD="$SOCKS_PASS" \
python3 /opt/adrange/socks_scoped.py &

# DEBUG ONLY (ADRANGE_DIAG): a loopback DCSync self-test. Runs impacket secretsdump against the DC on
# 127.0.0.1 with NO proxy, so we can tell an impacket<->Samba DRS reply-parse failure apart from the
# SOCKS pivot. Local success + pivot failure => the pivot/splice; local failure => impacket<->Samba.
# svc_mssql keeps its seed password (Password123!) and is already in TierAdmins (DCSync rights).
if [ -n "${ADRANGE_DIAG:-}" ] && command -v secretsdump.py >/dev/null 2>&1; then
  ( sleep 25
    echo "[adrange][selftest] ===== loopback DCSync self-test (no proxy) ====="
    echo "[adrange][selftest] --- A) whole-NC replication: -just-dc-ntlm (no per-user EXOP) ---"
    secretsdump.py "qwalora.range/svc_mssql:Password123!@127.0.0.1" \
      -just-dc-ntlm 2>&1 | sed 's/^/[adrange][selftest] /'
    echo "[adrange][selftest] --- B) single-object path with traceback: -just-dc-user Administrator -debug ---"
    secretsdump.py "qwalora.range/svc_mssql:Password123!@127.0.0.1" \
      -just-dc-user 'QWALORA\Administrator' -debug 2>&1 | sed 's/^/[adrange][selftest] /' | head -60
    echo "[adrange][selftest] ===== self-test done ====="
  ) &
fi

echo "[adrange] starting samba AD DC (foreground)"
exec samba --foreground --no-process-group --debug-stdout -d 1 -s /etc/samba/smb.conf
