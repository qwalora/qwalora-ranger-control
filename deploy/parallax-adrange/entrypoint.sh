#!/usr/bin/env bash
# Live AD range entrypoint: provision a fresh Samba AD Domain Controller, plant the attack path,
# start the private proof server, then run the DC in the foreground.
#
# The domain is provisioned fresh on every boot (ephemeral range). The Administrator password comes
# from ADRANGE_ADMIN_PASSWORD, so the proof target (its NT hash) is STABLE across restarts as long as
# that secret is stable; krbtgt and machine keys are random per provision.
set -euo pipefail

REALM="${ADRANGE_REALM:-QWALORA.RANGE}"
DOMAIN="${ADRANGE_NETBIOS:-QWALORA}"
ADMINPASS="${ADRANGE_ADMIN_PASSWORD:?ADRANGE_ADMIN_PASSWORD must be set}"
FOOTHOLD_USER="${ADRANGE_FOOTHOLD_USER:-ranger}"
FOOTHOLD_PASS="${ADRANGE_FOOTHOLD_PASSWORD:?ADRANGE_FOOTHOLD_PASSWORD must be set}"
FORWARDER="${ADRANGE_DNS_FORWARDER:-1.1.1.1}"

SAMDB=/var/lib/samba/private/sam.ldb

provision() {
  echo "[adrange] provisioning AD DC: realm=$REALM domain=$DOMAIN"
  rm -f /etc/samba/smb.conf
  samba-tool domain provision \
    --use-rfc2307 \
    --realm="$REALM" \
    --domain="$DOMAIN" \
    --server-role=dc \
    --adminpass="$ADMINPASS" \
    --option="dns forwarder=$FORWARDER" \
    --option="ad dc functional level=2016" \
    --option="vfs objects=" \
    >/tmp/provision.log 2>&1 || { echo "[adrange] provision FAILED"; cat /tmp/provision.log; exit 1; }
  # Allow weak/legacy crypto so standard offensive tooling (impacket NTLM, RC4 Kerberoast) works as it
  # would against a real misconfigured enterprise DC. This is a TRAINING range, intentionally weak.
  {
    echo "    ntlm auth = yes"
    echo "    server min protocol = NT1"
    echo "    kdc:force enable rc4 weak session keys = yes"
  } >> /etc/samba/smb.conf
}

if [ ! -f "$SAMDB" ]; then
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

echo "[adrange] starting samba AD DC (foreground)"
exec samba --foreground --no-process-group -s /etc/samba/smb.conf
