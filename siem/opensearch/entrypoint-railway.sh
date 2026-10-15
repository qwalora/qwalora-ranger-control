#!/bin/bash
# Ranger SIEM OpenSearch entrypoint for Railway.
#   1. (as root) fix volume ownership, write managed TLS certs from runtime secrets,
#      ensure the snapshot repo dir exists, then drop to uid 1000.
#   2. (as uid 1000) on FIRST boot only, rotate the reserved admin/kibanaserver
#      credentials and install least-privilege users via securityadmin (the REST API
#      cannot touch reserved users), guarded by a sentinel so restarts never clobber
#      runtime-provisioned candidate users. Then exec OpenSearch in the foreground.
set -euo pipefail

CONF=/usr/share/opensearch/config
CERTS="$CONF/certs"
SEC="$CONF/opensearch-security"
TOOLS=/usr/share/opensearch/plugins/opensearch-security/tools
DATA="${RAILWAY_VOLUME_MOUNT_PATH:-/usr/share/opensearch/data}"
OS_ENTRYPOINT=/usr/share/opensearch/opensearch-docker-entrypoint.sh

write_cert() { # $1 env var holding base64, $2 destination filename
  local v="${1}"; local f="$2"
  if [ -n "${!v:-}" ]; then echo "${!v}" | base64 -d > "$CERTS/$f"; fi
}

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA" "$DATA/snapshots" "$CERTS"
  write_cert RANGER_CA_B64 ca.pem
  write_cert RANGER_NODE_CERT_B64 node.pem
  write_cert RANGER_NODE_KEY_B64 node-key.pem
  write_cert RANGER_ADMIN_CERT_B64 admin.pem
  write_cert RANGER_ADMIN_KEY_B64 admin-key.pem
  chmod 600 "$CERTS"/*-key.pem 2>/dev/null || true
  chmod 644 "$CERTS"/ca.pem "$CERTS"/node.pem "$CERTS"/admin.pem 2>/dev/null || true
  chown -R 1000:1000 "$DATA" "$CERTS"
  exec chroot --skip-chdir --userspec=1000:1000 / "$0" "$@"
fi

# ---- running as uid 1000 ----
SENTINEL="$DATA/.ranger_security_applied"
# Bumped to _v2: the config now also enables Security-plugin multitenancy (private
# tenants), so the dynamic config must be re-applied once on the next boot.
SENTINEL_JWT="$DATA/.ranger_jwt_applied_v2"

# v2: install the candidate JWT authc domain via securityadmin (config type). The
# roles claim is intentionally NOT trusted (no roles_key); authz is by username
# (sub) -> server-side roles_mapping. Guarded so it applies once.
if [ ! -f "$SENTINEL_JWT" ] && [ -n "${RANGER_JWT_PUBLIC_B64:-}" ]; then
  (
    cat > "$CONF/opensearch-security/config.yml" <<EOF
---
_meta:
  type: "config"
  config_version: 2
config:
  dynamic:
    http:
      anonymous_auth_enabled: false
    authc:
      jwt_auth_domain:
        description: "Ranger candidate JWT (RS256, issuer/audience enforced)"
        http_enabled: true
        transport_enabled: false
        order: 0
        http_authenticator:
          type: jwt
          challenge: false
          config:
            signing_key: "$RANGER_JWT_PUBLIC_B64"
            jwt_header: "Authorization"
            required_issuer: "qwalora-ranger"
            required_audience: "qwalora-siem"
            subject_key: "sub"
            jwt_clock_skew_tolerance_seconds: 30
        authentication_backend:
          type: noop
      basic_internal_auth_domain:
        description: "Internal users (admin, kibanaserver, ranger_*)"
        http_enabled: true
        transport_enabled: true
        order: 1
        http_authenticator:
          type: basic
          challenge: true
          config: {}
        authentication_backend:
          type: internal
    authz: {}
    kibana:
      # Enable OpenSearch Dashboards multitenancy at the Security layer so per-user
      # PRIVATE tenants work (saved-object isolation per candidate and the SOC admin).
      # Without this block the plugin denies any requestedTenant=__user__.
      multitenancy_enabled: true
      private_tenant_enabled: true
      default_tenant: ""
      server_username: kibanaserver
      index: ".kibana"
EOF
    for i in $(seq 1 60); do
      if "$TOOLS/securityadmin.sh" -t config -f "$CONF/opensearch-security/config.yml" \
          -icl -nhnv -cacert "$CERTS/ca.pem" -cert "$CERTS/admin.pem" \
          -key "$CERTS/admin-key.pem" -h localhost -p 9200 >/tmp/sa-jwt.log 2>&1; then
        touch "$SENTINEL_JWT"
        echo "[ranger] securityadmin applied JWT authc domain."
        break
      fi
      sleep 5
    done
    [ -f "$SENTINEL_JWT" ] || { echo "[ranger] JWT authc NOT applied; retry next boot."; tail -n 20 /tmp/sa-jwt.log || true; }
  ) &
fi

if [ ! -f "$SENTINEL" ] && [ -n "${RANGER_NEW_ADMIN_PW:-}" ]; then
  (
    hash_pw() { bash "$TOOLS/hash.sh" -p "$1" 2>/dev/null | tr -d '\r' | tail -n 1; }
    AH=$(hash_pw "$RANGER_NEW_ADMIN_PW")
    KH=$(hash_pw "$RANGER_NEW_KIBANA_PW")
    IH=$(hash_pw "$RANGER_INGEST_PW")
    SH=$(hash_pw "$RANGER_SEARCH_PW")
    VH=$(hash_pw "$RANGER_VALIDATOR_PW")
    cat > "$SEC/internal_users.yml" <<EOF
---
_meta:
  type: "internalusers"
  config_version: 2
admin:
  hash: "$AH"
  reserved: true
  backend_roles: ["admin"]
  description: "Ranger break-glass admin"
kibanaserver:
  hash: "$KH"
  reserved: true
  description: "Dashboards server account"
ranger_ingest:
  hash: "$IH"
  reserved: false
  opendistro_security_roles: ["ranger_ingest_role"]
  description: "Ingestion identity (write ranger-*)"
ranger_search:
  hash: "$SH"
  reserved: false
  opendistro_security_roles: ["ranger_search_role"]
  description: "Backend search identity (read ranger-*)"
ranger_validator:
  hash: "$VH"
  reserved: false
  opendistro_security_roles: ["all_access", "security_rest_api_access"]
  description: "Isolated validation identity (disableable)"
EOF
    # Wait for the node, then apply ONLY the internalusers config via the admin cert.
    ok=0
    for i in $(seq 1 60); do
      if "$TOOLS/securityadmin.sh" -t internalusers -f "$SEC/internal_users.yml" \
          -icl -nhnv -cacert "$CERTS/ca.pem" -cert "$CERTS/admin.pem" \
          -key "$CERTS/admin-key.pem" -h localhost -p 9200 >/tmp/sa.log 2>&1; then
        ok=1; break
      fi
      sleep 5
    done
    if [ "$ok" = "1" ]; then
      touch "$SENTINEL"
      echo "[ranger] securityadmin applied internalusers; reserved creds rotated."
    else
      echo "[ranger] securityadmin did NOT apply (node not ready or error); will retry next boot."
      tail -n 20 /tmp/sa.log || true
    fi
  ) &
fi

exec "$OS_ENTRYPOINT" "$@"
