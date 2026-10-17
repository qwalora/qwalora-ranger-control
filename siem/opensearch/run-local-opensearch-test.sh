#!/usr/bin/env bash
# STRATA S5.1 - bring up a DISPOSABLE local OpenSearch 2.17.1 node with POSITIVE readiness
# verification, create the authorizing sentinel only after verification, and print the exact env
# exports the real-node validation suite needs. Run on a Docker-capable host with authorized access
# to opensearchproject/opensearch:2.17.1. Run the test process ON THE HOST (not in a container), so
# it reaches 127.0.0.1:9200 directly with no egress proxy or CA rewriting involved.
#
# Usage:
#   OPENSEARCH_INITIAL_ADMIN_PASSWORD='<StrongPass123!>' ./run-local-opensearch-test.sh up
#   ./run-local-opensearch-test.sh down     # destroy ONLY this compose project's node + volumes
#
# The node is loopback-only, uses the image's demo TLS (self-signed), keeps the Security plugin
# ENABLED, and holds no production data. See docker-compose.test.yml for the precise differences from
# the production security configuration. Secrets are never printed to the log.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE=(docker compose -f "${HERE}/docker-compose.test.yml")
URL="https://127.0.0.1:9200"
SENTINEL=".ranger-ostest-sentinel"
REQUIRED_VERSION="2.17.1"
CONTAINER="ranger-ostest-2171"

die() { echo "ERROR: $*" >&2; exit 1; }

# Authenticated HTTP status for a request; prints only the numeric code (never the password).
http_code() {
  local method="$1" path="$2"
  curl -sk -o /dev/null -w '%{http_code}' -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
    -X "$method" "${URL}${path}"
}
# Authenticated body (used for identity/plugin checks). Caller must not echo secrets.
http_body() {
  curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" "${URL}$1"
}

cmd="${1:-up}"

if [ "$cmd" = "down" ]; then
  # (10) safe teardown of ONLY this compose project's resources
  "${COMPOSE[@]}" down -v
  echo "disposable OpenSearch node and its volumes destroyed."
  exit 0
fi

: "${OPENSEARCH_INITIAL_ADMIN_PASSWORD:?set OPENSEARCH_INITIAL_ADMIN_PASSWORD to a strong test password}"
export OPENSEARCH_INITIAL_ADMIN_PASSWORD

"${COMPOSE[@]}" up -d

# (1) confirm the container actually started and is running
echo "[1/8] waiting for container ${CONTAINER} to be running..."
for _ in $(seq 1 30); do
  state="$(docker inspect -f '{{.State.Status}}' "${CONTAINER}" 2>/dev/null || echo missing)"
  [ "$state" = "running" ] && break
  sleep 2
done
[ "${state:-}" = "running" ] || die "container ${CONTAINER} is not running (state=${state:-missing}); see: ${COMPOSE[*]} logs"

# (2) confirm an AUTHENTICATED API request actually succeeds (HTTP 200, not merely a curl exit).
echo "[2/8] waiting for an authenticated 200 from the cluster health API..."
code=000
for _ in $(seq 1 60); do
  code="$(http_code GET /_cluster/health || echo 000)"
  [ "$code" = "200" ] && break
  sleep 3
done
[ "$code" = "200" ] || die "cluster health did not return 200 (last HTTP ${code}); a 401/403 means the admin password is wrong, 000 means not reachable yet"

# (3) verify distribution identity and EXACT version
echo "[3/8] verifying distribution identity and version..."
root_json="$(http_body /)"
dist="$(printf '%s' "$root_json" | sed -n 's/.*"distribution"[ ]*:[ ]*"\([^"]*\)".*/\1/p' | head -1)"
ver="$(printf '%s'  "$root_json" | sed -n 's/.*"number"[ ]*:[ ]*"\([^"]*\)".*/\1/p' | head -1)"
[ "$dist" = "opensearch" ] || die "node is not OpenSearch (distribution='${dist:-unknown}')"
[ "$ver" = "$REQUIRED_VERSION" ] || die "node version is '${ver:-unknown}', required ${REQUIRED_VERSION}"
echo "       distribution=opensearch version=${ver}"

# (4) confirm the Security plugin is active (health endpoint + installed-plugin list)
echo "[4/8] confirming the Security plugin is active..."
sec_code="$(http_code GET /_plugins/_security/health || echo 000)"
plugins="$(http_body '/_cat/plugins?h=component' || true)"
if [ "$sec_code" != "200" ] && ! printf '%s' "$plugins" | grep -qi 'opensearch-security'; then
  die "the Security plugin is not active (security health HTTP ${sec_code}); refusing to proceed with security disabled"
fi

# (5) confirm this is the intended DISPOSABLE instance: no production-like or unexpected non-test
#     indices. A fresh image node has only system (dot) indices at this point.
echo "[5/8] confirming the node is a fresh disposable instance..."
idx_json="$(http_body '/_cat/indices?format=json&h=index&expand_wildcards=all' || echo '[]')"
bad="$(printf '%s' "$idx_json" \
  | tr ',' '\n' | sed -n 's/.*"index"[ ]*:[ ]*"\([^"]*\)".*/\1/p' \
  | grep -Ev '^\.' | grep -Ev 'ostest|test' || true)"
[ -z "$bad" ] || die "node is not fresh/disposable; unexpected non-test indices present: $(printf '%s' "$bad" | tr '\n' ' ')"

# (6) create the authorizing sentinel ONLY after positive verification, and (7) verify it was created
echo "[6/8] creating the authorizing sentinel ${SENTINEL}..."
put_code="$(http_code PUT "/${SENTINEL}")"
[ "$put_code" = "200" ] || [ "$put_code" = "201" ] || die "failed to create sentinel ${SENTINEL} (HTTP ${put_code})"
echo "[7/8] verifying the sentinel exists..."
head_code="$(http_code HEAD "/${SENTINEL}")"
[ "$head_code" = "200" ] || die "sentinel ${SENTINEL} not found after creation (HTTP ${head_code})"

echo "[8/8] node verified disposable, 2.17.1, security-enabled, sentinel present."

# (9) never print the admin password; the exports below reference an env var the operator set.
cat <<'EOF'

# ---------------------------------------------------------------------------
# Export these (the password comes from the env var YOU set), then run the
# real-node validation suite ON THIS HOST:
# ---------------------------------------------------------------------------
export RANGER_TEST_ALLOW_OS_MUTATION=1
export RANGER_TEST_OPENSEARCH_URL='https://127.0.0.1:9200'
export RANGER_TEST_OPENSEARCH_USER='admin'
export RANGER_TEST_OPENSEARCH_PASSWORD="$OPENSEARCH_INITIAL_ADMIN_PASSWORD"
# optional full TLS verification:  export RANGER_TEST_OS_CA='/path/to/node-ca.pem'
# only if the node is knowingly not 2.17.1:  export RANGER_TEST_OS_ALLOW_VERSION_MISMATCH=1

python3 -m pytest siem/tests/test_strata_s5_real_opensearch.py -v
EOF
echo "# tear down when done:  ${HERE}/run-local-opensearch-test.sh down"
