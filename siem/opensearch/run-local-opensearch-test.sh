#!/usr/bin/env bash
# STRATA S5.1 - bring up a DISPOSABLE local OpenSearch 2.17.1 node, create the authorizing sentinel,
# and print the exact env exports the real-node validation suite needs. Run on a machine that CAN
# pull opensearchproject/opensearch:2.17.1 and run Docker. Run the test process ON THE HOST (not in a
# container), so it reaches 127.0.0.1:9200 directly and no egress proxy / CA rewriting is involved.
#
# Usage:
#   OPENSEARCH_INITIAL_ADMIN_PASSWORD='<StrongPass123!>' ./run-local-opensearch-test.sh up
#   ./run-local-opensearch-test.sh down        # destroy the node and all data
#
# The node is loopback-only, uses the image's demo TLS (self-signed), keeps the Security plugin
# ENABLED, and holds no production data. See docker-compose.test.yml for the precise differences from
# the production security configuration.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="docker compose -f ${HERE}/docker-compose.test.yml"
URL="https://127.0.0.1:9200"
SENTINEL=".ranger-ostest-sentinel"

cmd="${1:-up}"

if [ "$cmd" = "down" ]; then
  ${COMPOSE} down -v
  echo "disposable OpenSearch node destroyed."
  exit 0
fi

: "${OPENSEARCH_INITIAL_ADMIN_PASSWORD:?set OPENSEARCH_INITIAL_ADMIN_PASSWORD to a strong test password}"
export OPENSEARCH_INITIAL_ADMIN_PASSWORD

${COMPOSE} up -d

echo "waiting for the node to report healthy..."
for i in $(seq 1 60); do
  if curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" "${URL}/_cluster/health" >/dev/null 2>&1; then
    break
  fi
  sleep 3
done

ver="$(curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" "${URL}/" | sed -n 's/.*"number"[ ]*:[ ]*"\([^"]*\)".*/\1/p' | head -1)"
echo "node version: ${ver:-unknown} (required: 2.17.1)"

# Create the authorizing sentinel index (its mere presence authorizes destructive tests; a localhost
# address alone is not sufficient proof - see siem/tests/_ostest.py).
curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" -X PUT "${URL}/${SENTINEL}" >/dev/null || true
echo "authorizing sentinel index created: ${SENTINEL}"

cat <<EOF

# ---------------------------------------------------------------------------
# Export these, then run the real-node validation suite ON THIS HOST:
# ---------------------------------------------------------------------------
export RANGER_TEST_ALLOW_OS_MUTATION=1
export RANGER_TEST_OPENSEARCH_URL='${URL}'
export RANGER_TEST_OPENSEARCH_USER='admin'
export RANGER_TEST_OPENSEARCH_PASSWORD='${OPENSEARCH_INITIAL_ADMIN_PASSWORD}'
# (optional, for full TLS verification instead of the relaxed test context):
# export RANGER_TEST_OS_CA='/path/to/node-ca.pem'
# (only if the node is not exactly 2.17.1, and only knowingly):
# export RANGER_TEST_OS_ALLOW_VERSION_MISMATCH=1

python3 -m pytest siem/tests/test_strata_s5_real_opensearch.py -v
# tear down when done:  ${HERE}/run-local-opensearch-test.sh down
EOF
