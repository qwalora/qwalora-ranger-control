#!/bin/bash
# Ranger Dashboards entrypoint. Writes the full opensearch_dashboards.yml from a
# template at runtime (so the kibanaserver password comes from the environment, not
# the image), then execs Dashboards directly, bypassing the image's env-translation
# so there are no duplicate/ambiguous keys. JWT auth is enabled for candidates: the
# token is read from the Authorization header, which the Ranger gateway injects, so
# it never appears in a URL, browser storage, or client-visible logs.
set -euo pipefail

CFG=/usr/share/opensearch-dashboards/config/opensearch_dashboards.yml
cat > "$CFG" <<EOF
server.host: "0.0.0.0"
server.port: 5601
server.name: "ranger-soc"
server.basePath: "/soc"
server.rewriteBasePath: true
opensearch.hosts: ["https://opensearch.railway.internal:9200"]
opensearch.ssl.verificationMode: full
opensearch.ssl.certificateAuthorities: ["/usr/share/opensearch-dashboards/config/ranger-ca.pem"]
opensearch.username: "kibanaserver"
opensearch.password: "${KIBANASERVER_PW}"
opensearch.requestHeadersAllowlist: ["authorization", "securitytenant"]
opensearch_security.auth.type: "jwt"
opensearch_security.jwt.url_param: "authorization"
opensearch_security.jwt.header: "Authorization"
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.enable_global: false
opensearch_security.multitenancy.tenants.enable_private: true
opensearch_security.multitenancy.tenants.preferred: ["Private"]
opensearch_security.cookie.secure: false
opensearch_security.cookie.ttl: 3600000
opensearch_security.session.ttl: 3600000
opensearch_security.session.keepalive: true
EOF

exec /usr/share/opensearch-dashboards/bin/opensearch-dashboards
