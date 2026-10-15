# Qwalora Ranger SIEM — OpenSearch Dashboards for Railway (Phase 2b).
# Bakes ONLY the Ranger CA public certificate (not secret) so Dashboards can verify
# the OpenSearch node certificate (full TLS verification, no insecure "none" mode).
FROM opensearchproject/opensearch-dashboards:2.17.1

COPY ca.pem /usr/share/opensearch-dashboards/config/ranger-ca.pem
