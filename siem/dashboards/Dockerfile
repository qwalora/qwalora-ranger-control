# Qwalora Ranger SIEM — OpenSearch Dashboards for Railway (Phase 2b).
# Bakes the Ranger CA (public) for full TLS verification to OpenSearch, and a
# runtime entrypoint that writes the Dashboards config (JWT auth for candidates;
# token taken from the Authorization header, injected by the Ranger gateway). The
# kibanaserver password is supplied at runtime (KIBANASERVER_PW), never baked.
FROM opensearchproject/opensearch-dashboards:2.17.1

COPY ca.pem /usr/share/opensearch-dashboards/config/ranger-ca.pem
COPY osd-entrypoint.sh /usr/local/bin/osd-entrypoint.sh

USER root
RUN chmod +x /usr/local/bin/osd-entrypoint.sh
USER 1000

ENTRYPOINT ["/usr/local/bin/osd-entrypoint.sh"]
