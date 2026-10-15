# Qwalora Ranger SIEM — OpenSearch node for Railway (Phase 2b hardened).
# Pinned single-node OpenSearch with the Security plugin, managed Ranger TLS, and a
# first-boot credential rotation. Certs and passwords are supplied as RUNTIME env
# vars (never build args), so they are not baked into image layers.
FROM opensearchproject/opensearch:2.17.1

USER root

# Full managed config replaces the stock opensearch.yml (no demo security settings).
COPY opensearch.yml /usr/share/opensearch/config/opensearch.yml
COPY entrypoint-railway.sh /usr/local/bin/entrypoint-railway.sh
RUN chmod +x /usr/local/bin/entrypoint-railway.sh \
 && chown 1000:1000 /usr/share/opensearch/config/opensearch.yml

ENTRYPOINT ["/usr/local/bin/entrypoint-railway.sh"]
CMD ["opensearch"]
