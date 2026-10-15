# Qwalora Ranger SIEM — OpenSearch node for the Railway Phase 2a validation pilot.
# Pinned single-node OpenSearch with the Security plugin enabled. The only customization
# over the stock image is a root entrypoint that fixes Railway volume ownership (the image
# runs as uid 1000; Railway volumes mount as root) before dropping privileges.
FROM opensearchproject/opensearch:2.17.1

USER root

# Single-node discovery is appended (the key is absent from the stock opensearch.yml, so no
# duplicate-key error). Single-node mode also skips the production bootstrap checks
# (vm.max_map_count, memlock), which is what makes OpenSearch viable on Railway's shared host.
RUN echo "discovery.type: single-node" >> /usr/share/opensearch/config/opensearch.yml

COPY entrypoint-railway.sh /usr/local/bin/entrypoint-railway.sh
RUN chmod +x /usr/local/bin/entrypoint-railway.sh

ENTRYPOINT ["/usr/local/bin/entrypoint-railway.sh"]
CMD ["opensearch"]
