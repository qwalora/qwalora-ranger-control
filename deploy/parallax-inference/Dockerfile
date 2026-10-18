# PARALLAX private inference service (PREPARED, not deployed).
# A single genuine small instruction model served by Ollama on Railway's PRIVATE network only.
# No public domain is attached; candidates never reach this service directly - the portal mediates.
#
# This file is deployment configuration only. It is NOT built or deployed by committing it: the portal
# service's autodeploy hold (watchPatterns=["/.railway-autodeploy-hold/**"]) is unaffected by anything
# under deploy/, and this service does not yet exist. Deploy only after explicit provisioning approval.
FROM ollama/ollama:0.12.3

# Model weights persist on a Railway volume mounted at /root/.ollama (see railway.service.json).
ENV OLLAMA_MODELS=/root/.ollama/models
# Bind to the IPv6 wildcard so the service is reachable over Railway private networking
# (<service>.railway.internal) and NOT exposed publicly.
ENV OLLAMA_HOST=[::]:11434
# Keep the model resident to avoid reload latency; single model, low concurrency.
ENV OLLAMA_KEEP_ALIVE=24h
ENV OLLAMA_MAX_LOADED_MODELS=1
ENV OLLAMA_NUM_PARALLEL=1

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 11434
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
