#!/usr/bin/env sh
# PARALLAX private inference entrypoint (PREPARED, not deployed).
# Starts Ollama, ensures the pinned genuine model is present on the persistent volume, and stays up.
# Model acquisition happens INSIDE Railway at first boot; it is NOT assumed to work until verified in
# Railway egress (a Phase 2C post-approval check), because Claude's build container cannot reach the
# model registry. If the pull fails, the container exits non-zero so the failure is visible, never faked.
set -eu

MODEL="${PARALLAX_MODEL_TAG:-qwen2.5:0.5b-instruct}"

# start the server in the background
ollama serve &
OLLAMA_PID=$!

# wait for the local API to answer (private bind)
i=0
until ollama list >/dev/null 2>&1; do
  i=$((i+1))
  if [ "$i" -gt 60 ]; then echo "ollama did not become ready in time" >&2; exit 1; fi
  sleep 1
done

# ensure the pinned model is present (idempotent; persisted on the mounted volume)
if ! ollama list | grep -q "$MODEL"; then
  echo "pulling model $MODEL ..."
  ollama pull "$MODEL"      # requires Railway egress to the Ollama registry; verify post-approval
fi

# record the resolved model digest for provenance (operators capture this in the run manifest)
ollama show "$MODEL" --modelfile 2>/dev/null | head -5 || true

wait "$OLLAMA_PID"
