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
echo "=== PARALLAX MODEL PROVENANCE ==="
ollama show "$MODEL" 2>/dev/null | head -20 || true

# GENUINE-INFERENCE SELF-TEST: run one benign generation through the local API and log the actual
# response + timing. This is read from Railway deploy logs to VERIFY real inference without exposing
# any public endpoint. It is a liveness proof, never a research finding.
echo "=== PARALLAX INFERENCE SELF-TEST ==="
# Use the ollama CLI (the image has no curl) to run ONE real generation and log it. Genuine liveness
# proof read from Railway logs; never a research finding.
T0=$(date +%s)
RESP=$(ollama run "$MODEL" "Reply with exactly the single token: PARALLAX-LIVE" 2>&1 || echo "selftest_failed")
T1=$(date +%s)
echo "SELFTEST_MODEL=$MODEL"
echo "SELFTEST_RESPONSE<<<$RESP>>>"
echo "SELFTEST_DURATION_S=$((T1 - T0))"
echo "=== END SELF-TEST ==="

wait "$OLLAMA_PID"
