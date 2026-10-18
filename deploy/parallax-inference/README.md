# PARALLAX private inference service (PREPARED, not deployed)

These files describe a single, genuine, small instruction model served by Ollama on Railway's private
network, for the PARALLAX AI-security research workspace. Nothing here is deployed. Provision only after
explicit cost + isolation approval, and only in a nonproduction environment. See
`docs/PARALLAX_PHASE_2C_RAILWAY_WORKSPACE_REPORT.md` for the full plan, cost estimate, isolation design,
and the deploy-time verification checklist.

Contents:
- `Dockerfile` - Ollama base, private IPv6 bind, single resident model.
- `entrypoint.sh` - starts Ollama, pulls the pinned model onto the volume at first boot (fails loudly if
  Railway egress to the model registry is blocked; never fabricates success).
- `railway.service.json` - reference service spec (region, private networking, volume, resources,
  healthcheck) and the portal wiring variables. Not a deploy manifest.

Hard boundaries (unchanged this phase):
- No public domain on this service; candidates never reach Ollama directly (the portal mediates and
  enforces rate/size/time limits).
- Deploy into a PARALLAX nonproduction environment only; never production; never mutate production
  PostgreSQL or use the production signing authority for research runs.
- The portal autodeploy hold (`watchPatterns=["/.railway-autodeploy-hold/**"]`) and the staged Railway
  patch are not touched by anything here.
