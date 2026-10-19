# WS6 - parallax-nonprod cost and reliability (measured)

All figures below are MEASURED from Railway (service metrics + volume config), observed over a
~1 hour window on 2026-10-19 (approx 01:55-02:55 UTC, 5-minute samples), unless explicitly labelled
an estimate. No numbers here are fabricated; where something is not measured it is said so.

## 1. Service inventory and observed consumption (measured)

| Service | Idle resident mem | Idle CPU | Replicas | Volume | Source |
|---|---|---|---|---|---|
| parallax-portal (control plane) | ~0.13 GB | ~0.0001 vCPU | 1 | none | repo, branch feature/parallax-p1-architecture-foundations |
| parallax-inference (Qwen/Ollama) | ~0.64 GB (flat) | ~0.0002 vCPU | 1 | parallax-inference-volume | repo, root deploy/parallax-inference |
| parallax-postgres | ~0.06 GB | ~0.0002 vCPU | 1 | parallax-postgres-volume | image ghcr.io/railwayapp-templates/postgres-ssl:18 |
| qwalora-ranger-control (accidental) | ~0.12 GB | ~0.0001 vCPU | 1 | none | repo qwalora/qwalora-ranger-control |

All services: 1 replica, region us-west2, a 24 GB per-service memory limit (actual use is a small
fraction). All four are live/SUCCESS.

## 2. Always-on Qwen inference (measured)

- Model: `qwen2.5:0.5b-instruct` (Qwen2, Q4_K_M, ~494M params, ~0.40 GB on disk, confirmed via the
  Ollama `/api/tags` on the private network). A `/api/generate` returns real text (verified: "OK.").
- Idle resident memory ~0.64 GB and flat across the hour; a generate briefly raised it to ~0.66 GB and
  it returned to ~0.65 GB. Consistent with the model being kept loaded (warm).
- Scale-to-zero is NOT in effect and is not practical here: an attached volume generally pins a Railway
  service on, and a cold start reloads the model (~6 s first request). Treat inference as always-on
  while a cohort is active.

## 3. Oversized volumes (measured) - the main avoidable cost

| Volume | Provisioned | Actual used | Attached |
|---|---|---|---|
| parallax-postgres-volume | 50,000 MB (~50 GB) | 0.87 GB | parallax-postgres:/var/lib/postgresql/data |
| parallax-inference-volume | 50,000 MB (~50 GB) | 1.19 GB | parallax-inference:/root/.ollama |

Both volumes are the Railway default 50 GB but only ~1 GB is used (~98% unused). Railway bills by
PROVISIONED size, so this is the largest avoidable line in the environment.

## 4. Accidental service: qwalora-ranger-control

Measured: no volumes, no service variables, no domains (public or custom), and no other service
references it (checked portal/inference/postgres variable references). It is an idle copy of the app
from `main`, ~0.12 GB resident. Safe for the operator to delete.

Safe manual cleanup (operator, Railway dashboard - I did not perform this; tooling delete was declined
earlier and this is an operator action):
1. Railway -> project qwalora-ranger -> environment parallax-nonprod -> service `qwalora-ranger-control`.
2. Confirm (again) it has no volumes, no variables, no domains, no dependents (Settings + Variables + Domains tabs).
3. Settings -> Danger -> Remove service. It has no persistent data, so removal is non-destructive here.
External consumers (a DNS record or another project pointing at it) cannot be seen from inside this
environment; confirm none exist before removing.

## 5. Restart, recovery, backup, resource-failure (assessed from observations)

- Restart/recovery: each service is a Railway deployment. The portal restart is safe and stateless (all
  state is in Postgres); it redeploys from the tracked feature branch. OBSERVED recovery: the inference
  service had a FAILED deployment (`f8e75a19`, 2026-10-18 23:13 UTC) and then a SUCCESS deployment
  (`1552228d`) that is the current live one - real evidence that a failed deploy did not take the
  environment down and recovery worked.
- Model reload: on a restart the inference service reloads the model from its volume; on a fresh/empty
  volume Ollama re-pulls `qwen2.5:0.5b-instruct` from the registry (prior observation ~9 s). The first
  request after a cold start pays a model-load latency (~6 s); the portal's model-health probe surfaces
  this honestly (live=False or a higher latency) rather than hiding it.
- Backup: Postgres data persists on its Railway volume across restarts. No application-level `pg_dump`
  schedule is configured. RECOMMEND a periodic `pg_dump` of the (small, ~0.87 GB) nonprod database to an
  object store or artifact - it is non-destructive and gives a portable restore point independent of the
  volume. (Railway may also offer volume-level backups at the platform level; confirm in the dashboard.)
- Resource-failure: with a 24 GB memory limit and <1 GB actual use per service, OOM risk is negligible.
  Single replica means no HA - a restart is a brief outage, acceptable for a nonproduction assessment
  environment. The disposable per-candidate datasets regenerate deterministically, so a portal restart
  loses no candidate-visible lab state.

## 6. Cost improvement recommendations

Safe to do without new billable infra (destructive ones are AUTHORIZATION-GATED and NOT performed here):
1. Delete the accidental `qwalora-ranger-control` service (operator, section 4) - pure waste, no data.
2. Reduce both 50 GB volumes to ~5 GB (create-new-smaller + migrate + delete-old). Railway volumes cannot
   shrink in place. Inference volume is lowest risk (the model re-pulls); the Postgres volume needs
   pg_dump -> new volume -> restore -> verify row counts + a signature check -> delete old. Requires your
   explicit authorization; NOT performed.
3. Add a scheduled `pg_dump` backup of the nonprod DB (small, safe, non-destructive).
4. Keep inference always-on while a cohort is active; for long inter-cohort idle, snapshot + destroy the
   inference service and recreate on the next cohort (adds a one-time model re-pull + cold start), only
   if the volume line is not already reduced.

The dominant avoidable cost is the two oversized volumes (item 2); the quickest zero-risk win is deleting
the accidental service (item 1). I provisioned nothing, deleted nothing, and shrank nothing - these are
recommendations and operator steps, pending your authorization.
