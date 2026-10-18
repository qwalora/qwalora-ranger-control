# PARALLAX Phase 2C - Railway Workspace Readiness Report

**Railway AI inference and first usable research workspace**

Branch: `feature/parallax-p1-architecture-foundations` · HEAD at report time: `62dba87` (+ this commit)
`main`: unchanged at `431a183` · Railway production hold: intact · Both qualification flags: OFF

Status vocabulary: **VERIFIED** (executed and observed), **PREPARED** (implemented/specified, awaiting a
gated action), **BLOCKED** (cannot proceed without an external action), **FAILED** (attempted and
demonstrably unsuccessful).

**This phase stops at the provisioning approval gate, by instruction.** All work here is read-only
reconnaissance plus non-billable repository/configuration preparation. No Railway resource was created,
modified, deployed, or redeployed; the staged patch and the portal autodeploy hold were not touched; no
model was deployed and no real inference was run (that is gated on approval and is **BLOCKED** until
then). The primary acceptance criterion (a user conducting a real investigation backed by Railway
inference) is therefore **BLOCKED pending approval**, with everything up to that gate **PREPARED**.

**Update - founder approvals received (this session):** provisioning APPROVED with idle-scaling; isolation
target APPROVED as a new `parallax-nonprod` environment; first model APPROVED as Qwen2.5-0.5B-Instruct.
A new, narrower prerequisite then surfaced: the available Railway MCP tooling has **no
create-environment operation** (it exposes create-project/service/volume/deployment/variables, not
environment creation). Creating the `parallax-nonprod` environment is therefore an **operator action**
(Section 2). Once it exists, the inference service, volume, variables, and deployment can be provisioned
through MCP within that environment, and inference verified via the nonprod portal. Live provisioning is
held at this operator prerequisite; no production environment was used as a substitute.

---

## 1. Existing Railway inventory (VERIFIED, read-only)

Project `qwalora-ranger` (`ee093894-30f7-4c82-ab5d-d7ef4d1a6454`), workspace "Franck Kengne's Projects".
Single environment: `production` (`10fa3e73-9a53-42dd-84a2-bd9a9f628e55`). Region observed: `us-west2`.

| Service | ID | Volume | Last deploy |
|---|---|---|---|
| Postgres | 61497bbf... | postgres-volume 50 GB @ us-west2 (`/var/lib/postgresql/data`) | SUCCESS |
| portal | f5b563f8... | none | SUCCESS |
| opensearch-5IDf | 604d93ce... | opensearch-data-e7s6 10 GB @ us-west2 | SUCCESS |
| dashboards | e8cb46dc... (svc) | none | SUCCESS |
| siem-validator | 9e7cacc0... | none | SUCCESS |

- **portal**: source repo `qwalora/qwalora-ranger-control`; custom domain `portal.qwalora.com` (+ a
  `*.up.railway.app` domain); builder RAILPACK; **`watchPatterns=["/.railway-autodeploy-hold/**"]`**
  (autodeploy hold intact); 1 replica in us-west2. Its variables include the signing authority
  (`RANGER_JWT_PRIVATE_B64`), `DATABASE_URL`, `OPENSEARCH_URL`, OAuth secrets, and `SECRET_KEY` (names
  only were read; no secret values were retrieved or stored). There is no `RANGER_RESEARCH_MODEL_URL`
  set, as expected.
- **Staged patch** `73857663-dec6-4a6d-81bd-4d3c62bbbe8b`: STAGED, now showing **5 changes** (the brief
  cited 13; the live count differs). It targets the staged, undeployed `opensearch` service
  `6d14666e-c08c-4d84-b1f1-a957205bdac3` (resource update, three variable sets incl.
  `OPENSEARCH_INITIAL_ADMIN_PASSWORD`, and a volume update). **Left entirely untouched.** The
  discrepancy in change count is flagged, not acted on.
- The additional `opensearch` service exists but is not deployed, consistent with the brief.

## 2. Nonproduction isolation design (PREPARED)

The production portal holds the production signing authority and `DATABASE_URL`. Running PARALLAX
research in production would write research-run rows to the production PostgreSQL and sign them with the
production authority, which the brief forbids. There is currently only a `production` environment, so a
separate target is required.

Design:
1. **Separate Railway environment `parallax-nonprod`** in the same project (isolated variables,
   services, and deploys). The available MCP tooling exposes no environment-create operation, so this is
   an operator step, confirmed not performed here. Exact procedure (Railway CLI):
   ```
   railway link --project ee093894-30f7-4c82-ab5d-d7ef4d1a6454
   railway environment new parallax-nonprod          # creates the isolated environment
   ```
   Then hand back the new environment id (or it will be listed), after which the inference service,
   volume, variables, and deployment are provisioned through MCP within `parallax-nonprod` (never
   production). Do NOT fork production variables into it wholesale: set only what the nonprod portal and
   inference service need, with a fresh signing key and a dedicated database (below).
2. **Separate PostgreSQL** for `parallax-nonprod` (new service or a dedicated database), so research runs
   never touch production records. The research persistence already isolates by `researcher_id` and is
   owner-scoped; environment separation adds the hard boundary.
3. **Separate signing key** for the nonproduction environment (a distinct `RANGER_JWT_PRIVATE_B64` /
   PARALLAX signing kid), so no research evidence is signed by the production authority.
4. **Gating unchanged**: the PARALLAX research routes remain behind `_nonprod()` + `RANGER_PARALLAX_LABA`
   and authenticated candidate sessions; both qualification flags remain OFF. Lab A stays labeled a
   simulation; the genuine research service does not silently replace Lab A's scoring contract.
5. **Private networking**: the model service is attached to Railway private networking only
   (`parallax-inference.railway.internal:11434`), with no public domain, so inference is never reachable
   from the internet. The portal mediates all candidate access.

## 3. Cost and capacity estimate (PREPARED, to confirm at provision time)

Target model Qwen2.5-0.5B-Instruct (Q4_K_M GGUF ~0.4 GB) under Ollama on CPU:

| Resource | Estimate |
|---|---|
| Memory | ~2 GB (model resident + KV cache at 2k context) |
| vCPU | 1 (adequate for 0.5B at low concurrency; ~tens of tokens/s on CPU) |
| Volume | ~3 GB for weights (`/root/.ollama`) |
| Replicas | 1 |

Rough monthly cost at Railway usage-based rates (confirm current pricing at provision time): RAM about
$10/GB-month, vCPU about $20/vCPU-month, volume about $0.25/GB-month. Always-on 2 GB / 1 vCPU / 3 GB vol
is approximately **$30-50/month**; idle-scaling (if acceptable given cold-start model-load latency)
reduces it. This fits comfortably within the stated $300/month infrastructure budget and would be the
only new recurring cost in this phase.

## 4. Model acquisition and deployment verification (PREPARED / BLOCKED)

Prepared, non-deployed artifacts under `deploy/parallax-inference/`: `Dockerfile` (Ollama base, private
IPv6 bind, single resident model), `entrypoint.sh` (starts Ollama and pulls the pinned model onto the
volume at first boot, failing loudly if the registry is unreachable), `railway.service.json` (reference
spec: region, private networking, volume, resources, healthcheck), and `README.md`.

**BLOCKED until approval + Railway egress verification.** The brief is explicit: do not assume Railway
can retrieve the model merely because this container cannot. Whether Railway's egress reaches the Ollama
model registry (or Hugging Face, for a baked GGUF) must be tested on the deployed service; it cannot be
verified from here. No model has been pulled, so no artifact digest is recorded yet.

## 5. Real inference observations

**BLOCKED - none.** No model service exists, so no genuine generation was run and no inference duration
or resource consumption was measured. No fixture or synthetic response is presented as model inference.
(The existing `HTTPBackend` already speaks Ollama's `/api/generate` wire format, verified against a
loopback endpoint in Phase 2B; that is wire-compatibility, not model inference, and is labeled as such.)

## 6. Private networking evidence (PREPARED)

Railway provides private networking by default; services in an environment resolve each other at
`<service>.railway.internal` over IPv6. The inference service is specified to bind `[::]:11434` and to
have no public domain, so only the portal (same environment, private network) can reach it. Verification
that the portal resolves and reaches `parallax-inference.railway.internal` is a post-deploy check and is
**BLOCKED** until the service exists.

## 7. Workspace interface and implemented routes (PREPARED, deferred to post-approval)

Per the execution sequence, the full user-facing workspace (overview, assessment brief, experiment
workspace, investigation history, evidence submission, assessment status) is built AFTER inference is
verified, to avoid shipping a console with no genuine model behind it ("do not claim the workspace is
ready merely because its UI renders"). It reuses the existing portal navigation, branding, GitHub OAuth,
authenticated candidate sessions, CSRF, `_nonprod` gating, the `parallax/research/` harness, the single
`HTTPBackend` model client, and the existing signed research-run persistence and routes - no second
governance framework and no duplicate model client.

Implemented and tested this phase (non-billable backend, model-independent):
- **`GET /parallax/research/model/health`** (VERIFIED) - nonprod-gated, authenticated; reports the
  configured backend's identity and provenance, and for a real backend performs a tiny liveness
  generation with the backend timeout, surfacing failures honestly (never faked). Tested against both
  the deterministic stub (reports `simulated`/not-live) and a real loopback endpoint (reports
  `infrastructure_backed`/live).
- This is the integration seam the workspace will call to show "target model: live" before an
  experiment; it talks to the same single `HTTPBackend`, so the Railway endpoint drops in with no code
  change via `RANGER_RESEARCH_MODEL_URL`.

## 8. Candidate research workflow (PREPARED)

Target end-to-end flow (Phase F), to implement post-approval: GitHub sign-in -> authorized PARALLAX
workspace -> read technical assignment -> start an isolated, candidate-scoped experiment session ->
interact with the Railway-hosted model through controlled, permitted lower-trust document inputs ->
observe actual model behavior and technical evidence -> review persisted evidence -> submit an
investigation -> retrieve persisted assessment status. A benign control and an adversarial trial against
the genuine model are required before any result is reported; a successful exploit is declared only if
the preregistered unauthorized behavior (canary emission) actually occurs.

## 9. Evidence and audit integration (VERIFIED for the existing path; extension PREPARED)

The existing signed, owner-scoped research-run persistence (Ed25519 + hash-chained audit) is VERIFIED
(417/17/0 PG-on baseline; standalone PostgreSQL durability check). Real trials will flow through this
same path unchanged; the two record fields that only a real backend populates (model artifact
digest, generation parameters) are the first additions when the live model exists. No alternative
governance is introduced.

## 10. Security controls (PREPARED)

Implemented and tested this phase:
- **Research-run rate limiting** (VERIFIED) - per-candidate, server-side, window-based
  (`RANGER_RESEARCH_RUN_LIMIT_PER_MIN`, default 20); a test sets the limit to 1 and confirms the second
  run returns HTTP 429. Best-effort in-process (a multi-worker deployment would use a shared store; noted
  as a limitation).
- **Candidate-scoped, server-side session ownership** and **no cross-candidate evidence access**
  (VERIFIED, from Phase 2A/2B) - identity is the authenticated session, runs are owner-scoped, a
  non-owner gets 404.

Specified, PREPARED for the workspace implementation: maximum inference duration (the `HTTPBackend`
timeout plus a server-side cap); request/response size limits on submitted lower-trust document content;
compute/concurrency quotas; experiment cancellation/timeout; synthetic-only corpus (already the case);
no production credentials in the nonproduction environment (environment isolation); no arbitrary external
URL fetching by the model path (the model sees only the harness-assembled, trust-fenced prompt); no model
tool execution; no production database mutation (environment isolation); signed evidence and audit
records (existing). Ollama's admin API is never exposed to candidates - the portal is the only
private-network client.

## 11. End-to-end experimental verification

**BLOCKED** - requires the deployed model (gated on approval). No end-to-end real experiment was run.

## 12. Full regression results (VERIFIED)

Additive backend changes this phase (`parallax_routes.py`: model-health route + per-candidate run rate
limiting) are covered by 3 new tests. Full PG-on regression (disposable PostgreSQL 16.15,
`ranger_test_sentinel` boundary): **420 passed / 17 skipped / 0 failed / 0 errors** - the 417 baseline
plus the 3 new Phase 2C tests, skips unchanged. The 1 model-execution skip remains the
`TransformersBackend` test (no CPU torch here). Tests exercising a genuine trained model: **0** (no model
is deployed yet). Real model execution is distinguished from simulation throughout: the health route and
run route report `backend_provenance` and the stub is always labeled `simulated`/not-a-finding.

## 13. Remaining limitations

- No genuine model is deployed yet; real inference and the end-to-end experiment are BLOCKED on approval
  and on Railway-side model-registry egress (unverifiable from here).
- No `parallax-nonprod` environment exists yet; it must be created (dashboard/CLI) as the isolation
  boundary before any research write path is pointed at a real backend.
- OpenSearch (12 infra tests) and independent audit anchoring remain OPEN from prior phases; neither is
  required for the first real-model RAG experiment.

## 14. Production safety verification (VERIFIED)

`main` unchanged at `431a183`. Portal autodeploy hold `watchPatterns=["/.railway-autodeploy-hold/**"]`
intact; this commit touches only `deploy/**` and `docs/**`, which do not match the hold path, so no
portal deploy is triggered. The staged patch `73857663` was not accepted, modified, or overwritten. Both
`RANGER_PARALLAX_QUALIFICATION_ACTIVE` and `RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE` remain OFF.
STRATA's 95% policy is unchanged. No billable resource was provisioned. No secret values were retrieved
or stored (variable names only).

## 15. Deployment readiness and founder decisions (APPROVAL GATE)

Founder decisions received this session: **provisioning APPROVED (idle-scaled)**, **isolation = new
`parallax-nonprod` environment**, **model = Qwen2.5-0.5B-Instruct**, region us-west2 (default).

The remaining blocker is the **operator environment-creation step**, because the available Railway MCP
tooling cannot create an environment (Section 2). Required operator action, in order:
1. Create the `parallax-nonprod` environment (`railway environment new parallax-nonprod`).
2. Add a dedicated PostgreSQL to that environment and a fresh PARALLAX signing key
   (`RANGER_JWT_PRIVATE_B64`), so research runs never touch production records or the production signing
   authority.
3. Hand back the new environment id.

On receipt, the sequence resumes under the granted approval: provision the private `parallax-inference`
service (idle-scaled, no public domain) + its volume + variables via MCP in `parallax-nonprod` -> verify
Railway can pull Qwen2.5-0.5B-Instruct and serve genuine generations (this is where real inference stops
being BLOCKED) -> wire `RANGER_RESEARCH_MODEL_URL` on the nonprod portal -> `GET /parallax/research/model/health`
turns live -> build and test the full workspace UI -> run the benign control and adversarial trial
against the genuine model -> validate signed evidence -> full regression -> update this report with
VERIFIED real-inference observations.
