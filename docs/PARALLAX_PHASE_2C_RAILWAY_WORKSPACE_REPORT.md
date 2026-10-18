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
   services, and deploys). Railway environments are created in the dashboard (Project -> Environments ->
   New) or via the Railway CLI (`railway environment new parallax-nonprod`). The available MCP tooling
   here does not expose an environment-create operation, and creating an environment is a gated
   configuration change, so it is **documented, not performed**.
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

Per the execution sequence, the user-facing workspace (overview, assessment brief, experiment workspace,
investigation history, evidence submission, assessment status) is built AFTER inference is verified, to
avoid shipping a console with no genuine model behind it ("do not claim the workspace is ready merely
because its UI renders"). It will reuse the existing portal navigation, branding, GitHub OAuth,
authenticated candidate sessions, CSRF, `_nonprod` gating, the `parallax/research/` harness, the single
`HTTPBackend` model client, and the existing signed research-run persistence and routes - no second
governance framework and no duplicate model client. The route surface is specified in Section 15 as a
founder decision to confirm before implementation.

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

Specified for the workspace implementation: GitHub-authenticated access; candidate-scoped, server-side
session ownership; research-run rate limiting; maximum inference duration (enforced via the
`HTTPBackend` timeout and a server-side cap); request/response size limits; compute/concurrency quotas; 
experiment cancellation/timeout; synthetic-only corpus (already the case); no production credentials in
the nonproduction environment; no arbitrary external URL fetching by the model path (the model sees only
the harness-assembled, trust-fenced prompt); no model tool execution; no cross-candidate evidence access
(owner-scoped, already enforced); no production database mutation (environment isolation); signed
evidence and audit records (existing). Ollama's admin API is never exposed to candidates - the portal is
the only private-network client.

## 11. End-to-end experimental verification

**BLOCKED** - requires the deployed model (gated on approval). No end-to-end real experiment was run.

## 12. Full regression results (VERIFIED)

No application code changed this phase (only `deploy/` config and `docs/`). The Phase 2B PG-on baseline
stands at **417 passed / 17 skipped / 0 failed**; the research + real-path suites were re-confirmed green
in this container (21 passed / 1 skipped). The 1 skip remains the `TransformersBackend` execution test
(no CPU torch here). Tests exercising a genuine trained model: **0**.

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

Everything up to provisioning is PREPARED. The following require explicit founder decisions before any
billable or deploy action:

1. **Provisioning approval** for the `parallax-inference` service (~$30-50/month always-on, within the
   $300 budget): approve, approve with idle-scaling, or hold.
2. **Isolation target**: create a new `parallax-nonprod` environment (recommended) with its own
   PostgreSQL and signing key, versus another isolation approach.
3. **Model**: confirm Qwen2.5-0.5B-Instruct (Apache-2.0) as the first model, or name an alternative.
4. **Region**: us-west2 (co-located with existing services) unless otherwise directed.

On approval, the sequence resumes: create the nonproduction environment -> deploy the private inference
service -> verify Railway can pull the model and serve genuine generations -> wire
`RANGER_RESEARCH_MODEL_URL` on the nonproduction portal -> build and test the workspace -> run the benign
control and adversarial trial against the genuine model -> validate signed evidence -> full regression ->
update this report with VERIFIED observations.
