# STRATA S5.1 - Live Integration Validation Readiness

Repository: `qwalora/qwalora-ranger-control`
Branch: `feature/strata-s5-real-opensearch-validation`
Accepted commit: `13e48d7` (offline-tested development milestone)
Scope of THIS report: real-integration validation preparation and non-destructive preflight only.
No live writes, no Railway contact, no production mutation. Stops at the plan while blocked.

Acceptance recorded: 32 passed, 1 skipped, 0 failures (offline). This is NOT production or
real-OpenSearch validation.

---

## 1. What S5.1 implements, and what the 32 passing tests establish

S5.1 added only test harness and documentation on top of the accepted S5 baseline `f50ff20`. No
production code changed (verified by diff): `siem/tests/_ostest.py`,
`siem/tests/test_strata_s5_real_opensearch.py`, `siem/opensearch/docker-compose.test.yml`,
`siem/opensearch/run-local-opensearch-test.sh`, and two docs.

The 32 passing tests are the S5 acceptance suite `siem/tests/test_strata_s5_board2.py`. They exercise
the Board 2 Ranger-side logic against the in-process `FakeCluster` double (a faithful stand-in that
enforces the same role/DLS model), plus SQLite and, where authorized, Postgres. They establish, on the
Ranger side:

- One authoritative assignment, pinned generation contract, fail-closed provisioning state machine
  (idempotent reuse, foreign/unknown-index refusal, corrupted/same-count-mutation refusal,
  interrupted-ingest convergence).
- Protected metadata off candidate-readable surfaces; no seed/truth in the index.
- Signed evidence (full-payload digest), signed decision authority, the shared promotion gate, the
  95% objective standard, exactly-once Board 3 promotion, idempotent re-evaluation.
- Negative controls: unsigned/modified evidence, foreign/forged citation, wrong version, below-95,
  missing/invalid activation, shadow/generic paths, unauthorized evaluator.
- Cross-module: candidate-safe mission projection, `Case.case_ref` vs F5 `Case.scenario_ref`.

What they do NOT establish: real OpenSearch behavior. The double is not the Security plugin, the real
REST API, real mappings, or real DLS. That is exactly what S5.1 real validation is for, and it has not
executed.

## 2. The blocker, classified

Two distinct skips, not to be conflated:

- The 1 skip inside the accepted S5 suite is `test_concurrent_authorized_decision_is_idempotent_postgres`.
  Reason: no authorized disposable POSTGRES (not OpenSearch). It passes when a disposable PG is
  authorized (gives 33 passed), as verified at the baseline. Classification: unavailable service
  (Postgres), not credentials/permissions/config.
- The 12 real-OpenSearch tests (`test_strata_s5_real_opensearch.py`) all skip. Reason, classified
  precisely:
  - Network reachability / unavailable service: there is no disposable OpenSearch 2.17.1 node, and
    this environment cannot provision one because every image/distribution source is egress-policy
    denied (Docker Hub, ghcr.io, artifacts.opensearch.org, GitHub assets all HTTP 403), with nothing
    cached. The Docker daemon itself is startable.
  - NOT missing credentials: no node exists to hold credentials for.
  - NOT permissions: no permission was requested and denied; the denial is the egress policy on image
    sources, which is correct and must not be circumvented.
  - NOT configuration: the suite, boundary and bring-up are configured and collect cleanly (12/12).
  - NOT intentionally-disabled: the tests are enabled; they gate on a positively-authorized node and
    skip fail-closed by design rather than silently using `FakeCluster`.

## 3. Preflight results (read-only, non-destructive)

- Branch/commit: `feature/strata-s5-real-opensearch-validation` @ `13e48d7`.
- Real-OS suite: 12 collected, 12 skipped, reason "no authorized real OpenSearch 2.17.1 node".
- Runtime prerequisites present: `cryptography` (JWT mint in the HTTP-chain test) and `psycopg2`
  (optional disposable-PG path) both import. The suite is runnable the moment a node exists.
- Docker daemon: startable (UP in this check); image pull remains egress-denied (not re-probed).
- Safety boundary behavior: `_ostest` refuses a production/non-loopback target. A check against
  `opensearch.railway.internal` is refused ("non-local host ... not loopback"). This means the live
  Railway cluster is not a valid test target by design: the boundary blocks it, and it must never be
  used. Production config for comparison is taken from the repo (`siem/opensearch/Dockerfile`,
  `opensearch.yml`), not the live node.
- No Railway API calls, no OpenSearch connections, no secret reads were performed.

## 4. Controlled live integration validation plan

Target: a DISPOSABLE OpenSearch 2.17.1 node (loopback or an explicitly allow-listed test host),
never a shared or production cluster. Runs on the host, not inside a container.

### 4.1 Commands and prerequisites
```
# A) host with image access:
OPENSEARCH_INITIAL_ADMIN_PASSWORD='<StrongTestPass!>' siem/opensearch/run-local-opensearch-test.sh up
#    (verifies container/auth/version/plugin/fresh-node, creates+verifies the sentinel, prints exports)
# B) pre-provisioned disposable node: create the sentinel once, then set:
export RANGER_TEST_ALLOW_OS_MUTATION=1 RANGER_TEST_OPENSEARCH_URL='https://127.0.0.1:9200' \
       RANGER_TEST_OPENSEARCH_USER='admin' RANGER_TEST_OPENSEARCH_PASSWORD='<admin>'
# then:
python3 -m pytest siem/tests/test_strata_s5_real_opensearch.py -v
python3 -m pytest siem/tests/test_strata_s5_board2.py            # S5 regressions
```
Prerequisites: Docker + access to `opensearchproject/opensearch:2.17.1` (path A), OR a reachable
disposable 2.17.1 node URL + admin credentials (path B); Python with `cryptography` and (optional)
`psycopg2`; host-local execution.

### 4.2 Expected indices, roles, namespaces (all per-run disposable)
- Indices: `ranger-<cohort>-<slug>-b2-q<attempt>` (qualification), `.ranger-qualmeta` (protected
  system meta), `.ranger-ostest-sentinel` (authorizing sentinel). Every cohort/slug carries a per-run
  token `ostest-<hex>`.
- Security principals: `cand_<slug>` role + internal user + rolesmapping per candidate; the HTTP-chain
  test also creates `ranger_soc_admin`.
- Namespaces: a unique disposable cohort token per test (`ostest-<hex>` and `-a/-b/-c/...` variants).

### 4.3 Create / mutate / delete behavior
- The real suite CREATES indices, roles, internal users, rolesmappings and documents, and DELETES
  only resources carrying its per-run marker (indices, principals, and its own `.ranger-qualmeta`
  stamps by `_id`). No wildcard deletion; the shared meta index is never dropped wholesale.
- All writes go to the DISPOSABLE node only. The suite performs NO writes to any live/production
  cluster, and `_ostest` refuses any non-loopback/non-allow-listed or non-fresh target.

### 4.4 Expected synthetic telemetry and findings
- Profile B enterprise world per variant (hundreds of benign events plus the variant's incident
  families), every event tagged `data.plane=qualification`, carrying `ranger.candidate_id`, with no
  seed and no truth labels.
- Reference findings use the truth-derived `board2_reference_submission`, a protected test fixture
  only; it is never exposed to candidate-facing interfaces. Objective standard stays 95%.

### 4.5 Authorization and cohort-isolation checks
- Per-candidate role + DLS on `ranger.candidate_id`; candidate reads own index, is refused (403) on
  another candidate's index and on `.ranger-qualmeta`, and cannot write.
- Cross-cohort worlds are materially different and have disjoint event-id sets; cohort A citations do
  not reproduce in cohort B.
- The slug-vs-github_id identity contract (Test C) is asserted so a real run surfaces the known
  coupling risk if present.

### 4.6 Cleanup and rollback
- Per-test: `_ostest.isolated_os_namespace` marker-guarded teardown removes only this run's resources.
- Full: `run-local-opensearch-test.sh down` destroys the disposable node and its volume.
- Rollback: because all state is on a disposable node, rollback is teardown; nothing persists.

### 4.7 Required credentials and minimum permissions
- A node-admin (broker) credential on the DISPOSABLE node only, with the Security API permissions to
  create/delete indices, roles, internal users and rolesmappings, and to bulk-index. No production
  credentials. No candidate-facing access is enabled.

### 4.8 Resource consumption and infrastructure cost
- Single-node 2.17.1, ~1 GiB JVM heap, loopback-only, ephemeral storage. If run on an existing
  developer host: zero cloud cost. If on a throwaway VM: a small instance for well under an hour.
  No persistent or shared infrastructure is created.

## 5. Risks
- The slug/github_id DLS coupling (section 4.5) may fail on first real run; if confirmed, the fix is
  to align the ingested identity with the DLS term at the root, not to weaken DLS. Small, localized.
- Profile B scale and ingestion timing are unmeasured until the first run.
- Demo self-signed TLS on the disposable node differs from the production Ranger CA; a local pass is
  development validation, not production readiness.
- Fault-injection cases (429/5xx/partial-bulk/transport) are injected, not observed under real load.
- Mis-targeting a shared cluster is mitigated: `_ostest` refuses non-loopback/non-fresh nodes.

## 6. Approval needed to execute
- Provide ONE of: (a) a Docker-capable host with access to `opensearchproject/opensearch:2.17.1`, or
  (b) a pre-provisioned disposable 2.17.1 node URL + admin credentials satisfying `_ostest` (loopback
  or allow-listed host, sentinel created, no production data).
- Writes to the disposable node are the intended, cleaned-up design and need no separate approval
  beyond providing the node. Pointing any live/shared/production cluster at these tests is out of
  scope and not recommended; the boundary refuses it, and it would require explicit, separate approval
  and a different safety plan. No such live writes will be executed without that explicit approval.

## 7. Preservation guarantees (unchanged by this milestone)
Cohort isolation, protected assessment truth, signed evidence, the 95% objective standard, the
separate human-review gate, and qualification/promotion behavior are all preserved. No production
code changed in S5.1. This work is kept separate from PARALLAX F4; F1-F3 are untouched.

---

Status: LIVE VALIDATION REMAINS BLOCKED pending a disposable 2.17.1 node. Preflight and plan are
complete; execution stops here per the authorized scope.

---

## 8. CI automation and its current outcome

`.github/workflows/strata-s5-real-opensearch.yml` provisions a disposable real OpenSearch 2.17.1
node on a GitHub-hosted Ubuntu runner (open egress, so it can pull the image this sandbox cannot),
runs the full real-OS suite against `siem.live.LiveCluster`, and fails the job via
`siem/tests/ci_check_junit.py` on any skipped/failed/errored/zero/partial result. Evidence is
uploaded even on failure; the disposable node is always torn down. A separate `fast-regression` job
runs the offline S5 + F5 suites and cannot substitute for the real-OS job.

Current CI outcome: **BLOCKED (account billing lock), not GREEN.** The workflow registers, parses,
and triggers correctly, but GitHub will not start the hosted runners. Both jobs ended in ~2-3s with
the annotation: "The job was not started because your account is locked due to a billing issue." No
test executed, so no real-OpenSearch assertion is validated.

To unblock (founder action, outside this scope): resolve the GitHub Actions billing/spending-limit
lock on the `qwalora` org (GitHub -> Settings -> Billing; clear any failed payment or raise the
Actions spending limit), then re-run via `workflow_dispatch` or any code push to the branch. The
workflow needs no production secrets and uses only a GitHub-hosted runner. This billing lock was not
worked around; no self-hosted runner or Railway substitution was used.
