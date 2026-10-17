# STRATA S5.1 - Real OpenSearch 2.17.1 Qualification Validation

Repository: `qwalora/qwalora-ranger-control`
Review branch: `feature/strata-s5-real-opensearch-validation`
Base commit: `f50ff203a3ec0e43121df083735aa1fff8215292` (accepted S5 baseline)

This milestone validates the S5 Board 2 qualification chain against a REAL OpenSearch 2.17.1 node
with the real Security plugin, rather than the in-process `siem.fake_cluster.FakeCluster` double.

## 1. Status summary (read this first)

A real OpenSearch 2.17.1 node could NOT be stood up inside this execution environment: every source
of an OpenSearch distribution is blocked by the environment's outbound egress policy, and nothing is
cached locally. Per the spec (section 4), the validation tests were PREPARED against the real
`siem.live.LiveCluster` and the exact blocker is reported below. `FakeCluster` was NOT substituted at
any point. The prepared suite SKIPS fail-closed until it is pointed at a positively-authorized
disposable real node.

What is in this branch:

- `siem/tests/_ostest.py` - a positively-verified disposable real-OpenSearch authorization boundary
  (mirrors the PostgreSQL `_pgtest` safeguards). Fail-closed; never returns a double.
- `siem/tests/test_strata_s5_real_opensearch.py` - the validation suite (spec sections 5-12),
  written against the real `LiveCluster`; skips fail-closed with no authorized node.
- `siem/opensearch/docker-compose.test.yml` + `run-local-opensearch-test.sh` - a disposable,
  loopback-only 2.17.1 bring-up for a machine that CAN pull the image, wired to the `_ostest` env.
- This document.

No merge, no deployment, no Railway operation, no production migration, no S6, no PARALLAX. The 95%
objective standard and all accepted F1-F5 / S1-S5 work are preserved.

## 2. The exact environment blocker

The execution environment can run a Docker daemon (started successfully: Docker 29.8.2, overlayfs
snapshotter, 7.3 GiB free RAM, 30 GiB free disk). It cannot obtain an OpenSearch 2.17.1 distribution
with the Security plugin, because outbound HTTPS goes through a policy-enforcing egress proxy that
allow-lists only package registries and a few hosts, and every distribution source returns HTTP 403
(CONNECT tunnel refused) at the policy layer:

| Source | Result |
|---|---|
| `registry-1.docker.io` / `auth.docker.io` (opensearchproject/opensearch:2.17.1) | 403 CONNECT refused; `docker pull` -> `Forbidden` |
| `ghcr.io` | 403 CONNECT refused |
| `artifacts.opensearch.org` (official linux tarball bundle) | 403 CONNECT refused |
| `github.com` / `codeload.github.com` release + source assets | 403 on the release/codeload paths |

Notes:
- The agent proxy README states policy denials (403/407) must be reported, not worked around, and
  that in-container processes cannot reach the proxy regardless. The `docker build --network host`
  CA workaround addresses TLS trust only, not the registry allow-list denial.
- `git`-over-HTTPS to `github.com` works, but OpenSearch's runnable bundle (bundled JDK + Security
  plugin) is not a GitHub release asset; it lives on `artifacts.opensearch.org`, which is blocked.
  Building a full distribution from source offline (Gradle, the separate Security-plugin repo) is not
  feasible here and would not be a faithful 2.17.1 release build.
- No OpenSearch server image or tarball is cached on disk (only client-side SVGs and `opensearch-py`
  style client data). There is no shared/other OpenSearch instance to reach, and reaching one would
  violate the "no shared instance / no production data" boundary anyway.

Conclusion: the real-node run must be performed on a machine that can pull
`opensearchproject/opensearch:2.17.1` (or load it from a local mirror). The suite and the disposable
bring-up are prepared for exactly that.

## 3. How to run against a real node

On a host with Docker and image access, from the repo root:

```
OPENSEARCH_INITIAL_ADMIN_PASSWORD='<StrongTestPass123!>' \
  siem/opensearch/run-local-opensearch-test.sh up
```

The script brings up a loopback-only 2.17.1 node (Security plugin ENABLED), waits for health, creates
the authorizing sentinel index `.ranger-ostest-sentinel`, and prints the exact exports:

```
export RANGER_TEST_ALLOW_OS_MUTATION=1
export RANGER_TEST_OPENSEARCH_URL='https://127.0.0.1:9200'
export RANGER_TEST_OPENSEARCH_USER='admin'
export RANGER_TEST_OPENSEARCH_PASSWORD='<StrongTestPass123!>'
# optional full TLS verification: export RANGER_TEST_OS_CA='/path/to/node-ca.pem'

python3 -m pytest siem/tests/test_strata_s5_real_opensearch.py -v
siem/opensearch/run-local-opensearch-test.sh down   # destroy node + data
```

Run the test process ON THE HOST (not inside a container) so it reaches `127.0.0.1:9200` directly,
with no egress proxy or CA rewriting involved. Disposable Postgres (via `_pgtest`) is used by the
HTTP-chain test if authorized; otherwise it falls back to the in-memory portal DB (the DB is not the
system under test in this milestone; OpenSearch is).

## 4. Safety boundary (`_ostest`)

Destructive operations (create/delete indices, create/delete security roles and users) are refused
unless ALL of the following positively hold, fail-closed:

1. `RANGER_TEST_ALLOW_OS_MUTATION` opt-in is set.
2. A DEDICATED `RANGER_TEST_OPENSEARCH_URL` is set (never the app's `OPENSEARCH_URL`).
3. The URL host is loopback or explicitly allow-listed (`RANGER_TEST_OS_AUTHORIZED_HOSTS`). A
   localhost address alone is NOT sufficient (spec section 4).
4. The node is reachable and self-reports distribution `opensearch` version `2.17.1` (a labelled
   near-version run requires an explicit `RANGER_TEST_OS_ALLOW_VERSION_MISMATCH=1`).
5. No production-like index (`ranger-prod*`, `ranger-live*`, `.ranger-qualmeta-prod*`) is present.
6. The authorizing sentinel index is present (created once by the operator on the disposable node).

Each test derives every index/role/user name from a unique per-run token and cleans them up in a
marker-guarded teardown (`isolated_os_namespace`), deleting only names that carry the run token and
removing only its own `.ranger-qualmeta` stamps by document id (never the shared meta index wholesale).

## 5. Disposable node vs production security config (precise differences)

The disposable node uses the stock image's demo bootstrap; production (`siem/opensearch/Dockerfile`
+ `opensearch.yml`) uses a managed configuration. Differences, all intentional and local-only:

- TLS: demo self-signed certificates vs Ranger-issued CA/node/admin certs written from runtime
  secrets. The test client relaxes verification unless `RANGER_TEST_OS_CA` is provided; production
  verifies against the Ranger CA.
- Admin identity: a throwaway `OPENSEARCH_INITIAL_ADMIN_PASSWORD` vs a rotated runtime secret and a
  cert-DN admin (`CN=admin.ranger.internal`).
- Security config: the image's demo internalusers/roles vs the managed securityconfig.
- Exposure: bound to `127.0.0.1` only; no public endpoint, no Railway, no shared instance.
- `.ranger-qualmeta` protection is identical in kind to production: it is protected by NOT matching
  any candidate role's index pattern (`ranger-<cohort>-<slug>-b*`), NOT by the Security plugin's
  system-index list (production's `opensearch.yml` deliberately does not list it either). Section 6
  of the suite validates exactly this boundary on the real plugin.

The Security plugin stays ENABLED on the disposable node. TLS/auth are not disabled to pass a test.

## 6. Spec coverage (sections 5-12)

Each maps to a prepared test in `siem/tests/test_strata_s5_real_opensearch.py`. Status is "prepared;
blocked from execution here" for all, pending a real node.

- 5 Index creation/lifecycle/isolation + manifest inventory + no seed/truth/variant leakage + plane
  label: `test_s5_real_index_creation_lifecycle_and_isolation` (Profile B).
- 6 `.ranger-qualmeta` protection on the real Security plugin: broker read; candidate denied by
  `_search`, direct `_doc`, `_msearch`, and wildcard `*/_search`:
  `test_s6_real_qualmeta_protection`.
- 7 Real candidate permissions + DLS: own-index read, cross-candidate 403, system-index 403,
  read-only (write refused): `test_s7_real_candidate_permissions_and_dls`.
- 8 Real evidence verification via `case_routes.LiveReader`: valid citation, invalid id, foreign
  index, non-matching query, and real 404 -> `NotFound`: `test_s8_real_evidence_verification`.
- 9 Provisioning state machine A/B/D/F/G against the real cluster (fresh, idempotent reuse, foreign
  index refusal, corrupted/same-count mutation refusal): `test_s9_provisioning_state_machine`.
  Cases C/E/H/I (interrupted-ingest convergence, missing-claim, concurrent provisioning, and
  429/5xx/partial-bulk fault injection) are documented below as first-run additions.
- 10 Full HTTP qualification chain to Board 3 through the real cluster and the real gateway/JWT mint:
  `test_s10_full_http_qualification_chain`.
- 11 Scenario diversity measured from QUERIED telemetry (identities, hosts, disjoint event-id sets;
  cohort A evidence ids absent from cohort B): `test_s11_scenario_diversity_from_queried_telemetry`.
- 12 Historical replay + crypto integrity (pinned regeneration matches the real indexed manifest;
  signed evidence verifies; tampered digest fails): `test_s12_historical_replay_and_crypto_integrity`.

## 7. What is and is NOT proven

Proven offline at this commit (unchanged by this branch):
- S5 acceptance suite: 33 passed (including the Postgres evaluator-concurrency test).
- F5/workbench/case regressions: 22 passed.

NOT yet proven (requires the real-node run):
- Every section-5-12 assertion above against a real Security plugin, mappings, roles and DLS.

First-run items to confirm honestly when a real node is available:
- DLS term vs ingested value: the gateway sets candidate DLS to `ranger.candidate_id == <slug>`,
  while generated events carry `ranger.candidate_id == <subject>` (the binding's `github_id`). When
  slug and github_id diverge after slugification, a candidate could see zero of their own documents
  on a real node. `test_s7` reads the actual stored value to prove DLS enforcement; the gateway's
  own slug coupling must be confirmed end-to-end on first run (and corrected only if a genuine defect
  is observed, per the "narrowly justified corrections" boundary).
- Section-9 cases C/E/H/I: interrupted-ingest convergence, missing-claim rejection, concurrent
  provisioning (exactly one coherent dataset), and 429/5xx/partial-bulk handling. Transport-failure
  cases will use labelled fault injection, kept separate from failures produced by a real node.
- Profile B scale and ingestion timing on the target node.

Live-infrastructure honesty: results obtained against `FakeCluster` are not evidence of real
OpenSearch behavior, and no such substitution was made here. Until the suite is executed against a
real 2.17.1 node, S5.1 is PREPARED, not validated.
