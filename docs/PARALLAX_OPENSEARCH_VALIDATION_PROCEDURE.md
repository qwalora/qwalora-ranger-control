# Real OpenSearch 2.17.1 Validation Procedure (STRATA S5.1)

Status: **OPEN** in the current engineering environment. The 12 real-OpenSearch tests in
`siem/tests/test_strata_s5_real_opensearch.py` require a genuine OpenSearch 2.17.1 node with the
Security plugin. They are gated by `siem/tests/_ostest.py` and SKIP fail-closed when that node is not
positively authorized; they NEVER substitute the in-process `FakeCluster`. Their assertions are
unchanged.

This document is the executable procedure to run them in an environment that permits the required
infrastructure. It provisions a disposable, isolated node only — never production, never a paid service
without authorization.

## Why it is OPEN here (confirmed, not assumed)

- No Docker daemon is running in this container, and starting one does not help: the image registry is
  unreachable through the egress allowlist (`registry-1.docker.io` returns HTTP 403 via the proxy and
  direct DNS is blocked), so `opensearchproject/opensearch:2.17.1` cannot be pulled.
- No cached OpenSearch image, no local OpenSearch install, and no authorized `RANGER_TEST_OPENSEARCH_URL`.
- The Security plugin additionally needs TLS certificates and ~2 GB RAM.

These are the same restrictions confirmed in Phase 1C; no further pull attempts were made.

## The 12 OPEN test cases (all in test_strata_s5_real_opensearch.py)

1. `test_s5_real_index_creation_lifecycle_and_isolation`
2. `test_s6_real_qualmeta_protection`
3. `test_s7_real_candidate_permissions_and_dls`
4. `test_s8_real_evidence_verification`
5. `test_s9_provisioning_state_machine`
6. `test_s10_full_http_qualification_chain`
7. `test_s11_scenario_diversity_from_queried_telemetry`
8. `test_s12_historical_replay_and_crypto_integrity`
9. `test_c_candidate_dls_slug_vs_github_id_and_reconnect`
10. `test_d_evidence_edge_cases_real`
11. `test_e_provisioning_states_c_e_h_i`
12. `test_s9neg_real_context_refusals`

## Prerequisites

- A host that can pull/run container images or run a local OpenSearch 2.17.1 tarball, with ≥2 GB RAM
  free and Java 11+ (present here as `/usr/bin/java`).
- Network egress to the image registry or the OpenSearch download, OR a pre-provisioned disposable node.
- The node MUST be disposable and isolated — never a shared or production cluster.

## Procedure

### 1. Start a disposable OpenSearch 2.17.1 node with the Security plugin

Container (preferred):

```
docker run -d --name os-ranger-test \
  -p 9200:9200 \
  -e discovery.type=single-node \
  -e OPENSEARCH_INITIAL_ADMIN_PASSWORD='<StrongPassw0rd!>' \
  opensearchproject/opensearch:2.17.1
```

Confirm it self-reports 2.17.1 and the Security plugin is active:

```
curl -k -u admin:'<StrongPassw0rd!>' https://127.0.0.1:9200 | grep -i '"number"'
```

### 2. Create the authorizing sentinel index (operator's one-time statement "this node is disposable")

```
curl -k -u admin:'<StrongPassw0rd!>' -XPUT https://127.0.0.1:9200/.ranger-ostest-sentinel
```

### 3. Export the `_ostest` authorization environment (all required, fail-closed)

```
export RANGER_TEST_ALLOW_OS_MUTATION=1
export RANGER_TEST_OPENSEARCH_URL=https://127.0.0.1:9200
export RANGER_TEST_OPENSEARCH_USER=admin
export RANGER_TEST_OPENSEARCH_PASSWORD='<StrongPassw0rd!>'
# optional: RANGER_TEST_OS_CA=/path/ca.pem for full TLS verification
# optional: RANGER_TEST_OS_SENTINEL_INDEX=.ranger-ostest-sentinel (default)
```

The host must be loopback or listed in `RANGER_TEST_OS_AUTHORIZED_HOSTS`; the node must not carry a
production-like index; the sentinel index must be present. If any check fails, the suite SKIPS — it
never runs destructively against an unauthorized node.

### 4. Run the 12 tests

```
cd siem
python -m pytest tests/test_strata_s5_real_opensearch.py -v
```

### 5. Tear down the disposable node

```
docker rm -f os-ranger-test
```

## Acceptance

All 12 tests report PASS (not SKIP) against the real node, with their original assertions unchanged.
Until then the capability is **OPEN**; the skip count (12) is reported as OPEN in the engineering
record, never as PASS.
