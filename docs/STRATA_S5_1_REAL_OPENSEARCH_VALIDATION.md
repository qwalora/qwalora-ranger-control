# STRATA S5.1 - Real OpenSearch 2.17.1 Qualification Validation

Repository: `qwalora/qwalora-ranger-control`
Review branch: `feature/strata-s5-real-opensearch-validation`
Accepted S5 baseline: `f50ff203a3ec0e43121df083735aa1fff8215292`

This is the engineering acceptance report for STRATA S5.1: validating the accepted S5 Board 2
qualification chain against a REAL OpenSearch 2.17.1 node with the Security plugin, rather than the
in-process `siem.fake_cluster.FakeCluster` double.

The status distinctions required by the assignment are maintained throughout: (1) test code
implemented, (2) infrastructure available, (3) test collected, (4) test executed against real
OpenSearch, (5) test passed with genuine evidence. These are never collapsed.

---

## A. Engineering status

**REAL OPENSEARCH VALIDATION BLOCKED - TESTS PREPARED, NOT EXECUTED.**

- Test code implemented: YES (12 real-cluster tests + hardened safety boundary + hardened bring-up).
- Infrastructure available in this environment: NO (no runnable OpenSearch 2.17.1 obtainable here).
- Tests collected: YES (12 collected).
- Tests executed against real OpenSearch: NO (all 12 skip fail-closed with no authorized node).
- Tests passed with genuine evidence: N/A (not executed).

S5.1 is NOT classified REAL-OPENSEARCH VALIDATED. A prepared suite does not satisfy the acceptance
standard (section 16 of the assignment). The suite runs, and this report is actionable, the moment an
authorized disposable 2.17.1 node is provided (see J/K).

---

## B. Execution environment (capability + authorization assessment)

Assessed on the S5.1 branch at this commit. The environment can run a Docker daemon (Docker 29.8.2,
overlayfs snapshotter) and has adequate disk/memory (~30 GiB free disk, ~7.3 GiB free RAM). It
cannot obtain an OpenSearch 2.17.1 distribution with the Security plugin:

| Capability | Result |
|---|---|
| Docker CLI + daemon | Present; daemon can be started |
| Cached OpenSearch image | None |
| On-disk OpenSearch distribution | None |
| Docker Hub `opensearchproject/opensearch:2.17.1` | Egress policy denied (HTTP 403 CONNECT); `docker pull` -> Forbidden |
| GitHub Container Registry (ghcr.io) | Egress policy denied (403) |
| `artifacts.opensearch.org` tarball bundle | Egress policy denied (403) |
| GitHub release / codeload assets | Egress policy denied (403) |
| Authorized disposable test node | None provided |
| Test credentials/secrets for a node | None provided |

Per the assignment, known-denied download endpoints were not repeatedly retried, the egress policy
was not circumvented, and no production infrastructure was repurposed to obtain an image. Outcome B
applies: safe, offline-verifiable harness and test-code work was completed and an operator runbook is
provided. `FakeCluster` was not substituted at any point; the suite skips rather than falling back.

Proof-of-authorization is therefore NOT satisfiable here: there is no node to positively identify as
disposable. On a host with image access, authorization is established by `_ostest` (see E) before any
destructive call.

---

## C. Test matrix (assignment sections 5-12)

All statuses are "PREPARED; collected; SKIPPED (no authorized node)". None executed against real
OpenSearch in this environment. Evidence column states what each test will assert on a real node.

| Assignment section | Test (`test_strata_s5_real_opensearch.py`) | Evidence it produces on a real node |
|---|---|---|
| 5 Index creation/lifecycle/isolation | `test_s5_real_index_creation_lifecycle_and_isolation` | Real index + ECS mapping accepted; Profile B ingest; count+manifest measured from OpenSearch; `data.plane=qualification`; no seed/truth/variant/family/fingerprint in candidate events; distinct per-candidate indices |
| 6 Protected `.ranger-qualmeta` | `test_s6_real_qualmeta_protection` | Broker reads meta; candidate denied via `_search`, direct `_doc`, `_msearch`, wildcard `*/_search` on the real Security plugin |
| 7 Candidate roles + DLS | `test_s7_real_candidate_permissions_and_dls`, `test_c_candidate_dls_slug_vs_github_id_and_reconnect` | Own-index read; cross-candidate 403; system-index 403; write refused; slug-vs-github_id identity contract; reconnect/role-refresh survives |
| 7 (Test D) Citation verification | `test_s8_real_evidence_verification`, `test_d_evidence_edge_cases_real` | Valid citation; invalid id; foreign/missing index; non-matching query; timestamp-context match/mismatch; real 404 -> `NotFound`; unavailable cluster -> no credit (fault-injection) |
| 7 (Test E) Provisioning state machine | `test_s9_provisioning_state_machine` (A/B/D/F/G), `test_e_provisioning_states_c_e_h_i` (C/E/H/I) | Fresh; idempotent reuse; interrupted->verified retry; foreign-index refusal; no-claim refusal; corrupt/same-count mutation refusal; concurrent -> one coherent dataset; 429/5xx/partial (labelled fault-injection) never stamped complete |
| 8/10 Full HTTP qualification chain | `test_s10_full_http_qualification_chain` | Real gateway + JWT mint, `/soc/launch` provisioning, candidate-scoped queries, `/case`, draft/verify/submit via `LiveReader`, authorized test-only decision, 95% objective, separate report approval, Board 2 clearance, exactly-once Board 3 promotion |
| 9 Negative qualification controls | `test_s9neg_real_context_refusals` + offline S5 suite | Foreign-candidate citation and non-reproducible citations earn no credit (real index); crypto/activation/score negatives covered by the offline S5 suite (re-run as regressions) |
| 11 Scenario diversity | `test_s11_scenario_diversity_from_queried_telemetry` | Distinct identities/hosts/event-id sets from QUERIED telemetry; cohort A ids absent in cohort B |
| 12 Replay + crypto integrity | `test_s12_historical_replay_and_crypto_integrity` | Pinned regeneration matches the real indexed manifest; signed evidence verifies; tampered digest fails; preservation-contract version correct |

Offline regressions re-run at this commit (NOT real-OpenSearch validation, included for
no-regression assurance): see H.

---

## D. Defects and resolutions

None fixed in this milestone, because no real-node execution was possible here. One defect is
PRE-IDENTIFIED and has a dedicated failing-on-real-node test ready:

- Candidate DLS identity coupling (`test_c_candidate_dls_slug_vs_github_id_and_reconnect`): the SOC
  gateway grants DLS on `ranger.candidate_id == slug`, while the enterprise generator stamps events
  with the generation subject (the binding's raw `github_id`). When slugification changes the id
  (case, dots, underscores), the DLS term and the stored value diverge and a candidate could see zero
  of their own events on a real node. The test asserts the CORRECT contract (candidate sees own
  events). If it fails on first real run, the fix is to align the ingested identity and the DLS term
  at the root (one identity used by both ingestion and authorization), NOT to weaken DLS. No code was
  changed speculatively.

---

## E. Index and access integrity (how it is proven, once executed)

- Dataset counts: measured from OpenSearch (`_count` / `_fetch_all`), not the generator's returned
  list, and cross-checked against the keyed dataset manifest recorded at provision time.
- Mapping: the real `schema.INDEX_MAPPING` is applied by `create_index`; ingestion errors fail closed.
- Role/DLS: real per-candidate role (`candidate_index_pattern` + `dls` on `ranger.candidate_id`),
  internal user, and rolesmapping created via the real Security API; isolation proven by candidate
  basic-auth calls returning 403 across candidates and on the metadata index.
- Metadata isolation: `.ranger-qualmeta` is protected by role-pattern exclusion (its dotted name
  never matches `ranger-<cohort>-<slug>-b*`), validated against the real plugin via `_doc`, `_search`,
  `_msearch` and wildcard.
- Cleanup: `_ostest.isolated_os_namespace` deletes only indices/principals carrying the per-run
  marker and removes only its own `.ranger-qualmeta` stamps by `_id`. No wildcard deletion; the shared
  meta index is never dropped wholesale.

Safety boundary (`siem/tests/_ostest.py`), hardened in this milestone. Destructive operations are
refused unless ALL hold, fail-closed: opt-in env set; a dedicated loopback (or allow-listed) test
URL; node reachable and self-reporting distribution `opensearch` version `2.17.1`; the authorizing
sentinel index present; AND the node looks fresh and unshared (no production-like or unexpected
non-test indices, no populated `.ranger-qualmeta`, no leftover `cand_*`/`ranger_*` security
principals). The sentinel alone is explicitly NOT sufficient proof. Ambiguous ownership defaults to
refusal.

---

## F. Qualification progression (what the chain test demonstrates, once executed)

`test_s10_full_http_qualification_chain` walks the real candidate and reviewer HTTP routes end to end:
eligibility -> approved cohort assignment -> pinned binding -> real OpenSearch provisioning ->
`/soc/launch` -> candidate-scoped telemetry -> `/case` bound to the binding -> draft -> citation
verification against real events -> signed submission -> authorized isolated-test decision -> 95%
objective -> separate human report approval -> Board 2 clearance -> exactly-once Board 3 promotion ->
idempotent re-evaluation with no duplicate award. The signed submission is produced through the real
routes, not pre-inserted into the database. The real gateway JWT mint is exercised; any external
Dashboards interaction is best-effort and is not claimed as validated.

---

## G. Security assessment (scope once executed)

Protected truth and seed never enter candidate-readable events (asserted on queried telemetry);
evidence is Ed25519-signed with a full-payload digest (`PRESERVATION_VERSION`), verified and tamper-
checked; authorization is enforced by OpenSearch (roles + DLS), not by frontend filtering; test-only
activation is signed and environment-bound and must be absent/invalid outside the authorized isolated
test context; the signed qualification decision is authoritative and idempotent; pinned generation
uses a keyed contract MAC with a dataset fingerprint; historical replay reproduces a pinned world
after a live variant edit. The crypto/activation negative controls are covered by the offline S5
suite; the real-index-dependent negatives are in `test_s9neg_real_context_refusals`.

---

## H. Operational behavior

NOT MEASURED in this environment (no node). Ingestion time, Profile B document count, bulk throughput,
429/throttling behavior, concurrency timing and resource usage are to be recorded on the real-node
run and inserted here. No operational numbers are estimated or fabricated.

Offline regressions re-run at this commit for no-regression assurance (these are NOT real-OpenSearch
validation; a passing SQLite/offline test is not proof of OpenSearch behavior):

- `siem/tests/test_strata_s5_board2.py`: 32 passed, 1 skipped offline at this commit (the skipped
  test is the Postgres evaluator-concurrency test; it passes when a disposable Postgres is authorized,
  giving 33 passed, as verified at the S5 baseline). 0 failures.
- F5/workbench/case suites (`test_strata_missions`, `test_workbench`, `test_scenario_eligibility`,
  `test_case_routes`, `test_case_contract`, `test_mission_responsive`, `test_strata_board2_compat`):
  22 passed, 0 failures.
- `siem/tests/test_strata_s5_real_opensearch.py`: 12 collected, 12 skipped (fail-closed; no node).

---

## I. Limitations (not proven)

- No assertion in sections 5-12 has executed against a real Security plugin, mapping, role or DLS.
- Operational metrics (H) are unmeasured.
- The DLS identity-coupling defect (D) is identified but unconfirmed and unfixed, pending a real run.
- Section 7 Test E case I uses labelled fault injection for 429/5xx/partial-bulk/transport; those are
  injected faults, not failures observed from a real node under genuine load.
- A passing local disposable-node run is NOT production (Railway) validation; see section 12 below.

---

## Section 12 - Production configuration compatibility (disposable node vs Railway)

The disposable node must not be described as production validation. Documented differences from the
Railway deployment (`siem/opensearch/Dockerfile`, `opensearch.yml`), from the repository config (the
live node was not accessed):

| Aspect | Disposable test node | Production (Railway) |
|---|---|---|
| OpenSearch version | 2.17.1 (asserted by `_ostest`) | 2.17.1 |
| Security plugin | Enabled, image demo bootstrap | Enabled, managed securityconfig |
| TLS trust | Demo self-signed; client relaxes verify unless `RANGER_TEST_OS_CA` | Ranger-issued CA/node/admin certs from runtime secrets; clients verify the CA |
| Auth principals | Throwaway `admin` + `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | Rotated runtime secret; cert-DN admin `CN=admin.ranger.internal` |
| Role mappings / DLS syntax | Same API calls (`put_role` dls on `ranger.candidate_id`, `put_rolesmapping`) | Same |
| Index permissions / mappings | Same `schema.INDEX_MAPPING`; same `qualification_index_name` patterns | Same |
| Dot-prefixed metadata index | `.ranger-qualmeta` protected by role-pattern exclusion (not in the plugin system-index list) | Same; `opensearch.yml` deliberately does not list it |
| Networking | Loopback 127.0.0.1 only | Private Railway networking |
| Data volume | Ephemeral; destroyed on teardown | Persistent OpenSearch data volume |
| Dashboards | Not run | Dashboards 2.17.1 with multitenancy |

Items that most affect whether a local pass is representative of production: TLS trust (demo vs CA),
the managed securityconfig vs demo bootstrap, Dashboards multitenancy (not exercised locally), and
persistent-volume behavior. These are flagged as production release gates (J).

---

## J. Production release gates (remaining, unchanged by this milestone)

Real-node validation is a development gate, not production authorization. Remaining before any
production candidate activation:

1. Execute this suite on an authorized disposable 2.17.1 node and attach the evidence (B-H filled in).
2. Resolve the DLS identity-coupling defect (D) if the real run confirms it, with a regression test.
3. Validate against the managed securityconfig and Ranger CA TLS (not just demo bootstrap).
4. Validate Dashboards 2.17.1 multitenancy and candidate tenant isolation.
5. Persistent-volume provisioning/backup/restore behavior on Railway.
6. Key management for signing/MAC keys (rotation, key-version verification, missing-key behavior).
7. Rubric calibration sign-off and the separate human-review gate.
8. Production activation issuance (signed, environment-bound) under change control.
9. Independent security review of the above.

None of these are performed here. No merge, deploy, Railway operation, production migration,
candidate activation, S6 or PARALLAX.

---

## K. Handoff

- Branch: `feature/strata-s5-real-opensearch-validation`.
- Base: `f50ff20` (accepted S5). This milestone adds only test harness, tests, disposable bring-up and
  this document; no production code changed.
- Changed/added files this milestone:
  - `siem/tests/_ostest.py` (hardened: shared/previously-used environment detection, fail-closed).
  - `siem/tests/test_strata_s5_real_opensearch.py` (12 real-cluster tests: sections 5-12, Test C/D/E,
    real-context negatives).
  - `siem/opensearch/run-local-opensearch-test.sh` (readiness checks 1-10, no secret printing).
  - `siem/opensearch/docker-compose.test.yml` (loopback-only disposable 2.17.1, Security enabled).
  - `docs/STRATA_S5_1_REAL_OPENSEARCH_VALIDATION.md` (this report).
- Test results at this commit: real-OS suite 12 collected / 12 skipped (no node); offline regressions
  S5 32 passed + 1 skipped (PG concurrency; 33 with PG authorized), F5/workbench 22 passed, 0 failures.
- Remaining blocker: an authorized, Docker-capable host with access to
  `opensearchproject/opensearch:2.17.1`. The founder must supply EITHER that host/image access OR a
  pre-provisioned disposable 2.17.1 node URL + admin credentials that satisfy `_ostest` (loopback or
  allow-listed host, sentinel index created, no production data).
- Cleanup: no real OpenSearch resources were created in this environment (no node). The started Docker
  daemon holds no OpenSearch containers or images.

### Operator runbook (Docker-capable host with image access)

```
# from the repo root, on the host (not inside a container):
OPENSEARCH_INITIAL_ADMIN_PASSWORD='<StrongTestPass123!>' \
  siem/opensearch/run-local-opensearch-test.sh up
# the script verifies: container running, authenticated 200, distribution=opensearch version=2.17.1,
# Security plugin active, fresh/disposable node, then creates + verifies the sentinel. It prints the
# exact RANGER_TEST_OS_* exports (password sourced from your env var, never printed).

# then, with those exports set, on the host:
python3 -m pytest siem/tests/test_strata_s5_real_opensearch.py -v
python3 -m pytest siem/tests/test_strata_s5_board2.py        # S5 regressions
# teardown (destroys only this compose project):
siem/opensearch/run-local-opensearch-test.sh down
```

### Pre-provisioned node (operator already has a disposable 2.17.1 node)

```
# create the authorizing sentinel once on the disposable node, then:
export RANGER_TEST_ALLOW_OS_MUTATION=1
export RANGER_TEST_OPENSEARCH_URL='https://127.0.0.1:9200'   # loopback or an allow-listed host
export RANGER_TEST_OPENSEARCH_USER='admin'
export RANGER_TEST_OPENSEARCH_PASSWORD='<admin-password>'
# optional: RANGER_TEST_OS_CA=/path/to/ca.pem   RANGER_TEST_OS_AUTHORIZED_HOSTS=myhost.test
python3 -m pytest siem/tests/test_strata_s5_real_opensearch.py -v
```

No fabricated measurements or simulated outcomes appear in this report. Until the suite executes
against a real 2.17.1 node, S5.1 remains BLOCKED - TESTS PREPARED, NOT EXECUTED.
