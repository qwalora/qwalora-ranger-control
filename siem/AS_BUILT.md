# Phase 2a as-built: Railway SIEM deployment and rollback

Project `qwalora-ranger` (id `ee093894-30f7-4c82-ab5d-d7ef4d1a6454`), environment
`production` (`10fa3e73-...`), region `us-west2`. Provisioned live on 2026-10-15.

## Services

| Service | id | Source | Private endpoint | Volume | Notes |
|---|---|---|---|---|---|
| opensearch-5IDf | 604d93ce-... | repo `qwalora/qwalora-ranger-control` @ `6603a72`, root `/siem/opensearch` | `opensearch.railway.internal:9200` (TLS) | `opensearch-data` 10 GB at `/usr/share/opensearch/data` | single-node 2.17.1, Security plugin, 1 GB heap |
| dashboards | db02d42e-... | image `opensearchproject/opensearch-dashboards:2.17.1` | `dashboards.railway.internal:5601` | none | connects as `kibanaserver` over private TLS |
| siem-validator | 9e7cacc0-... | repo @ `d1801cb`, start `python -m siem.validate_live`, restart NEVER | none | none | one-shot Phase 2a validator |
| portal | f5b563f8-... | repo (unchanged) | — | — | untouched by Phase 2a |
| Postgres | 61497bbf-... | image | — | 50 GB | untouched by Phase 2a |

No public domains on any SIEM service. No candidate OpenSearch users exist in
steady state. No workspace-wide usage hard limit is set (per directive); spend is
observed via metrics, not a cutoff that could take down portal/Postgres.

## Key configuration

- OpenSearch cluster settings baked in the image: `discovery.type: single-node`
  (also skips the production bootstrap checks that would otherwise block Railway).
- Volume ownership fixed by `entrypoint-railway.sh`: container starts as root
  (`RAILWAY_RUN_UID=0`), chowns the data dir to uid 1000, then drops to 1000 via
  `chroot --userspec` and execs the stock OpenSearch entrypoint. OpenSearch does
  NOT run as root.
- Heap pinned by `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g`.
- Admin password in `OPENSEARCH_INITIAL_ADMIN_PASSWORD` (Railway variable, secret).
- Dashboards: `OPENSEARCH_HOSTS=https://opensearch.railway.internal:9200`,
  `OPENSEARCH_SSL_VERIFICATIONMODE=none` (demo certs), `kibanaserver` credentials.

## Rollback

- Remove a SIEM service: delete `dashboards`, `siem-validator`, `opensearch-5IDf`
  in the Railway dashboard (service → Settings → Delete). Deleting a service does
  not delete its volume; delete `opensearch-data` separately to reclaim storage.
- Roll back OpenSearch image only: the service is pinned to commit `6603a72`;
  redeploy an earlier deployment from the service's Deployments tab.
- The portal and Postgres are independent; removing the SIEM leaves boards 1-4 on
  the pre-SIEM dataset model exactly as before.

## Cleanup still owed (blocked by the destructive-action approval gate in this run)

- A leftover **staged-create** service `opensearch` (`6d14666e-...`) and its staged
  volume `opensearch-data` (`4e3fc1c1-...`) remain in the environment's pending
  changes. They are inert (never deploy unless committed). Discard them in the
  dashboard: Pending changes → discard, or delete the staged `opensearch` service.
  Do NOT "commit/deploy" the pending changes, which would create a duplicate node.
