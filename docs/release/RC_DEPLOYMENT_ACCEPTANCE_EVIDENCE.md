# PARALLAX RC - deployment and post-deployment acceptance evidence

Isolated nonproduction validation of the release candidate in the `parallax-rc` environment.
This record is evidence only; it changes no accepted artifact. The deployed revision, historical
research records, signing keys, and the preserved publication baseline are unchanged.

## Deployed release

| Field | Value |
|---|---|
| Railway project | `qwalora-ranger` (`ee093894-30f7-4c82-ab5d-d7ef4d1a6454`) |
| Environment | `parallax-rc` (`6abda105-12e3-4310-b764-bd92cd354957`) |
| Application service | `parallax-portal-rc` (`709cb0d3-6ef8-4670-b772-cf49ae3b873d`) |
| Database service | `parallax-postgres-rc` (`f14887e3-4f6e-433b-9ec7-4fb8c77f7628`) |
| Deployed commit | `acf50ec011d7e0f51f9c21e15a80b8b7df2e8331` (branch `integration/release-candidate`) |
| Deployment ID | `30d13aba-7462-4e79-88d3-850c33933086` |
| Deployment status | `SUCCESS` (build ~2 min; created 2026-10-20 22:53:55 UTC) |
| Deployment method | `serviceInstanceDeploy` on the existing service (not repository-level create) |

## Startup health (Railway-side, read-only)

- Gunicorn 23.0.0 started, `Listening at http://0.0.0.0:8080`, 2 sync workers (pids 4, 5).
- Single clean boot, no restart cycles, no crash loop, no stack traces.
- Service state `online`, 1/1 replica running, 0 crashed.
- Database-identity guard passed: `rc_guard.assert_rc_identity()` is the first statement in
  `create_app()` and runs before any write; successful worker boot proves the guard accepted the
  marked disposable fork and the app connected to `parallax-postgres-rc`. A failed guard fails
  closed before any table is created.
- No schema or permission errors observed at startup.
- Resource usage: portal CPU idle (max 0.043 cores) / memory ~129 MB; Postgres CPU idle
  (max 0.004 cores) / memory ~64 MB. Combined ~193 MB, negligible compute.

## Public exposure

- `parallax-portal-rc`: no service domains, no custom domains, no TCP proxies, no new volumes.
- The RC portal is private; candidate access is not enabled.

## Post-deployment acceptance after INITIAL deployment (operator-side, read-only against the RC fork)

Executed by the operator against the disposable fork over the read-only `rc_ro` role, with
`RANGER_SIGNING_KEYS` set to the verify-only public entry; no record modified. These results are
as of initial deployment, before the superuser password rotation below.

| Check | Result |
|---|---|
| RC acceptance checks | 22 / 22 passed |
| Historical integrity checks (`scripts/px_review_audit.py`) | 41 / 41 passed |
| Publication fingerprints unchanged | 24 / 24 matched |
| Process exit code | 0 |

- Preserved pre-startup publication baseline: `rc-publications-before-startup.json`
  (operator host), SHA-256 `cab041be0f896a1c0c49eed7e5eb75f383d12cea6e53b91c38ae6ea35b0d4c95`.
  Baseline not regenerated.
- Protected historical records verified (hash + Ed25519 + trusted kid): `run-f0d33a285717`,
  `run-e07852969609`.

## Boundaries respected

- No change to production, `parallax-nonprod`, historical research evidence, signing keys, the
  accepted deployment commit `acf50ec`, or the preserved publication baseline.
- No public domain, no TCP proxy, no additional services, volumes, GPU, subscriptions, or infra.
- PR #4 (design-completion into `integration/parallax-research-platform`) remains open and
  unmerged, independent of this release.

## Operational evidence after superuser rotation (operator-reported)

Completed and verified by the operator over the authorized private connection:

| Item | Status |
|---|---|
| RC deployment at `acf50ec` | VERIFIED (SUCCESS) |
| Direct `/healthz` (private) | VERIFIED - HTTP 200, `db:true` |
| RC Postgres superuser password rotated (RC-only) | VERIFIED |
| Railway configuration updated to match | VERIFIED |
| Fresh PostgreSQL administrative connection post-rotation | VERIFIED |
| Application health re-checked post-rotation | VERIFIED |
| Post-rotation historical integrity audit (41-check) | PENDING - not yet rerun |
| Post-rotation publication fingerprint recheck (24) | PENDING - not yet rerun |

The most recent acceptance rerun attempt did not execute its checks: the fresh shell was missing
the seven required environment variables, so the run aborted at setup. This is a shell/environment
setup condition, NOT a database, rotation, or integrity failure. The post-rotation recheck is
therefore PENDING, neither passed nor failed. The pre-rotation 41/41 and 24/24 results above stand
as of initial deployment and are unaffected.

## Open items

1. Post-rotation historical-integrity recheck (41-check over `rc_ro`) and publication-fingerprint
   recheck (24) - PENDING. To be rerun once a safe execution path is chosen; see the automation
   assessment in `RC_OPERATIONAL_READINESS_NOTES.md`.
2. GitHub OAuth and external researcher/reviewer access - intentionally DISABLED until their
   separate security requirements (dedicated test OAuth app, verified protected access path) are met.

Deployment is operationally healthy and the superuser rotation is complete; full RC sign-off is
gated only on the post-rotation integrity recheck above.
