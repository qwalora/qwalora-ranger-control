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

## Post-deployment acceptance (operator-side, read-only against the RC fork)

Executed by the operator against the disposable fork over the read-only `rc_ro` role, with
`RANGER_SIGNING_KEYS` set to the verify-only public entry; no record modified.

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

## Open operational-readiness items (tracked separately)

1. `/healthz` direct HTTP check over the private network - pending an in-network exec
   (`railway ssh` into a `parallax-rc` service, or dashboard exec):
   `curl -i http://parallax-portal-rc.railway.internal:8080/healthz` (expect `{"status":"ok","db":true}`).
2. Rotation of the previously exposed RC Postgres superuser password - RC-only, operator-executed
   over a private connection (see the RC readiness notes).
3. Separate RC GitHub OAuth app + controlled authenticated researcher/reviewer acceptance -
   depends on an access-controlled RC reachability decision (no public domain).

Deployment is operationally healthy; full RC acceptance is gated on the items above.
