# Phase 2b Priority 2 — Candidate JWT authentication (security gate PASSED)

Date: 2026-10-15. Validated against the live OpenSearch Security plugin (not a
fake) by `siem/validate_live.py` mode `jwt`, running inside the private network and
driving OpenSearch exactly as Dashboards forwards a token. Candidate access remains
DISABLED.

## Design

- **Minting (portal/broker):** Ranger validates the candidate's GitHub session,
  admission status, board authorization, and identity, then mints a short-lived
  (10 min) RS256 JWT: `iss=qwalora-ranger`, `aud=qwalora-siem`, `sub=<candidate
  OpenSearch username>`, `iat`/`nbf`/`exp`, `jti`, `ranger.{cohort,board}`. Signed
  with the Ranger JWT private key.
- **Verification (OpenSearch):** a `jwt_auth_domain` holds only the PUBLIC key as
  `signing_key`; it enforces signature, `required_issuer`, `required_audience`, and
  expiry (with 30s clock skew). `subject_key=sub`; **no `roles_key`** — the token's
  roles claim is never trusted. Authorization is purely by server-side
  `roles_mapping(users=[sub])` to the per-candidate role, which defeats role-claim
  spoofing even on a validly-signed token.
- **Isolation:** per-candidate index (`ranger-<cohort>-<cid>-b*`) + document-level
  security on `ranger.candidate_id`.
- **Revocation (enforceable, not expiry-only):** deleting the candidate's
  `roles_mapping` makes any live token map to no role -> 403 on the next request,
  independent of `exp`. Short TTL is defense in depth.
- **Admin separation:** `ranger_soc_admin` least-privilege role (read SIEM + manage
  detectors/monitors) via basic auth, distinct from candidate JWT access and from
  the break-glass `admin`. Grading logic and the answer key live in the Ranger
  portal + Postgres, never in OpenSearch, so SOC admins cannot see them; the
  security index itself is denied to `ranger_soc_admin` (403).

## Demonstrated (all PASS, real Security plugin)

| Required demonstration | Result |
|---|---|
| Candidate A accesses their assigned data | `own_access_ok` 200 |
| A cannot access B's indices/documents | `cross_candidate_denied` 403 (+ DLS from P1 F5) |
| Candidates cannot grant themselves permissions | `role_spoof_ineffective` (cross 403, security-API 403); `privilege_escalation_blocked` (put_role 403, security index 403) |
| Expired / forged / revoked tokens rejected | `expired_rejected`, `tampered_rejected`, `wrong_key_rejected`, `revocation_enforced` |
| Board authorization removed -> access lost | `revocation_enforced`: roles_mapping delete -> live token 403 |
| Authorized admins reach permitted SOC functions | `admin_least_privilege`: SIEM read 200 |
| Admin accounts cannot expose grading secrets/evidence | security index read 403; grading never in OpenSearch |
| No shared admin password reachable by candidates | JWT-only; candidates receive no OpenSearch password |
| Issuer / audience validated | `wrong_issuer_rejected`, `wrong_audience_rejected` |

## Key-management posture (per your security requirements)

- The TLS **CA private key** is NOT in any OpenSearch/service runtime env (offline
  only; used to sign leaf certs). OpenSearch holds only its leaf node + admin keys.
- The **JWT signing (private) key** is held by the minting side (portal/validator),
  NOT on OpenSearch; OpenSearch holds only the JWT public key.
- **Cert/key lifecycle:** leaf certs valid 10y (pilot); rotate by re-issuing from
  the CA and updating the node/admin key vars + redeploy. CA rotation: issue a new
  CA, cross-sign or redeploy nodes + update the CA var and every client's trust
  store, then retire the old CA. JWT key rotation: generate a new keypair, update
  OpenSearch `signing_key` (config via securityadmin) and the portal's private key;
  support an overlap window by listing both public keys during rollout.

## Not yet done (candidate-enablement steps, intentionally deferred)

- Dashboards `opensearch_security.auth.type: jwt` wiring and an authenticated
  public access gateway (OpenSearch stays private; the gateway is the only public
  entry and is Ranger-authenticated). Screenshots of the real Dashboards candidate
  experience depend on that gateway.
- These are the ENABLEMENT steps the directive says not to turn on yet. The
  security gate above is complete, so enablement is unblocked on your approval.

## Disaster recovery note

The snapshot repo is a filesystem repo on the SAME volume (validated restore in
P1.7). That is NOT disaster recovery. Recommend adding an object-storage snapshot
repo (e.g., an S3-compatible bucket) for off-volume/off-site backups before GA;
this needs a storage bucket (new resource) and your approval.

## Release recommendation

The candidate authentication and isolation security gate PASSES on the real
Security plugin. Recommend: (1) approve the Dashboards JWT wiring + authenticated
gateway as the enablement step, captured with screenshots and a final end-to-end
candidate walkthrough; (2) add off-site snapshots before GA; (3) then enable
candidate access for a limited pilot cohort. Do not enable production candidate
access until (1) and the end-to-end walkthrough are signed off.
