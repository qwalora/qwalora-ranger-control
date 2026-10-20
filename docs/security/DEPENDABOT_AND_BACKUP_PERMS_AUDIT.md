# Qwalora Ranger - Dependabot and backup-permissions security audit

Read-only assessment. No infrastructure, role, grant, key, deployment, or dependency was changed by
this assessment. Portal baseline `b0f1588`, PITR, and both buckets intact at time of writing.

## Source of findings: important distinction
- ACTUAL Dependabot alerts: NOT retrieved. The GitHub token bound to this session is an integration
  token without the `security_events` scope, so `GET repos/qwalora/qwalora-ranger-control/dependabot/
  alerts` returns `403 "Resource not accessible by integration"`; GraphQL and the public `/advisories`
  REST endpoint are also blocked ("sessions are bound to their configured repositories"). The exact
  seven-item Dependabot list and its 3 High / 1 Moderate / 3 Low severity split could NOT be read.
- INDEPENDENT findings (what this document relies on): obtained by resolving the full dependency
  closure of `requirements.txt` and running `pip-audit` (OSV / PyPI Advisory data). GHSA/CVE IDs,
  affected and fixed versions below are VERIFIED from OSV. Because `requirements.txt` pins only the
  eight direct dependencies (transitive packages unpinned) and every vulnerable package found is
  direct, the seven Dependabot alerts almost certainly correspond to this set, but that mapping is
  NOT verified.

## Pinned direct dependencies (requirements.txt)
`Flask==3.0.3`, `Flask-SQLAlchemy==3.1.1`, `SQLAlchemy==2.0.36`, `psycopg2-binary==2.9.10`,
`gunicorn==23.0.0`, `cryptography==43.0.3`, `APScheduler==3.10.4`, `Markdown==3.7`.

Resolved transitive packages were clean in pip-audit: `werkzeug==3.1.9`, `jinja2==3.1.6`,
`markupsafe==3.0.4`, `gunicorn==23.0.0`, `sqlalchemy==2.0.36`, `psycopg2-binary==2.9.10`,
`requests==2.34.2`, `urllib3==2.8.0`, `certifi==2026.10.19`.

## Findings matrix (VERIFIED via pip-audit / OSV; deduped to 8 unique advisories)

| # | Package (installed) | GHSA / CVE | Fix | Direct | Nature | Reachable under Ranger config | Effective class |
|---|---|---|---|---|---|---|---|
| 1 | cryptography 43.0.3 | GHSA-79v4-65xg-pq4g / CVE-2024-12797 | 44.0.1 | yes | Bundled OpenSSL, RFC7250 raw public keys | No (no raw-pubkey TLS via cryptography; TLS terminates at Railway edge) | Low (upstream High) |
| 2 | cryptography 43.0.3 | GHSA-537c-gmf6-5ccf | 48.0.1 | yes | Bundled OpenSSL (TLS/x509 path) | No (only Ed25519 + Fernet primitives used) | Low |
| 3 | cryptography 43.0.3 | GHSA-m959-cc7f-wv43 / CVE-2026-34073 | 46.0.6 | yes | X.509 DNS name-constraint validation flaw | No (no X.509 verification in code) | Low |
| 4 | cryptography 43.0.3 | GHSA-m2h6-j472-rp4c / CVE-2026-69248 | 49.0.0 | yes | Wildcard SAN vs name-constraint bypass | No (no X.509 verification) | Low |
| 5 | cryptography 43.0.3 | GHSA-jwv3-5hgf-82ww / CVE-2026-69249 | 49.0.0 | yes | Recursive cert-chain DoS (duplicate self-signed) | No (no cert-chain building) | Low |
| 6 | cryptography 43.0.3 | GHSA-r6ph-v2qm-q3c2 / CVE-2026-26007 | 46.0.5 | yes | EC `public_key_from_numbers`/`load_der_public_key` | No (Ed25519 only; not NIST-EC number loading) | Low |
| 7 | Flask 3.0.3 | GHSA-68rp-wp8r-4726 / CVE-2026-27205 | 3.1.3 | yes | Missing `Vary: Cookie` on session access -> shared-cache cross-user exposure | Conditional (only if a shared cache fronts authenticated responses) | Medium |
| 8 | Markdown 3.7 | GHSA-5wmx-573v-2qwq / CVE-2025-69534 | 3.8.1 | yes | Malformed HTML-like input -> unhandled `AssertionError` (DoS) | Low (input is admin-authored resource bodies) | Low |

## Production exploitability assessment (evidence-based)
- cryptography (1-6): VERIFIED by source that Ranger uses cryptography only for Ed25519 signing/
  verification (`signing.py`, `parallax/audit_integrity.py`, `parallax/research/store.py`) and Fernet
  symmetric encryption (`crypto.py`). No use of `x509`, `load_der_public_key`, `EllipticCurve`,
  `public_key_from_numbers`, name constraints, cert-chain verification, or raw-public-key TLS. The
  vulnerable code paths are not reached. This is a reachability judgment from code, not a dismissal
  for lack of observed exploitation; upstream High severity is acknowledged but off the reachable
  path.
- Flask (7): sessions are used (OAuth, CSRF). The missing `Vary: Cookie` matters only if an
  intermediary/shared cache caches authenticated responses. No cacheable `Cache-Control` on
  authenticated routes is evidenced and Railway's edge does not cache dynamic authenticated responses
  by default. Effective risk Medium pending confirmation of edge/CDN behavior.
- Markdown (8): `_render_markdown` (app.py:3629) renders admin-authored `resource.body`. Triggering
  the DoS needs admin write access; impact is a single-request 500. Effective risk Low.

No verified exploitable path exists under Ranger's current configuration.

## Remediation plan (smallest compatible updates; versions re-verified against PyPI at implementation)
1. cryptography -> a current patched release that clears all six (>= 49.0.0 per OSV; exact version
   pinned against PyPI metadata and Python 3.12 support at implementation). Ed25519/Fernet/hashes APIs
   are stable; re-run signing + evidence-integrity suites.
2. Flask -> >= 3.1.3 (keeps Flask-SQLAlchemy 3.1.1 compatible; Werkzeug 3.1.x). Validate OAuth,
   sessions, CSRF.
3. Markdown -> >= 3.8.1 (3.8 moved to `html.parser`; the DoS was fixed in 3.8.1). Validate resource
   rendering.

No change needed for SQLAlchemy, psycopg2-binary, gunicorn, APScheduler, Flask-SQLAlchemy, or any
transitive package.

## PostgreSQL backup-permissions assessment (source-verified; live proof pending)
Runner command: `pg_dump -h <host> -p <port> -U <user> -d <db> -Fc --no-owner --no-privileges
--no-password` (full single-DB custom dump; large objects included since `--no-large-objects` is
absent).

Source evidence (`models.py`, `app.py`): 33 ORM tables; column types only String/Integer/DateTime/
Text/Boolean/Float/BigInteger (no `LargeBinary`); no `CREATE EXTENSION`; no partitioning; sequences
are implicit identity/serial (owned, SELECT-covered); schema is `create_all` + additive
`ALTER TABLE ADD COLUMN`.

Conclusion: `CONNECT + pg_read_all_data` on a `LOGIN` role is the necessary and sufficient minimum,
contingent on the live Phase 0 checks. `pg_read_all_data` sufficiency is NOT assumed without
verification, and `BYPASSRLS` is NOT recommended unless Phase 0 finds RLS on dumped tables. Detail and
the read-only test procedure are in `docs/backup/BACKUP_DR_ROLE_PERMISSIONS.md`.

## RLS and large-object risk
- RLS: no `ENABLE ROW LEVEL SECURITY` / `CREATE POLICY` in source. If present live, a non-`BYPASSRLS`
  role would silently under-dump; must be confirmed by the Phase 0 query. Remedy only if found.
- Large objects: no `lo_*` / `LargeBinary` usage; expect empty `pg_largeobject_metadata`. If non-empty
  live, add `--no-large-objects` (if not needed) or grant read on them.

## Remaining live verification (operator, read-only; Phase 0)
```sql
SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE c.relrowsecurity AND n.nspname NOT IN ('pg_catalog','information_schema');   -- expect 0 rows
SELECT count(*) FROM pg_largeobject_metadata;                                      -- expect 0
SELECT extname FROM pg_extension;                                                  -- expect no custom ext
-- plus a trusted per-table row-count baseline for restore parity (query_to_xml count per table).
```

## Release-blocker determination
- No verified exploitable vulnerability under Ranger's actual configuration, so no technical,
  exploitability-based blocker.
- Governance note: if the production gate blocks on any unpatched upstream High regardless of
  reachability, items 1-2 must be remediated first. That is an owner policy decision.

## Final decision (as of this assessment)
- Vulnerability remediation before production: not required on exploitability grounds; recommended as
  low-risk hygiene; required only if policy blocks on unpatched High.
- Backup permissions understood enough to authorize role creation: yes; completeness sign-off waits on
  the Phase 0 / Phase 1 live parity proof; `BYPASSRLS` stays off unless Phase 0 finds RLS.
- Railway encrypted backup pilot next stage: safe to proceed to role creation plus live verification.

Unresolved: the exact Dependabot 7-item list/severities (access-limited; OSV substituted), the live
RLS/large-object/row-count confirmation, the Railway edge-cache question, and the pending post-PITR
41-check integrity audit.
