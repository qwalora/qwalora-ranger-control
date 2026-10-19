# Release-aligned documentation validation

This describes the controlled mechanism that keeps candidate-facing documentation from silently
falling behind the deployed application (task section C), and records the exact dependency that
blocks public handbook publication.

## The check

`scripts/doc_release_check.py` is the documentation gate. It is fail-closed and must pass before
a release is considered documentation-safe. It validates, against the live application:

1. **Routes** — every candidate-facing route the docs rely on still exists in the Flask URL map
   (`/me`, `/me/workspace`, `/me/workspace/incident`, `/me/mission`, `/account`,
   `/parallax/workspace`, `/resources`). A renamed or removed route fails the check.
2. **Environment facts** — each board's `environment_kind` still matches what the docs state
   (Board 1 portal dataset, Board 2 OpenSearch SIEM, Boards 5-6 isolated range). This prevents a
   document describing the wrong platform.
3. **No false OpenSearch promise** — Board 2 must not report its OpenSearch environment as
   available unless the SOC gateway and Board-2 UI are actually configured in this environment.
4. **Handbook link** — the candidate Handbook points at the authoritative published manual
   (`/downloads/Qwalora-Ranger-Manual.pdf`), never the removed `/handbook` path.
5. **Internal links** — relative links inside `docs/` resolve to files that exist.

It emits release metadata (app git commit, UTC timestamp, `RANGER_DEPLOYMENT_ID`, `RANGER_ENV`)
for the release record. It is covered by `siem/tests/test_doc_release_check.py` (including negative
controls that prove it catches a missing route and environment drift), so it runs in the normal
PostgreSQL-backed regression.

## How it ties to the release process

- **Pre-deploy:** run `python scripts/doc_release_check.py` (exit 0 required) as part of the
  release checklist for the portal; it runs automatically in the test suite.
- **Documentation-impact review trigger:** any change to candidate navigation, lab-launch
  mechanisms, assessment instructions, submission schemas, grading requirements, program
  permissions, candidate-facing terminology, or evidence/review workflows MUST re-run this check
  and review the candidate documentation. A route rename or an `environment_kind` change will fail
  the check until the docs are reconciled.
- **Stale-document detection:** a doc that references a route or environment the app no longer
  provides fails the check; obsolete documentation cannot be presented as authoritative.

## Public handbook publication — BLOCKED dependency (honest status)

Generating or editing a PDF locally is **not** publication. The published manual is served from a
**separate system**:

- Source + PDF live in `qwalora/qwalora-cyber-range` at
  `portfolio/site/src/downloads/Qwalora-Ranger-Manual.{md,pdf}` (not in this portal repo).
- The site build (`portfolio/site/build.mjs`) only copies `src/ -> dist/`; **no MD->PDF generation
  tool is committed**, so regenerating the PDF requires an external tool that must first be added
  to that repo for reproducibility.
- Publication is a **Vercel deploy** of `qwalora-cyber-range`, triggered by **merge to its `main`**.

Therefore, updating the live manual at `ranger.qwalora.com` requires, and is BLOCKED pending:
1. A program-model/policy decision (see `HANDBOOK_AUDIT_DISCREPANCY_REGISTER.md`) on what the manual
   should say, since the current manual describes a different delivery model than the portal.
2. A committed, reproducible MD->PDF generation step in `qwalora-cyber-range`.
3. Explicit authorization to merge `qwalora-cyber-range` to `main` and deploy to Vercel.

Until the live URL serves the corrected version, publication status is **BLOCKED**, never
"published". The release check above deliberately does **not** claim the public PDF is current.
