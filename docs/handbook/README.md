# Ranger candidate handbook — source, build, and publication

## Single source

`RANGER_CANDIDATE_HANDBOOK.md` is the single, version-controlled source for the candidate handbook,
accurate to the deployed portal under the approved unified-platform architecture. Both the navigable
web handbook and the downloadable PDF are generated from this one file — there is no second
documentation system to drift from it.

## Build (local)

```
python scripts/build_handbook.py
```

Produces (into the git-ignored `docs/handbook/dist/`):
- `ranger-candidate-handbook.html` — navigable, standalone, with a table of contents.
- `Qwalora-Ranger-Candidate-Handbook.pdf` — downloadable PDF from the same source.

Each build embeds the app git commit and a UTC build timestamp as document metadata, so a built
artifact is traceable to a specific portal commit.

Verified on build at commit 62800ee: 7-page PDF, table of contents present, and the key policy
statements (95% standard, portal-hosted Board 1, Board-2 OpenSearch unavailable in nonproduction,
PARALLAX assessment-only, GitHub-OAuth authentication, the PENDING POLICY REVIEW items) all present.

## Release synchronization

`scripts/doc_release_check.py` validates that the candidate-facing routes and per-board environment
facts this handbook relies on still match the live application, so a change to candidate routes, lab
access, drafts, evidence schemas, or assessment requirements fails the check until the handbook is
reviewed. The handbook must never claim to be synchronized with a deployment unless that exact
version is actually published and reachable.

## Publication — BLOCKED pending authorization (publication diff for review)

The public manual at `ranger.qwalora.com/downloads/Qwalora-Ranger-Manual.pdf` is served from the
**separate `qwalora-cyber-range` repository** (`portfolio/site/src/downloads/`) and deployed through
Vercel. Publishing this corrected handbook would require, and is BLOCKED pending, explicit
authorization for all of:

1. **Content/policy sign-off** — adopt this handbook as the public manual and resolve the PENDING
   POLICY REVIEW items in `docs/HANDBOOK_AUDIT_DISCREPANCY_REGISTER.md` (program model, SIEM
   technology, legacy prerequisites, rubric weights, the "no AI" clause as it applies to PARALLAX).
2. **Publication diff in `qwalora-cyber-range`** (prepared for review; NOT applied here):
   - replace `portfolio/site/src/downloads/Qwalora-Ranger-Manual.md` (legacy v4.0) with this
     handbook's content;
   - add a committed, reproducible MD→PDF generation step to that repo (it currently commits a
     pre-generated PDF binary with no in-repo generator), e.g. the pandoc + wkhtmltopdf step in
     `scripts/build_handbook.py`;
   - regenerate `Qwalora-Ranger-Manual.pdf` from that source.
3. **Deploy authorization** — merge `qwalora-cyber-range` to its `main` and let Vercel publish.

Until the live URL serves the corrected version, the public handbook status is **BLOCKED**, never
"published". This repository does not merge `qwalora-cyber-range` to `main` or publish the PDF.
