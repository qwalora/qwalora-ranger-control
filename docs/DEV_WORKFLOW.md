# Dev workflow: strong local build, one push

The goal: iterate and prove as much as possible in-container, then push once, when
the build is green. GitHub is the deploy source and the durability layer, but a
push does not have to mean a deploy, and a batch of work does not have to mean a
batch of pushes.

## The facts this is built on

1. **Deploy is already decoupled from push.** Railway deploys a pinned commit SHA,
   and production has an autodeploy hold. A push to the branch does not deploy
   anything until you move a service's pin. So you can push freely without going
   live.
2. **CI is already lean.** The only committed workflow is
   `.github/workflows/strata-s5-real-opensearch.yml`, which runs on PRs that touch
   core paths (`siem/**`, `strata_*.py`, `app.py`, `models.py`, ...) or on pushes to
   `feature/strata-s5-real-opensearch-validation`. Routine pushes to the parallax
   deploy branch do not run Actions.
3. **The container is ephemeral.** It is wiped between sessions and can reset
   mid-session. So local-only work that is never pushed can be lost. Git is the
   backup, which is why the harness Stop hook insists the current branch is pushed
   at the end of a turn. Do not disable that hook; route around it instead (below).

## Branch convention

- `feat/parallax-submission` is the **deploy branch**. It should receive clean,
  proven commits only, ideally one per batch of work.
- `wip/<topic>` is where you **iterate**. Commit as often as you like. The Stop
  hook pushes `wip/<topic>` to origin each turn, which is just a backup: nothing
  deploys from it and it does not trigger CI. Your messy history lives here.
- When a batch is proven, `scripts/release.sh` squashes `wip/<topic>` into **one**
  commit on the deploy branch and pushes once. That single push is the only thing
  the deploy branch sees.

So: many local commits and harmless `wip/` backup pushes during iteration, then one
clean commit on the deploy branch at the end.

## The two gates

Run from the repo root. Both are serial on purpose: the suite shares an in-memory
database, so `pytest -n` (xdist) produces false failures from cross-worker state
bleed. Those same tests pass serially.

- `scripts/dev_prove.sh fast` - quick iteration gate. App factory plus the suite
  minus the heavy signing/integration files. Run this constantly.
- `scripts/dev_prove.sh` - authoritative gate. App factory plus the full suite,
  serial. This is the green that matches CI. Run before a release.

`scripts/release.sh "message"` runs the full gate first and refuses to push a red
build.

## Typical loop

    git checkout -b wip/credential-endpoint feat/parallax-submission
    # ... edit, iterate ...
    scripts/dev_prove.sh fast          # seconds; run often
    # ... more edits ...
    scripts/dev_prove.sh               # full green before release
    scripts/release.sh "parallax: add verifiable-credential endpoint"
    # one commit on feat/parallax-submission, one push

## Deploy (separate, deliberate)

A push does not deploy. To go live, move the Railway service pin to the new SHA,
nonprod first, then promote. Production stays behind the autodeploy hold until you
release it.

## Notes

- Commits are authored `cloudcwfranck <yakengne@gmail.com>` by project policy. With
  commit signing on, GitHub shows them "Unverified" because the committer email is
  not the harness signing identity. That is cosmetic and clears nothing about
  authorship; it is expected.
- xdist and pytest-timeout are useful locally for triage but are not the gate. The
  gate is serial.
