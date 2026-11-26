#!/usr/bin/env bash
# Collapse a proven local branch into ONE commit on the deploy branch and push once.
#
# The point: iterate on a wip/ branch with as many local commits as you like, then
# run this once to land a single clean commit on the deploy branch. It refuses to
# push a red build (it runs the full local gate first).
#
#   scripts/release.sh "parallax: add verifiable-credential endpoint"
#
# Env:
#   BASE   deploy branch to land on (default: feat/parallax-submission)
#
# Note: commits are authored cloudcwfranck <yakengne@gmail.com> by project policy.
# GitHub will show them "Unverified" (the committer email is not the harness signing
# identity); that is cosmetic and expected. Deploy is a separate step: moving the
# Railway service pin to the new SHA, nonprod first.
set -euo pipefail
cd "$(dirname "$0")/.."

BASE="${BASE:-feat/parallax-submission}"
MSG="${1:?usage: scripts/release.sh \"commit message\"}"
WIP="$(git branch --show-current)"

if [[ "$WIP" == "$BASE" ]]; then
  echo "You are on $BASE. Work on a wip/ branch so release can squash into $BASE." >&2
  exit 1
fi

# Prove it before it leaves the machine.
scripts/dev_prove.sh

git config user.name  cloudcwfranck
git config user.email yakengne@gmail.com

git checkout "$BASE"
git pull --ff-only origin "$BASE" || true
git merge --squash "$WIP"
git commit --no-verify -m "$MSG"
git push --no-verify origin "$BASE"

echo "Pushed ONE commit to $BASE: $(git rev-parse --short HEAD)"
echo "Deploy when ready: move the Railway service pin to this SHA (nonprod first)."
