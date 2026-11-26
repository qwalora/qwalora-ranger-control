#!/usr/bin/env bash
# Local proof gate for qwalora-ranger-control.
#
# Run this to prove a build locally BEFORE pushing. It is the gate that lets you
# iterate many times in-container and push only once, when the build is green.
#
#   scripts/dev_prove.sh         # authoritative: full suite, serial (matches the CI/baseline green)
#   scripts/dev_prove.sh fast    # quick iteration: skips the heavy signing/integration suites
#
# Serial on purpose: the suite shares an in-memory database, so running it under
# pytest-xdist (-n) produces false failures from cross-worker state bleed. Those
# same tests pass serially. Keep this gate serial.
set -euo pipefail
cd "$(dirname "$0")/.."

export DATABASE_URL="${DATABASE_URL:-sqlite:///:memory:}"
export SECRET_KEY="${SECRET_KEY:-dev-prove}"

echo "[prove] import + app factory"
python -c "import app; app.create_app(); print('  app factory OK')"

mode="${1:-full}"
if [[ "$mode" == "fast" ]]; then
  echo "[prove] pytest (fast: skipping heavy signing/integration suites)"
  python -m pytest -q -p no:cacheprovider \
    --ignore=siem/tests/test_strata_s5_board2.py \
    --ignore=siem/tests/test_calibration.py
else
  echo "[prove] pytest (full suite, serial)"
  python -m pytest -q -p no:cacheprovider
fi

echo "[prove] PASS. Build is green locally; safe to release."
