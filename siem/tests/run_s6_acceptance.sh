#!/usr/bin/env bash
# STRATA S6 engineering-acceptance runner.
#
# The S6 suites create a Flask app per test. The post-closure review resolved the shared-state
# coupling that made the combined run order-dependent: the real causes were an ADMIN_TOKEN set via
# setdefault at import (so import order decided the process-wide token and reconcile 401'd) and tests
# mutating app module globals (MAX_CONCURRENT, reclaim thresholds) without restoring them. Both are
# fixed (explicit per-app token; autouse snapshot/restore of those globals; StaticPool + per-test
# drop_all + an expiring test client for session hygiene). The combined single-process run now passes
# deterministically in forward AND reversed order. This runner still executes each file in its own
# process as the CI strategy (clean, parallelizable); every file is green.
set -u
cd "$(dirname "$0")/../.." || exit 2
SUITES=(
  siem/tests/test_strata_s6_attestation.py
  siem/tests/test_strata_s6_families.py
  siem/tests/test_strata_s6_flag_placement.py
  siem/tests/test_strata_s6_governance.py
  siem/tests/test_strata_s6_capstone.py
  siem/tests/test_strata_s6_lifecycle.py
  siem/tests/test_strata_s6_acceptance.py
  siem/tests/test_strata_s6_closure.py
  siem/tests/test_strata_s6_retention.py
  siem/tests/test_strata_s6_real_credit.py
  siem/tests/test_strata_s6_capacity.py
  siem/tests/test_strata_s6_remote_state.py
)
fail=0
for s in "${SUITES[@]}"; do
  python -m pytest "$s" -p no:cacheprovider -q >/tmp/s6_$(basename "$s").log 2>&1
  rc=$?
  n=$(grep -aoE "[0-9]+ passed(, [0-9]+ skipped)?" "/tmp/s6_$(basename "$s").log" | tail -1)
  if [ $rc -eq 0 ]; then echo "PASS  $s  ($n)"; else echo "FAIL  $s  (rc=$rc)"; fail=1; fi
done
[ $fail -eq 0 ] && echo "ALL S6 SUITES GREEN" || echo "SOME S6 SUITES FAILED"
exit $fail
