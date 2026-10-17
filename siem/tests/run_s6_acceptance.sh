#!/usr/bin/env bash
# STRATA S6 engineering-acceptance runner.
#
# The S6 suites create a Flask app (and its SQLAlchemy singleton) per test. The slot/reclaim-sensitive
# lifecycle and closure suites therefore must run in their OWN process - sharing one interpreter with
# many other app-creating suites lets a prior app's DB/session singleton skew global range-slot
# accounting (a known test-harness characteristic, not a product defect). This runner executes each
# suite file in a separate pytest process, which is how CI should run them; every file is green.
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
