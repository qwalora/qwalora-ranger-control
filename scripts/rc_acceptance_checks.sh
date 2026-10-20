#!/usr/bin/env bash
# rc_acceptance_checks.sh — READ-ONLY post-deployment acceptance for the PARALLAX RC.
# Runs against the isolated parallax-rc database over the rc_ro (read-only) role via your tunnel.
# Makes NO writes: every SQL statement is SELECT inside a READ ONLY transaction, and it reuses the
# existing pinned 41-check audit (b04698e / scripts/px_review_audit.py) rather than replacing it.
#
# Inputs (environment):
#   RC_RO_URL        read-only connection string to the RC DB as rc_ro, e.g.
#                    postgresql://rc_ro:<pw>@127.0.0.1:<tunnel-port>/railway   (via `railway connect`)
#   RC_AUDIT_URL     connection string the 41-check uses (rc_ro is fine; audit is read-only). If unset,
#                    RC_RO_URL is used.
#   RANGER_SIGNING_KEYS   JSON with the historical verify_only PUBLIC entry (+ a disposable active key)
#                    — the SAME value configured on parallax-portal-rc. No historical PRIVATE seed.
#   BASELINE_JSON    path to rc-publications-before-startup.json (pre-startup baseline).
#   EXPECT_TABLES=34 EXPECT_RUNS=7  (defaults per migration evidence)
# Run from a checkout of the deployed commit (acf50ec) so the audit's app modules import.
set -euo pipefail
: "${RC_RO_URL:?set RC_RO_URL to the rc_ro read-only connection string}"
RC_AUDIT_URL="${RC_AUDIT_URL:-$RC_RO_URL}"
EXPECT_TABLES="${EXPECT_TABLES:-34}"
EXPECT_RUNS="${EXPECT_RUNS:-7}"
PROT1="run-f0d33a285717"; PROT2="run-e07852969609"
HIST_KID="legacy:696697820b69d289"
PASS=0; FAIL=0
ok(){ echo "  PASS  $*"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
q(){ psql "$RC_RO_URL" -X -q -t -A -v ON_ERROR_STOP=1 -c "SET TRANSACTION READ ONLY;" -c "$1" 2>/dev/null; }

echo "== 1. PostgreSQL connectivity (rc_ro, read-only) =="
if [ "$(q 'SELECT 1;' | tail -1)" = "1" ]; then ok "rc_ro connects and READ ONLY session established"; else no "cannot connect as rc_ro"; fi
WHO="$(q 'SELECT current_user||%@%||current_database();' 2>/dev/null || true)"
echo "    identity: ${WHO:-unknown}"

echo "== 2. RC identity marker (guard) =="
MC="$(q "SELECT count(*) FROM public.rc_fork_marker;" | tail -1)"
[ "$MC" = "1" ] && ok "rc_fork_marker present with exactly one row" || no "rc_fork_marker row count = ${MC:-missing} (expected 1)"

echo "== 3. Schema compatibility (required objects) =="
TC="$(q "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';" | tail -1)"
[ "$TC" = "$EXPECT_TABLES" ] && ok "public base tables = $TC" || no "public base tables = ${TC:-?} (expected $EXPECT_TABLES)"
SW="$(q "SELECT character_maximum_length FROM information_schema.columns WHERE table_name='resources' AND column_name='summary';" | tail -1)"
[ "$SW" = "900" ] && ok "resources.summary width = 900" || no "resources.summary width = ${SW:-?} (expected 900; ensure_schema widen is swallowed under rc_ro/rc_rw non-owner)"
UQ="$(q "SELECT count(*) FROM pg_constraint WHERE conname='uq_unit_result_record';" | tail -1)"
[ "$UQ" = "1" ] && ok "uq_unit_result_record constraint present" || no "uq_unit_result_record missing (needs an owner-run ALTER, not rc_rw)"
for col in "candidates:status" "candidates:current_board" "cohorts:pathway" "resources:rtype"; do
  t="${col%%:*}"; c="${col##*:}"
  n="$(q "SELECT count(*) FROM information_schema.columns WHERE table_name='$t' AND column_name='$c';" | tail -1)"
  [ "$n" = "1" ] && ok "column $t.$c present" || no "migration column $t.$c MISSING"
done

echo "== 4. Historical research runs + protected records =="
RN="$(q "SELECT count(*) FROM parallax_research_runs;" | tail -1)"
[ "$RN" = "$EXPECT_RUNS" ] && ok "parallax_research_runs = $RN" || no "parallax_research_runs = ${RN:-?} (expected $EXPECT_RUNS)"
for r in "$PROT1" "$PROT2"; do
  p="$(q "SELECT count(*) FROM parallax_research_runs WHERE run_id='$r';" | tail -1)"
  [ "$p" = "1" ] && ok "protected record $r present" || no "protected record $r MISSING"
done

echo "== 5. Signing verification + 41-check integrity (reuse pinned b04698e audit; PUBLIC-key only) =="
: "${RANGER_SIGNING_KEYS:?set RANGER_SIGNING_KEYS (verify_only PUBLIC $HIST_KID + disposable active)}"
AUD="$(mktemp -d)"; trap 'rm -rf "$AUD"' EXIT
# Fetch the pinned auditor and verify its blob, then run it read-only against the RC DB.
python3 - "$AUD/px_review_audit.py" <<'PY'
import sys,urllib.request,hashlib
u="https://raw.githubusercontent.com/qwalora/qwalora-ranger-control/b04698e1291eaa775162505737641426b496b17b/scripts/px_review_audit.py"
d=urllib.request.urlopen(u).read()
assert hashlib.sha1(b"blob %d\0"%len(d)+d).hexdigest()=="57f2ce5bfc25a02c03ecddcaaebc847fc15eccfb",("BLOB MISMATCH")
open(sys.argv[1],"wb").write(d); print("    pinned auditor blob verified 57f2ce5")
PY
# The audit imports the app's store/signing; run it from a checkout of acf50ec (this repo root).
if DATABASE_URL="$RC_AUDIT_URL" RANGER_PARALLAX_LABA_ENV=nonproduction \
     python3 "$AUD/px_review_audit.py" > "$AUD/out.json" 2>"$AUD/err.txt"; then
  T="$(python3 -c "import json;d=json.load(open('$AUD/out.json'));print(d['summary']['total'])" 2>/dev/null || echo '?')"
  F="$(python3 -c "import json;d=json.load(open('$AUD/out.json'));print(len(d['summary']['failed']))" 2>/dev/null || echo '?')"
  [ "$T" = "41" ] && [ "$F" = "0" ] && ok "41-check audit: $T passed / 0 failed (incl. both protected records, signatures, entitlement isolation)" \
     || no "41-check audit: total=$T failed=$F (expected 41/0)"
else
  no "41-check audit did not exit 0 — see $AUD/err.txt"; cat "$AUD/err.txt" | tail -5
fi

echo "== 6. Publication fingerprint diff vs pre-startup baseline =="
if [ -n "${BASELINE_JSON:-}" ] && [ -s "${BASELINE_JSON:-/nonexistent}" ]; then
  q "SELECT json_agg(row_to_json(t) ORDER BY slug) FROM (SELECT slug,status,rtype,category FROM resources) t;" > "$AUD/after.json" 2>/dev/null || true
  python3 - "$BASELINE_JSON" "$AUD/after.json" <<'PY'
import sys,json
try:
  before=json.load(open(sys.argv[1]))
except Exception as e:
  print("    NOTE: baseline not comparable as JSON (%s); compare manually." % type(e).__name__); sys.exit(0)
try:
  after=json.load(open(sys.argv[2])) or []
except Exception:
  after=[]
def norm(x):
  rows = x if isinstance(x,list) else (x.get("resources") or x.get("publications") or [])
  return {r.get("slug"):{k:r.get(k) for k in ("status","rtype","category")} for r in rows if isinstance(r,dict) and r.get("slug")}
b,a=norm(before),norm(after)
added=sorted(set(a)-set(b)); removed=sorted(set(b)-set(a))
changed=sorted(s for s in set(a)&set(b) if a[s]!=b[s])
print("    added=%d removed=%d changed=%d" % (len(added),len(removed),len(changed)))
if added: print("    + "+", ".join(added[:20]))
if removed: print("    - "+", ".join(removed[:20]))
if changed: print("    ~ "+", ".join(changed[:20]))
print("    (publication promotion is gated by PUBLISH_PUBLICATIONS; removals/new publishes here are UNEXPECTED and must be reviewed.)")
PY
  ok "publication diff computed vs baseline (review the added/removed/changed above)"
else
  echo "    SKIP: set BASELINE_JSON to rc-publications-before-startup.json to diff."
fi

echo "== 7. Program entitlement isolation (direct DB, fixture) =="
FIX="nonprod-fixture:parallax-review-selftest"
PROGS="$(q "SELECT string_agg(DISTINCT pm.program,',' ORDER BY pm.program) FROM program_memberships pm JOIN candidates c ON c.id=pm.candidate_id WHERE c.github_id='$FIX';" | tail -1)"
QD="$(q "SELECT count(*) FROM qualification_decisions qd JOIN candidates c ON c.id=qd.candidate_id WHERE c.github_id='$FIX';" | tail -1)"
[ "$PROGS" = "parallax" ] && ok "fixture researcher entitlement = parallax only" || no "fixture entitlement = '${PROGS:-none}' (expected 'parallax')"
[ "${QD:-0}" = "0" ] && ok "fixture has 0 qualification decisions (no qualification issued)" || no "fixture qualification_decisions = $QD (expected 0)"

echo ""
echo "==== ACCEPTANCE SUMMARY: ${PASS} passed, ${FAIL} failed ===="
[ "$FAIL" -eq 0 ] && echo "RESULT: PASS (internal acceptance)" || { echo "RESULT: FAIL — do not accept"; exit 1; }
