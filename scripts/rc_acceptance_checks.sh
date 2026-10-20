#!/usr/bin/env bash
# rc_acceptance_checks.sh - READ-ONLY, FAIL-CLOSED post-deployment acceptance for the PARALLAX RC.
#
# Runs against the ISOLATED parallax-rc database over the rc_ro (read-only) role via your tunnel.
# It makes NO writes: the whole psql session is forced read-only at the server
# (PGOPTIONS=-c default_transaction_read_only=on) and that state is asserted as a hard gate before
# any check runs. It reuses the pinned 41-check audit (b04698e / scripts/px_review_audit.py, blob
# 57f2ce5) rather than reimplementing it.
#
# FAIL-CLOSED CONTRACT
#   * The identity gate (connectivity, current_user, current_database, read-only session, RC marker)
#     runs FIRST; any gate failure aborts immediately with a non-zero exit and never prints PASS.
#   * Every mandatory check must affirmatively succeed. A SQL error, an unparsable/missing baseline,
#     an audit that does not exit 0 with 41/0, or a count that is off by one is a FAIL, never a SKIP.
#   * "RESULT: PASS" is printed only when control reaches the end with zero failures; any mid-script
#     error exits non-zero before that line is ever reached.
#
# SECRET HYGIENE (no secrets or active signing seeds to stdout/logs/args/temp files)
#   * The connection string (which contains the rc_ro password) is NEVER placed on a psql argv.
#     RC_RO_URL is parsed once into PG* environment variables (PGHOST/PGPORT/PGUSER/PGPASSWORD/
#     PGDATABASE); psql is then invoked with no connection string on the command line.
#   * The 41-check auditor reads DATABASE_URL and RANGER_SIGNING_KEYS from its ENVIRONMENT (never
#     argv). RANGER_SIGNING_KEYS is a verify-only public key (+ a disposable active key); no
#     historical PRIVATE seed is used here. No connection string, password, or seed is written to
#     any temp file. The auditor's JSON output is sanitized (no key material).
#
# INPUTS (environment)
#   RC_RO_URL        read-only connection string for the RC DB as rc_ro, e.g.
#                    postgresql://rc_ro:<pw>@127.0.0.1:<tunnel-port>/railway   (via `railway connect`)
#   RC_AUDIT_URL     connection string the 41-check uses (rc_ro is correct; the audit is read-only).
#                    Defaults to RC_RO_URL.
#   RANGER_SIGNING_KEYS   JSON: historical verify_only PUBLIC entry (legacy:696697820b69d289) plus a
#                    disposable active key - the SAME value configured on parallax-portal-rc. No seed.
#   BASELINE_JSON    REQUIRED path to rc-publications-before-startup.json (the pre-startup full-row
#                    MD5 fingerprint baseline). Missing/empty/unparsable => FAIL.
#   REPO_ROOT        checkout of the deployed commit (acf50ec); defaults to the parent of this script.
#                    The auditor imports the app (models, parallax.*) from here.
#   EXPECT_TABLES=34 EXPECT_RUNS=7 EXPECT_PUBLICATIONS=24 EXPECT_CHECKS=41   (migration-evidence defaults)
#
# MODE
#   EMIT_BASELINE=1  Print the canonical publication fingerprint JSON for the CURRENT DB to stdout
#                    (for redirection to a baseline file) and exit. Uses the identity gate first.
#                    The acceptance comparison and this emitter use the IDENTICAL canonical method:
#                    key = resources.pub_id, fingerprint = md5(resources::text) over the full row.
#                    The pre-startup baseline MUST have been produced by this same method for the
#                    comparison to be meaningful; if it was not, regenerate it with EMIT_BASELINE.
#
# EXIT CODES: 0 = PASS; 1 = one or more checks failed; 2 = identity/gate fatal or usage error.

set -uo pipefail   # NOT errexit: checks capture their own exit codes so every check reports; a PASS
                   # line is reachable only at the clean end, so an uncaught error still fails closed.

HIST_KID="legacy:696697820b69d289"
PROT1="run-f0d33a285717"; PROT2="run-e07852969609"
FIXTURE="nonprod-fixture:parallax-review-selftest"
EXPECT_TABLES="${EXPECT_TABLES:-34}"
EXPECT_RUNS="${EXPECT_RUNS:-7}"
EXPECT_PUBLICATIONS="${EXPECT_PUBLICATIONS:-24}"
EXPECT_CHECKS="${EXPECT_CHECKS:-41}"

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$SELF/.." >/dev/null 2>&1 && pwd)}"

PASS=0; FAIL=0
ok(){ echo "  PASS  $*"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
die(){ echo "  FATAL $*" >&2; echo "RESULT: FAIL - $*"; exit 2; }

command -v psql  >/dev/null 2>&1 || die "psql not found on PATH"
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"
: "${RC_RO_URL:?set RC_RO_URL to the rc_ro read-only connection string}"
RC_AUDIT_URL="${RC_AUDIT_URL:-$RC_RO_URL}"

umask 077
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# --- Parse RC_RO_URL into PG* env (password never reaches any argv) -----------------------------
# The URL is read from the environment by the parser (not passed as an argument), and the emitted
# export lines are shell-quoted. Nothing here echoes the password.
PGENV="$(RC_RO_URL="$RC_RO_URL" python3 -I -c '
import os, shlex, sys, urllib.parse as u
try:
    p = u.urlparse(os.environ["RC_RO_URL"])
except Exception as e:
    sys.stderr.write("bad RC_RO_URL: %s\n" % type(e).__name__); sys.exit(3)
if p.scheme not in ("postgresql", "postgres"):
    sys.stderr.write("RC_RO_URL is not a postgresql URL\n"); sys.exit(3)
def ex(k, v): print("export %s=%s" % (k, shlex.quote(v or "")))
ex("PGHOST", p.hostname or "")
ex("PGPORT", str(p.port or 5432))
ex("PGUSER", u.unquote(p.username or ""))
ex("PGPASSWORD", u.unquote(p.password or ""))
ex("PGDATABASE", (p.path or "/").lstrip("/") or "railway")
')" || die "could not parse RC_RO_URL"
eval "$PGENV"
unset PGENV
# Force a server-side read-only session for EVERY libpq connection (psql and the auditor's psycopg).
export PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=60000'
export PGCONNECT_TIMEOUT=10

# psql helper: no conninfo on argv; one scalar per call; strict errors; stderr captured to $TMP/q.err
q(){
  psql -X -q -t -A -w -v ON_ERROR_STOP=1 -c "$1" 2>"$TMP/q.err"
}

# In EMIT_BASELINE mode the ONLY thing on real stdout must be the baseline JSON. Save real stdout on
# fd 3 and send all informational output (gate lines, notices) to stderr; the emitter writes to fd 3.
if [ "${EMIT_BASELINE:-0}" = "1" ]; then exec 3>&1 1>&2; fi

# ================================================================================================
# IDENTITY GATE (fail-closed, runs first). A failure here is FATAL (exit 2) - nothing else runs.
# ================================================================================================
echo "== GATE. RC identity, isolation, and read-only session =="

ONE="$(q 'SELECT 1;')" || die "cannot connect as rc_ro ($(tr -d '\n' <"$TMP/q.err"))"
[ "$ONE" = "1" ] || die "connectivity probe returned '${ONE:-<empty>}'"

CU="$(q 'SELECT current_user;')"       || die "current_user query errored"
CD="$(q 'SELECT current_database();')" || die "current_database query errored"
RO="$(q "SELECT current_setting('transaction_read_only');")" || die "read-only probe errored"
[ "$CU" = "rc_ro" ]    || die "connected as '${CU:-?}', expected rc_ro (refusing to run acceptance as a write-capable or wrong role)"
[ "$CD" = "railway" ]  || die "connected to database '${CD:-?}', expected railway"
[ "$RO" = "on" ]       || die "transaction_read_only='${RO:-?}', expected on (read-only session not enforced)"
ok "connected rc_ro@railway, read-only session enforced (transaction_read_only=on)"

# Prove the session truly rejects writes (belt-and-braces; must raise, no row is created).
if q 'CREATE TEMP TABLE _rc_probe(x int);' >/dev/null 2>"$TMP/q.err"; then
  die "read-only session unexpectedly allowed a write (CREATE TEMP TABLE succeeded)"
else
  ok "write attempt correctly rejected by the read-only session"
fi

# RC fork marker: the isolation guard's identity record - exactly one row.
MC="$(q 'SELECT count(*) FROM public.rc_fork_marker;')" || die "rc_fork_marker not readable ($(tr -d '\n' <"$TMP/q.err"))"
[ "$MC" = "1" ] || die "rc_fork_marker row count = ${MC:-?} (expected exactly 1; this may be the ACCEPTED DB, not the RC fork)"
ok "rc_fork_marker present with exactly one row (RC identity confirmed)"

# ------------------------------------------------------------------------------------------------
# EMIT mode: after the gate, print the canonical publication fingerprints and exit.
# ------------------------------------------------------------------------------------------------
if [ "${EMIT_BASELINE:-0}" = "1" ]; then
  echo "-- emitting canonical publication baseline (method: md5(resources::text), key=pub_id) --" >&2
  ROWS="$(q "SELECT coalesce(json_agg(json_build_object('pub_id', pub_id, 'fp', md5(resources::text)) ORDER BY pub_id), '[]'::json) FROM resources WHERE pub_id IS NOT NULL;")" \
    || die "fingerprint query errored ($(tr -d '\n' <"$TMP/q.err"))"
  printf '%s' "$ROWS" | python3 -I -c '
import json, sys, datetime
rows = json.load(sys.stdin)
print(json.dumps({
  "method": "md5(resources::text) full-row; key=pub_id; predicate=pub_id IS NOT NULL",
  "generated_at_utc": datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z",
  "count": len(rows),
  "fingerprints": {r["pub_id"]: r["fp"] for r in rows},
}, indent=2, sort_keys=True))
' >&3
  exit 0
fi

echo ""
echo "== 1. Schema compatibility (required objects verified against the acf50ec model schema) =="
if TC="$(q "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';")"; then
  if [ "$TC" = "$EXPECT_TABLES" ]; then ok "public base tables = $TC"; else no "public base tables = ${TC:-?} (expected $EXPECT_TABLES)"; fi
else
  no "base-table count query errored ($(tr -d '\n' <"$TMP/q.err"))"
fi

if SW="$(q "SELECT character_maximum_length FROM information_schema.columns WHERE table_name='resources' AND column_name='summary';")"; then
  if [ "$SW" = "900" ]; then ok "resources.summary width = 900 (post-migration widen present)"
  else no "resources.summary width = ${SW:-missing} (expected 900; the ensure_schema widen is swallowed under non-owner rc_rw, so this must already be migrated)"; fi
else
  no "resources.summary width query errored"
fi

# uq_unit_result_record is a MODEL constraint on unit_results (models.py). create_all applies it to
# FRESH databases only; a logically-migrated table keeps it only if the dump carried it. Its absence
# is a real DB-level idempotency gap requiring an owner-run ALTER, so absence is a FAIL (fail-closed).
if UQ="$(q "SELECT count(*) FROM pg_constraint WHERE conname='uq_unit_result_record' AND conrelid='public.unit_results'::regclass;")"; then
  if [ "$UQ" = "1" ]; then ok "uq_unit_result_record present on unit_results"
  else no "uq_unit_result_record missing on unit_results (needs an owner-run ADD CONSTRAINT; not creatable by rc_rw)"; fi
else
  no "uq_unit_result_record lookup errored (is unit_results present?)"
fi

# Verified table/column pairs (names checked against models.py: candidates.status/current_board,
# cohorts.pathway, resources.rtype, resources.pub_id).
for col in "candidates:status" "candidates:current_board" "cohorts:pathway" "resources:rtype" "resources:pub_id"; do
  t="${col%%:*}"; c="${col##*:}"
  if n="$(q "SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='$t' AND column_name='$c';")"; then
    if [ "$n" = "1" ]; then ok "column $t.$c present"; else no "column $t.$c MISSING (expected in the migrated schema)"; fi
  else
    no "column probe $t.$c errored"
  fi
done

echo ""
echo "== 2. Historical research runs + protected records =="
if RN="$(q "SELECT count(*) FROM parallax_research_runs;")"; then
  if [ "$RN" = "$EXPECT_RUNS" ]; then ok "parallax_research_runs = $RN"; else no "parallax_research_runs = ${RN:-?} (expected $EXPECT_RUNS)"; fi
else
  no "parallax_research_runs count errored"
fi
for r in "$PROT1" "$PROT2"; do
  if p="$(q "SELECT count(*) FROM parallax_research_runs WHERE run_id='$r';")"; then
    if [ "$p" = "1" ]; then ok "protected record $r present"; else no "protected record $r MISSING (expected exactly 1)"; fi
  else
    no "protected-record probe $r errored"
  fi
done

echo ""
echo "== 3. Signing verification + pinned 41-check audit (public-key only; reuse b04698e) =="
: "${RANGER_SIGNING_KEYS:?set RANGER_SIGNING_KEYS (verify_only PUBLIC $HIST_KID + disposable active; no seed)}"
if [ ! -f "$REPO_ROOT/models.py" ] || [ ! -d "$REPO_ROOT/parallax" ]; then
  no "REPO_ROOT=$REPO_ROOT is not a checkout of acf50ec (models.py / parallax/ not found); the audit cannot import the app"
else
  # Fetch the pinned auditor into its OWN isolated subdir and verify its git blob hash BEFORE running.
  mkdir -p "$TMP/aud"
  if python3 -I - "$TMP/aud/px_review_audit.py" <<'PY' 2>"$TMP/fetch.err"
import sys, urllib.request, hashlib
url = ("https://raw.githubusercontent.com/qwalora/qwalora-ranger-control/"
       "b04698e1291eaa775162505737641426b496b17b/scripts/px_review_audit.py")
data = urllib.request.urlopen(url, timeout=30).read()
blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
if blob != "57f2ce5bfc25a02c03ecddcaaebc847fc15eccfb":
    sys.stderr.write("BLOB MISMATCH %s\n" % blob); sys.exit(4)
open(sys.argv[1], "wb").write(data)
PY
  then
    ok "pinned auditor fetched and blob verified (57f2ce5)"
    # Run with cwd=REPO_ROOT and PYTHONPATH=REPO_ROOT so `from models import ...` resolves to the
    # acf50ec app. python -I (isolated) is intentionally NOT used: it would IGNORE PYTHONPATH, and the
    # auditor's own sys.path insert points at its temp dir, not the repo. The fetched, blob-verified
    # auditor is alone in $TMP/aud so nothing there can shadow a stdlib/app module. DATABASE_URL and
    # RANGER_SIGNING_KEYS are passed via the environment only - never on argv.
    ( cd "$REPO_ROOT" && \
      env PYTHONPATH="$REPO_ROOT" \
          DATABASE_URL="$RC_AUDIT_URL" \
          RANGER_PARALLAX_LABA_ENV=nonproduction \
          RANGER_SIGNING_KEYS="$RANGER_SIGNING_KEYS" \
          ${RANGER_SIGNING_VERIFY_KIDS:+RANGER_SIGNING_VERIFY_KIDS="$RANGER_SIGNING_VERIFY_KIDS"} \
          python3 "$TMP/aud/px_review_audit.py" >"$TMP/audit.json" 2>"$TMP/audit.err" )
    arc=$?
    # Fail-closed: the audit passes ONLY when it exits 0 AND summary.total == EXPECT_CHECKS AND
    # summary.failed is empty. An abort, a crash, a non-zero exit, or unparsable JSON all => FAIL.
    read -r AT AF < <(python3 -I -c '
import json, sys
try:
    d = json.load(open(sys.argv[1])); s = d["summary"]; print(int(s["total"]), len(s["failed"]))
except Exception:
    print("ERR ERR")
' "$TMP/audit.json")
    if [ "$arc" -eq 0 ] && [ "$AT" = "$EXPECT_CHECKS" ] && [ "$AF" = "0" ]; then
      ok "41-check audit: $AT checks, 0 failed (signatures, chain, protected records, entitlement isolation)"
    else
      no "41-check audit not clean: exit=$arc total=$AT failed=$AF (expected exit 0 / $EXPECT_CHECKS / 0)"
      tail -3 "$TMP/audit.err" | sed 's/^/        /'
      python3 -I -c 'import json,sys
try:
    d=json.load(open(sys.argv[1]))
    if isinstance(d,dict) and d.get("abort"): print("        abort: %s (%s)"%(d.get("abort"),d.get("code")))
    elif isinstance(d,dict) and isinstance(d.get("summary"),dict) and d["summary"].get("failed"):
        print("        failed checks: "+", ".join(map(str,d["summary"]["failed"][:30])))
except Exception:
    pass' "$TMP/audit.json" 2>/dev/null
    fi
  else
    no "could not fetch/verify the pinned auditor ($(tr -d '\n' <"$TMP/fetch.err"))"
  fi
fi

echo ""
echo "== 4. Publication full-row fingerprint diff vs pre-startup baseline (all $EXPECT_PUBLICATIONS records) =="
if [ -z "${BASELINE_JSON:-}" ]; then
  no "BASELINE_JSON is not set (rc-publications-before-startup.json is REQUIRED; cannot verify publications)"
elif [ ! -s "${BASELINE_JSON}" ]; then
  no "BASELINE_JSON '$BASELINE_JSON' is missing or empty (REQUIRED)"
else
  # Canonical live fingerprints: md5 over the full resources row, keyed by pub_id, for every
  # publication (pub_id IS NOT NULL). Only {pub_id, fp} leaves the DB - no row content, no secrets.
  AFTER="$(q "SELECT coalesce(json_agg(json_build_object('pub_id', pub_id, 'fp', md5(resources::text)) ORDER BY pub_id), '[]'::json) FROM resources WHERE pub_id IS NOT NULL;")" \
    || { no "live publication fingerprint query errored ($(tr -d '\n' <"$TMP/q.err"))"; AFTER=""; }
  if [ -n "$AFTER" ]; then
    printf '%s' "$AFTER" > "$TMP/after.json"
    if python3 -I - "$BASELINE_JSON" "$TMP/after.json" "$EXPECT_PUBLICATIONS" <<'PY'
import json, sys
baseline_path, after_path, expect = sys.argv[1], sys.argv[2], int(sys.argv[3])

def fail(msg):
    print("    FAIL: " + msg); sys.exit(1)

# --- Load + normalise the baseline into {key: md5hex}. Unparsable/empty => FAIL (never skip). ---
try:
    with open(baseline_path) as fh:
        raw = json.load(fh)
except Exception as e:
    fail("baseline not parseable as JSON (%s) - cannot verify publications" % type(e).__name__)

def as_map(obj):
    # Accept: {key: hex}; {"fingerprints": {key: hex}}; {"publications"/"records": [ ... ]};
    # or a list of records each carrying a key field and a fingerprint field.
    if isinstance(obj, dict) and "fingerprints" in obj and isinstance(obj["fingerprints"], dict):
        obj = obj["fingerprints"]
    if isinstance(obj, dict):
        for wrap in ("publications", "records", "rows", "resources"):
            if wrap in obj and isinstance(obj[wrap], list):
                obj = obj[wrap]; break
    if isinstance(obj, dict):
        # flat {key: hex}
        out = {}
        for k, v in obj.items():
            if isinstance(v, str):
                out[str(k)] = v.lower()
            elif isinstance(v, dict):
                fp = v.get("fp") or v.get("md5") or v.get("fingerprint") or v.get("hash")
                if isinstance(fp, str):
                    out[str(k)] = fp.lower()
        return out
    if isinstance(obj, list):
        out = {}
        for r in obj:
            if not isinstance(r, dict):
                return {}
            key = r.get("pub_id") or r.get("slug") or r.get("key") or r.get("id")
            fp = r.get("fp") or r.get("md5") or r.get("fingerprint") or r.get("hash")
            if key is not None and isinstance(fp, str):
                out[str(key)] = fp.lower()
        return out
    return {}

base = as_map(raw)
if not base:
    fail("baseline contained no usable {key: full-row-md5} fingerprints")

try:
    after_rows = json.load(open(after_path)) or []
    live = {str(r["pub_id"]): str(r["fp"]).lower() for r in after_rows}
except Exception as e:
    fail("live fingerprint set not parseable (%s)" % type(e).__name__)

# Counts must match the expected publication population exactly (fail-closed on drift).
if len(base) != expect:
    fail("baseline has %d fingerprints, expected %d publications" % (len(base), expect))
if len(live) != expect:
    fail("live DB has %d publications (pub_id IS NOT NULL), expected %d" % (len(live), expect))

# The baseline may be keyed by pub_id or by slug. We key live by pub_id; if the baseline keys do not
# line up with pub_id, re-key live by slug and retry so we compare like-for-like.
if set(base) != set(live):
    # try slug-keying by reading slug alongside (not available here) -> report as structural change.
    missing = sorted(set(base) - set(live))
    extra = sorted(set(live) - set(base))
    msg = []
    if missing: msg.append("missing in live: " + ", ".join(missing[:20]))
    if extra:   msg.append("unexpected in live: " + ", ".join(extra[:20]))
    fail("publication key sets differ (" + "; ".join(msg) + ")")

changed = sorted(k for k in base if base[k] != live[k])
if changed:
    alln = len(changed) == expect
    note = " [ALL records differ - this usually means the baseline was produced with a DIFFERENT " \
           "fingerprint method; regenerate it with EMIT_BASELINE=1 for an apples-to-apples compare]" if alln else ""
    fail("%d of %d publication full-row fingerprints changed since pre-startup%s: %s"
         % (len(changed), expect, note, ", ".join(changed[:20])))

print("    OK: all %d publication full-row fingerprints match the pre-startup baseline" % expect)
PY
    then
      ok "publication fingerprints: all $EXPECT_PUBLICATIONS match the pre-startup baseline (no publication changed during startup)"
    else
      no "publication fingerprint comparison failed (see detail above)"
    fi
  fi
fi

echo ""
echo "== 5. Program entitlement isolation (direct DB, review self-test fixture) =="
if ! FC="$(q "SELECT count(*) FROM candidates WHERE github_id='$FIXTURE';")"; then
  no "fixture candidate probe errored ($(tr -d '\n' <"$TMP/q.err"))"
elif [ "$FC" != "1" ]; then
  no "review self-test fixture candidate (github_id=$FIXTURE) count=${FC:-?} (expected exactly 1; entitlement isolation cannot be verified)"
else
  ok "fixture candidate present (github_id=$FIXTURE)"
  if PROGS="$(q "SELECT coalesce(string_agg(DISTINCT pm.program, ',' ORDER BY pm.program), '') FROM program_memberships pm JOIN candidates c ON c.id=pm.candidate_id WHERE c.github_id='$FIXTURE';")"; then
    if [ "$PROGS" = "parallax" ]; then ok "fixture entitlement = parallax only (no cross-program leakage)"
    else no "fixture entitlement = '${PROGS:-none}' (expected exactly 'parallax')"; fi
  else
    no "entitlement query errored"
  fi
  if QD="$(q "SELECT count(*) FROM qualification_decisions qd JOIN candidates c ON c.id=qd.candidate_id WHERE c.github_id='$FIXTURE';")"; then
    if [ "$QD" = "0" ]; then ok "fixture has 0 qualification decisions (no qualification issued to the self-test fixture)"
    else no "fixture qualification_decisions = ${QD:-?} (expected 0)"; fi
  else
    no "qualification_decisions query errored"
  fi
fi

echo ""
echo "==== ACCEPTANCE SUMMARY: ${PASS} passed, ${FAIL} failed ===="
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT: PASS (internal acceptance)"
  exit 0
else
  echo "RESULT: FAIL - do not accept"
  exit 1
fi
