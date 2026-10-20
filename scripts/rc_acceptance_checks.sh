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
#   RANGER_SIGNING_KEYS   JSON array of {kid,alg,state,seed_b64?,public_b64?}: the historical
#                    verify_only entry (legacy:696697820b69d289, PUBLIC ONLY, no seed) plus the single
#                    disposable active key (which legitimately carries its private seed_b64) - the SAME
#                    value configured on parallax-portal-rc. The shape is validated before the audit.
#   BASELINE_JSON    REQUIRED path to the preserved pre-startup baseline rc-publications-before-startup
#                    .json. The baseline fingerprints were produced with md5(row_to_json(r)::text) over
#                    complete resource rows; this script matches that exact expression. The file is
#                    read-only here and never regenerated or overwritten. Missing/empty/unparsable,
#                    wrong record count, differing identifier sets, or any fingerprint change => FAIL.
#   BASELINE_SHA256  OPTIONAL expected SHA-256 of BASELINE_JSON. When set, the file must match it
#                    byte-for-byte before it is trusted (preserves the original evidence). The known
#                    value for the current baseline is
#                    cab041be0f896a1c0c49eed7e5eb75f383d12cea6e53b91c38ae6ea35b0d4c95
#   REPO_ROOT        checkout of the deployed commit (acf50ec); defaults to the parent of this script.
#                    The auditor imports the app (models, parallax.*) from here.
#   EXPECT_TABLES=34 EXPECT_RUNS=7 EXPECT_PUBLICATIONS=24 EXPECT_CHECKS=41   (migration-evidence defaults)
#
# MODE
#   EMIT_BASELINE=1  Print publication fingerprints for the CURRENT DB to stdout (records with
#                    id/pub_id/slug/fp) using the SAME expression the comparison uses -
#                    md5(row_to_json(r)::text) over the full resource row, predicate pub_id IS NOT NULL
#                    - then exit, after the identity gate. This is a pre-startup / documentation aid.
#                    Do NOT use it to regenerate or overwrite the preserved baseline, and do NOT create
#                    a new baseline after deployment.
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

# --- URL -> PG* env export lines (password never reaches any argv) ------------------------------
# Reads the URL from the NAMED env var given as $1 (never the value on argv) and prints shell-quoted
# `export` lines for PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE. Nothing here echoes the password.
pgenv_for(){
  python3 -I -c '
import os, shlex, sys, urllib.parse as u
name = sys.argv[1]
try:
    p = u.urlparse(os.environ[name])
except Exception as e:
    sys.stderr.write("bad %s: %s\n" % (name, type(e).__name__)); sys.exit(3)
if p.scheme not in ("postgresql", "postgres"):
    sys.stderr.write("%s is not a postgresql URL\n" % name); sys.exit(3)
def ex(k, v): print("export %s=%s" % (k, shlex.quote(v or "")))
ex("PGHOST", p.hostname or "")
ex("PGPORT", str(p.port or 5432))
ex("PGUSER", u.unquote(p.username or ""))
ex("PGPASSWORD", u.unquote(p.password or ""))
ex("PGDATABASE", (p.path or "/").lstrip("/") or "railway")
' "$1"
}

PGENV="$(pgenv_for RC_RO_URL)" || die "could not parse RC_RO_URL"
eval "$PGENV"; unset PGENV
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
  echo "-- emitting publication fingerprints (method: md5(row_to_json(r)::text) over full resource rows) --" >&2
  echo "-- WARNING: never redirect this over the preserved pre-startup baseline; it is evidence --" >&2
  ROWS="$(q "SELECT coalesce(json_agg(json_build_object('id', r.id, 'pub_id', r.pub_id, 'slug', r.slug, 'fp', md5(row_to_json(r)::text)) ORDER BY r.pub_id), '[]'::json) FROM resources r WHERE r.pub_id IS NOT NULL;")" \
    || die "fingerprint query errored ($(tr -d '\n' <"$TMP/q.err"))"
  printf '%s' "$ROWS" | python3 -I -c '
import json, sys, datetime
rows = json.load(sys.stdin)
print(json.dumps({
  "method": "md5(row_to_json(r)::text) over full resource row; predicate=pub_id IS NOT NULL",
  "generated_at_utc": datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z",
  "count": len(rows),
  "records": rows,
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
AUDIT_OK=1

# 3a. Validate the signing registry SHAPE without printing any key material. The registry is a JSON
#     array of {kid,alg,state,seed_b64?,public_b64?}. Exactly one `active` entry, which MUST carry a
#     private seed_b64 (it is the disposable signer - legitimately private). Every verify_only /
#     retired / revoked entry MUST NOT carry a seed_b64. The historical kid must be present exactly
#     once as verify_only, with public_b64 and NO seed. Only kid/state/counts are ever printed.
if RANGER_SIGNING_KEYS="$RANGER_SIGNING_KEYS" HIST_KID="$HIST_KID" python3 -I -c '
import os, json, sys
try:
    reg = json.loads(os.environ["RANGER_SIGNING_KEYS"])
except Exception as e:
    print("registry is not valid JSON (%s)" % type(e).__name__); sys.exit(1)
if not isinstance(reg, list) or not reg:
    print("registry must be a non-empty JSON array"); sys.exit(1)
for e in reg:
    if not isinstance(e, dict) or not e.get("kid") or not e.get("state"):
        print("every entry needs kid and state"); sys.exit(1)
active = [e for e in reg if e.get("state") == "active"]
if len(active) != 1:
    print("expected exactly one active entry, found %d" % len(active)); sys.exit(1)
if not active[0].get("seed_b64"):
    print("active entry %r has no seed_b64 (cannot sign)" % active[0].get("kid")); sys.exit(1)
for e in reg:
    if e.get("state") in ("verify_only", "retired", "revoked") and e.get("seed_b64"):
        print("non-active entry %r (state=%s) carries a private seed_b64 - forbidden"
              % (e.get("kid"), e.get("state"))); sys.exit(1)
hist = [e for e in reg if e.get("kid") == os.environ["HIST_KID"]]
if len(hist) != 1:
    print("historical kid present %d times (expected 1)" % len(hist)); sys.exit(1)
if hist[0].get("state") != "verify_only":
    print("historical kid state=%r (expected verify_only)" % hist[0].get("state")); sys.exit(1)
if hist[0].get("seed_b64"):
    print("historical verify-only kid carries a private seed_b64 - forbidden"); sys.exit(1)
if not hist[0].get("public_b64"):
    print("historical verify-only kid has no public_b64 to verify with"); sys.exit(1)
print("ok")
' >"$TMP/signing.err" 2>&1; then
  ok "signing registry shape valid (one active with seed; $HIST_KID verify_only, public-only; no seed in any verify-only entry)"
else
  no "signing registry invalid: $(tr -d '\n' <"$TMP/signing.err")"; AUDIT_OK=0
fi

# 3b. The audit connects with RC_AUDIT_URL as DATABASE_URL, which may differ from RC_RO_URL. Apply
#     the SAME identity gate to that exact connection: current_user=rc_ro, current_database=railway,
#     and a read-only session (PGOPTIONS default_transaction_read_only=on, which the auditor's psycopg
#     inherits too). The password reaches psql only via PG* env parsed from the URL, never on argv.
if AUERR="$(
      PE="$(pgenv_for RC_AUDIT_URL)" || { echo "RC_AUDIT_URL unparsable"; exit 1; }
      eval "$PE"
      acu="$(psql -X -tAqw -c 'SELECT current_user;' 2>/dev/null)"
      acd="$(psql -X -tAqw -c 'SELECT current_database();' 2>/dev/null)"
      aro="$(psql -X -tAqw -c "SELECT current_setting('transaction_read_only');" 2>/dev/null)"
      if [ "$acu" = "rc_ro" ] && [ "$acd" = "railway" ] && [ "$aro" = "on" ]; then exit 0; fi
      echo "user=${acu:-?} db=${acd:-?} read_only=${aro:-?}"; exit 1
    )"; then
  ok "audit DB connection (RC_AUDIT_URL) is rc_ro@railway, read-only (same gate as the psql checks)"
else
  no "audit DB connection (RC_AUDIT_URL) failed identity gate: ${AUERR:-connect error} (expected rc_ro@railway, read-only)"; AUDIT_OK=0
fi

if [ "$AUDIT_OK" != "1" ]; then
  no "skipping the 41-check audit because a pre-run gate (signing registry or audit connection) failed (fail-closed)"
elif [ ! -f "$REPO_ROOT/models.py" ] || [ ! -d "$REPO_ROOT/parallax" ]; then
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
  # Live fingerprints computed with the SAME expression the pre-startup baseline used:
  # md5(row_to_json(r)::text) over the FULL resource row, for every publication (pub_id IS NOT NULL).
  # id/pub_id/slug are exposed so we match whatever record identifier the baseline keyed on. Only
  # {id, pub_id, slug, fp} leaves the DB - no row content, no secrets.
  AFTER="$(q "SELECT coalesce(json_agg(json_build_object('id', r.id, 'pub_id', r.pub_id, 'slug', r.slug, 'fp', md5(row_to_json(r)::text)) ORDER BY r.pub_id), '[]'::json) FROM resources r WHERE r.pub_id IS NOT NULL;")" \
    || { no "live publication fingerprint query errored ($(tr -d '\n' <"$TMP/q.err"))"; AFTER=""; }
  if [ -n "$AFTER" ]; then
    printf '%s' "$AFTER" > "$TMP/after.json"
    if python3 -I - "$BASELINE_JSON" "$TMP/after.json" "$EXPECT_PUBLICATIONS" "${BASELINE_SHA256:-}" <<'PY'
import json, sys, hashlib
baseline_path, after_path, expect = sys.argv[1], sys.argv[2], int(sys.argv[3])
expected_sha = (sys.argv[4] if len(sys.argv) > 4 else "").strip().lower()

def fail(msg):
    print("    FAIL: " + msg); sys.exit(1)

# Preserve the original evidence: read the baseline read-only; if a SHA-256 is supplied, the file
# must match it byte-for-byte before we trust or compare it. We never write to this file.
try:
    raw_bytes = open(baseline_path, "rb").read()
except Exception as e:
    fail("baseline not readable (%s)" % type(e).__name__)
if expected_sha:
    actual_sha = hashlib.sha256(raw_bytes).hexdigest()
    if actual_sha != expected_sha:
        fail("baseline SHA-256 %s does not match expected %s (evidence changed, or wrong file)"
             % (actual_sha, expected_sha))

try:
    raw = json.loads(raw_bytes)
except Exception as e:
    fail("baseline not parseable as JSON (%s) - cannot verify publications" % type(e).__name__)

# --- Pull the baseline's records out of whatever envelope it uses. ---
def baseline_records(obj):
    if isinstance(obj, dict) and isinstance(obj.get("fingerprints"), dict):
        return [{"__k": k, "__fp": v} for k, v in obj["fingerprints"].items()]
    if isinstance(obj, dict):
        for wrap in ("records", "publications", "rows", "resources"):
            if isinstance(obj.get(wrap), list):
                return obj[wrap]
        return [{"__k": k, "__fp": v} for k, v in obj.items()]   # flat {key: hex-or-obj}
    if isinstance(obj, list):
        return obj
    return []

def fp_of(rec):
    if not isinstance(rec, dict):
        return None
    for f in ("__fp", "fp", "md5", "fingerprint", "hash"):
        v = rec.get(f)
        if isinstance(v, str):
            return v.lower()
    return None

brecs = baseline_records(raw)
if not brecs:
    fail("baseline contained no usable records")

# Build a baseline map for each candidate identifier field; keep only fields present+complete on
# every record (so we match the baseline's OWN record identifier, be it id, pub_id, or slug).
bmaps = {}
for fld in ("__k", "pub_id", "slug", "id", "key"):
    m = {}
    good = True
    for rec in brecs:
        if not isinstance(rec, dict):
            good = False; break
        k = rec.get(fld); fp = fp_of(rec)
        if k is None or fp is None:
            good = False; break
        m[str(k)] = fp
    if good and len(m) == len(brecs):
        bmaps[fld] = m
if not bmaps:
    fail("could not extract a consistent identifier+fingerprint from the baseline records")

# Live rows carry id/pub_id/slug + fp.
try:
    live_rows = json.loads(open(after_path).read()) or []
except Exception as e:
    fail("live fingerprint set not parseable (%s)" % type(e).__name__)
live_by = {}
for fld in ("id", "pub_id", "slug"):
    m = {}
    good = True
    for r in live_rows:
        k = r.get(fld); fp = r.get("fp")
        if k is None or not isinstance(fp, str):
            good = False; break
        m[str(k)] = fp.lower()
    if good and len(m) == len(live_rows):
        live_by[fld] = m

# Choose the baseline-field / live-field pairing whose key sets overlap most (match like-for-like).
best = None
for bfld, bm in bmaps.items():
    for lfld, lm in live_by.items():
        ov = len(set(bm) & set(lm))
        if best is None or ov > best[0]:
            best = (ov, bfld, lfld, bm, lm)
_, bfld, lfld, base, live = best

# Counts must match the expected publication population exactly (fail-closed on drift).
if len(base) != expect:
    fail("baseline has %d records, expected %d publications" % (len(base), expect))
if len(live) != expect:
    fail("live DB has %d publications (pub_id IS NOT NULL), expected %d" % (len(live), expect))

removed = sorted(set(base) - set(live))   # in baseline, absent live
added = sorted(set(live) - set(base))     # in live, absent baseline
if removed or added:
    parts = []
    if removed: parts.append("in baseline but not live: " + ", ".join(removed[:20]))
    if added:   parts.append("in live but not baseline: " + ", ".join(added[:20]))
    fail("publication identifier sets differ (baseline key=%s, live key=%s): %s"
         % (bfld, lfld, "; ".join(parts)))

changed = sorted(k for k in base if base[k] != live[k])
if changed:
    alln = len(changed) == expect
    note = (" [ALL records differ - confirm the baseline used md5(row_to_json(r)::text) over the "
            "full resource row]") if alln else ""
    fail("%d of %d publication fingerprints changed since pre-startup%s: %s"
         % (len(changed), expect, note, ", ".join(changed[:20])))

print("    OK: all %d publication fingerprints match the pre-startup baseline (matched on %s)"
      % (expect, bfld))
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
