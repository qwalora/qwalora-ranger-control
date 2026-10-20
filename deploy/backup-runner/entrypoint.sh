#!/usr/bin/env bash
# Daily backup chain for parallax-nonprod. Runs inside the Railway cron runner (private network +
# the service's own DATABASE_URL). Fails the whole run (non-zero exit) if any step fails, which is
# the alert signal. Never echoes secrets: pg_backup redacts the DB URL; aws/age read creds/keys from
# env or files and do not print them. `set -u` is deliberately NOT used so an unset optional var does
# not abort before the explicit checks below.
set -eo pipefail

log() { printf '{"ts":"%s","level":"%s","event":"%s"}\n' "$(date -u +%FT%TZ)" "$1" "$2"; }

: "${RANGER_BACKUP_DEST:=/tmp/ranger-backups}"
mkdir -p "$RANGER_BACKUP_DEST"

# 1) Encrypted logical backup of the live DB (source = this service's DATABASE_URL or
#    RANGER_BACKUP_SOURCE_URL; encrypted to RANGER_BACKUP_AGE_RECIPIENT, a PUBLIC key).
log info backup.begin
python /app/scripts/pg_backup.py

# 2) Upload to durable off-service storage (S3-compatible: a Railway bucket or external S3).
#    RANGER_BACKUP_S3_URL e.g. s3://ranger-nonprod-backups/pg/ ; creds via the standard AWS_* env
#    (and AWS_ENDPOINT_URL_S3 for a non-AWS/Railway bucket). Only encrypted artifacts + sidecars leave.
if [ -n "${RANGER_BACKUP_S3_URL:-}" ]; then
  log info upload.begin
  AWS_ARGS=()
  [ -n "${AWS_ENDPOINT_URL_S3:-}" ] && AWS_ARGS+=(--endpoint-url "$AWS_ENDPOINT_URL_S3")
  aws "${AWS_ARGS[@]}" s3 cp "$RANGER_BACKUP_DEST/" "$RANGER_BACKUP_S3_URL" \
      --recursive --exclude "*" --include "*.dump.age" --include "*.sha256" --include "*.manifest.json"
  log info upload.ok

  # 2b) Durable-upload confirmation: the job must NOT report success until the newest encrypted
  #     artifact is confirmed present offsite at the exact byte size. Fails closed on mismatch/absence.
  #     This needs s3:GetObject/HeadObject (a read), so it is slightly more than pure write-only; set
  #     RANGER_BACKUP_VERIFY_UPLOAD=0 to keep write-only credentials and rely only on the upload exit
  #     code (weaker: an incomplete-but-non-erroring upload would not be detected).
  if [ "${RANGER_BACKUP_VERIFY_UPLOAD:-1}" = "1" ]; then
    newest="$(ls -1t "$RANGER_BACKUP_DEST"/*.dump.age 2>/dev/null | head -1)"
    [ -n "$newest" ] || { log error upload.verify_no_artifact; exit 2; }
    lsize="$(stat -c %s "$newest")"
    url="${RANGER_BACKUP_S3_URL%/}/$(basename "$newest")"
    bkt="$(printf '%s' "$url" | sed -E 's#^s3://([^/]+)/.*#\1#')"
    key="$(printf '%s' "$url" | sed -E 's#^s3://[^/]+/(.*)$#\1#')"
    rsize="$(aws "${AWS_ARGS[@]}" s3api head-object --bucket "$bkt" --key "$key" \
             --query ContentLength --output text 2>/dev/null)" \
             || { log error upload.verify_head_failed; exit 2; }
    [ "$rsize" = "$lsize" ] || { log error upload.verify_size_mismatch; exit 2; }
    log info upload.verify_ok
  else
    log info upload.verify_skipped
  fi
else
  log error upload.skipped_no_target   # no durable target configured -> fail (not operational)
  exit 2
fi

# 3) Freshness / integrity healthcheck over what we just wrote (dead-man's-switch).
python /app/scripts/backup_healthcheck.py "$RANGER_BACKUP_DEST"

# 4) Local retention prune (bucket retention is primarily S3 lifecycle rules; this is the secondary,
#    auditable pass over the runner's local mirror). Dry-run unless RANGER_BACKUP_PRUNE_APPLY=1.
python /app/scripts/pg_backup_prune.py "$RANGER_BACKUP_DEST" || true

log info backup.done
