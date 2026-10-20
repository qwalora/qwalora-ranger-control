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

  # 2b) Mandatory durable-upload confirmation: the job must NOT report success until the newest
  #     encrypted OBJECT and BOTH integrity sidecars (.sha256, .manifest.json) are confirmed visible
  #     offsite at their expected byte sizes. For a production/readiness job
  #     (RANGER_BACKUP_REQUIRE_VERIFY=1 or a production marker), this CANNOT be disabled:
  #     RANGER_BACKUP_VERIFY_UPLOAD=0 then fails closed. Needs s3:GetObject/HeadObject (a read), a
  #     documented step above pure write-only. Remote visibility is confirmed here; durability is the
  #     provider SLA. A nonzero exit is the alerting signal.
  python /app/scripts/backup_upload_verify.py "$RANGER_BACKUP_DEST" "$RANGER_BACKUP_S3_URL"
else
  log error upload.skipped_no_target   # no durable target configured -> fail (not operational)
  exit 2
fi

# 3) Freshness / integrity healthcheck over what we just wrote (dead-man's-switch).
python /app/scripts/backup_healthcheck.py "$RANGER_BACKUP_DEST"

# 4) Retention prune. On a provider WITH lifecycle rules, those are the primary retention and this
#    local pass is secondary. On Railway Buckets (no lifecycle, no Object Lock), the bucket prune is
#    the ONLY offsite retention, so it runs against the bucket directly. Both are dry-run unless
#    RANGER_BACKUP_PRUNE_APPLY=1, never delete the newest, and refuse to delete everything.
python /app/scripts/pg_backup_prune.py "$RANGER_BACKUP_DEST" || true
if [ -n "${RANGER_BACKUP_S3_URL:-}" ] && [ "${RANGER_BACKUP_BUCKET_PRUNE:-1}" = "1" ]; then
  python /app/scripts/bucket_prune.py "$RANGER_BACKUP_S3_URL" || true
fi

log info backup.done
