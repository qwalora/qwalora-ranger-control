#!/bin/bash
# Railway mounts persistent volumes owned by root (see docs.railway.com/volumes#permissions).
# OpenSearch runs as uid 1000 and refuses to run as root, so the container is started as
# root (RAILWAY_RUN_UID=0), we fix ownership of the data volume, then drop to uid 1000 and
# exec the stock OpenSearch entrypoint. This is the only reason a custom image exists.
set -euo pipefail

DATA_DIR="${RAILWAY_VOLUME_MOUNT_PATH:-/usr/share/opensearch/data}"
OS_ENTRYPOINT="/usr/share/opensearch/opensearch-docker-entrypoint.sh"

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA_DIR"
  # Own the volume (and the config dir the security demo installer writes into) as opensearch.
  chown -R 1000:1000 "$DATA_DIR" || true
  chown -R 1000:1000 /usr/share/opensearch/config || true
  # chroot --userspec drops to uid:gid 1000 without needing gosu/setpriv to be installed.
  exec chroot --skip-chdir --userspec=1000:1000 / "$OS_ENTRYPOINT" "$@"
fi

exec "$OS_ENTRYPOINT" "$@"
