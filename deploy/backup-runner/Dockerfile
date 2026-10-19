# Backup runner image for parallax-nonprod encrypted logical backups.
# Ships the PostgreSQL 18 client (the live server is 18.6; pg_dump must be >= the server major),
# age for public-key encryption, and awscli for S3-compatible upload. Build context = repo root:
#   docker build -f deploy/backup-runner/Dockerfile -t ranger-backup-runner .
# On Railway, point a cron service at this Dockerfile (Root Directory = repo root, Dockerfile path
# deploy/backup-runner/Dockerfile) and set the cron schedule + variables per deploy/backup-runner/README.md.
FROM python:3.12-slim-bookworm

# PostgreSQL 18 client from the PGDG apt repo (Debian bookworm).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg age awscli; \
    install -d /usr/share/postgresql-common/pgdg; \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc; \
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends postgresql-client-18; \
    rm -rf /var/lib/apt/lists/*

# Verify the client is >= 18 at build time (fail the build otherwise).
RUN pg_dump --version | grep -qE 'PostgreSQL\) 1[89]|PostgreSQL\) 2[0-9]' \
    || (echo "FATAL: pg_dump must be >= 18 for the PG 18.6 server" && exit 1)

WORKDIR /app
COPY scripts/ /app/scripts/
COPY deploy/backup-runner/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# The runner has NO decryption key: it encrypts with the age RECIPIENT (public) only.
ENV RANGER_PG_BIN=/usr/lib/postgresql/18/bin \
    RANGER_BACKUP_DEST=/tmp/ranger-backups

ENTRYPOINT ["/app/entrypoint.sh"]
