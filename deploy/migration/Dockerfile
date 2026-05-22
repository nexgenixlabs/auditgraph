# ─────────────────────────────────────────────────────────────────────────────
# One-shot migration image for cus-ag-nonprod dev DB
#
# Phases (selected via $PHASE env var):
#   setup-roles → run setup_dev_db_roles.sql as server admin
#   migrate     → run scripts/run_migrations.py --include-ddl as auditgraph_dev_admin
#   restore     → run migrate_to_cloud_dev.py restore as auditgraph_dev_admin
#   all         → setup-roles, then migrate, then restore (default)
#
# Required env vars per phase:
#   setup-roles: DB_HOST DB_NAME SERVER_ADMIN_USER SERVER_ADMIN_PASSWORD
#   migrate:     DB_HOST DB_NAME DB_ADMIN_USER DB_ADMIN_PASSWORD
#   restore:     CLOUD_DSN  (full DSN string)
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# psycopg2, xmlsec deps for backend imports, psql client for raw SQL
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        pkg-config \
        libxml2-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        postgresql-client \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Backend code, migrations, the migration runner scripts
COPY backend /app/backend
COPY scripts /app/scripts

# Sandbox data dump (orgs 1,2,9) bundled at /data/sandbox_dump.json
COPY deploy/migration/sandbox_dump.json /data/sandbox_dump.json
COPY deploy/migration/local_cols.json /data/local_cols.json
COPY deploy/migration/local_schema.json /data/local_schema.json
COPY deploy/migration/local_schema.sql /data/local_schema.sql

# Entrypoint
COPY deploy/migration/run.sh /app/run.sh
RUN chmod +x /app/run.sh

ENV PYTHONUNBUFFERED=1
ENV PHASE=all

ENTRYPOINT ["/app/run.sh"]
