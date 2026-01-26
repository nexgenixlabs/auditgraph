#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env.local}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "❌ Env file not found: $ENV_FILE"
  echo "Usage: ./scripts/migrate.sh .env.local  OR  ./scripts/migrate.sh .env.docker"
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

: "${DB_HOST:?missing}"
: "${DB_PORT:?missing}"
: "${DB_NAME:?missing}"
: "${DB_USER:?missing}"
: "${DB_PASSWORD:?missing}"
: "${DB_SSLMODE:=require}"

PSQL_CONN="host=$DB_HOST port=$DB_PORT dbname=$DB_NAME user=$DB_USER password=$DB_PASSWORD sslmode=$DB_SSLMODE"

echo "=================================================="
echo "🗄️  Running migrations on: $DB_HOST:$DB_PORT/$DB_NAME"
echo "=================================================="

for f in migrations/*.sql; do
  [[ -e "$f" ]] || { echo "⚠️  No migrations found in migrations/"; exit 0; }
  echo "➡️  Applying: $f"
  psql "$PSQL_CONN" -v ON_ERROR_STOP=1 -f "$f"
done

echo "✅ Migrations complete"
