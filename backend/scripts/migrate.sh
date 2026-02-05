#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# Enterprise-grade migration runner:
# - Works from any current directory
# - Uses migrations relative to repo/backend root
# ------------------------------------------------------------

ENV_FILE="${1:-.env.local}"

# Resolve backend root (scripts/..)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MIGRATIONS_DIR="$BACKEND_ROOT/migrations"

if [[ ! -f "$ENV_FILE" ]]; then
  # If user passed a relative env file while running elsewhere, also try from backend root
  if [[ -f "$BACKEND_ROOT/$ENV_FILE" ]]; then
    ENV_FILE="$BACKEND_ROOT/$ENV_FILE"
  else
    echo "❌ Env file not found: $ENV_FILE"
    echo "Usage: ./scripts/migrate.sh .env.local  OR  ./scripts/migrate.sh .env.docker"
    exit 1
  fi
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
echo "📁 Migrations dir: $MIGRATIONS_DIR"
echo "=================================================="

if [[ ! -d "$MIGRATIONS_DIR" ]]; then
  echo "❌ Migrations directory not found: $MIGRATIONS_DIR"
  exit 1
fi

shopt -s nullglob
FILES=("$MIGRATIONS_DIR"/*.sql)
shopt -u nullglob

if (( ${#FILES[@]} == 0 )); then
  echo "⚠️  No migrations found in $MIGRATIONS_DIR"
  exit 0
fi

for f in "${FILES[@]}"; do
  echo "➡️  Applying: $(basename "$f")"
  psql "$PSQL_CONN" -v ON_ERROR_STOP=1 -f "$f"
done

echo "✅ Migrations complete"
