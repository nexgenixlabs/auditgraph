#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AuditGraph DEV Environment — One-Command Deployment
#
# Runs the full deployment pipeline:
#   1. Build & push container images to ACR
#   2. Deploy infrastructure via Bicep
#   3. Wait for API readiness
#   4. Bind custom domains + TLS certificates
#   5. Bootstrap database (migrations + DDL + demo seed)
#   6. Validate all endpoints
#
# Prerequisites:
#   - az CLI logged in (az login)
#   - Environment variables set (DB creds, JWT secrets)
#
# Usage:
#   ./scripts/deploy-dev.sh                # Full deploy
#   ./scripts/deploy-dev.sh --skip-build   # Skip image build
#   ./scripts/deploy-dev.sh --skip-domains # Skip custom domain binding
#   ./scripts/deploy-dev.sh --skip-db      # Skip database bootstrap
#   ./scripts/deploy-dev.sh --infra-only   # Only deploy Bicep template
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# ── Configuration ────────────────────────────────────────────────────────────

RG="${RG:-eus2-ag-nonprod-rg}"
ACR="${ACR:-auditgraphcr}"
ACR_SERVER="${ACR_SERVER:-auditgraphcr.azurecr.io}"
CAE="${CAE:-dev-cae}"
IMAGE_TAG="${IMAGE_TAG:-dev}"

API_APP="auditgraph-api-dev"
CLIENT_APP="auditgraph-app-dev"
ADMIN_APP="auditgraph-admin-dev"

# Database — support both DEV_ prefixed (CI) and unprefixed (local) var names
export DB_HOST="${DEV_DB_HOST:-${DB_HOST:-eus2-ag-nonprod-pg.postgres.database.azure.com}}"
export DB_NAME="${DEV_DB_NAME:-${DB_NAME:-auditgraph_dev_eastus2}}"
export DB_USER="${DEV_DB_USER:-${DB_USER:-auditgraph_dev_app}}"
export DB_PASSWORD="${DEV_DB_PASSWORD:-${DB_PASSWORD:-}}"
export DB_ADMIN_USER="${DEV_DB_ADMIN_USER:-${DB_ADMIN_USER:-auditgraph_dev_admin}}"
export DB_ADMIN_PASSWORD="${DEV_DB_ADMIN_PASSWORD:-${DB_ADMIN_PASSWORD:-}}"
export DB_SSLMODE="${DB_SSLMODE:-require}"
export DB_PORT="${DB_PORT:-5432}"

# JWT secrets — support DEV_ prefix
export JWT_SECRET="${DEV_JWT_SECRET:-${JWT_SECRET:-}}"
export ADMIN_JWT_SECRET="${DEV_ADMIN_JWT_SECRET:-${ADMIN_JWT_SECRET:-}}"
export CLIENT_JWT_SECRET="${DEV_CLIENT_JWT_SECRET:-${CLIENT_JWT_SECRET:-}}"

API_DOMAIN="dev.api.auditgraph.ai"
APP_DOMAIN="dev.app.auditgraph.ai"
ADMIN_DOMAIN="dev.admin.auditgraph.ai"
DEMO_DOMAIN="demo.auditgraph.ai"
REACT_APP_API_URL="https://${API_DOMAIN}"

# ── Flags ────────────────────────────────────────────────────────────────────

SKIP_BUILD=false
SKIP_DOMAINS=false
SKIP_DB=false
INFRA_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --skip-build)   SKIP_BUILD=true ;;
    --skip-domains) SKIP_DOMAINS=true ;;
    --skip-db)      SKIP_DB=true ;;
    --infra-only)   INFRA_ONLY=true; SKIP_BUILD=true; SKIP_DOMAINS=true; SKIP_DB=true ;;
    --help|-h)
      sed -n '2,22p' "$0"; exit 0 ;;
    *)
      echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────

log()  { echo -e "\n\033[1;34m▸ $*\033[0m"; }
ok()   { echo -e "  \033[1;32m✓ $*\033[0m"; }
warn() { echo -e "  \033[1;33m⚠ $*\033[0m"; }
fail() { echo -e "  \033[1;31m✗ $*\033[0m"; exit 1; }

require_env() {
  if [[ -z "${!1:-}" ]]; then
    fail "Required environment variable $1 is not set"
  fi
}

# ── Preflight ────────────────────────────────────────────────────────────────

log "Preflight checks"

az account show --output none 2>/dev/null || fail "Not logged in to Azure. Run: az login"
ok "Azure CLI authenticated"

az acr show --name "$ACR" --output none 2>/dev/null || fail "ACR '$ACR' not found"
ok "ACR accessible"

require_env DB_PASSWORD
require_env DB_ADMIN_PASSWORD
require_env JWT_SECRET
require_env ADMIN_JWT_SECRET
require_env CLIENT_JWT_SECRET
ok "All required secrets set"

echo "  DB_HOST=$DB_HOST"
echo "  DB_NAME=$DB_NAME"
echo "  DB_USER=$DB_USER"
echo "  DB_ADMIN_USER=$DB_ADMIN_USER"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1: Build & Push Images
# ══════════════════════════════════════════════════════════════════════════════

if [[ "$SKIP_BUILD" == "false" ]]; then
  log "Building and pushing images to ACR (linux/amd64)"

  for img_spec in \
    "auditgraph-api:${IMAGE_TAG}|Dockerfile.api|" \
    "auditgraph-app:${IMAGE_TAG}|Dockerfile.app|REACT_APP_API_URL=${REACT_APP_API_URL}" \
    "auditgraph-admin:${IMAGE_TAG}|Dockerfile.admin|REACT_APP_API_URL=${REACT_APP_API_URL}"; do

    IFS='|' read -r img dockerfile build_arg <<< "$img_spec"
    echo "  Building $img..."

    BUILD_ARGS=()
    if [[ -n "$build_arg" ]]; then
      BUILD_ARGS=(--build-arg "$build_arg")
    fi

    az acr build \
      --registry "$ACR" \
      --platform linux/amd64 \
      --image "$img" \
      --file "$dockerfile" \
      "${BUILD_ARGS[@]}" \
      . \
      --no-logs 2>/dev/null || \
    az acr build \
      --registry "$ACR" \
      --platform linux/amd64 \
      --image "$img" \
      --file "$dockerfile" \
      "${BUILD_ARGS[@]}" \
      .
    ok "$img"
  done
else
  log "Skipping image build (--skip-build)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2: Deploy Infrastructure via Bicep
# ══════════════════════════════════════════════════════════════════════════════

log "Deploying Container Apps via Bicep (containerapps-dev.bicep)"

az deployment group create \
  --resource-group "$RG" \
  --template-file infra/containerapps-dev.bicep \
  --parameters \
    environmentName="$CAE" \
    acrLoginServer="$ACR_SERVER" \
    apiImageTag="$IMAGE_TAG" \
    appImageTag="$IMAGE_TAG" \
    adminImageTag="$IMAGE_TAG" \
    dbHost="$DB_HOST" \
    dbName="$DB_NAME" \
    dbUser="$DB_USER" \
    dbPassword="$DB_PASSWORD" \
    dbAdminUser="$DB_ADMIN_USER" \
    dbAdminPassword="$DB_ADMIN_PASSWORD" \
    jwtSecret="$JWT_SECRET" \
    adminJwtSecret="$ADMIN_JWT_SECRET" \
    clientJwtSecret="$CLIENT_JWT_SECRET" \
  --output none

ok "Bicep deployment complete"

# Fetch FQDNs
API_FQDN=$(az containerapp show -n "$API_APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
APP_FQDN=$(az containerapp show -n "$CLIENT_APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
ADMIN_FQDN=$(az containerapp show -n "$ADMIN_APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)

echo "  API   FQDN: $API_FQDN"
echo "  App   FQDN: $APP_FQDN"
echo "  Admin FQDN: $ADMIN_FQDN"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3: Wait for API Readiness
# ══════════════════════════════════════════════════════════════════════════════

log "Waiting for API to become ready"

for i in $(seq 1 24); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://${API_FQDN}/health/ready" 2>/dev/null || echo "000")
  if [[ "$STATUS" == "200" ]]; then
    ok "API healthy after $((i * 5))s"
    break
  fi
  if [[ "$i" == "24" ]]; then
    fail "API did not become healthy within 120s (last status: HTTP $STATUS)"
  fi
  echo "  Attempt $i: HTTP $STATUS (waiting 5s...)"
  sleep 5
done

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4: Custom Domains + TLS
# ══════════════════════════════════════════════════════════════════════════════

if [[ "$SKIP_DOMAINS" == "false" ]]; then
  log "Binding custom domains + TLS certificates"
  bash "$REPO_ROOT/scripts/setup_dev_domains.sh"
else
  log "Skipping domain binding (--skip-domains)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5: Database Bootstrap (migrations + demo seed)
# ══════════════════════════════════════════════════════════════════════════════

if [[ "$SKIP_DB" == "false" ]]; then
  log "Bootstrapping database"
  bash "$REPO_ROOT/scripts/bootstrap_dev_db.sh"
else
  log "Skipping database bootstrap (--skip-db)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 6: Validate Endpoints
# ══════════════════════════════════════════════════════════════════════════════

log "Running post-deployment validation"

SKIP_CUSTOM="--fqdn-only"
if [[ "$SKIP_DOMAINS" == "false" ]]; then
  SKIP_CUSTOM=""
fi
bash "$REPO_ROOT/scripts/validate_dev.sh" $SKIP_CUSTOM || true

# ══════════════════════════════════════════════════════════════════════════════
# FINAL OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "  ═══════════════════════════════════════════════"
echo "  AuditGraph DEV Environment Ready"
echo "  ═══════════════════════════════════════════════"
echo ""
echo "  https://dev.api.auditgraph.ai"
echo "  https://dev.app.auditgraph.ai"
echo "  https://dev.admin.auditgraph.ai"
echo "  https://demo.auditgraph.ai"
echo ""
echo "  Container FQDNs:"
echo "    API:   $API_FQDN"
echo "    App:   $APP_FQDN"
echo "    Admin: $ADMIN_FQDN"
echo ""
echo "  Cloudflare CNAME records (DNS Only):"
echo "    dev.api    -> $API_FQDN"
echo "    dev.app    -> $APP_FQDN"
echo "    dev.admin  -> $ADMIN_FQDN"
echo "    demo       -> $APP_FQDN"
echo ""
echo "  Logins:"
echo "    Client:  nexgenadmin / changeme              @ https://dev.app.auditgraph.ai"
echo "    Admin:   techadmin / changeme                @ https://dev.admin.auditgraph.ai"
echo "    Demo:    demo@auditgraph.ai / DemoAdmin@2026 @ https://demo.auditgraph.ai"
echo ""
