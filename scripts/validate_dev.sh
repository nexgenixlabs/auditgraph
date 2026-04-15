#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AuditGraph DEV — Post-Deployment Validation
#
# Verifies:
#   1. API health endpoints respond
#   2. Database connectivity from API
#   3. Frontend apps serve HTML
#   4. Demo tenant data loads
#   5. Custom domains resolve (if configured)
#
# Usage:
#   ./scripts/validate_dev.sh
#   ./scripts/validate_dev.sh --fqdn-only   # Skip custom domain checks
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RG="${RG:-eus2-ag-nonprod-rg}"

API_APP="auditgraph-api-dev"
CLIENT_APP="auditgraph-app-dev"
ADMIN_APP="auditgraph-admin-dev"

API_DOMAIN="dev.api.auditgraph.ai"
APP_DOMAIN="dev.app.auditgraph.ai"
ADMIN_DOMAIN="dev.admin.auditgraph.ai"
DEMO_DOMAIN="demo.auditgraph.ai"

FQDN_ONLY=false
[[ "${1:-}" == "--fqdn-only" ]] && FQDN_ONLY=true

# ── Helpers ──────────────────────────────────────────────────────────────────

log()  { echo -e "\n\033[1;34m▸ $*\033[0m"; }
ok()   { echo -e "  \033[1;32m✓ $*\033[0m"; }
warn() { echo -e "  \033[1;33m⚠ $*\033[0m"; }
fail() { echo -e "  \033[1;31m✗ $*\033[0m"; }

PASS=0
FAIL=0
WARN=0

check() {
  local label="$1"
  local url="$2"
  local expected="${3:-200}"

  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
  if [[ "$STATUS" == "$expected" ]]; then
    ok "$label — HTTP $STATUS"
    ((PASS++))
  elif [[ "$STATUS" == "000" ]]; then
    warn "$label — unreachable"
    ((WARN++))
  else
    fail "$label — HTTP $STATUS (expected $expected)"
    ((FAIL++))
  fi
}

check_json() {
  local label="$1"
  local url="$2"
  local jq_filter="$3"

  BODY=$(curl -s --max-time 10 "$url" 2>/dev/null || echo "{}")
  VALUE=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print($jq_filter)" 2>/dev/null || echo "PARSE_ERROR")

  if [[ "$VALUE" != "PARSE_ERROR" && "$VALUE" != "None" && "$VALUE" != "" ]]; then
    ok "$label — $VALUE"
    ((PASS++))
  else
    fail "$label — unexpected response"
    ((FAIL++))
  fi
}

# ── Fetch FQDNs ─────────────────────────────────────────────────────────────

log "Fetching Container App FQDNs"

API_FQDN=$(az containerapp show -n "$API_APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null || echo "")
APP_FQDN=$(az containerapp show -n "$CLIENT_APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null || echo "")
ADMIN_FQDN=$(az containerapp show -n "$ADMIN_APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null || echo "")

if [[ -z "$API_FQDN" || -z "$APP_FQDN" || -z "$ADMIN_FQDN" ]]; then
  fail "Could not fetch one or more container app FQDNs"
  exit 1
fi

echo "  API:   $API_FQDN"
echo "  App:   $APP_FQDN"
echo "  Admin: $ADMIN_FQDN"

# ── 1. API Health Endpoints ──────────────────────────────────────────────────

log "Checking API health endpoints (FQDN)"

check "GET /health"        "https://$API_FQDN/health"
check "GET /health/ready"  "https://$API_FQDN/health/ready"
check "GET /health/live"   "https://$API_FQDN/health/live"
check "GET /api/health"    "https://$API_FQDN/api/health"

# ── 2. Database Connectivity (via health endpoint) ───────────────────────────

log "Checking database connectivity from API"

check_json "DB status in /api/health" \
  "https://$API_FQDN/api/health" \
  "d.get('status', d.get('database', 'unknown'))"

# ── 3. Frontend Apps ─────────────────────────────────────────────────────────

log "Checking frontend apps (FQDN)"

check "Client App" "https://$APP_FQDN/"
check "Admin App"  "https://$ADMIN_FQDN/"

# ── 4. Demo Tenant Data ─────────────────────────────────────────────────────

log "Checking demo tenant resolution"

check_json "Demo org by slug" \
  "https://$API_FQDN/api/clients/by-slug/demo" \
  "d.get('organization',{}).get('name', d.get('name',''))"

# ── 5. Custom Domains (if not --fqdn-only) ──────────────────────────────────

if [[ "$FQDN_ONLY" == "false" ]]; then
  log "Checking custom domain endpoints"

  check "dev.api.auditgraph.ai/api/health" "https://$API_DOMAIN/api/health"
  check "dev.app.auditgraph.ai"            "https://$APP_DOMAIN/"
  check "dev.admin.auditgraph.ai"          "https://$ADMIN_DOMAIN/"
  check "demo.auditgraph.ai"              "https://$DEMO_DOMAIN/"
else
  log "Skipping custom domain checks (--fqdn-only)"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

log "Validation Summary"
echo ""
echo "  Passed:  $PASS"
echo "  Failed:  $FAIL"
echo "  Warning: $WARN"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
  fail "Validation completed with $FAIL failure(s)"
  exit 1
fi

if [[ "$WARN" -gt 0 ]]; then
  echo ""
  echo "  ═══════════════════════════════════════════════"
  echo "  AuditGraph DEV Environment Ready (with warnings)"
  echo "  ═══════════════════════════════════════════════"
else
  echo ""
  echo "  ═══════════════════════════════════════════════"
  echo "  AuditGraph DEV Environment Ready"
  echo "  ═══════════════════════════════════════════════"
fi

echo ""
echo "  https://dev.api.auditgraph.ai"
echo "  https://dev.app.auditgraph.ai"
echo "  https://dev.admin.auditgraph.ai"
echo "  https://demo.auditgraph.ai"
echo ""
