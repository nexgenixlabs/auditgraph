#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AuditGraph DEV — Custom Domain Binding & TLS Certificate Provisioning
#
# Binds custom domains to Container Apps and provisions managed TLS certs.
# Prints required Cloudflare DNS records (CNAME + TXT validation).
#
# Usage:
#   ./scripts/setup_dev_domains.sh
#
# Prerequisites:
#   - az CLI logged in
#   - Container apps already deployed
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RG="${RG:-eus2-ag-nonprod-rg}"
CAE="${CAE:-dev-cae}"

API_APP="auditgraph-api-dev"
CLIENT_APP="auditgraph-app-dev"
ADMIN_APP="auditgraph-admin-dev"

API_DOMAIN="dev.api.auditgraph.ai"
APP_DOMAIN="dev.app.auditgraph.ai"
ADMIN_DOMAIN="dev.admin.auditgraph.ai"
DEMO_DOMAIN="demo.auditgraph.ai"

# ── Helpers ──────────────────────────────────────────────────────────────────

log()  { echo -e "\n\033[1;34m▸ $*\033[0m"; }
ok()   { echo -e "  \033[1;32m✓ $*\033[0m"; }
warn() { echo -e "  \033[1;33m⚠ $*\033[0m"; }
fail() { echo -e "  \033[1;31m✗ $*\033[0m"; exit 1; }

# ── Fetch Container App FQDNs ────────────────────────────────────────────────

log "Fetching Container App FQDNs"

API_FQDN=$(az containerapp show -n "$API_APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
APP_FQDN=$(az containerapp show -n "$CLIENT_APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
ADMIN_FQDN=$(az containerapp show -n "$ADMIN_APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)

ok "API   = $API_FQDN"
ok "App   = $APP_FQDN"
ok "Admin = $ADMIN_FQDN"

# ── Get Environment Default Domain for TXT validation ────────────────────────

log "Getting environment verification ID"

ENV_VERIFY_ID=$(az containerapp env show -n "$CAE" -g "$RG" --query properties.customDomainConfiguration.customDomainVerificationId -o tsv 2>/dev/null || echo "")

if [[ -z "$ENV_VERIFY_ID" ]]; then
  # Fallback: extract from a container app
  ENV_VERIFY_ID=$(az containerapp show -n "$API_APP" -g "$RG" --query properties.customDomainVerificationId -o tsv 2>/dev/null || echo "UNABLE_TO_RETRIEVE")
fi

# ── Print Required DNS Records ───────────────────────────────────────────────

log "Required Cloudflare DNS records (DNS Only — no proxy)"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │ CNAME Records (DNS Only, no orange cloud)                          │"
echo "  ├──────────────────────┬──────────────────────────────────────────────┤"
echo "  │ dev.api              │ $API_FQDN   │"
echo "  │ dev.app              │ $APP_FQDN   │"
echo "  │ dev.admin            │ $ADMIN_FQDN │"
echo "  │ demo                 │ $APP_FQDN   │"
echo "  ├──────────────────────┴──────────────────────────────────────────────┤"
echo "  │ TXT Records (for Azure domain verification)                        │"
echo "  ├──────────────────────┬──────────────────────────────────────────────┤"
echo "  │ asuid.dev.api        │ $ENV_VERIFY_ID │"
echo "  │ asuid.dev.app        │ $ENV_VERIFY_ID │"
echo "  │ asuid.dev.admin      │ $ENV_VERIFY_ID │"
echo "  │ asuid.demo           │ $ENV_VERIFY_ID │"
echo "  └──────────────────────┴──────────────────────────────────────────────┘"
echo ""

# ── Bind Custom Domains ──────────────────────────────────────────────────────

log "Binding custom domains"

bind_domain() {
  local app_name="$1"
  local hostname="$2"

  # Check if already bound
  existing=$(az containerapp hostname list -n "$app_name" -g "$RG" \
    --query "[?name=='$hostname'].name" -o tsv 2>/dev/null || true)
  if [[ -n "$existing" ]]; then
    ok "$hostname already bound to $app_name"
    return 0
  fi

  echo "  Adding $hostname to $app_name..."
  if az containerapp hostname add -n "$app_name" -g "$RG" --hostname "$hostname" --output none 2>/dev/null; then
    ok "$hostname added"
    return 0
  else
    warn "$hostname failed — ensure DNS CNAME + TXT records are configured first"
    return 1
  fi
}

bind_domain "$API_APP"    "$API_DOMAIN"
bind_domain "$CLIENT_APP" "$APP_DOMAIN"
bind_domain "$CLIENT_APP" "$DEMO_DOMAIN"
bind_domain "$ADMIN_APP"  "$ADMIN_DOMAIN"

# ── Provision Managed TLS Certificates ───────────────────────────────────────

log "Provisioning managed TLS certificates"

provision_cert() {
  local app_name="$1"
  local hostname="$2"

  echo "  Binding TLS for $hostname..."
  if az containerapp hostname bind \
    -n "$app_name" -g "$RG" \
    --hostname "$hostname" \
    --environment "$CAE" \
    --validation-method CNAME \
    --output none 2>/dev/null; then
    ok "TLS certificate provisioned for $hostname"
  else
    warn "TLS pending for $hostname — DNS validation may not be complete"
    echo "    Ensure these records exist:"
    echo "      CNAME: $hostname -> (container FQDN)"
    echo "      TXT:   asuid.${hostname#*.} -> $ENV_VERIFY_ID"
  fi
}

provision_cert "$API_APP"    "$API_DOMAIN"
provision_cert "$CLIENT_APP" "$APP_DOMAIN"
provision_cert "$CLIENT_APP" "$DEMO_DOMAIN"
provision_cert "$ADMIN_APP"  "$ADMIN_DOMAIN"

# ── Verify ───────────────────────────────────────────────────────────────────

log "Domain binding status"

for app in "$API_APP" "$CLIENT_APP" "$ADMIN_APP"; do
  echo "  $app:"
  az containerapp hostname list -n "$app" -g "$RG" \
    --query "[].{hostname:name, status:bindingType}" -o table 2>/dev/null || echo "    (none)"
done

echo ""
echo "  Domain setup complete."
echo "  If TLS certs are pending, wait 5-10 minutes for Azure to validate DNS."
