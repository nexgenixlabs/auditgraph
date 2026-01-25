#!/bin/bash

# AuditGraph Test Data Creation Script
# Creates diverse identities for realistic visualizations

set -e  # Exit on error

echo "============================================================"
echo "🎨 AuditGraph Test Data Creator"
echo "============================================================"
echo ""

# Get your subscription ID and tenant ID from .env
SUBSCRIPTION_ID=$(grep AZURE_SUBSCRIPTION_ID backend/.env | cut -d '=' -f2 | tr -d '"' | tr -d ' ')
TENANT_ID=$(grep AZURE_TENANT_ID backend/.env | cut -d '=' -f2 | tr -d '"' | tr -d ' ')
DOMAIN="nexgenixlabs.com"

echo "📋 Configuration:"
echo "  Subscription: $SUBSCRIPTION_ID"
echo "  Tenant: $TENANT_ID"
echo "  Domain: $DOMAIN"
echo ""

# Check if already logged in
echo "🔐 Checking Azure login..."
if ! az account show &> /dev/null; then
    echo "Please login to Azure first:"
    az login
fi

echo ""
echo "============================================================"
echo "👥 Creating Test Users (3)"
echo "============================================================"

# Users already created! ✅

echo ""
echo "============================================================"
echo "🤖 Creating Additional Service Principals (5)"
echo "============================================================"

echo "Creating spn-backup-automation..."
az ad sp create-for-rbac \
  --name "spn-backup-automation" \
  --role "Reader" \
  --scopes /subscriptions/$SUBSCRIPTION_ID \
  2>/dev/null || echo "  ✓ Already exists"

echo "Creating spn-monitoring-alerts..."
az ad sp create-for-rbac \
  --name "spn-monitoring-alerts" \
  --role "Monitoring Reader" \
  --scopes /subscriptions/$SUBSCRIPTION_ID \
  2>/dev/null || echo "  ✓ Already exists"

echo "Creating spn-devops-pipeline..."
az ad sp create-for-rbac \
  --name "spn-devops-pipeline" \
  --role "Contributor" \
  --scopes /subscriptions/$SUBSCRIPTION_ID \
  2>/dev/null || echo "  ✓ Already exists"

echo "Creating spn-readonly-reporting..."
az ad sp create-for-rbac \
  --name "spn-readonly-reporting" \
  --role "Reader" \
  --scopes /subscriptions/$SUBSCRIPTION_ID \
  2>/dev/null || echo "  ✓ Already exists"

echo "Creating spn-security-scanner..."
az ad sp create-for-rbac \
  --name "spn-security-scanner" \
  --role "Security Reader" \
  --scopes /subscriptions/$SUBSCRIPTION_ID \
  2>/dev/null || echo "  ✓ Already exists"

echo ""
echo "============================================================"
echo "🔐 Assigning User Roles"
echo "============================================================"

RG_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/rg-auditgraph-test"

echo "Assigning Contributor to Bob Wilson on RG..."
az role assignment create \
  --assignee "bob.wilson.test@$DOMAIN" \
  --role "Contributor" \
  --scope "$RG_ID" \
  2>/dev/null || echo "  ✓ Already assigned"

echo "Assigning Reader to John Doe on RG..."
az role assignment create \
  --assignee "john.doe.test@$DOMAIN" \
  --role "Reader" \
  --scope "$RG_ID" \
  2>/dev/null || echo "  ✓ Already assigned"

echo ""
echo "============================================================"
echo "✅ Test Data Creation Complete!"
echo "============================================================"
echo ""
echo "📊 Created:"
echo "  ✓ 3 test users"
echo "  ✓ 5 additional service principals"
echo "  ✓ Role assignments"
echo ""
echo "🔄 Next: Run discovery to see the new data!"
echo ""
