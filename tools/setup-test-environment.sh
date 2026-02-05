#!/bin/bash

##############################################################################
# AuditGraph Test Environment Setup Script
# Purpose: Create dummy identities with security issues for testing discovery
# Author: AuditGraph Team
# Date: January 2026
##############################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SUBSCRIPTION_ID="34780384-6a21-4b79-ac90-1e3976b58a33"
REGION="eastus"
RESOURCE_GROUP="rg-auditgraph-test"
STORAGE_ACCOUNT="stauditgraph001"

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  AuditGraph Test Environment Setup${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check if logged in
echo "Checking Azure login status..."
if ! az account show &> /dev/null; then
    print_error "Not logged in to Azure. Please run 'az login' first."
    exit 1
fi
print_status "Logged in to Azure"

# Set subscription
echo "Setting subscription..."
az account set --subscription "$SUBSCRIPTION_ID"
print_status "Subscription set to: $SUBSCRIPTION_ID"

echo ""
echo -e "${YELLOW}Creating Test Environment...${NC}"
echo ""

##############################################################################
# 1. Create Resource Group
##############################################################################
echo "Step 1: Creating Resource Group..."
if az group show --name "$RESOURCE_GROUP" &> /dev/null; then
    print_warning "Resource group already exists"
else
    az group create \
      --name "$RESOURCE_GROUP" \
      --location "$REGION" \
      --output none
    print_status "Resource group created: $RESOURCE_GROUP"
fi

##############################################################################
# 2. Create Overprivileged Service Principals (Security Risks!)
##############################################################################
echo ""
echo "Step 2: Creating Test Service Principals..."

# SPN #1: Owner on Subscription (CRITICAL RISK!)
echo "  Creating: spn-overprivileged-owner (Owner role)"
SPN1=$(az ad sp create-for-rbac \
  --name "spn-overprivileged-owner" \
  --role "Owner" \
  --scopes "/subscriptions/$SUBSCRIPTION_ID" \
  --output json 2>/dev/null)

if [ $? -eq 0 ]; then
    print_status "spn-overprivileged-owner created (Owner role - CRITICAL RISK!)"
    echo "    AppId: $(echo $SPN1 | jq -r '.appId')"
else
    print_warning "spn-overprivileged-owner may already exist"
fi

# SPN #2: Contributor on Subscription (HIGH RISK)
echo "  Creating: spn-contributor-sub (Contributor role)"
SPN2=$(az ad sp create-for-rbac \
  --name "spn-contributor-sub" \
  --role "Contributor" \
  --scopes "/subscriptions/$SUBSCRIPTION_ID" \
  --output json 2>/dev/null)

if [ $? -eq 0 ]; then
    print_status "spn-contributor-sub created (Contributor role - HIGH RISK)"
    echo "    AppId: $(echo $SPN2 | jq -r '.appId')"
else
    print_warning "spn-contributor-sub may already exist"
fi

# SPN #3: Reader on Resource Group (ACCEPTABLE)
echo "  Creating: spn-reader-rg (Reader role)"
SPN3=$(az ad sp create-for-rbac \
  --name "spn-reader-rg" \
  --role "Reader" \
  --scopes "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP" \
  --output json 2>/dev/null)

if [ $? -eq 0 ]; then
    print_status "spn-reader-rg created (Reader role - Acceptable)"
    echo "    AppId: $(echo $SPN3 | jq -r '.appId')"
else
    print_warning "spn-reader-rg may already exist"
fi

# SPN #4: Unused/Orphan with no role assignment (MEDIUM RISK)
echo "  Creating: spn-unused-orphan (No role - orphaned)"
SPN4=$(az ad sp create-for-rbac \
  --name "spn-unused-orphan" \
  --skip-assignment \
  --output json 2>/dev/null)

if [ $? -eq 0 ]; then
    print_status "spn-unused-orphan created (No role - Orphaned identity)"
    echo "    AppId: $(echo $SPN4 | jq -r '.appId')"
else
    print_warning "spn-unused-orphan may already exist"
fi

# SPN #5: User Access Administrator (Can grant permissions - CRITICAL!)
echo "  Creating: spn-user-access-admin (User Access Administrator)"
SPN5=$(az ad sp create-for-rbac \
  --name "spn-user-access-admin" \
  --role "User Access Administrator" \
  --scopes "/subscriptions/$SUBSCRIPTION_ID" \
  --output json 2>/dev/null)

if [ $? -eq 0 ]; then
    print_status "spn-user-access-admin created (Can grant access - CRITICAL!)"
    echo "    AppId: $(echo $SPN5 | jq -r '.appId')"
else
    print_warning "spn-user-access-admin may already exist"
fi

##############################################################################
# 3. Create Storage Account with Managed Identity
##############################################################################
echo ""
echo "Step 3: Creating Storage Account with Managed Identity..."

if az storage account show --name "$STORAGE_ACCOUNT" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
    print_warning "Storage account already exists"
    STORAGE_EXISTS=true
else
    az storage account create \
      --name "$STORAGE_ACCOUNT" \
      --resource-group "$RESOURCE_GROUP" \
      --location "$REGION" \
      --sku Standard_LRS \
      --assign-identity \
      --output none
    print_status "Storage account created with system-assigned managed identity"
    STORAGE_EXISTS=false
fi

# Get managed identity principal ID
IDENTITY_ID=$(az storage account show \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --query identity.principalId \
  --output tsv)

if [ -z "$IDENTITY_ID" ]; then
    print_error "Failed to get managed identity ID"
else
    print_status "Managed Identity ID: $IDENTITY_ID"
    
    # Assign overprivileged Contributor role (RISK!)
    echo "  Assigning Contributor role to managed identity..."
    az role assignment create \
      --assignee "$IDENTITY_ID" \
      --role "Contributor" \
      --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP" \
      --output none 2>/dev/null || print_warning "Role may already be assigned"
    
    print_status "Managed identity assigned Contributor role (OVERPRIVILEGED!)"
fi

##############################################################################
# 4. Create Additional Test Resources
##############################################################################
echo ""
echo "Step 4: Creating Additional Test Resources..."

# Create a Key Vault (to demonstrate secrets access risk)
echo "  Creating Key Vault..."
KEYVAULT_NAME="kv-auditgraph-${RANDOM}"
az keyvault create \
  --name "$KEYVAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$REGION" \
  --output none 2>/dev/null && print_status "Key Vault created: $KEYVAULT_NAME" || print_warning "Key Vault creation skipped"

# Create a Virtual Network (for realistic environment)
echo "  Creating Virtual Network..."
az network vnet create \
  --name "vnet-auditgraph-test" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$REGION" \
  --address-prefix "10.0.0.0/16" \
  --subnet-name "subnet-default" \
  --subnet-prefix "10.0.1.0/24" \
  --output none 2>/dev/null && print_status "Virtual Network created" || print_warning "VNet creation skipped"

##############################################################################
# 5. Create Risky Role Assignments
##############################################################################
echo ""
echo "Step 5: Creating Additional Risky Role Assignments..."

# Give spn-reader-rg Key Vault Secrets Officer role (escalation!)
if [ ! -z "$(echo $SPN3 | jq -r '.appId')" ]; then
    READER_APPID=$(echo $SPN3 | jq -r '.appId')
    az role assignment create \
      --assignee "$READER_APPID" \
      --role "Key Vault Secrets Officer" \
      --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP" \
      --output none 2>/dev/null && print_status "Reader SPN escalated to Key Vault Secrets Officer!" || print_warning "Role assignment skipped"
fi

##############################################################################
# 6. Summary Report
##############################################################################
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "Test Environment Summary:"
echo "-------------------------"
echo "Subscription: $SUBSCRIPTION_ID"
echo "Region: $REGION"
echo "Resource Group: $RESOURCE_GROUP"
echo ""
echo "Service Principals Created:"
echo "  1. spn-overprivileged-owner (Owner - CRITICAL RISK)"
echo "  2. spn-contributor-sub (Contributor - HIGH RISK)"
echo "  3. spn-reader-rg (Reader + Key Vault Secrets - RISK)"
echo "  4. spn-unused-orphan (No role - Orphaned)"
echo "  5. spn-user-access-admin (Can grant access - CRITICAL)"
echo ""
echo "Managed Identities:"
echo "  1. $STORAGE_ACCOUNT (Contributor - OVERPRIVILEGED)"
echo ""
echo "Resources Created:"
echo "  - Storage Account: $STORAGE_ACCOUNT"
echo "  - Key Vault: $KEYVAULT_NAME"
echo "  - Virtual Network: vnet-auditgraph-test"
echo ""

# List all SPNs
echo "All Service Principals:"
az ad sp list --all --query "[?contains(displayName, 'spn-')].{Name:displayName, AppId:appId}" --output table

echo ""
echo "All Role Assignments:"
az role assignment list --all --query "[?contains(principalName, 'spn-')]" --output table

echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Run the AuditGraph Discovery Engine to find these identities"
echo "2. Verify it detects all security risks"
echo "3. Test risk scoring and compliance checks"
echo ""
echo -e "${GREEN}Ready to build the Discovery Engine! 🚀${NC}"
