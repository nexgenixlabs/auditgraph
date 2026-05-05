-- Migration 108: Discovered resources table
--
-- Canonical resource inventory extracted from role assignment scopes.
-- Provides a unified view of all Azure resources that identities have
-- RBAC access to, normalized by provider/type for blast radius computation.
--
-- Source: role_assignments.scope (ARM resource IDs) + azure_storage_accounts + azure_key_vaults
-- Zero additional API calls required.

CREATE TABLE IF NOT EXISTS discovered_resources (
    id BIGSERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    -- ARM resource identity
    resource_id TEXT NOT NULL,            -- Full ARM path (lowercased)
    resource_name TEXT,                   -- Extracted resource name
    resource_type TEXT NOT NULL,          -- Normalized: e.g. 'sql_server', 'data_factory', 'app_service'
    provider_type TEXT NOT NULL,          -- ARM provider: e.g. 'Microsoft.Sql/servers'
    -- Location
    subscription_id TEXT,
    resource_group TEXT,
    -- Classification
    is_high_value BOOLEAN DEFAULT FALSE,
    high_value_reason TEXT,               -- e.g. 'key_vault', 'sql_server', 'cognitive_services'
    data_classification TEXT,             -- PII, Confidential, Internal, Public (if known)
    risk_level TEXT,                      -- critical, high, medium, low (if known from source table)
    -- RBAC exposure context
    identity_count INTEGER DEFAULT 0,     -- How many identities can reach this resource
    privileged_identity_count INTEGER DEFAULT 0,
    -- Discovery context
    discovery_source TEXT NOT NULL DEFAULT 'rbac_scope',  -- rbac_scope, storage_discovery, keyvault_discovery
    discovery_run_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One resource per run
    UNIQUE(organization_id, resource_id, discovery_run_id)
);

CREATE INDEX IF NOT EXISTS idx_dr_org_run
ON discovered_resources(organization_id, discovery_run_id);

CREATE INDEX IF NOT EXISTS idx_dr_type
ON discovered_resources(organization_id, resource_type);

CREATE INDEX IF NOT EXISTS idx_dr_subscription
ON discovered_resources(organization_id, subscription_id);

CREATE INDEX IF NOT EXISTS idx_dr_high_value
ON discovered_resources(organization_id, discovery_run_id)
WHERE is_high_value = true;
