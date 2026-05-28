-- Phase 2.1: AI Model Discovery (architecture-only — no logs required)
--
-- Surfaces Cognitive Services / Azure OpenAI / AI Foundry model deployments
-- so we can answer "WHICH model is this agent using?" purely from the
-- management plane. Aligns with the no-log-dependency product principle.

-- ============================================================
-- 1. Cognitive Services accounts (the parent resource that hosts deployments)
-- ============================================================
CREATE TABLE IF NOT EXISTS azure_cognitive_services_accounts (
    id                          SERIAL PRIMARY KEY,
    discovery_run_id            INTEGER NOT NULL,
    organization_id             INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource_id                 TEXT NOT NULL,
    name                        TEXT NOT NULL,
    kind                        TEXT,           -- OpenAI | AIServices | ComputerVision | etc.
    sku                         TEXT,
    location                    TEXT,
    resource_group              TEXT,
    subscription_id             TEXT,
    subscription_name           TEXT,
    public_network_access       TEXT,           -- Enabled | Disabled
    network_acls_default_action TEXT,           -- Allow | Deny
    private_endpoint_count      INTEGER DEFAULT 0,
    custom_subdomain            TEXT,
    endpoint_url                TEXT,
    created_at                  TIMESTAMPTZ,
    ingested_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, resource_id, discovery_run_id)
);

CREATE INDEX IF NOT EXISTS ix_cs_accounts_org_resource
    ON azure_cognitive_services_accounts (organization_id, resource_id);
CREATE INDEX IF NOT EXISTS ix_cs_accounts_run
    ON azure_cognitive_services_accounts (discovery_run_id);

-- ============================================================
-- 2. Model deployments (gpt-4, gpt-4o, claude-3-haiku, etc.)
-- ============================================================
-- One row per deployment. Linked to its parent account via account_resource_id.
-- Capacity tells us provisioned throughput; high capacity = high blast radius.
CREATE TABLE IF NOT EXISTS azure_ai_model_deployments (
    id                          SERIAL PRIMARY KEY,
    discovery_run_id            INTEGER NOT NULL,
    organization_id             INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    account_resource_id         TEXT NOT NULL,  -- FK shape to azure_cognitive_services_accounts.resource_id
    account_name                TEXT,
    deployment_name             TEXT NOT NULL,
    model_name                  TEXT NOT NULL,  -- e.g. gpt-4, gpt-4o, claude-3-haiku
    model_version               TEXT,
    model_format                TEXT,           -- e.g. OpenAI, Cohere, Meta
    sku_name                    TEXT,           -- Standard | GlobalStandard | ProvisionedManaged
    sku_capacity                INTEGER,        -- provisioned throughput units
    provisioning_state          TEXT,           -- Succeeded | Failed | Creating
    rai_policy_name             TEXT,           -- responsible-AI content filter policy
    created_at                  TIMESTAMPTZ,
    ingested_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, account_resource_id, deployment_name, discovery_run_id)
);

CREATE INDEX IF NOT EXISTS ix_ai_deployments_org_account
    ON azure_ai_model_deployments (organization_id, account_resource_id);
CREATE INDEX IF NOT EXISTS ix_ai_deployments_model
    ON azure_ai_model_deployments (model_name);
CREATE INDEX IF NOT EXISTS ix_ai_deployments_run
    ON azure_ai_model_deployments (discovery_run_id);
