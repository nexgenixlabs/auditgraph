-- Migration 106: Workload attributions table
--
-- Unified parent workload attribution for identities.
-- Synthesizes signals from managed identity bindings, ARM resource
-- associations, workload type inference, and naming conventions
-- into a single queryable model with confidence scoring.

CREATE TABLE IF NOT EXISTS workload_attributions (
    id BIGSERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    identity_id TEXT NOT NULL,
    identity_db_id BIGINT,
    -- Workload identification
    workload_type TEXT NOT NULL,        -- app_service, function_app, aks, vm, container_app,
                                        -- logic_app, automation, data_factory, static_web_app,
                                        -- ai_service, ml_workspace, cicd_pipeline, unknown
    workload_name TEXT,                 -- human-readable resource name
    workload_resource_id TEXT,          -- full ARM resource ID (if known)
    workload_resource_group TEXT,
    workload_subscription_id TEXT,
    -- Attribution quality
    attribution_confidence INTEGER NOT NULL DEFAULT 0,  -- 0-100
    attribution_basis TEXT NOT NULL,    -- managed_identity_system, managed_identity_user,
                                        -- arm_resource_binding, workload_type_inference,
                                        -- display_name_pattern, ownership_link,
                                        -- federated_credential, role_scope_inference
    attribution_signals JSONB DEFAULT '[]'::jsonb,  -- all contributing signals
    -- Context
    is_ai_workload BOOLEAN DEFAULT FALSE,
    discovery_run_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One attribution per identity per workload resource per basis
    UNIQUE(organization_id, identity_db_id, workload_resource_id, attribution_basis)
);

CREATE INDEX IF NOT EXISTS idx_wa_org_type
ON workload_attributions(organization_id, workload_type);

CREATE INDEX IF NOT EXISTS idx_wa_identity
ON workload_attributions(identity_db_id);

CREATE INDEX IF NOT EXISTS idx_wa_org_run
ON workload_attributions(organization_id, discovery_run_id);
