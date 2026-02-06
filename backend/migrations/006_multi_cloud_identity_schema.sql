-- 006_multi_cloud_identity_schema.sql
-- Multi-cloud identity normalization
-- Adds normalized fields for Azure, AWS, and GCP identity support

-- Add new normalized columns
ALTER TABLE identities ADD COLUMN IF NOT EXISTS cloud TEXT DEFAULT 'azure';
ALTER TABLE identities ADD COLUMN IF NOT EXISTS identity_type_normalized TEXT;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS canonical_name TEXT;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS principal_id TEXT;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS tenant_or_org_id TEXT;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS source_normalized TEXT;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS is_federated BOOLEAN DEFAULT FALSE;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
ALTER TABLE identities ADD COLUMN IF NOT EXISTS last_seen_auth TIMESTAMPTZ;

-- Create indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_identities_cloud ON identities(cloud);
CREATE INDEX IF NOT EXISTS idx_identities_type_normalized ON identities(identity_type_normalized);
CREATE INDEX IF NOT EXISTS idx_identities_principal_id ON identities(principal_id);
CREATE INDEX IF NOT EXISTS idx_identities_status ON identities(status);
CREATE INDEX IF NOT EXISTS idx_identities_tenant_org ON identities(tenant_or_org_id);

-- Backfill existing Azure data from legacy fields
UPDATE identities SET
  cloud = 'azure',
  canonical_name = display_name,
  principal_id = object_id,
  tenant_or_org_id = NULL,  -- Will be populated by discovery engine going forward
  source_normalized = 'entra',
  status = CASE WHEN enabled THEN 'active' ELSE 'disabled' END,
  last_seen_auth = last_sign_in,
  identity_type_normalized = CASE COALESCE(identity_category, identity_type)
    WHEN 'service_principal' THEN 'app'
    WHEN 'managed_identity_system' THEN 'workload'
    WHEN 'managed_identity_user' THEN 'workload'
    WHEN 'managed_identity' THEN 'workload'
    WHEN 'human_user' THEN 'human'
    WHEN 'user' THEN 'human'
    WHEN 'guest' THEN 'human'
    WHEN 'microsoft_internal' THEN 'system'
    ELSE 'app'
  END,
  is_federated = (identity_category = 'guest')
WHERE cloud IS NULL OR identity_type_normalized IS NULL;

-- Add comment for documentation
COMMENT ON COLUMN identities.cloud IS 'Cloud provider: azure, aws, gcp';
COMMENT ON COLUMN identities.identity_type_normalized IS 'Normalized type: human, workload, app, group, role, system';
COMMENT ON COLUMN identities.canonical_name IS 'Display name (same as display_name for consistency)';
COMMENT ON COLUMN identities.principal_id IS 'Cloud-specific principal ID (Azure objectId, AWS ARN, GCP email)';
COMMENT ON COLUMN identities.tenant_or_org_id IS 'Tenant/Account/Org ID (Azure tenant, AWS account, GCP org/project)';
COMMENT ON COLUMN identities.source_normalized IS 'Identity source: entra, iam, cloud_identity';
COMMENT ON COLUMN identities.is_federated IS 'Whether identity uses federated authentication';
COMMENT ON COLUMN identities.status IS 'Identity status: active, disabled, deleted';
COMMENT ON COLUMN identities.last_seen_auth IS 'Last authentication timestamp (best-effort)';
