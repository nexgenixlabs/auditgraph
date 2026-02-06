-- 009_role_usage_intelligence.sql
-- Add inference-based role usage tracking columns
-- Provides usage intelligence without depending on Activity Logs

-- ============================================================
-- Azure RBAC Role Assignments - Usage Intelligence
-- ============================================================

-- Scope validation
ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS scope_exists BOOLEAN DEFAULT TRUE;

-- Usage status: orphaned, definitely_unused, likely_unused, possibly_overprivileged, assumed_active
ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS usage_status TEXT DEFAULT 'unknown';

-- Days since role was assigned (calculated from created_on)
ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS days_since_assigned INTEGER;

-- If this role overlaps with another broader role (e.g., has Contributor when Owner exists)
ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS redundant_with TEXT;

-- Role-level risk assessment
ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS role_type TEXT DEFAULT 'azure';
ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS risk_level TEXT;
ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS why_critical TEXT;

-- Resource info for scope validation
ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS resource_type TEXT;
ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS resource_name TEXT;

-- Indexes for usage queries
CREATE INDEX IF NOT EXISTS idx_role_assignments_usage_status ON role_assignments(usage_status);
CREATE INDEX IF NOT EXISTS idx_role_assignments_scope_exists ON role_assignments(scope_exists);
CREATE INDEX IF NOT EXISTS idx_role_assignments_risk_level ON role_assignments(risk_level);

-- ============================================================
-- Entra Directory Role Assignments - Usage Intelligence
-- ============================================================

-- Usage status for Entra roles
ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS usage_status TEXT DEFAULT 'unknown';

-- Days since role was assigned
ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS assigned_on TIMESTAMPTZ;
ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS days_since_assigned INTEGER;

-- If this role overlaps with another (e.g., has User Admin when Global Admin exists)
ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS redundant_with TEXT;

-- Role-level risk assessment
ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS role_type TEXT DEFAULT 'entra';
ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS risk_level TEXT;
ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS why_critical TEXT;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_entra_roles_usage_status ON entra_role_assignments(usage_status);
CREATE INDEX IF NOT EXISTS idx_entra_roles_risk_level ON entra_role_assignments(risk_level);

-- ============================================================
-- Comments for documentation
-- ============================================================
COMMENT ON COLUMN role_assignments.scope_exists IS 'Whether the target resource/scope still exists in Azure';
COMMENT ON COLUMN role_assignments.usage_status IS 'Inferred usage: orphaned, definitely_unused, likely_unused, possibly_overprivileged, assumed_active, unknown';
COMMENT ON COLUMN role_assignments.days_since_assigned IS 'Days since role was assigned (from created_on)';
COMMENT ON COLUMN role_assignments.redundant_with IS 'Name of broader role that makes this one redundant';
COMMENT ON COLUMN role_assignments.why_critical IS 'Explanation of why this role assignment is risky';

COMMENT ON COLUMN entra_role_assignments.usage_status IS 'Inferred usage status for Entra directory roles';
COMMENT ON COLUMN entra_role_assignments.redundant_with IS 'Name of broader Entra role that makes this one redundant';
COMMENT ON COLUMN entra_role_assignments.why_critical IS 'Explanation of why this Entra role is risky';
