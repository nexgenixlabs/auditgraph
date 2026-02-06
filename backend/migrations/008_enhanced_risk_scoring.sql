-- 008_enhanced_risk_scoring.sql
-- Enhanced risk scoring with points-based system
-- Supports detailed risk analysis combining multiple factors

-- Add risk score column (integer points for granular scoring)
ALTER TABLE identities ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;

-- Add additional columns for risk factors
ALTER TABLE identities ADD COLUMN IF NOT EXISTS api_permission_count INTEGER DEFAULT 0;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS app_role_count INTEGER DEFAULT 0;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS days_since_last_use INTEGER;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS last_activity_source TEXT;

-- Create indexes for efficient risk-based queries
CREATE INDEX IF NOT EXISTS idx_identities_risk_score ON identities(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_identities_api_perm_count ON identities(api_permission_count);
CREATE INDEX IF NOT EXISTS idx_identities_app_role_count ON identities(app_role_count);
CREATE INDEX IF NOT EXISTS idx_identities_days_since_use ON identities(days_since_last_use);

-- Comments for documentation
COMMENT ON COLUMN identities.risk_score IS 'Points-based risk score (0-200+). Higher = riskier';
COMMENT ON COLUMN identities.api_permission_count IS 'Number of Graph API permissions';
COMMENT ON COLUMN identities.app_role_count IS 'Number of custom app role assignments';
COMMENT ON COLUMN identities.days_since_last_use IS 'Days since last authentication (null = never used)';
COMMENT ON COLUMN identities.last_activity_source IS 'Source of last activity (e.g., Azure DevOps, GitHub Actions)';
