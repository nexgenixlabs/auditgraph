-- Migration 061: Identity Attack Predictions
-- Phase 26: Identity Attack Prediction

CREATE TABLE IF NOT EXISTS identity_attack_predictions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    identity_id VARCHAR(500) NOT NULL,
    prediction_score FLOAT NOT NULL DEFAULT 0,
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    risk_drivers JSONB DEFAULT '[]',
    recommended_actions JSONB DEFAULT '[]',
    confidence FLOAT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iap_org ON identity_attack_predictions(organization_id);
CREATE INDEX IF NOT EXISTS idx_iap_identity ON identity_attack_predictions(identity_id);
CREATE INDEX IF NOT EXISTS idx_iap_risk ON identity_attack_predictions(risk_level);
CREATE INDEX IF NOT EXISTS idx_iap_score ON identity_attack_predictions(prediction_score DESC);
CREATE INDEX IF NOT EXISTS idx_iap_created ON identity_attack_predictions(created_at DESC);

ALTER TABLE identity_attack_predictions ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_attack_predictions FORCE ROW LEVEL SECURITY;

CREATE POLICY iap_strict_sel ON identity_attack_predictions FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iap_strict_ins ON identity_attack_predictions FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iap_strict_upd ON identity_attack_predictions FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iap_strict_del ON identity_attack_predictions FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_attack_predictions TO auditgraph_app;
