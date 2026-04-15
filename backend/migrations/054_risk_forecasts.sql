-- Migration 054: Risk Forecasts
-- Phase 18: Identity Risk Forecasting

CREATE TABLE IF NOT EXISTS risk_forecasts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         INTEGER NOT NULL,
    forecast_window_days    INTEGER NOT NULL DEFAULT 30,
    current_risk_score      FLOAT DEFAULT 0,
    predicted_risk_score    FLOAT DEFAULT 0,
    trend_direction         VARCHAR(20) NOT NULL CHECK (trend_direction IN ('increasing', 'stable', 'decreasing')),
    drivers                 JSONB DEFAULT '[]',
    created_at              TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rf_org ON risk_forecasts(organization_id);
CREATE INDEX IF NOT EXISTS idx_rf_created ON risk_forecasts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rf_window ON risk_forecasts(forecast_window_days);

ALTER TABLE risk_forecasts ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_forecasts FORCE ROW LEVEL SECURITY;

CREATE POLICY rfc_strict_sel ON risk_forecasts FOR SELECT TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY rfc_strict_ins ON risk_forecasts FOR INSERT TO auditgraph_app
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY rfc_strict_upd ON risk_forecasts FOR UPDATE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY rfc_strict_del ON risk_forecasts FOR DELETE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON risk_forecasts TO auditgraph_app;
