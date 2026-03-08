-- Migration 060: Copilot Queries
-- Phase 25: AI Security Copilot

CREATE TABLE IF NOT EXISTS copilot_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    user_id VARCHAR(100),
    query TEXT NOT NULL,
    response TEXT,
    context JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cq_org ON copilot_queries(organization_id);
CREATE INDEX IF NOT EXISTS idx_cq_user ON copilot_queries(user_id);
CREATE INDEX IF NOT EXISTS idx_cq_created ON copilot_queries(created_at DESC);

ALTER TABLE copilot_queries ENABLE ROW LEVEL SECURITY;
ALTER TABLE copilot_queries FORCE ROW LEVEL SECURITY;

CREATE POLICY cq_strict_sel ON copilot_queries FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY cq_strict_ins ON copilot_queries FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY cq_strict_upd ON copilot_queries FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY cq_strict_del ON copilot_queries FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON copilot_queries TO auditgraph_app;
