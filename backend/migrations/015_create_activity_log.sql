-- Phase 17: Activity Log & Audit Trail
-- Append-only audit trail for tracking user and system actions

CREATE TABLE IF NOT EXISTS activity_log (
    id SERIAL PRIMARY KEY,
    action_type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activity_log_created_at ON activity_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_log_action_type ON activity_log(action_type);
