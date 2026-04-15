-- Remediation Queue — tracks attack-path items that need remediation action.
--
-- One attack path can appear at most once per org (UNIQUE constraint).
-- RLS scoped by organization_id via app.current_organization_id session var.

BEGIN;

CREATE TABLE IF NOT EXISTS remediation_queue (
    id              SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    attack_path_id  INTEGER REFERENCES attack_paths(id) ON DELETE SET NULL,
    identity_id     BIGINT  REFERENCES identities(id) ON DELETE SET NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    status          VARCHAR(20) NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','in_progress','resolved','dismissed')),
    assigned_to     TEXT,
    priority_score  NUMERIC(5,2),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    resolution_notes TEXT,
    created_by      TEXT NOT NULL,

    CONSTRAINT uq_remediation_queue_org_attack_path
        UNIQUE (organization_id, attack_path_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_rq_org_status
    ON remediation_queue (organization_id, status);

CREATE INDEX IF NOT EXISTS idx_rq_org_severity
    ON remediation_queue (organization_id, severity);

CREATE INDEX IF NOT EXISTS idx_rq_org_created
    ON remediation_queue (organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_rq_attack_path
    ON remediation_queue (attack_path_id);

-- updated_at trigger
CREATE OR REPLACE FUNCTION trg_rq_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_remediation_queue_updated_at ON remediation_queue;
CREATE TRIGGER trg_remediation_queue_updated_at
    BEFORE UPDATE ON remediation_queue
    FOR EACH ROW EXECUTE FUNCTION trg_rq_updated_at();

-- Row Level Security
ALTER TABLE remediation_queue ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_strict_sel_rq ON remediation_queue;
CREATE POLICY tenant_strict_sel_rq ON remediation_queue
    FOR SELECT USING (
        organization_id = current_setting('app.current_organization_id', true)::integer
    );

DROP POLICY IF EXISTS tenant_strict_ins_rq ON remediation_queue;
CREATE POLICY tenant_strict_ins_rq ON remediation_queue
    FOR INSERT WITH CHECK (
        organization_id = current_setting('app.current_organization_id', true)::integer
    );

DROP POLICY IF EXISTS tenant_strict_upd_rq ON remediation_queue;
CREATE POLICY tenant_strict_upd_rq ON remediation_queue
    FOR UPDATE USING (
        organization_id = current_setting('app.current_organization_id', true)::integer
    );

DROP POLICY IF EXISTS tenant_strict_del_rq ON remediation_queue;
CREATE POLICY tenant_strict_del_rq ON remediation_queue
    FOR DELETE USING (
        organization_id = current_setting('app.current_organization_id', true)::integer
    );

COMMIT;
