-- 093_execution_engine.sql
-- W3: Execution engine — tracks every execution attempt per approval

BEGIN;

CREATE TABLE IF NOT EXISTS execution_runs (
  id                  BIGSERIAL PRIMARY KEY,
  organization_id     INTEGER NOT NULL,
  approval_ref        VARCHAR(50) NOT NULL,
  execution_mode      VARCHAR(20) NOT NULL
    CHECK (execution_mode IN ('dry_run', 'live', 'rollback')),
  action_type         VARCHAR(50) NOT NULL,
  action_payload      JSONB NOT NULL,
  identity_id         VARCHAR(512) NOT NULL,
  worker_id           VARCHAR(100),
  started_by          INTEGER REFERENCES users(id),
  started_at          TIMESTAMPTZ DEFAULT NOW(),
  completed_at        TIMESTAMPTZ,
  duration_ms         INTEGER,
  outcome             VARCHAR(20)
    CHECK (outcome IN (
      'success', 'failure', 'partial',
      'simulated', 'rolled_back'
    )),
  arm_request_id      VARCHAR(255),
  arm_correlation_id  VARCHAR(255),
  result_payload      JSONB,
  error_code          VARCHAR(100),
  error_message       TEXT,
  rollback_of         BIGINT REFERENCES execution_runs(id),
  can_rollback        BOOLEAN DEFAULT false,
  rollback_payload    JSONB,
  CONSTRAINT fk_exec_org
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_exec_org_approval
  ON execution_runs (organization_id, approval_ref);
CREATE INDEX IF NOT EXISTS idx_exec_org_identity
  ON execution_runs (organization_id, identity_id);
CREATE INDEX IF NOT EXISTS idx_exec_org_outcome
  ON execution_runs (organization_id, outcome, started_at DESC);

ALTER TABLE execution_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_runs FORCE ROW LEVEL SECURITY;

CREATE POLICY org_strict_sel ON execution_runs
  FOR SELECT USING (
    organization_id = current_setting('app.current_organization_id', true)::integer
  );
CREATE POLICY org_strict_ins ON execution_runs
  FOR INSERT WITH CHECK (
    organization_id = current_setting('app.current_organization_id', true)::integer
  );

GRANT SELECT, INSERT, UPDATE ON execution_runs TO auditgraph_app;
GRANT USAGE, SELECT ON SEQUENCE execution_runs_id_seq TO auditgraph_app;

COMMIT;
