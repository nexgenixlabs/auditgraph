-- 092_approval_workflow.sql
-- W2-A1: Approval workflow + W2-A2: Platform audit trail
-- Includes FIX 1-4: normalized_payload, state machine columns, execution tracking

BEGIN;

-- ═══════════════════════════════════════════════════
-- Approval Requests
-- ═══════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS approval_requests (
  id                    BIGSERIAL PRIMARY KEY,
  organization_id       INTEGER NOT NULL,
  request_ref           VARCHAR(50) NOT NULL,
  identity_id           VARCHAR(512) NOT NULL,
  identity_display_name VARCHAR(255),
  action_type           VARCHAR(50) NOT NULL
    CHECK (action_type IN (
      'remove_role',
      'assign_owner',
      'disable_identity',
      'revoke_credential',
      'scope_reduction',
      'enable_pim'
    )),
  action_payload        JSONB NOT NULL,
  normalized_payload    TEXT NOT NULL,
  risk_reduction_score  FLOAT DEFAULT 0,
  compliance_frameworks VARCHAR(255)[],
  status                VARCHAR(30) NOT NULL DEFAULT 'pending'
    CHECK (status IN (
      'pending',
      'approved',
      'queued',
      'executing',
      'executed',
      'failed',
      'failed_permanent',
      'rejected',
      'cancelled'
    )),
  priority              INTEGER DEFAULT 2
    CHECK (priority BETWEEN 1 AND 3),
  requested_by          INTEGER REFERENCES users(id),
  requested_at          TIMESTAMPTZ DEFAULT NOW(),
  reviewed_by           INTEGER REFERENCES users(id),
  reviewed_at           TIMESTAMPTZ,
  review_note           TEXT,
  queued_by             INTEGER REFERENCES users(id),
  queued_at             TIMESTAMPTZ,
  execution_started_at  TIMESTAMPTZ,
  execution_completed_at TIMESTAMPTZ,
  execution_eta_minutes INTEGER,
  projected_score_delta FLOAT,
  retry_count           INTEGER DEFAULT 0,
  max_retries           INTEGER DEFAULT 3,
  last_retry_at         TIMESTAMPTZ,
  execution_error       TEXT,
  created_at            TIMESTAMPTZ DEFAULT NOW(),
  updated_at            TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT fk_approval_org
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id)
    ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_ref_org
  ON approval_requests (organization_id, request_ref);
CREATE INDEX IF NOT EXISTS idx_approval_org_status
  ON approval_requests (organization_id, status);
CREATE INDEX IF NOT EXISTS idx_approval_org_identity
  ON approval_requests (organization_id, identity_id);
CREATE INDEX IF NOT EXISTS idx_approval_requested_by
  ON approval_requests (organization_id, requested_by);

-- Idempotency: one pending request per (org, identity, action_type, payload)
CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_no_duplicates
  ON approval_requests (organization_id, identity_id, action_type, normalized_payload)
  WHERE status = 'pending';

-- Execution queue: fast lookup for approved/queued work items
CREATE INDEX IF NOT EXISTS idx_approval_execution_queue
  ON approval_requests (organization_id, status, priority)
  WHERE status IN ('approved', 'queued');

ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_requests FORCE ROW LEVEL SECURITY;

CREATE POLICY org_strict_sel ON approval_requests
  FOR SELECT USING (
    organization_id = current_setting('app.current_organization_id', true)::integer
  );
CREATE POLICY org_strict_ins ON approval_requests
  FOR INSERT WITH CHECK (
    organization_id = current_setting('app.current_organization_id', true)::integer
  );
CREATE POLICY org_strict_upd ON approval_requests
  FOR UPDATE USING (
    organization_id = current_setting('app.current_organization_id', true)::integer
  );

-- ═══════════════════════════════════════════════════
-- Platform Audit Log (append-only)
-- ═══════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS platform_audit_log (
  id                  BIGSERIAL PRIMARY KEY,
  organization_id     INTEGER NOT NULL,
  event_type          VARCHAR(100) NOT NULL,
  actor_user_id       INTEGER REFERENCES users(id),
  actor_display_name  VARCHAR(255),
  actor_role          VARCHAR(50),
  target_type         VARCHAR(50),
  target_id           VARCHAR(512),
  target_display_name VARCHAR(255),
  action              VARCHAR(100) NOT NULL,
  outcome             VARCHAR(20) NOT NULL
    CHECK (outcome IN ('success','failure','pending','cancelled')),
  before_state        JSONB,
  after_state         JSONB,
  metadata            JSONB,
  ip_address          VARCHAR(64),
  user_agent          VARCHAR(512),
  request_id          VARCHAR(100),
  created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_org_created
  ON platform_audit_log (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_org_event
  ON platform_audit_log (organization_id, event_type);
CREATE INDEX IF NOT EXISTS idx_audit_org_target
  ON platform_audit_log (organization_id, target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_org_actor
  ON platform_audit_log (organization_id, actor_user_id);

ALTER TABLE platform_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_audit_log FORCE ROW LEVEL SECURITY;

CREATE POLICY org_strict_sel ON platform_audit_log
  FOR SELECT USING (
    organization_id = current_setting('app.current_organization_id', true)::integer
  );
CREATE POLICY org_strict_ins ON platform_audit_log
  FOR INSERT WITH CHECK (
    organization_id = current_setting('app.current_organization_id', true)::integer
  );

-- Grants to app role
GRANT SELECT, INSERT, UPDATE ON approval_requests TO auditgraph_app;
GRANT USAGE, SELECT ON SEQUENCE approval_requests_id_seq TO auditgraph_app;
GRANT SELECT, INSERT ON platform_audit_log TO auditgraph_app;
GRANT USAGE, SELECT ON SEQUENCE platform_audit_log_id_seq TO auditgraph_app;

COMMIT;
