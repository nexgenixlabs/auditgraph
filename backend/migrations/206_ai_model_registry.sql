-- AG-T2.2: AI Model Registry — approval workflow on top of the existing
-- azure_ai_model_deployments table.
--
-- Why a separate `ai_model_approvals` table (not just columns on the
-- deployments row)?
--   1. Deployments come from discovery and get re-upserted every run.
--      We don't want our approval state being trampled by discovery.
--   2. Approvals carry a workflow: requested → reviewed → approved /
--      rejected / revoked, plus the reviewer, justification, and
--      expires_at. That's its own entity.
--   3. Multiple deployments can share the same (model_name, model_format,
--      version) — the approval is on the MODEL identity, not the
--      individual deployment row.
--
-- Status values: 'unverified' (default), 'pending_review', 'approved',
-- 'rejected', 'revoked'.
--
-- A model is "approved for production" iff (status='approved' AND
-- expires_at IS NULL OR expires_at > NOW()).

\set ON_ERROR_STOP on

BEGIN;

CREATE TABLE IF NOT EXISTS ai_model_approvals (
    id                  SERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL,
    model_name          TEXT NOT NULL,
    model_format        TEXT,              -- vendor: OpenAI, AzureOpenAI, custom-finetune, …
    model_version       TEXT,
    status              TEXT NOT NULL DEFAULT 'unverified'
        CHECK (status IN ('unverified','pending_review','approved','rejected','revoked')),
    risk_classification TEXT             -- 'baseline'|'medium'|'high'|'custom'|'finetune'
        CHECK (risk_classification IS NULL OR
               risk_classification IN ('baseline','medium','high','custom','finetune')),
    requested_by        TEXT,
    requested_at        TIMESTAMPTZ,
    reviewed_by         TEXT,
    reviewed_at         TIMESTAMPTZ,
    justification       TEXT,
    review_notes        TEXT,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ai_model_approvals_unique
        UNIQUE (organization_id, model_name, model_format, model_version)
);

CREATE INDEX IF NOT EXISTS idx_ai_model_approvals_org_status
    ON ai_model_approvals (organization_id, status);
CREATE INDEX IF NOT EXISTS idx_ai_model_approvals_model
    ON ai_model_approvals (organization_id, model_name);

-- Grant: app role can read; admin can write
DO $$ BEGIN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE ON ai_model_approvals TO auditgraph_app';
EXCEPTION WHEN undefined_object THEN NULL; END $$;
DO $$ BEGIN
    EXECUTE 'GRANT ALL ON ai_model_approvals TO auditgraph_admin';
    EXECUTE 'GRANT USAGE, SELECT, UPDATE ON SEQUENCE ai_model_approvals_id_seq TO auditgraph_app';
EXCEPTION WHEN undefined_object THEN NULL; END $$;

-- Updated_at trigger
CREATE OR REPLACE FUNCTION _ai_model_approvals_touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ai_model_approvals_touch ON ai_model_approvals;
CREATE TRIGGER trg_ai_model_approvals_touch
    BEFORE UPDATE ON ai_model_approvals
    FOR EACH ROW EXECUTE FUNCTION _ai_model_approvals_touch_updated_at();

COMMIT;

\echo ''
\d ai_model_approvals
