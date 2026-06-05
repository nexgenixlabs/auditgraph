-- AG-WK3.1: Ownership Center — assign / certify / exception workflow.
--
-- The SailPoint-money capability: governance teams need a workflow to
-- assign owners to unowned NHIs, run periodic certifications, and
-- process exception requests when an owner cannot be assigned.
--
-- 3 tables:
--   nhi_ownership_assignments      — current owner per NHI (one active row)
--   nhi_certification_campaigns    — campaign metadata + status
--   nhi_certification_items        — per-NHI certification decisions
--
-- All multi-tenant via organization_id + RLS.

\set ON_ERROR_STOP on

BEGIN;

-- 1) Current ownership (active assignment per NHI)
CREATE TABLE IF NOT EXISTS nhi_ownership_assignments (
    id                      BIGSERIAL PRIMARY KEY,
    organization_id         INTEGER NOT NULL,

    identity_db_id          BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    identity_id             TEXT NOT NULL,

    owner_user_id           INTEGER REFERENCES users(id) ON DELETE SET NULL,
    owner_display_name      TEXT NOT NULL,    -- snapshot so it survives user deletion
    owner_email             TEXT,
    delegate_user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    delegate_display_name   TEXT,

    status                  TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','pending_review','exception','revoked')),
    assignment_reason       TEXT,
    expires_at              TIMESTAMPTZ,      -- when re-cert is needed

    assigned_by_user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Only one ACTIVE assignment per identity at a time
    CONSTRAINT nhi_ownership_one_active UNIQUE (organization_id, identity_db_id, status)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX IF NOT EXISTS idx_nhi_ownership_org ON nhi_ownership_assignments (organization_id);
CREATE INDEX IF NOT EXISTS idx_nhi_ownership_identity ON nhi_ownership_assignments (identity_db_id);
CREATE INDEX IF NOT EXISTS idx_nhi_ownership_owner ON nhi_ownership_assignments (owner_user_id);
CREATE INDEX IF NOT EXISTS idx_nhi_ownership_expires ON nhi_ownership_assignments (expires_at);


-- 2) Certification campaigns
CREATE TABLE IF NOT EXISTS nhi_certification_campaigns (
    id                      BIGSERIAL PRIMARY KEY,
    organization_id         INTEGER NOT NULL,

    name                    TEXT NOT NULL,
    description             TEXT,
    scope_filter            JSONB NOT NULL DEFAULT '{}'::jsonb,
        -- e.g., {"identity_category":["service_principal"], "trust_below":60}

    status                  TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('draft','open','closed','cancelled')),
    due_at                  TIMESTAMPTZ NOT NULL,

    total_items             INTEGER NOT NULL DEFAULT 0,
    decided_items           INTEGER NOT NULL DEFAULT 0,
    approved_items          INTEGER NOT NULL DEFAULT 0,
    revoked_items           INTEGER NOT NULL DEFAULT 0,

    created_by_user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at               TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_nhi_cert_campaigns_org ON nhi_certification_campaigns (organization_id, status);


-- 3) Per-item certification decisions
CREATE TABLE IF NOT EXISTS nhi_certification_items (
    id                      BIGSERIAL PRIMARY KEY,
    organization_id         INTEGER NOT NULL,
    campaign_id             BIGINT NOT NULL REFERENCES nhi_certification_campaigns(id) ON DELETE CASCADE,

    identity_db_id          BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    identity_id             TEXT NOT NULL,
    assigned_to_user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,

    decision                TEXT
        CHECK (decision IN ('approved','revoked','delegated','needs_change',NULL)),
    decision_comment        TEXT,
    decided_by_user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    decided_at              TIMESTAMPTZ,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT nhi_cert_item_unique UNIQUE (campaign_id, identity_db_id)
);
CREATE INDEX IF NOT EXISTS idx_nhi_cert_items_campaign ON nhi_certification_items (campaign_id);
CREATE INDEX IF NOT EXISTS idx_nhi_cert_items_org ON nhi_certification_items (organization_id);


-- 4) updated_at trigger on assignments
CREATE OR REPLACE FUNCTION _nhi_ownership_touch()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_nhi_ownership_touch ON nhi_ownership_assignments;
CREATE TRIGGER trg_nhi_ownership_touch
    BEFORE UPDATE ON nhi_ownership_assignments
    FOR EACH ROW EXECUTE FUNCTION _nhi_ownership_touch();


-- 5) RLS — strict tenant policies (same pattern as 211)
DO $$
DECLARE
    t TEXT;
    using_clause TEXT := 'organization_id = (current_setting(''app.current_organization_id'', true))::integer';
BEGIN
    FOREACH t IN ARRAY ARRAY['nhi_ownership_assignments',
                              'nhi_certification_campaigns',
                              'nhi_certification_items'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_strict_sel ON %I', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_strict_ins ON %I', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_strict_upd ON %I', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_strict_del ON %I', t);
        EXECUTE format('CREATE POLICY tenant_strict_sel ON %I FOR SELECT USING (%s)', t, using_clause);
        EXECUTE format('CREATE POLICY tenant_strict_ins ON %I FOR INSERT WITH CHECK (%s)', t, using_clause);
        EXECUTE format('CREATE POLICY tenant_strict_upd ON %I FOR UPDATE USING (%s) WITH CHECK (%s)',
                       t, using_clause, using_clause);
        EXECUTE format('CREATE POLICY tenant_strict_del ON %I FOR DELETE USING (%s)', t, using_clause);
    END LOOP;
END $$;


-- 6) Grants
DO $$ BEGIN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_ownership_assignments TO auditgraph_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_certification_campaigns TO auditgraph_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_certification_items TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE nhi_ownership_assignments_id_seq TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE nhi_certification_campaigns_id_seq TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE nhi_certification_items_id_seq TO auditgraph_app';
EXCEPTION WHEN undefined_object THEN NULL; END $$;
DO $$ BEGIN
    EXECUTE 'GRANT ALL ON nhi_ownership_assignments TO auditgraph_admin';
    EXECUTE 'GRANT ALL ON nhi_certification_campaigns TO auditgraph_admin';
    EXECUTE 'GRANT ALL ON nhi_certification_items TO auditgraph_admin';
EXCEPTION WHEN undefined_object THEN NULL; END $$;

COMMIT;
