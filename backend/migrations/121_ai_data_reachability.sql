-- AG-180 (Tier 2A): Sensitive Data Reachability schema
--
-- Adds SQL + Cosmos resource tables (the missing data surfaces beyond
-- the existing azure_storage_accounts + azure_key_vaults) and a
-- per-AI-agent reachability rollup.
--
-- Honors migration 100 regression rule: explicit PK + sequence per table.
-- All tenant-data tables are RLS-strict per Phase 87.

BEGIN;

-- ── Azure SQL ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS azure_sql_servers (
    id                       BIGSERIAL PRIMARY KEY,
    organization_id          INTEGER NOT NULL,
    discovery_run_id         BIGINT,
    connection_id            INTEGER,
    subscription_id          TEXT NOT NULL,
    resource_id              TEXT NOT NULL,
    resource_group           TEXT,
    server_name              TEXT NOT NULL,
    location                 TEXT,
    administrator_login      TEXT,
    public_network_access    TEXT,                    -- Enabled / Disabled
    minimal_tls_version      TEXT,
    azuread_only_auth        BOOLEAN,
    private_endpoint_count   INTEGER NOT NULL DEFAULT 0,
    firewall_rules_count     INTEGER NOT NULL DEFAULT 0,
    tags                     JSONB,
    raw_properties           JSONB,
    discovered_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_sql_servers_org ON azure_sql_servers(organization_id, discovery_run_id);

CREATE TABLE IF NOT EXISTS azure_sql_databases (
    id                          BIGSERIAL PRIMARY KEY,
    organization_id             INTEGER NOT NULL,
    discovery_run_id            BIGINT,
    connection_id               INTEGER,
    server_id                   BIGINT,                -- soft FK to azure_sql_servers (no PK exists on identities-style tables)
    subscription_id             TEXT NOT NULL,
    resource_id                 TEXT NOT NULL,
    server_resource_id          TEXT,
    database_name               TEXT NOT NULL,
    sku_name                    TEXT,
    sku_tier                    TEXT,
    capacity                    INTEGER,
    status                      TEXT,
    data_classification         TEXT,                  -- PHI / PCI / PII / Source / HR / Financial / Confidential
    classification_source       TEXT,                  -- 'tag' | 'name_pattern' | 'override'
    classification_confidence   TEXT,                  -- 'high' | 'medium' | 'low'
    record_count_estimate       BIGINT,                -- nullable: SKU-based estimate or NULL when unknown
    tags                        JSONB,
    raw_properties              JSONB,
    discovered_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_sql_dbs_org      ON azure_sql_databases(organization_id, discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_sql_dbs_class    ON azure_sql_databases(organization_id, data_classification)
    WHERE data_classification IS NOT NULL;

-- ── Azure Cosmos ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS azure_cosmos_accounts (
    id                            BIGSERIAL PRIMARY KEY,
    organization_id               INTEGER NOT NULL,
    discovery_run_id              BIGINT,
    connection_id                 INTEGER,
    subscription_id               TEXT NOT NULL,
    resource_id                   TEXT NOT NULL,
    resource_group                TEXT,
    account_name                  TEXT NOT NULL,
    location                      TEXT,
    kind                          TEXT,                -- GlobalDocumentDB / MongoDB / Cassandra
    public_network_access         TEXT,
    is_virtual_network_filter_enabled BOOLEAN,
    private_endpoint_count        INTEGER NOT NULL DEFAULT 0,
    disable_local_auth            BOOLEAN,
    tags                          JSONB,
    raw_properties                JSONB,
    discovered_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_cosmos_accounts_org ON azure_cosmos_accounts(organization_id, discovery_run_id);

CREATE TABLE IF NOT EXISTS azure_cosmos_databases (
    id                          BIGSERIAL PRIMARY KEY,
    organization_id             INTEGER NOT NULL,
    discovery_run_id            BIGINT,
    connection_id               INTEGER,
    account_id                  BIGINT,
    subscription_id             TEXT NOT NULL,
    resource_id                 TEXT NOT NULL,
    account_resource_id         TEXT,
    database_name               TEXT NOT NULL,
    api_kind                    TEXT,                  -- sql / mongo / cassandra / gremlin / table
    data_classification         TEXT,
    classification_source       TEXT,
    classification_confidence   TEXT,
    record_count_estimate       BIGINT,
    tags                        JSONB,
    raw_properties              JSONB,
    discovered_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_cosmos_dbs_org   ON azure_cosmos_databases(organization_id, discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_cosmos_dbs_class ON azure_cosmos_databases(organization_id, data_classification)
    WHERE data_classification IS NOT NULL;

-- ── Storage classification enrichment (additive) ──────────────
ALTER TABLE azure_storage_accounts ADD COLUMN IF NOT EXISTS data_classification TEXT;
ALTER TABLE azure_storage_accounts ADD COLUMN IF NOT EXISTS classification_source TEXT;
ALTER TABLE azure_storage_accounts ADD COLUMN IF NOT EXISTS classification_confidence TEXT;
ALTER TABLE azure_storage_accounts ADD COLUMN IF NOT EXISTS record_count_estimate BIGINT;

-- ── Per-AI-agent data reachability rollup ────────────────────

CREATE TABLE IF NOT EXISTS agent_data_reachability (
    id                       BIGSERIAL PRIMARY KEY,
    organization_id          INTEGER NOT NULL,
    discovery_run_id         BIGINT,
    identity_db_id           BIGINT NOT NULL,
    identity_id              TEXT NOT NULL,
    data_classification      TEXT NOT NULL,            -- PHI / PCI / PII / Source / HR / Financial / Confidential
    resource_count           INTEGER NOT NULL DEFAULT 0,
    write_resource_count     INTEGER NOT NULL DEFAULT 0,
    est_records              BIGINT,                   -- nullable: sum of record_count_estimate across reachable resources
    top_resources            JSONB,                    -- [{resource_id, resource_type, access_level}]
    computed_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, discovery_run_id, identity_db_id, data_classification)
);

CREATE INDEX IF NOT EXISTS idx_adr_org_run ON agent_data_reachability(organization_id, discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_adr_identity ON agent_data_reachability(identity_db_id, discovery_run_id);

-- ── RLS policies (Phase 87 strict) ───────────────────────────

DO $$
DECLARE
    _tbl TEXT;
    _tables TEXT[] := ARRAY[
        'azure_sql_servers',
        'azure_sql_databases',
        'azure_cosmos_accounts',
        'azure_cosmos_databases',
        'agent_data_reachability'
    ];
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='auditgraph_app') THEN
        FOREACH _tbl IN ARRAY _tables LOOP
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', _tbl);
            EXECUTE format('DROP POLICY IF EXISTS tenant_strict_sel ON %I', _tbl);
            EXECUTE format('DROP POLICY IF EXISTS tenant_strict_ins ON %I', _tbl);
            EXECUTE format('DROP POLICY IF EXISTS tenant_strict_upd ON %I', _tbl);
            EXECUTE format('DROP POLICY IF EXISTS tenant_strict_del ON %I', _tbl);
            EXECUTE format(
                'CREATE POLICY tenant_strict_sel ON %I FOR SELECT '
                'USING (organization_id = current_setting(''app.current_tenant_id'', true)::integer)',
                _tbl);
            EXECUTE format(
                'CREATE POLICY tenant_strict_ins ON %I FOR INSERT '
                'WITH CHECK (organization_id = current_setting(''app.current_tenant_id'', true)::integer)',
                _tbl);
            EXECUTE format(
                'CREATE POLICY tenant_strict_upd ON %I FOR UPDATE '
                'USING (organization_id = current_setting(''app.current_tenant_id'', true)::integer)',
                _tbl);
            EXECUTE format(
                'CREATE POLICY tenant_strict_del ON %I FOR DELETE '
                'USING (organization_id = current_setting(''app.current_tenant_id'', true)::integer)',
                _tbl);
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO auditgraph_app', _tbl);
        END LOOP;
    END IF;
END $$;

COMMIT;
