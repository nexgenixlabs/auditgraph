-- 001_create_core_schema.sql (kept filename for now)
-- NOTE: This migration is the authoritative schema initializer.
-- It creates all tables required by the backend runtime.

-- ============================================================
-- Table: discovery_runs
-- ============================================================
CREATE TABLE IF NOT EXISTS discovery_runs (
    id BIGSERIAL PRIMARY KEY,
    subscription_id TEXT NOT NULL,
    subscription_name TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL, -- running, completed, failed
    total_identities INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_discovery_runs_status ON discovery_runs(status);
CREATE INDEX IF NOT EXISTS idx_discovery_runs_started_at ON discovery_runs(started_at DESC);

-- ============================================================
-- Table: identities
-- ============================================================
CREATE TABLE IF NOT EXISTS identities (
    id BIGSERIAL PRIMARY KEY,
    discovery_run_id BIGINT REFERENCES discovery_runs(id) ON DELETE CASCADE,

    -- Core identity keys
    identity_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'azure', -- azure/aws/gcp (future)
    identity_type TEXT NOT NULL,          -- legacy: service_principal, managed_identity (keep)
    identity_category TEXT NOT NULL DEFAULT 'service_principal', -- ✅ new normalized category

    -- Entra identifiers
    app_id TEXT,
    object_id TEXT,

    -- Entra metadata (supports correct classification + debugging)
    entra_object_type TEXT,                -- user | servicePrincipal | group (future)
    service_principal_type TEXT,           -- Application | ManagedIdentity | etc.
    publisher_name TEXT,
    app_owner_organization_id TEXT,
    alternative_names JSONB,               -- list from Graph alternativeNames

    -- Status & timestamps
    created_datetime TIMESTAMPTZ,
    enabled BOOLEAN DEFAULT TRUE,
    is_microsoft_system BOOLEAN DEFAULT FALSE,

    -- Risk assessment
    risk_level TEXT,                       -- critical, high, medium, low, info
    risk_reasons TEXT[],

    -- Credentials
    credential_expiration TIMESTAMPTZ,
    credential_status TEXT,                -- expired, critical, warning, good, unknown

    -- Activity
    last_sign_in TIMESTAMPTZ,
    activity_status TEXT,                  -- active, inactive, stale, never_used, unknown

    -- Metadata
    tags JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (discovery_run_id, identity_id)
);

CREATE INDEX IF NOT EXISTS idx_identities_run_id ON identities(discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_identities_risk_level ON identities(risk_level);
CREATE INDEX IF NOT EXISTS idx_identities_identity_type ON identities(identity_type);
CREATE INDEX IF NOT EXISTS idx_identities_identity_category ON identities(identity_category);
CREATE INDEX IF NOT EXISTS idx_identities_microsoft_system ON identities(is_microsoft_system);
CREATE INDEX IF NOT EXISTS idx_identities_source ON identities(source);

-- ============================================================
-- Table: role_assignments (Azure RBAC)
-- ============================================================
CREATE TABLE IF NOT EXISTS role_assignments (
    id BIGSERIAL PRIMARY KEY,
    identity_db_id BIGINT REFERENCES identities(id) ON DELETE CASCADE,

    role_name TEXT NOT NULL,
    scope TEXT NOT NULL,
    scope_type TEXT NOT NULL,              -- subscription, resource_group, resource
    principal_id TEXT NOT NULL,
    assignment_id TEXT,
    created_on TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_identity_db_id ON role_assignments(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_role_name ON role_assignments(role_name);

-- ============================================================
-- Table: entra_role_assignments (Entra directory roles)
-- ============================================================
CREATE TABLE IF NOT EXISTS entra_role_assignments (
    id BIGSERIAL PRIMARY KEY,
    identity_db_id BIGINT REFERENCES identities(id) ON DELETE CASCADE,

    role_name TEXT NOT NULL,
    role_definition_id TEXT,
    directory_scope TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_entra_roles_identity_db_id ON entra_role_assignments(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_entra_roles_role_name ON entra_role_assignments(role_name);

-- ============================================================
-- OPTIONAL: identity_roles (Unified future table)
-- Not used by current code paths, but safe to keep for future consolidation.
-- ============================================================
CREATE TABLE IF NOT EXISTS identity_roles (
  id BIGSERIAL PRIMARY KEY,
  identity_db_id BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  role_name TEXT NOT NULL,
  role_type TEXT NOT NULL,                -- 'azure_rbac' | 'entra_directory_role'
  scope TEXT,
  inherited BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_roles_identity_db_id ON identity_roles(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_identity_roles_role_type ON identity_roles(role_type);
CREATE INDEX IF NOT EXISTS idx_identity_roles_role_name ON identity_roles(role_name);

-- ============================================================
-- Views
-- ============================================================
CREATE OR REPLACE VIEW v_latest_identities AS
SELECT i.*
FROM identities i
INNER JOIN (
    SELECT MAX(id) as run_id FROM discovery_runs WHERE status = 'completed'
) latest ON i.discovery_run_id = latest.run_id;

CREATE OR REPLACE VIEW v_critical_identities AS
SELECT * FROM v_latest_identities WHERE risk_level = 'critical';
