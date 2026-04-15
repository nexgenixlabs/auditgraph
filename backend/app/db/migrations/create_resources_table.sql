-- =============================================================================
-- G1 — First-class Resource model
-- =============================================================================
--
-- AuditGraph historically represented resources as raw ARM / ARN / GCP path
-- strings embedded in role assignments, attack paths, and graph edges. That
-- design made four things impossible:
--
--   1. Joining a resource to its sensitivity classification without a regex.
--   2. Correlating the same resource across clouds (the F1 cross-cloud UUID).
--   3. Filtering blast-radius queries by resource type or sensitivity.
--   4. Enforcing organization_id at the row level — strings have no tenant.
--
-- This migration creates ``resources`` as a typed, tenant-scoped graph node
-- with its own surrogate PK and the unique ``(organization_id, cloud_id,
-- cloud_provider)`` key that all upstream joins can use.
--
-- The table is listed in ``GUARDED_TABLES`` (see org_scope_guard.py); every
-- SELECT that touches it MUST filter on ``organization_id``. CI enforces this
-- via ``scripts/audit_org_scoping.py``.
-- =============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS resources (
    id                  SERIAL          PRIMARY KEY,
    organization_id     VARCHAR(255)    NOT NULL,
    cloud_id            VARCHAR(1024)   NOT NULL,
    cloud_provider      VARCHAR(32)     NOT NULL,
    type                VARCHAR(64)     NOT NULL,
    name                VARCHAR(512)    NOT NULL,
    sensitivity         VARCHAR(32)     NOT NULL DEFAULT 'Low',
    global_identity_id  UUID,
    resource_group      VARCHAR(512),
    subscription_id     VARCHAR(255),
    tags                JSONB           NOT NULL DEFAULT '{}'::jsonb,
    discovered_at       TIMESTAMPTZ     NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ,

    -- Idempotency key for discovery upserts — a single cloud resource is
    -- uniquely identified by (tenant, native id, provider).
    CONSTRAINT resources_org_cloud_unique
        UNIQUE (organization_id, cloud_id, cloud_provider),

    -- Canonical typed classification — the service layer writes these from
    -- ``ResourceType`` / ``SensitivityLevel`` enums, but the DB guards the
    -- invariant so bad imports cannot poison the table.
    CONSTRAINT resources_type_enum_chk
        CHECK (type IN (
            'key_vault',
            'storage',
            'database',
            'secret',
            'iam_system',
            'certificate_store'
        )),
    CONSTRAINT resources_sensitivity_enum_chk
        CHECK (sensitivity IN ('Critical', 'High', 'Medium', 'Low')),
    CONSTRAINT resources_cloud_provider_enum_chk
        CHECK (cloud_provider IN ('azure', 'aws', 'gcp'))
);

-- Primary tenant-scoping index — every query starts with organization_id.
CREATE INDEX IF NOT EXISTS idx_resources_org
    ON resources (organization_id);

-- Filter by sensitivity within a tenant (dashboard / blast radius queries).
CREATE INDEX IF NOT EXISTS idx_resources_sensitivity
    ON resources (organization_id, sensitivity);

-- Sparse index — most resources are not yet linked to an MSI / SPN.
CREATE INDEX IF NOT EXISTS idx_resources_gid
    ON resources (global_identity_id)
    WHERE global_identity_id IS NOT NULL;

-- Filter by type within a tenant (e.g. "show me all key vaults").
CREATE INDEX IF NOT EXISTS idx_resources_type
    ON resources (organization_id, type);

COMMENT ON TABLE  resources IS
    'G1 — typed first-class cloud resource nodes (tenant-scoped).';
COMMENT ON COLUMN resources.cloud_id IS
    'Provider-native identifier: ARM id, ARN, or GCP full resource name.';
COMMENT ON COLUMN resources.global_identity_id IS
    'F1 — stable cross-cloud UUID for MSI resources linked to an identity.';
COMMENT ON COLUMN resources.type IS
    'ResourceType enum — constrained by resources_type_enum_chk.';
COMMENT ON COLUMN resources.sensitivity IS
    'SensitivityLevel enum — constrained by resources_sensitivity_enum_chk.';

COMMIT;
