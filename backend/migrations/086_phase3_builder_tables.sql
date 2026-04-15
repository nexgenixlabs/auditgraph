-- Migration 086: Phase 3 builder dependency tables
--
-- The Phase 3 IdentityStateEngine orchestrates 9 builders, each of which
-- reads from a domain-specific table (plus a snapshot twin for DataMode.SNAPSHOT).
-- None of those tables existed in the legacy schema, so this migration
-- creates minimal skeletons so the builders can run against empty state
-- without raising UndefinedTableError. Each builder already handles the
-- "no row" case gracefully (returns a sensible default, empty list, etc.),
-- so an empty table is a valid production state until the discovery
-- pipeline starts populating these tables.
--
-- Tables created (paired live + snapshot):
--   1.  identity_activity / identity_activity_snapshots              (B02)
--   2.  identity_owners / identity_owners_snapshots                  (B03)
--   3.  identity_privilege_summary / identity_privilege_summary_snapshots (B05)
--   4.  identity_credentials / identity_credentials_snapshots        (B06 input)
--   5.  identity_role_assignments / identity_role_assignments_snapshots (B07)
--   6.  identity_attack_paths / identity_attack_paths_snapshots      (B08)
--   7.  identity_snapshots_rows                                      (B01 snapshot read)
--   8.  resources / resource_snapshots                               (B08 + BlastRadius)
--
-- Column lists mirror the enumerated SELECTs in:
--   app/services/builders/identity_profile_builder.py
--   app/services/builders/activity_builder.py
--   app/services/builders/attack_path_engine.py
--   app/services/graph/resource_batch_loader.py
-- Schema drift should cause test failures there first, so adding a new
-- column to a builder SELECT also requires adding the column here.

BEGIN;

-- ---------------------------------------------------------------------------
-- B02 identity_activity
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity_activity (
    organization_id      INTEGER      NOT NULL,
    identity_id          VARCHAR(255) NOT NULL,
    lifecycle_state      VARCHAR(32)  NOT NULL DEFAULT 'PROVISIONED',
    last_sign_in_at      TIMESTAMPTZ,
    last_activity_at     TIMESTAMPTZ,
    activity_confidence  VARCHAR(16)  NOT NULL DEFAULT 'none',
    has_p2_telemetry     BOOLEAN      NOT NULL DEFAULT FALSE,
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, identity_id)
);

CREATE TABLE IF NOT EXISTS identity_activity_snapshots (
    organization_id      INTEGER      NOT NULL,
    identity_id          VARCHAR(255) NOT NULL,
    snapshot_id          INTEGER      NOT NULL,
    lifecycle_state      VARCHAR(32)  NOT NULL DEFAULT 'PROVISIONED',
    last_sign_in_at      TIMESTAMPTZ,
    last_activity_at     TIMESTAMPTZ,
    activity_confidence  VARCHAR(16)  NOT NULL DEFAULT 'none',
    has_p2_telemetry     BOOLEAN      NOT NULL DEFAULT FALSE,
    PRIMARY KEY (organization_id, identity_id, snapshot_id)
);

-- ---------------------------------------------------------------------------
-- B03 identity_owners
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity_owners (
    organization_id   INTEGER      NOT NULL,
    identity_id       VARCHAR(255) NOT NULL,
    owner_id          VARCHAR(255) NOT NULL,
    owner_name        VARCHAR(500),
    owner_type        VARCHAR(64),
    last_active_days  INTEGER,
    has_reviewed      BOOLEAN      NOT NULL DEFAULT FALSE,
    last_review_at    TIMESTAMPTZ,
    PRIMARY KEY (organization_id, identity_id, owner_id)
);

CREATE TABLE IF NOT EXISTS identity_owners_snapshots (
    organization_id   INTEGER      NOT NULL,
    identity_id       VARCHAR(255) NOT NULL,
    snapshot_id       INTEGER      NOT NULL,
    owner_id          VARCHAR(255) NOT NULL,
    owner_name        VARCHAR(500),
    owner_type        VARCHAR(64),
    last_active_days  INTEGER,
    has_reviewed      BOOLEAN      NOT NULL DEFAULT FALSE,
    last_review_at    TIMESTAMPTZ,
    PRIMARY KEY (organization_id, identity_id, snapshot_id, owner_id)
);

-- ---------------------------------------------------------------------------
-- B05 identity_privilege_summary
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity_privilege_summary (
    organization_id                INTEGER      NOT NULL,
    identity_id                    VARCHAR(255) NOT NULL,
    privilege_level                VARCHAR(32)  NOT NULL DEFAULT 'standard',
    scope_breadth                  VARCHAR(32)  NOT NULL DEFAULT 'resource',
    highly_privileged_role_count   INTEGER      NOT NULL DEFAULT 0,
    privileged_role_count          INTEGER      NOT NULL DEFAULT 0,
    standard_role_count            INTEGER      NOT NULL DEFAULT 0,
    total_role_count               INTEGER      NOT NULL DEFAULT 0,
    can_escalate                   BOOLEAN      NOT NULL DEFAULT FALSE,
    blast_radius_resource_count    INTEGER      NOT NULL DEFAULT 0,
    PRIMARY KEY (organization_id, identity_id)
);

CREATE TABLE IF NOT EXISTS identity_privilege_summary_snapshots (
    organization_id                INTEGER      NOT NULL,
    identity_id                    VARCHAR(255) NOT NULL,
    snapshot_id                    INTEGER      NOT NULL,
    privilege_level                VARCHAR(32)  NOT NULL DEFAULT 'standard',
    scope_breadth                  VARCHAR(32)  NOT NULL DEFAULT 'resource',
    highly_privileged_role_count   INTEGER      NOT NULL DEFAULT 0,
    privileged_role_count          INTEGER      NOT NULL DEFAULT 0,
    standard_role_count            INTEGER      NOT NULL DEFAULT 0,
    total_role_count               INTEGER      NOT NULL DEFAULT 0,
    can_escalate                   BOOLEAN      NOT NULL DEFAULT FALSE,
    blast_radius_resource_count    INTEGER      NOT NULL DEFAULT 0,
    PRIMARY KEY (organization_id, identity_id, snapshot_id)
);

-- ---------------------------------------------------------------------------
-- B06 input: identity_credentials (minimal projection — full cred schema
-- lives in the discovery pipeline; this table only carries the aggregated
-- rotation status the CredentialLoader reads).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity_credentials (
    organization_id             INTEGER      NOT NULL,
    identity_id                 VARCHAR(255) NOT NULL,
    credential_key              VARCHAR(255) NOT NULL,
    rotation_status             VARCHAR(32)  NOT NULL DEFAULT 'healthy',
    rotation_status_priority    INTEGER      NOT NULL DEFAULT 0,
    PRIMARY KEY (organization_id, identity_id, credential_key)
);

CREATE TABLE IF NOT EXISTS identity_credentials_snapshots (
    organization_id             INTEGER      NOT NULL,
    identity_id                 VARCHAR(255) NOT NULL,
    snapshot_id                 INTEGER      NOT NULL,
    credential_key              VARCHAR(255) NOT NULL,
    rotation_status             VARCHAR(32)  NOT NULL DEFAULT 'healthy',
    rotation_status_priority    INTEGER      NOT NULL DEFAULT 0,
    PRIMARY KEY (organization_id, identity_id, snapshot_id, credential_key)
);

-- ---------------------------------------------------------------------------
-- B07 identity_role_assignments
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity_role_assignments (
    organization_id    INTEGER      NOT NULL,
    identity_id        VARCHAR(255) NOT NULL,
    role_key           VARCHAR(255) NOT NULL,
    role_name          VARCHAR(500) NOT NULL,
    scope              VARCHAR(1000) NOT NULL,
    scope_level        VARCHAR(32)  NOT NULL DEFAULT 'resource',
    source             VARCHAR(32)  NOT NULL DEFAULT 'direct',
    usage_used         BOOLEAN      NOT NULL DEFAULT FALSE,
    usage_confidence   VARCHAR(16)  NOT NULL DEFAULT 'none',
    usage_evidence     TEXT         NOT NULL DEFAULT '',
    PRIMARY KEY (organization_id, identity_id, role_key, scope)
);

CREATE TABLE IF NOT EXISTS identity_role_assignments_snapshots (
    organization_id    INTEGER      NOT NULL,
    identity_id        VARCHAR(255) NOT NULL,
    snapshot_id        INTEGER      NOT NULL,
    role_key           VARCHAR(255) NOT NULL,
    role_name          VARCHAR(500) NOT NULL,
    scope              VARCHAR(1000) NOT NULL,
    scope_level        VARCHAR(32)  NOT NULL DEFAULT 'resource',
    source             VARCHAR(32)  NOT NULL DEFAULT 'direct',
    usage_used         BOOLEAN      NOT NULL DEFAULT FALSE,
    usage_confidence   VARCHAR(16)  NOT NULL DEFAULT 'none',
    usage_evidence     TEXT         NOT NULL DEFAULT '',
    PRIMARY KEY (organization_id, identity_id, snapshot_id, role_key, scope)
);

-- ---------------------------------------------------------------------------
-- B08 identity_attack_paths (materialized pre-computed paths)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity_attack_paths (
    organization_id             INTEGER      NOT NULL,
    identity_id                 VARCHAR(255) NOT NULL,
    path_id                     VARCHAR(255) NOT NULL,
    path_type                   VARCHAR(64)  NOT NULL,
    source_identity_uuid        UUID,
    target_resource_id          VARCHAR(500),
    target_global_identity_id   UUID,
    target_cloud_id             VARCHAR(20),
    target_type                 VARCHAR(64),
    target_name                 VARCHAR(500),
    target_sensitivity          VARCHAR(32),
    severity                    VARCHAR(32)  NOT NULL DEFAULT 'low',
    score                       DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    chain                       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    mitre_techniques            JSONB        NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (organization_id, identity_id, path_id)
);

CREATE TABLE IF NOT EXISTS identity_attack_paths_snapshots (
    organization_id             INTEGER      NOT NULL,
    identity_id                 VARCHAR(255) NOT NULL,
    snapshot_id                 INTEGER      NOT NULL,
    path_id                     VARCHAR(255) NOT NULL,
    path_type                   VARCHAR(64)  NOT NULL,
    source_identity_uuid        UUID,
    target_resource_id          VARCHAR(500),
    target_global_identity_id   UUID,
    target_cloud_id             VARCHAR(20),
    target_type                 VARCHAR(64),
    target_name                 VARCHAR(500),
    target_sensitivity          VARCHAR(32),
    severity                    VARCHAR(32)  NOT NULL DEFAULT 'low',
    score                       DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    chain                       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    mitre_techniques            JSONB        NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (organization_id, identity_id, snapshot_id, path_id)
);

-- ---------------------------------------------------------------------------
-- B01 snapshot variant — identity_snapshots_rows
-- (mirrors the Phase 3 columns we added to identities in migration 085)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity_snapshots_rows (
    organization_id        INTEGER      NOT NULL,
    identity_id            VARCHAR(255) NOT NULL,
    snapshot_id            INTEGER      NOT NULL,
    global_identity_id     UUID,
    object_id              VARCHAR(255),
    display_name           VARCHAR(500),
    user_principal_name    VARCHAR(500),
    identity_type          VARCHAR(64),
    cloud_id               VARCHAR(20),
    source                 VARCHAR(32),
    status                 VARCHAR(32),
    is_federated_identity  BOOLEAN      NOT NULL DEFAULT FALSE,
    federated_from         VARCHAR(500),
    created_at             TIMESTAMPTZ,
    last_modified_at       TIMESTAMPTZ,
    discovered_at          TIMESTAMPTZ,
    PRIMARY KEY (organization_id, identity_id, snapshot_id)
);

-- ---------------------------------------------------------------------------
-- resources / resource_snapshots (BlastRadius bucket lookup)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS resources (
    organization_id     INTEGER      NOT NULL,
    id                  VARCHAR(500) NOT NULL,
    global_identity_id  UUID,
    cloud_id            VARCHAR(500) NOT NULL,
    cloud_provider      VARCHAR(20)  NOT NULL DEFAULT 'azure',
    type                VARCHAR(64)  NOT NULL DEFAULT 'storage',
    name                VARCHAR(500) NOT NULL,
    sensitivity         VARCHAR(32)  NOT NULL DEFAULT 'Low',
    PRIMARY KEY (organization_id, id)
);

CREATE TABLE IF NOT EXISTS resource_snapshots (
    organization_id     INTEGER      NOT NULL,
    id                  VARCHAR(500) NOT NULL,
    snapshot_id         INTEGER      NOT NULL,
    global_identity_id  UUID,
    cloud_id            VARCHAR(500) NOT NULL,
    cloud_provider      VARCHAR(20)  NOT NULL DEFAULT 'azure',
    type                VARCHAR(64)  NOT NULL DEFAULT 'storage',
    name                VARCHAR(500) NOT NULL,
    sensitivity         VARCHAR(32)  NOT NULL DEFAULT 'Low',
    PRIMARY KEY (organization_id, id, snapshot_id)
);

COMMIT;
