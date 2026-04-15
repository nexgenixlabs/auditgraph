-- Migration 087: Phase 3 route-layer dependency tables
--
-- The Phase 3 FastAPI routes in app/api/routes/{identities,resources,snapshots}.py
-- read from a handful of tables (and one derived view) that 086 did not create.
-- Specifically:
--
--   * snapshots                     (app/api/routes/snapshots.py: list/get/capture)
--   * identity_list                 (app/api/routes/identities.py: list + /global/{id})
--   * identity_list_snapshots       (app/api/routes/snapshots.py: list_snapshot_identities)
--   * role_assignments              (app/api/routes/resources.py: _IDENTITIES_FOR_RESOURCE_SQL)
--   * resources.{resource_group, subscription_id, discovered_at, last_seen}
--     (app/api/routes/resources.py: list/detail SELECT)
--
-- None of these exist in 086; the builder tables 086 created are the
-- *input* side of the Phase 3 pipeline, whereas the route tables created
-- here are the *output* / projection side that serves the REST API.
--
-- Schema rules:
--   * Mirror the columns the route SQL enumerates, verbatim. Schema drift
--     between a route SELECT and this migration is a bug in the route,
--     not this migration.
--   * All tables are tenant-scoped on organization_id — the strict RLS
--     story lives in the Phase 3 RLS migration, not here. These stubs
--     permit empty-state operation until the builder pipeline populates
--     them.
--   * Additive only — no DROP, no rename.

BEGIN;

-- ---------------------------------------------------------------------------
-- snapshots (Phase 3 snapshot catalogue)
-- ---------------------------------------------------------------------------

-- NOTE on organization_id typing: the Phase 3 route tables created
-- here use INTEGER organization_id to match migration 086's
-- `resources` + `resource_snapshots` tables and the legacy
-- `role_assignments` table (pre-Phase 3). Handlers cast the str
-- JWT claim to int once at entry; asyncpg does not silently coerce.
--
-- If you ever decide to switch to VARCHAR org_id, you must also
-- change the JOIN type match in resources.py `_IDENTITIES_FOR_RESOURCE_SQL`.

CREATE TABLE IF NOT EXISTS snapshots (
    id               SERIAL       PRIMARY KEY,
    organization_id  INTEGER      NOT NULL,
    captured_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    identity_count   INTEGER      NOT NULL DEFAULT 0,
    triggered_by     VARCHAR(32)  NOT NULL DEFAULT 'manual',
    status           VARCHAR(32)  NOT NULL DEFAULT 'complete',
    note             TEXT
);

CREATE INDEX IF NOT EXISTS ix_snapshots_org_captured
    ON snapshots (organization_id, captured_at DESC, id DESC);

-- ---------------------------------------------------------------------------
-- identity_list — flat projection read by GET /api/v1/identities and
-- GET /api/v1/identities/global/{id}. Column list mirrors the SELECT in
-- app/api/routes/identities.py:list_identities verbatim.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity_list (
    organization_id     INTEGER      NOT NULL,
    identity_id         VARCHAR(255) NOT NULL,
    global_identity_id  UUID         NOT NULL,
    display_name        VARCHAR(500) NOT NULL,
    identity_type       VARCHAR(64)  NOT NULL,
    cloud_provider      VARCHAR(20)  NOT NULL DEFAULT 'azure',
    risk_label          VARCHAR(16)  NOT NULL DEFAULT 'Low',
    risk_score          DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    governance          VARCHAR(32)  NOT NULL DEFAULT 'Governed',
    lifecycle_state     VARCHAR(32)  NOT NULL DEFAULT 'Provisioned',
    is_dormant          BOOLEAN      NOT NULL DEFAULT FALSE,
    privilege_level     VARCHAR(32)  NOT NULL DEFAULT 'standard',
    last_seen           TIMESTAMPTZ,
    PRIMARY KEY (organization_id, identity_id)
);

CREATE INDEX IF NOT EXISTS ix_identity_list_org_risk
    ON identity_list (organization_id, risk_score DESC);

CREATE TABLE IF NOT EXISTS identity_list_snapshots (
    organization_id     INTEGER      NOT NULL,
    snapshot_id         INTEGER      NOT NULL,
    identity_id         VARCHAR(255) NOT NULL,
    global_identity_id  UUID         NOT NULL,
    display_name        VARCHAR(500) NOT NULL,
    identity_type       VARCHAR(64)  NOT NULL,
    cloud_provider      VARCHAR(20)  NOT NULL DEFAULT 'azure',
    risk_label          VARCHAR(16)  NOT NULL DEFAULT 'Low',
    risk_score          DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    governance          VARCHAR(32)  NOT NULL DEFAULT 'Governed',
    lifecycle_state     VARCHAR(32)  NOT NULL DEFAULT 'Provisioned',
    is_dormant          BOOLEAN      NOT NULL DEFAULT FALSE,
    privilege_level     VARCHAR(32)  NOT NULL DEFAULT 'standard',
    last_seen           TIMESTAMPTZ,
    PRIMARY KEY (organization_id, snapshot_id, identity_id)
);

CREATE INDEX IF NOT EXISTS ix_identity_list_snapshots_org_snap
    ON identity_list_snapshots (organization_id, snapshot_id);

-- ---------------------------------------------------------------------------
-- global_identity_members — cross-cloud identity correlation table read by
-- app/services/global_identity_registry.py. The registry SELECTs on
-- (organization_id, cloud_id, cloud_provider) and INSERTs the full tuple
-- (global_identity_id, organization_id, cloud_id, cloud_provider,
-- identity_type, is_primary, discovered_at). Column list mirrors those
-- query signatures verbatim — schema drift here is a registry bug.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS global_identity_members (
    organization_id     INTEGER       NOT NULL,
    global_identity_id  UUID          NOT NULL,
    cloud_id            VARCHAR(500)  NOT NULL,
    cloud_provider      VARCHAR(20)   NOT NULL DEFAULT 'azure',
    identity_type       VARCHAR(64)   NOT NULL DEFAULT 'unknown',
    is_primary          BOOLEAN       NOT NULL DEFAULT FALSE,
    discovered_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, cloud_id, cloud_provider)
);

CREATE INDEX IF NOT EXISTS ix_global_identity_members_gid
    ON global_identity_members (organization_id, global_identity_id);

-- ---------------------------------------------------------------------------
-- role_assignments — used by the reverse-lookup SQL in resources.py to
-- enumerate identities that can reach a resource via an RBAC scope match.
-- The Phase 3 builder pipeline populates this from ARM role assignments;
-- this stub allows empty-state operation.
-- ---------------------------------------------------------------------------

-- NOTE: role_assignments already exists as a legacy INTEGER-org_id table.
-- This CREATE IF NOT EXISTS is a no-op on existing installs; on a pristine
-- Phase 3 install it provides the minimal 4-column shape the route SQL joins.
CREATE TABLE IF NOT EXISTS role_assignments (
    organization_id  INTEGER       NOT NULL,
    identity_id      VARCHAR(255)  NOT NULL,
    role_key         VARCHAR(255)  NOT NULL,
    scope            VARCHAR(1000) NOT NULL,
    PRIMARY KEY (organization_id, identity_id, role_key, scope)
);

CREATE INDEX IF NOT EXISTS ix_role_assignments_org_scope
    ON role_assignments (organization_id, scope);

-- ---------------------------------------------------------------------------
-- resources: ADD the 4 columns the list/detail handler SELECT enumerates
-- ---------------------------------------------------------------------------

ALTER TABLE resources
    ADD COLUMN IF NOT EXISTS resource_group  VARCHAR(500),
    ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS discovered_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_seen       TIMESTAMPTZ;

ALTER TABLE resource_snapshots
    ADD COLUMN IF NOT EXISTS resource_group  VARCHAR(500),
    ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS discovered_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_seen       TIMESTAMPTZ;

COMMIT;
