-- Identity Lineage Engine — Phase 1 schema
-- Maps service principals to their consuming Azure resources,
-- enriches with sign-in telemetry, and classifies orphan status.
--
-- FK targets use the ACTUAL AuditGraph schema:
--   identities.id        BIGINT  (not UUID — the spec's "service_principals")
--   cloud_connections.id  INTEGER (not UUID — the spec's "tenant_connections")
--
-- Data lifecycle: CASCADE DELETE on both FKs ensures lineage data
-- is cleaned up when an identity or connection is removed.

BEGIN;

-- ──────────────────────────────────────────────────────────────────
-- TABLE 1: identity_lineage_bindings
-- Links an SPN (identity) to the Azure resource that consumes it.
-- One SPN may bind to many resources; one resource may use many SPNs.
-- ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS identity_lineage_bindings (
    id                BIGSERIAL   PRIMARY KEY,
    spn_id            BIGINT      NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    connection_id     INTEGER     NOT NULL REFERENCES cloud_connections(id) ON DELETE CASCADE,
    resource_id       TEXT        NOT NULL,   -- full ARM resource ID
    resource_type     TEXT        NOT NULL,   -- AppService | FunctionApp | AKS | ContainerApp
                                              -- | LogicApp | AutomationAccount | DataFactory
                                              -- | FederatedGitHub | FederatedAKS
                                              -- | FederatedExternal | RoleInferred
    resource_name     TEXT,
    resource_group    TEXT,
    region            TEXT,
    subscription_id   TEXT,                   -- Azure subscription ID (nullable)
    binding_method    TEXT        NOT NULL,   -- HardcodedClientId | WorkloadIdentityAnnotation
                                              -- | FederatedCredential | RolePatternInferred
                                              -- | ReplyUrl | ManagedIdentitySystemAssigned
                                              -- | ManagedIdentityUserAssigned
    binding_evidence  JSONB,                  -- raw proof (JSON snippet, annotation, etc.)
    confidence_score  SMALLINT    NOT NULL DEFAULT 0
                      CHECK (confidence_score BETWEEN 0 AND 100),
    discovered_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified_at  TIMESTAMPTZ,

    -- Prevent duplicate bindings for the same SPN ↔ resource ↔ method triple
    CONSTRAINT uq_lb_spn_resource_method
        UNIQUE (spn_id, resource_id, binding_method)
);

CREATE INDEX IF NOT EXISTS idx_lb_spn      ON identity_lineage_bindings(spn_id);
CREATE INDEX IF NOT EXISTS idx_lb_conn     ON identity_lineage_bindings(connection_id);
CREATE INDEX IF NOT EXISTS idx_lb_type     ON identity_lineage_bindings(resource_type);
CREATE INDEX IF NOT EXISTS idx_lb_evidence ON identity_lineage_bindings USING GIN(binding_evidence);

-- ──────────────────────────────────────────────────────────────────
-- TABLE 2: identity_lineage_enrichment
-- Sign-in and telemetry signals attached to an SPN, bucketed by
-- enrichment tier (STATIC | P1_SIGNIN | P2_AUDIT).
-- ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS identity_lineage_enrichment (
    id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    spn_id                 BIGINT      NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    connection_id          INTEGER     NOT NULL REFERENCES cloud_connections(id) ON DELETE CASCADE,
    enrichment_source      TEXT        NOT NULL,   -- e.g. 'resource_graph', 'sign_in_log', 'audit_log'
    last_accessed_resource TEXT,
    last_accessed_at       TIMESTAMPTZ,
    source_ip              TEXT,
    workload_type_inferred TEXT,
    sign_in_type           TEXT,
    raw_signals            JSONB,
    enrichment_tier        TEXT        NOT NULL DEFAULT 'STATIC'
                           CHECK (enrichment_tier IN ('STATIC', 'P1_SIGNIN', 'P2_AUDIT', 'FULL')),
    captured_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_le_spn  ON identity_lineage_enrichment(spn_id);
CREATE INDEX IF NOT EXISTS idx_le_tier ON identity_lineage_enrichment(enrichment_tier);

-- ──────────────────────────────────────────────────────────────────
-- TABLE 3: identity_orphan_classifications
-- One row per SPN — summarises whether the identity is orphaned
-- and what action is recommended.  UNIQUE on spn_id so the
-- classifier always UPSERTs.
-- ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS identity_orphan_classifications (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    spn_id             BIGINT      NOT NULL UNIQUE REFERENCES identities(id) ON DELETE CASCADE,
    connection_id      INTEGER     NOT NULL REFERENCES cloud_connections(id) ON DELETE CASCADE,
    orphan_status      TEXT        NOT NULL DEFAULT 'UNKNOWN'
                       CHECK (orphan_status IN ('UNKNOWN', 'NOT_ORPHANED', 'SAFE_TO_RETIRE',
                                                'CAUTION', 'BLOCKED')),
    orphan_reasons     JSONB,
    active_role_count  SMALLINT    DEFAULT 0,
    recommended_action TEXT,
    classified_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oc_spn    ON identity_orphan_classifications(spn_id);
CREATE INDEX IF NOT EXISTS idx_oc_status ON identity_orphan_classifications(orphan_status);

-- ──────────────────────────────────────────────────────────────────
-- TABLE 4: identity_lineage_scores
-- Composite lineage-quality score per SPN.  Used by the AGIRS
-- scorer as an input signal — higher lineage = better visibility.
-- PK on spn_id (one score per identity, always UPSERT).
-- ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS identity_lineage_scores (
    spn_id        BIGINT   PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
    lineage_score SMALLINT NOT NULL DEFAULT 0
                  CHECK (lineage_score BETWEEN 0 AND 100),
    scored_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;
