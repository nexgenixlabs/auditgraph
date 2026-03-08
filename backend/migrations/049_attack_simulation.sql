-- Migration 049: Attack Simulation
-- Phase 13: Identity Attack Simulation

CREATE TABLE IF NOT EXISTS attack_simulations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    identity_id         VARCHAR NOT NULL,
    simulation_type     VARCHAR(50) DEFAULT 'identity_compromise'
        CHECK (simulation_type IN ('identity_compromise', 'service_principal_compromise')),
    max_depth           INTEGER DEFAULT 6,
    blast_radius        INTEGER DEFAULT 0,
    metadata            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_as_org ON attack_simulations(organization_id);
CREATE INDEX IF NOT EXISTS idx_as_connection ON attack_simulations(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_as_identity ON attack_simulations(identity_id);

ALTER TABLE attack_simulations ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_simulations FORCE ROW LEVEL SECURITY;

CREATE POLICY as_strict_sel ON attack_simulations FOR SELECT TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY as_strict_ins ON attack_simulations FOR INSERT TO auditgraph_app
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY as_strict_upd ON attack_simulations FOR UPDATE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY as_strict_del ON attack_simulations FOR DELETE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON attack_simulations TO auditgraph_app;

-- Attack paths (child table)
CREATE TABLE IF NOT EXISTS attack_sim_paths (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    simulation_id   UUID NOT NULL REFERENCES attack_simulations(id) ON DELETE CASCADE,
    path_index      INTEGER NOT NULL,
    source_identity VARCHAR NOT NULL,
    target_resource VARCHAR NOT NULL,
    path_length     INTEGER NOT NULL,
    path_nodes      JSONB DEFAULT '[]',
    risk_level      VARCHAR(20) DEFAULT 'medium',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asp_simulation ON attack_sim_paths(simulation_id);
CREATE INDEX IF NOT EXISTS idx_asp_source ON attack_sim_paths(source_identity);

-- attack_sim_paths inherits tenant isolation via simulation_id FK
-- No direct RLS needed since queries always join through attack_simulations
GRANT SELECT, INSERT, UPDATE, DELETE ON attack_sim_paths TO auditgraph_app;
