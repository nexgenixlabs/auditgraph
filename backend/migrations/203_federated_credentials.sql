-- Cloud-dev fix: federated_credentials table exists in local sandbox (created
-- ad-hoc, no migration ever shipped) but is missing in fresh cloud DBs.
-- Azure discovery writes here when /applications/{id}/federatedIdentityCredentials
-- returns data. Without this table the federated lineage detection silently
-- falls back to "inferred from name".

CREATE TABLE IF NOT EXISTS federated_credentials (
    id                SERIAL PRIMARY KEY,
    organization_id   INTEGER NOT NULL,
    identity_db_id    BIGINT NOT NULL,
    identity_id       VARCHAR NOT NULL,
    discovery_run_id  INTEGER NOT NULL,
    credential_id     VARCHAR NOT NULL,
    name              VARCHAR,
    issuer            VARCHAR NOT NULL,
    subject           VARCHAR,
    audiences         JSONB,
    issuer_type       VARCHAR NOT NULL,
    description       TEXT,
    discovered_at     TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (organization_id, identity_id, credential_id, discovery_run_id)
);

CREATE INDEX IF NOT EXISTS idx_federated_credentials_identity
    ON federated_credentials (identity_db_id, discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_federated_credentials_run
    ON federated_credentials (discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_federated_credentials_org
    ON federated_credentials (organization_id);

-- RLS (matches the pattern enforced on all tenant tables)
ALTER TABLE federated_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE federated_credentials FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='federated_credentials' AND policyname='org_strict_sel') THEN
    CREATE POLICY org_strict_sel ON federated_credentials FOR SELECT
      USING (organization_id = current_setting('app.current_organization_id', true)::integer);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='federated_credentials' AND policyname='org_strict_ins') THEN
    CREATE POLICY org_strict_ins ON federated_credentials FOR INSERT
      WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='federated_credentials' AND policyname='org_strict_upd') THEN
    CREATE POLICY org_strict_upd ON federated_credentials FOR UPDATE
      USING (organization_id = current_setting('app.current_organization_id', true)::integer);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='federated_credentials' AND policyname='org_strict_del') THEN
    CREATE POLICY org_strict_del ON federated_credentials FOR DELETE
      USING (organization_id = current_setting('app.current_organization_id', true)::integer);
  END IF;
END$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON federated_credentials TO auditgraph_dev_app;
GRANT USAGE, SELECT ON SEQUENCE federated_credentials_id_seq TO auditgraph_dev_app;
