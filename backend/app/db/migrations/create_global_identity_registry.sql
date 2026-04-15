-- =============================================================================
-- Global Identity Registry
-- =============================================================================
-- Cross-cloud identity correlation: a single canonical identity may have
-- multiple cloud-native "member" identities (e.g. the same human with an
-- Azure AD object + an AWS IAM user + a GCP service account).
--
-- Strict organization scoping: every row carries organization_id, and the
-- uniqueness + lookup paths are all org-scoped to guarantee zero cross-org
-- leakage regardless of application bugs.
-- =============================================================================

CREATE TABLE global_identity_registry (
  global_identity_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id    VARCHAR(255) NOT NULL,
  canonical_name     VARCHAR(512) NOT NULL,
  canonical_email    VARCHAR(512),
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen          TIMESTAMPTZ
);

CREATE TABLE global_identity_members (
  id                 SERIAL PRIMARY KEY,
  global_identity_id UUID NOT NULL REFERENCES global_identity_registry(global_identity_id) ON DELETE CASCADE,
  organization_id    VARCHAR(255) NOT NULL,
  cloud_id           VARCHAR(1024) NOT NULL,
  cloud_provider     VARCHAR(32) NOT NULL CHECK (cloud_provider IN ('azure','aws','gcp')),
  identity_type      VARCHAR(64) NOT NULL,
  is_primary         BOOLEAN NOT NULL DEFAULT false,
  discovered_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (organization_id, cloud_id, cloud_provider)
);

CREATE INDEX idx_gir_org  ON global_identity_registry(organization_id);
CREATE INDEX idx_gim_cloud ON global_identity_members(organization_id, cloud_id, cloud_provider);
CREATE INDEX idx_gim_gid   ON global_identity_members(global_identity_id);
