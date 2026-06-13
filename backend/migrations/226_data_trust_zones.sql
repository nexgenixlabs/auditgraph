-- 226_data_trust_zones.sql
-- 2026-06-12  ·  AG-193 / AG-194 (Sprint 1)
--
-- "Data Trust Zones" — CISO-asserted classification scope rules.
--
-- Customer-facing: "Data Trust Zones"
-- Internal code:   classification_scope_rules / data_trust_zones table
--
-- Solves: Unified Identity Graph shows Data Sources = 0 because most
-- tenants don't systematically tag classification. Reading data content
-- to fix that would destroy the read-only / no-data-plane moat. Instead
-- the CISO asserts classification at subscription / resource-group
-- scope; we propagate down the ARM tree at discovery time.
--
-- 6-tier precedence (highest → lowest):
--   1. Manual override (per-resource admin click)
--   2. Regex override (per-tenant settings)
--   3. Data Trust Zone (scope rule)           ← THIS MIGRATION
--   4. Purview classification                 ← slot reserved (Sprint 3)
--   5. Azure tag
--   6. Name pattern
--
-- Standing rules (memory):
--   - Always soft-delete via revoked_at (audit trail)
--   - Customer-facing copy says "Data Trust Zones"
--   - Every classification carries source + confidence
--   - Read-only + no data plane access

-- ─────────────────────────────────────────────────────────────────
-- 1. data_trust_zones — CISO scope assertions
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS data_trust_zones (
  id                   bigserial PRIMARY KEY,
  organization_id      integer NOT NULL,
  classification       varchar(20) NOT NULL,
  scope_type           varchar(40) NOT NULL,
  scope_value          text NOT NULL,
  asserted_by          text,
  asserted_at          timestamptz NOT NULL DEFAULT NOW(),
  revoked_at           timestamptz,
  revoked_by           text,
  notes                text,
  created_at           timestamptz NOT NULL DEFAULT NOW(),
  updated_at           timestamptz NOT NULL DEFAULT NOW(),

  CONSTRAINT data_trust_zones_classification_chk
    CHECK (classification IN ('PHI','PCI','PII','SOURCE','HR','FINANCIAL','CONFIDENTIAL')),

  CONSTRAINT data_trust_zones_scope_type_chk
    CHECK (scope_type IN (
      'subscription',
      'resource_group',
      'subscription_pattern',
      'resource_group_pattern'
    ))
);

CREATE INDEX IF NOT EXISTS idx_dtz_org_active
  ON data_trust_zones (organization_id)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_dtz_scope_lookup
  ON data_trust_zones (organization_id, scope_type, scope_value)
  WHERE revoked_at IS NULL;

-- ─────────────────────────────────────────────────────────────────
-- 2. RLS (matches the org_strict_* pattern used on the other tenant
--    tables — same auto-fill trigger story as the rest of the 44).
-- ─────────────────────────────────────────────────────────────────

ALTER TABLE data_trust_zones ENABLE ROW LEVEL SECURITY;
ALTER TABLE data_trust_zones FORCE  ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='data_trust_zones' AND policyname='org_strict_sel') THEN
    CREATE POLICY org_strict_sel ON data_trust_zones FOR SELECT
      USING (organization_id = current_setting('app.current_organization_id', true)::integer);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='data_trust_zones' AND policyname='org_strict_ins') THEN
    CREATE POLICY org_strict_ins ON data_trust_zones FOR INSERT
      WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='data_trust_zones' AND policyname='org_strict_upd') THEN
    CREATE POLICY org_strict_upd ON data_trust_zones FOR UPDATE
      USING (organization_id = current_setting('app.current_organization_id', true)::integer);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='data_trust_zones' AND policyname='org_strict_del') THEN
    CREATE POLICY org_strict_del ON data_trust_zones FOR DELETE
      USING (organization_id = current_setting('app.current_organization_id', true)::integer);
  END IF;
END$$;

-- ─────────────────────────────────────────────────────────────────
-- 3. Classification provenance columns on every resource table that
--    has data_classification. We store the rule id so we can show
--    "this resource is PHI because of CISO assertion on
--    sub:prod-healthcare on 2026-06-12 by alice@…".
-- ─────────────────────────────────────────────────────────────────

ALTER TABLE discovered_resources
  ADD COLUMN IF NOT EXISTS classification_source     text,
  ADD COLUMN IF NOT EXISTS classification_rule_id    bigint,
  ADD COLUMN IF NOT EXISTS classification_asserted_by text,
  ADD COLUMN IF NOT EXISTS classification_confidence  integer;

ALTER TABLE azure_storage_accounts
  ADD COLUMN IF NOT EXISTS classification_source     text,
  ADD COLUMN IF NOT EXISTS classification_rule_id    bigint,
  ADD COLUMN IF NOT EXISTS classification_asserted_by text,
  ADD COLUMN IF NOT EXISTS classification_confidence  integer;

ALTER TABLE azure_key_vaults
  ADD COLUMN IF NOT EXISTS classification_source     text,
  ADD COLUMN IF NOT EXISTS classification_rule_id    bigint,
  ADD COLUMN IF NOT EXISTS classification_asserted_by text,
  ADD COLUMN IF NOT EXISTS classification_confidence  integer;

-- These tables may not exist in all envs — wrap in DO blocks.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='azure_sql_databases') THEN
    EXECUTE 'ALTER TABLE azure_sql_databases
      ADD COLUMN IF NOT EXISTS classification_rule_id    bigint,
      ADD COLUMN IF NOT EXISTS classification_asserted_by text,
      ADD COLUMN IF NOT EXISTS classification_confidence  integer';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='azure_cosmos_databases') THEN
    EXECUTE 'ALTER TABLE azure_cosmos_databases
      ADD COLUMN IF NOT EXISTS classification_rule_id    bigint,
      ADD COLUMN IF NOT EXISTS classification_asserted_by text,
      ADD COLUMN IF NOT EXISTS classification_confidence  integer';
  END IF;
END$$;

-- ─────────────────────────────────────────────────────────────────
-- 4. updated_at trigger so audits see real edit times.
-- ─────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION _dtz_touch_updated_at()
RETURNS trigger AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_dtz_touch_updated_at') THEN
    CREATE TRIGGER trg_dtz_touch_updated_at
      BEFORE UPDATE ON data_trust_zones
      FOR EACH ROW EXECUTE FUNCTION _dtz_touch_updated_at();
  END IF;
END$$;
