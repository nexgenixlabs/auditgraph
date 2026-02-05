-- 005_create_role_intelligence.sql

-- Role permissions intelligence
CREATE TABLE IF NOT EXISTS role_permissions (
  id BIGSERIAL PRIMARY KEY,
  role_name TEXT NOT NULL,
  role_type TEXT NOT NULL, -- azure | entra
  privileged BOOLEAN DEFAULT FALSE,
  risk_level TEXT, -- critical | high | medium | low
  description TEXT,
  why_critical TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (role_name, role_type)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_type ON role_permissions(role_type);
CREATE INDEX IF NOT EXISTS idx_role_permissions_risk_level ON role_permissions(risk_level);

-- Role activity log
CREATE TABLE IF NOT EXISTS role_activity_log (
  id BIGSERIAL PRIMARY KEY,
  identity_db_id BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  role_name TEXT NOT NULL,
  last_activity_date TIMESTAMPTZ,
  days_since_last_use INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (identity_db_id, role_name)
);

CREATE INDEX IF NOT EXISTS idx_role_activity_identity_db_id ON role_activity_log(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_role_activity_last_date ON role_activity_log(last_activity_date);

-- Attack patterns mapped to roles
CREATE TABLE IF NOT EXISTS role_attack_patterns (
  id BIGSERIAL PRIMARY KEY,
  role_name TEXT NOT NULL,
  attack_scenario TEXT NOT NULL,
  real_world_example TEXT,
  company_affected TEXT,
  breach_year INTEGER,
  estimated_cost_usd BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_role_attack_patterns_role_name ON role_attack_patterns(role_name);
CREATE INDEX IF NOT EXISTS idx_role_attack_patterns_year ON role_attack_patterns(breach_year DESC);

-- HIPAA mappings for roles
CREATE TABLE IF NOT EXISTS role_hipaa_mappings (
  id BIGSERIAL PRIMARY KEY,
  role_name TEXT NOT NULL,
  hipaa_section TEXT NOT NULL,
  violation_explanation TEXT,
  violation_risk TEXT, -- critical | high | medium | low
  typical_penalty_min BIGINT,
  typical_penalty_max BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_role_hipaa_mappings_role_name ON role_hipaa_mappings(role_name);
CREATE INDEX IF NOT EXISTS idx_role_hipaa_mappings_risk ON role_hipaa_mappings(violation_risk);
