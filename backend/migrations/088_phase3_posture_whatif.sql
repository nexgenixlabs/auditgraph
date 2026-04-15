-- Migration 088: Phase 3 PostureScoreEngine + WhatIfService persistence
--
-- E1 task: persist posture score computations and what-if simulations so
-- that:
--   * the CISO Dashboard can read live scores without recomputing
--   * Phase 3 /api/v1/posture/score and /posture/score/history endpoints
--     have a backing store
--   * posture score trend over time is auditable
--   * every what-if simulation leaves a forensic trail
--
-- Schema rules (same as 086/087):
--   * organization_id is INTEGER (not VARCHAR). Handlers cast the str
--     JWT claim to int once at entry; asyncpg does not silently coerce.
--   * Additive only — no DROP, no rename.
--   * Idempotent — CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS.

BEGIN;

-- ---------------------------------------------------------------------------
-- posture_scores — one row per (organization, day). PostureScoreEngine.compute
-- upserts on (organization_id, score_date::date). dimension_scores is a JSONB
-- map of the 5 CVSS-aligned pillars (attack_surface, privilege, credentials,
-- activity, governance). computed_by is the ENGINE_VERSION constant from
-- app/services/posture_score_engine.py — bump it when scoring logic changes.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS posture_scores (
    id                 SERIAL       PRIMARY KEY,
    organization_id    INTEGER      NOT NULL,
    score_date         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    overall_score      NUMERIC(5,2) NOT NULL,
    dimension_scores   JSONB        NOT NULL DEFAULT '{}'::jsonb,
    identity_count     INTEGER      NOT NULL DEFAULT 0,
    governed_count     INTEGER      NOT NULL DEFAULT 0,
    orphaned_count     INTEGER      NOT NULL DEFAULT 0,
    stale_count        INTEGER      NOT NULL DEFAULT 0,
    at_risk_count      INTEGER      NOT NULL DEFAULT 0,
    computed_by        VARCHAR(64)  NOT NULL DEFAULT 'posture-engine@0.0.0',
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Expression-based uniqueness: one posture score row per org per calendar day.
-- Expression indexes cannot be expressed as a UNIQUE CONSTRAINT in Postgres,
-- so this is a CREATE UNIQUE INDEX with IF NOT EXISTS for idempotency.
CREATE UNIQUE INDEX IF NOT EXISTS uq_posture_scores_org_day
    ON posture_scores (organization_id, ((score_date AT TIME ZONE 'UTC')::date));

CREATE INDEX IF NOT EXISTS ix_posture_scores_org_date
    ON posture_scores (organization_id, score_date DESC);

-- ---------------------------------------------------------------------------
-- whatif_simulations — forensic log of every WhatIfService.simulate() call.
-- No uniqueness: multiple simulations per (org, identity) are valid — the
-- same identity may be simulated under different hypotheticals. result_payload
-- is the full serialized WhatIfResult Pydantic model (validated BEFORE
-- insert — if it cannot be validated, the simulate() call fails loudly
-- rather than writing garbage JSON).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS whatif_simulations (
    id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       INTEGER      NOT NULL,
    identity_id           VARCHAR(255) NOT NULL,
    simulation_type       VARCHAR(64)  NOT NULL,
    input_payload         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    result_payload        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    blast_radius_before   INTEGER      NOT NULL DEFAULT 0,
    blast_radius_after    INTEGER      NOT NULL DEFAULT 0,
    score_delta           NUMERIC(6,2) NOT NULL DEFAULT 0,
    simulated_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    simulated_by          INTEGER      REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_whatif_simulations_org_identity
    ON whatif_simulations (organization_id, identity_id, simulated_at DESC);

CREATE INDEX IF NOT EXISTS ix_whatif_simulations_org_simulated_at
    ON whatif_simulations (organization_id, simulated_at DESC);

COMMIT;
