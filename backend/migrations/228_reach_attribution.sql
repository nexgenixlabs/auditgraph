-- 228_reach_attribution.sql
-- 2026-06-13  ·  AG-193 Sprint B
--
-- Cache per-entity "reachable classified exposure" so the dashboard
-- can answer "which N entities can reach the most $$?" without
-- re-walking the RBAC graph on every render.
--
-- Peer feedback (2026-06-12):
--   "A GPT deployment is not inherently worth $1.4M. The value comes
--    from what data it can reach."
--
-- We replace the flat AI multiplier with reach attribution:
--   model_exposure[m] = sum(classified_resource.exposure
--                           for r reachable from m's managed identity)
--
-- Identities get the same column so the headline decorators
-- ("682 reachable identities · 115 attack paths · 108 orphans")
-- can derive top-exposers in one query.
--
-- All four classified-count columns are split out so the per-entity
-- drawer can show "reach 47 PHI / 0 PCI / 12 PII" rather than just
-- the rolled-up dollar figure.

-- ─────────────────────────────────────────────────────────────────
-- 1. identities — RBAC walker writes here
-- ─────────────────────────────────────────────────────────────────

ALTER TABLE identities
  ADD COLUMN IF NOT EXISTS reachable_classified_exposure  bigint,
  ADD COLUMN IF NOT EXISTS reachable_phi_count            integer,
  ADD COLUMN IF NOT EXISTS reachable_pci_count            integer,
  ADD COLUMN IF NOT EXISTS reachable_pii_count            integer,
  ADD COLUMN IF NOT EXISTS reach_computed_at              timestamptz;

CREATE INDEX IF NOT EXISTS idx_identities_reach_exposure
  ON identities (organization_id, reachable_classified_exposure DESC NULLS LAST)
  WHERE reachable_classified_exposure IS NOT NULL AND reachable_classified_exposure > 0;

-- ─────────────────────────────────────────────────────────────────
-- 2. azure_ai_model_deployments — managed-identity reach via the
--    parent Azure OpenAI / AI Services account_resource_id.
-- ─────────────────────────────────────────────────────────────────

ALTER TABLE azure_ai_model_deployments
  ADD COLUMN IF NOT EXISTS reachable_classified_exposure  bigint,
  ADD COLUMN IF NOT EXISTS reachable_phi_count            integer,
  ADD COLUMN IF NOT EXISTS reachable_pci_count            integer,
  ADD COLUMN IF NOT EXISTS reachable_pii_count            integer,
  ADD COLUMN IF NOT EXISTS reach_computed_at              timestamptz;

CREATE INDEX IF NOT EXISTS idx_ai_deployments_reach_exposure
  ON azure_ai_model_deployments (organization_id, reachable_classified_exposure DESC NULLS LAST)
  WHERE reachable_classified_exposure IS NOT NULL AND reachable_classified_exposure > 0;
