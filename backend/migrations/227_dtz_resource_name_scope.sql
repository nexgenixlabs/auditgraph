-- 227_dtz_resource_name_scope.sql
-- 2026-06-12  ·  AG-193 follow-up
--
-- Founder feedback (2026-06-12):
--   "carehub-centus-prd-rg is a resource group, doesn't mean all its
--    resources are PHI. Narrow down the pattern - like *phi*, *claims*,
--    *patient*. I don't want to classify just based on RG."
--
-- Extends Data Trust Zones with a new scope type — resource_name_pattern —
-- and lets the engine demote broad RG-only zones to Medium confidence
-- when the resource name carries no corroborating keyword.
--
-- Application-side changes:
--   backend/app/constants/data_classification.py
--     - new tier-3b matcher for resource_name_pattern (confidence 100)
--     - broad zones (sub/RG literal or pattern) drop to 60 (Medium)
--       unless the resource name corroborates the asserted class
--   frontend/src/pages/settings/DataTrustZones.tsx
--     - scope-type dropdown gains "Resource name pattern (recommended)"

ALTER TABLE data_trust_zones
  DROP CONSTRAINT IF EXISTS data_trust_zones_scope_type_chk;

ALTER TABLE data_trust_zones
  ADD CONSTRAINT data_trust_zones_scope_type_chk
  CHECK (scope_type IN (
    'subscription',
    'resource_group',
    'subscription_pattern',
    'resource_group_pattern',
    'resource_name_pattern'
  ));
