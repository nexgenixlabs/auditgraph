-- Migration 109: Add metadata columns to discovered_resources
--
-- Enriches the resource inventory with Azure Resource Graph metadata:
-- location, tags, sku/tier, kind, managed_by, parent_resource_id.
-- These columns are populated by the ResourceInventoryCollector which
-- queries Azure Resource Graph for full resource details.

ALTER TABLE discovered_resources
    ADD COLUMN IF NOT EXISTS location TEXT,
    ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS sku TEXT,
    ADD COLUMN IF NOT EXISTS kind TEXT,
    ADD COLUMN IF NOT EXISTS managed_by TEXT,
    ADD COLUMN IF NOT EXISTS parent_resource_id TEXT,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Index for location-based queries
CREATE INDEX IF NOT EXISTS idx_dr_location
ON discovered_resources(organization_id, location)
WHERE location IS NOT NULL;
