-- Migration 036: Demo Tenant System
-- Adds is_demo flag to organizations for demo environment support.

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS is_demo BOOLEAN DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_org_is_demo ON organizations(is_demo) WHERE is_demo = true;
