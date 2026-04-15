-- Performance index for get_inventory_summary() JOIN pattern
-- Covers: cloud_connection_id + organization_id WHERE deleted = false
CREATE INDEX IF NOT EXISTS idx_cs_conn_org_active
ON cloud_subscriptions(cloud_connection_id, organization_id)
WHERE deleted = false;
