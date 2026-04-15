-- Migration 037: Multi-Tenant Cloud Model
-- Enforce Organization → Cloud Connections → Subscriptions hierarchy:
--   cloud_connection_id becomes NOT NULL
--   Unique constraint changes to (cloud_connection_id, account_id)
--   RLS policies on cloud_subscriptions
--   Trigger to auto-sync organization_id from cloud_connections

-- 1a. Backfill cloud_connection_id from matching org+cloud connections
UPDATE cloud_subscriptions s
SET cloud_connection_id = (
    SELECT c.id FROM cloud_connections c
    WHERE c.organization_id = s.organization_id AND c.cloud = s.cloud
    ORDER BY c.created_at ASC LIMIT 1
)
WHERE s.cloud_connection_id IS NULL AND s.deleted = false;

-- 1b. Soft-delete any subscriptions that STILL have NULL cloud_connection_id
--     (no matching connection exists — these are truly orphaned)
UPDATE cloud_subscriptions
SET deleted = true, deleted_at = NOW(), status = 'archived'
WHERE cloud_connection_id IS NULL AND deleted = false;

-- 1c. Make cloud_connection_id NOT NULL (only non-deleted rows matter)
-- Note: deleted rows may still have NULL; we handle this by setting a default
-- or backfilling them too. For safety, backfill deleted rows with 0 first.
UPDATE cloud_subscriptions SET cloud_connection_id = 0
WHERE cloud_connection_id IS NULL AND deleted = true;

ALTER TABLE cloud_subscriptions
  ALTER COLUMN cloud_connection_id SET NOT NULL;

-- 1d. Drop old unique constraint, add new per-connection constraint
ALTER TABLE cloud_subscriptions
  DROP CONSTRAINT IF EXISTS cloud_subscriptions_organization_id_cloud_account_id_key;
ALTER TABLE cloud_subscriptions
  ADD CONSTRAINT uq_connection_account
  UNIQUE (cloud_connection_id, account_id);

-- 1e. Add index on cloud_connection_id for FK lookups
CREATE INDEX IF NOT EXISTS idx_cloud_subs_connection
  ON cloud_subscriptions(cloud_connection_id);

-- 1f. Enable RLS on cloud_subscriptions
ALTER TABLE cloud_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_subscriptions FORCE ROW LEVEL SECURITY;

-- RLS via cloud_connections JOIN (subscriptions inherit org isolation from their connection)
CREATE POLICY sub_strict_sel ON cloud_subscriptions FOR SELECT
  USING (cloud_connection_id IN (
    SELECT id FROM cloud_connections
    WHERE organization_id = current_setting('app.current_organization_id', true)::integer
  ));
CREATE POLICY sub_strict_ins ON cloud_subscriptions FOR INSERT
  WITH CHECK (cloud_connection_id IN (
    SELECT id FROM cloud_connections
    WHERE organization_id = current_setting('app.current_organization_id', true)::integer
  ));
CREATE POLICY sub_strict_upd ON cloud_subscriptions FOR UPDATE
  USING (cloud_connection_id IN (
    SELECT id FROM cloud_connections
    WHERE organization_id = current_setting('app.current_organization_id', true)::integer
  ));
CREATE POLICY sub_strict_del ON cloud_subscriptions FOR DELETE
  USING (cloud_connection_id IN (
    SELECT id FROM cloud_connections
    WHERE organization_id = current_setting('app.current_organization_id', true)::integer
  ));

-- 1g. Trigger to auto-fill organization_id from cloud_connections on INSERT/UPDATE
CREATE OR REPLACE FUNCTION fn_sync_sub_org_id()
RETURNS trigger AS $$
BEGIN
  SELECT organization_id INTO NEW.organization_id
    FROM cloud_connections WHERE id = NEW.cloud_connection_id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sync_sub_org_id ON cloud_subscriptions;
CREATE TRIGGER trg_sync_sub_org_id
  BEFORE INSERT OR UPDATE OF cloud_connection_id ON cloud_subscriptions
  FOR EACH ROW EXECUTE FUNCTION fn_sync_sub_org_id();
