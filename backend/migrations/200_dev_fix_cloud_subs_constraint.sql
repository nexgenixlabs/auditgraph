-- Dev-only patch: handlers.py uses ON CONFLICT (organization_id, cloud, account_id)
-- on cloud_subscriptions, but Python DDL only declares UNIQUE(cloud_connection_id, account_id).
-- Local sandbox has both constraints by historical accident; fresh cloud DB needs this one explicitly.

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'cloud_subs_org_cloud_account_uq'
  ) THEN
    ALTER TABLE cloud_subscriptions
      ADD CONSTRAINT cloud_subs_org_cloud_account_uq
      UNIQUE (organization_id, cloud, account_id);
    RAISE NOTICE 'Added cloud_subs_org_cloud_account_uq';
  ELSE
    RAISE NOTICE 'cloud_subs_org_cloud_account_uq already exists';
  END IF;
END
$$;
