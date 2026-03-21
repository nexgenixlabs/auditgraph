BEGIN;

-- ── Step 1: Lowercase all identity_type values ──────────────────────

UPDATE identities
SET identity_type = LOWER(identity_type)
WHERE identity_type != LOWER(identity_type);

UPDATE identity_risk_scores
SET identity_type = LOWER(identity_type)
WHERE identity_type != LOWER(identity_type);

UPDATE blast_radius_results
SET identity_type = LOWER(identity_type)
WHERE identity_type != LOWER(identity_type);

UPDATE campaign_reviews
SET identity_type = LOWER(identity_type)
WHERE identity_type != LOWER(identity_type);

UPDATE review_assignments
SET identity_type = LOWER(identity_type)
WHERE identity_type != LOWER(identity_type);

-- ── Step 2: Map PascalCase remnants to canonical snake_case ─────────
-- LOWER('ServicePrincipal') = 'serviceprincipal' → 'service_principal'
-- LOWER('ManagedIdentity')  = 'managedidentity'  → use identity_category

-- identities: serviceprincipal → service_principal
UPDATE identities SET identity_type = 'service_principal'
WHERE identity_type = 'serviceprincipal';

-- identities: managedidentity → pull from identity_category if valid
UPDATE identities SET identity_type = identity_category
WHERE identity_type = 'managedidentity'
  AND identity_category IN ('managed_identity_system', 'managed_identity_user');

-- identities: managedidentity fallback → managed_identity_system
UPDATE identities SET identity_type = 'managed_identity_system'
WHERE identity_type = 'managedidentity';

-- identity_risk_scores
UPDATE identity_risk_scores SET identity_type = 'service_principal'
WHERE identity_type = 'serviceprincipal';

UPDATE identity_risk_scores SET identity_type = 'managed_identity'
WHERE identity_type = 'managedidentity';

-- blast_radius_results, campaign_reviews, review_assignments (same pattern)
UPDATE blast_radius_results SET identity_type = 'service_principal'
WHERE identity_type = 'serviceprincipal';

UPDATE blast_radius_results SET identity_type = 'managed_identity'
WHERE identity_type = 'managedidentity';

UPDATE campaign_reviews SET identity_type = 'service_principal'
WHERE identity_type = 'serviceprincipal';

UPDATE campaign_reviews SET identity_type = 'managed_identity'
WHERE identity_type = 'managedidentity';

UPDATE review_assignments SET identity_type = 'service_principal'
WHERE identity_type = 'serviceprincipal';

UPDATE review_assignments SET identity_type = 'managed_identity'
WHERE identity_type = 'managedidentity';

-- ── Verify ──────────────────────────────────────────────────────────

DO $$
DECLARE
  bad_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO bad_count
  FROM identities
  WHERE identity_type IN ('serviceprincipal', 'ServicePrincipal',
                          'managedidentity', 'ManagedIdentity', 'User');

  IF bad_count > 0 THEN
    RAISE EXCEPTION 'identities: still % rows with non-canonical type', bad_count;
  END IF;

  SELECT COUNT(*) INTO bad_count
  FROM identity_risk_scores
  WHERE identity_type IN ('serviceprincipal', 'ServicePrincipal',
                          'managedidentity', 'ManagedIdentity', 'User');

  IF bad_count > 0 THEN
    RAISE EXCEPTION 'identity_risk_scores: still % rows with non-canonical type', bad_count;
  END IF;
END $$;

INSERT INTO schema_migrations (version, description)
VALUES ('073', 'Normalize identity_type to lowercase snake_case in all tables')
ON CONFLICT (version) DO NOTHING;

COMMIT;
