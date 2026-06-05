-- AG-T2.3: security_findings uniqueness for fingerprint upsert.
--
-- security_findings has finding_fingerprint as a text column but no
-- unique constraint, so ON CONFLICT (organization_id, finding_fingerprint)
-- fails. Add one. Idempotent.

\set ON_ERROR_STOP on

BEGIN;

-- Drop duplicate rows first (keep the lowest-id per fingerprint).
DELETE FROM security_findings sf
 WHERE sf.id > (
    SELECT MIN(id) FROM security_findings sf2
     WHERE sf2.organization_id = sf.organization_id
       AND sf2.finding_fingerprint IS NOT NULL
       AND sf2.finding_fingerprint = sf.finding_fingerprint
 )
   AND sf.finding_fingerprint IS NOT NULL;

-- Add the unique constraint (idempotent — DO block catches IF EXISTS)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'security_findings_org_fingerprint_unique'
    ) THEN
        ALTER TABLE security_findings
        ADD CONSTRAINT security_findings_org_fingerprint_unique
            UNIQUE (organization_id, finding_fingerprint);
    END IF;
END $$;

COMMIT;

\echo ''
SELECT conname FROM pg_constraint WHERE conrelid = 'security_findings'::regclass AND contype='u';
