-- Migration 075: Remove stale remediation entries for Microsoft/system identities
-- These should never have been generated — the is_microsoft_system filter was missing
-- from the remediation generation queries. This is a one-time cleanup.

-- 1. Remove generated_remediations linked to Microsoft system identities
DELETE FROM generated_remediations
WHERE identity_id IN (
    SELECT DISTINCT i.identity_id
    FROM identities i
    WHERE COALESCE(i.is_microsoft_system, FALSE) = TRUE
);

-- 2. Remove remediation_actions linked to Microsoft system identities
DELETE FROM remediation_actions
WHERE identity_id IN (
    SELECT DISTINCT i.identity_id
    FROM identities i
    WHERE COALESCE(i.is_microsoft_system, FALSE) = TRUE
);

-- 3. Remove soar_actions linked to Microsoft system identities
DELETE FROM soar_actions
WHERE identity_id IN (
    SELECT DISTINCT i.identity_id
    FROM identities i
    WHERE COALESCE(i.is_microsoft_system, FALSE) = TRUE
);
