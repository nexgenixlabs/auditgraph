-- Migration 077: Add last_service_principal_sign_in to agent_classifications
--
-- Stores the most recent sign-in timestamp from servicePrincipalSignIns
-- (Azure AD audit logs). This is separate from identities.last_sign_in which
-- only tracks interactive/delegated logins.
--
-- AI agents using client credentials (client_id + secret/cert) authenticate
-- via the service principal sign-in flow, which does NOT populate
-- lastSignInDateTime. Without this column, active agents are falsely
-- flagged as orphaned by the IASM-AG-001 detector.
--
-- Required Graph API permission: AuditLog.Read.All
--
-- UP:
ALTER TABLE agent_classifications
    ADD COLUMN IF NOT EXISTS last_service_principal_sign_in TIMESTAMPTZ;

-- DOWN (reverse migration):
-- ALTER TABLE agent_classifications
--     DROP COLUMN IF EXISTS last_service_principal_sign_in;
