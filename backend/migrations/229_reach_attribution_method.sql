-- 229_reach_attribution_method.sql
-- 2026-06-13  ·  AG-193 Sprint B tightening
--
-- Track HOW we attributed reach to an AI model deployment so the UI can
-- explain the confidence honestly:
--
--   'mi_principal_id'  — strongest: matched on the parent account's
--                        system-assigned MI principal_id (needs
--                        discovery-time capture; reserved for next iter).
--   'name_match'       — heuristic: account_name == identity.display_name
--                        where identity is a managed_identity_system in
--                        the same org. Reliable when Azure auto-created
--                        the system MI (Azure uses the resource name).
--   'rbac_upper_bound' — fallback: max reach among identities with any
--                        role assignment on the AI account. Soft upper
--                        bound; over-estimates when humans have roles.
--   'unresolved'       — no linkage found; reach left null.

ALTER TABLE azure_ai_model_deployments
  ADD COLUMN IF NOT EXISTS reach_attribution_method text;
