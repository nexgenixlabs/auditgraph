-- Schema alignment: RLS policies on AI/agent tables read `app.current_tenant_id`,
-- but the runtime Database class only sets `app.current_organization_id`.
-- Result: every query from auditgraph_app to those tables returns 0 rows,
-- even though the data exists.
--
-- Fix: switch the policies to read `app.current_organization_id`. This is
-- the variable the runtime guarantees, and it's the variable the majority
-- of policies in the codebase already use.
--
-- Affected tables (from cloud schema audit):
--   ai_agent_lifecycle_events
--   agent_data_reachability
--   agent_activity_events
--   agent_behavior_anomalies
--
-- Idempotent: DROP IF EXISTS + CREATE.

\set ON_ERROR_STOP on

BEGIN;

-- ai_agent_lifecycle_events
DROP POLICY IF EXISTS tenant_strict_sel ON ai_agent_lifecycle_events;
DROP POLICY IF EXISTS tenant_strict_ins ON ai_agent_lifecycle_events;
DROP POLICY IF EXISTS tenant_strict_upd ON ai_agent_lifecycle_events;
DROP POLICY IF EXISTS tenant_strict_del ON ai_agent_lifecycle_events;
CREATE POLICY tenant_strict_sel ON ai_agent_lifecycle_events FOR SELECT
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_ins ON ai_agent_lifecycle_events FOR INSERT
  WITH CHECK (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_upd ON ai_agent_lifecycle_events FOR UPDATE
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_del ON ai_agent_lifecycle_events FOR DELETE
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);

-- agent_data_reachability
DROP POLICY IF EXISTS tenant_strict_sel ON agent_data_reachability;
DROP POLICY IF EXISTS tenant_strict_ins ON agent_data_reachability;
DROP POLICY IF EXISTS tenant_strict_upd ON agent_data_reachability;
DROP POLICY IF EXISTS tenant_strict_del ON agent_data_reachability;
CREATE POLICY tenant_strict_sel ON agent_data_reachability FOR SELECT
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_ins ON agent_data_reachability FOR INSERT
  WITH CHECK (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_upd ON agent_data_reachability FOR UPDATE
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_del ON agent_data_reachability FOR DELETE
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);

-- agent_activity_events
DROP POLICY IF EXISTS tenant_strict_sel ON agent_activity_events;
DROP POLICY IF EXISTS tenant_strict_ins ON agent_activity_events;
DROP POLICY IF EXISTS tenant_strict_upd ON agent_activity_events;
DROP POLICY IF EXISTS tenant_strict_del ON agent_activity_events;
CREATE POLICY tenant_strict_sel ON agent_activity_events FOR SELECT
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_ins ON agent_activity_events FOR INSERT
  WITH CHECK (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_upd ON agent_activity_events FOR UPDATE
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_del ON agent_activity_events FOR DELETE
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);

-- agent_behavior_anomalies
DROP POLICY IF EXISTS tenant_strict_sel ON agent_behavior_anomalies;
DROP POLICY IF EXISTS tenant_strict_ins ON agent_behavior_anomalies;
DROP POLICY IF EXISTS tenant_strict_upd ON agent_behavior_anomalies;
DROP POLICY IF EXISTS tenant_strict_del ON agent_behavior_anomalies;
CREATE POLICY tenant_strict_sel ON agent_behavior_anomalies FOR SELECT
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_ins ON agent_behavior_anomalies FOR INSERT
  WITH CHECK (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_upd ON agent_behavior_anomalies FOR UPDATE
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);
CREATE POLICY tenant_strict_del ON agent_behavior_anomalies FOR DELETE
  USING (organization_id = (current_setting('app.current_organization_id', true))::integer);

COMMIT;

\echo ''
SELECT tablename, policyname, qual
FROM pg_policies
WHERE schemaname='public'
  AND tablename IN ('ai_agent_lifecycle_events','agent_data_reachability','agent_activity_events','agent_behavior_anomalies')
  AND policyname LIKE 'tenant_strict_%'
ORDER BY tablename, policyname;
