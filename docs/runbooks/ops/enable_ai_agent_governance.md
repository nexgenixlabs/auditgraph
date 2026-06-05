# Enable AI Agent Governance Feature Flag

## 1. Check Current Flag State

```sql
SELECT organization_id, feature_key, enabled, granted_at, expires_at, reason
FROM organization_entitlements
WHERE feature_key = 'ai_agent_governance'
ORDER BY granted_at DESC;
```

## 2. Enable for a Specific Organization

Replace `<target_org_id>` with the actual organization ID. Never hardcode org IDs in application code.

```sql
UPDATE organization_entitlements
SET enabled = true, granted_at = now()
WHERE feature_key = 'ai_agent_governance'
AND organization_id = <target_org_id>;
```

**Note:** The global kill switch is the `FEATURE_AI_AGENT_GOVERNANCE` env var on the backend
container. If this is `false` (production default), the `/api/tenant/config` endpoint
returns `feature_flags.ai_agent_governance: false` regardless of the DB row. To enable:

```bash
# Set env var on the backend container (Azure Container Apps)
az containerapp update \
  --name auditgraph-api \
  --resource-group auditgraph-dev-rg \
  --set-env-vars FEATURE_AI_AGENT_GOVERNANCE=true
```

## 3. Verify After Enabling

```sql
SELECT feature_key, enabled, expires_at
FROM organization_entitlements
WHERE feature_key = 'ai_agent_governance'
AND organization_id = <target_org_id>;
```

Expected: `enabled = true`, `expires_at` is NULL or in the future.

Also verify the env var is active:

```bash
curl -s -H "Authorization: Bearer <admin_token>" \
  https://api.auditgraph.ai/api/tenant/config | jq '.feature_flags'
```

Expected: `{ "ai_agent_governance": true }`

## 4. If Row Does Not Exist (Flag Never Initialized)

```sql
INSERT INTO organization_entitlements (organization_id, feature_key, enabled, reason)
VALUES (<target_org_id>, 'ai_agent_governance', true, 'Manual enable via runbook')
ON CONFLICT (organization_id, feature_key)
DO UPDATE SET enabled = true, granted_at = now(), reason = 'Manual enable via runbook';
```

## 5. Post-Enable Smoke Test

After enabling both the env var AND the DB entitlement:

- [ ] Navigate to CISO dashboard at `/` -- AI Agents tile should be visible
- [ ] Navigate to sidebar -- "AI Agents" entry should appear under "Identity Truth" group, after "Non-Human Identities"
- [ ] Click "AI Agents" -- navigates to `/identities?filter=ai_agent`
- [ ] AI Agent identities should load in the filtered identity list
- [ ] AI Agent filter pill should appear in the Identities page filter bar
- [ ] Agent count badge should show a non-zero value
