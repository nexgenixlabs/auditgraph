# Trigger Fresh Discovery Scan

## 1. Why This Is Needed

- Lineage verdict engine was fixed (false ORPHANED verdicts for active SPNs)
- Stale discovery data from pre-fix runs still exists in the database
- Dashboard will show inflated ORPHANED counts until a re-scan completes
- Re-scan must complete at least 24 hours before any demo

## 2. Pre-Scan Checklist

- [ ] All code fixes deployed to prod
- [ ] `FEATURE_AI_AGENT_GOVERNANCE` env var set to `true` on backend container
- [ ] `ai_agent_governance` entitlement enabled for target org (see `enable_ai_agent_governance.md`)
- [ ] Confirm no scan is already running:

```sql
SELECT id, status, started_at, completed_at
FROM discovery_runs
WHERE organization_id = <target_org_id>
ORDER BY started_at DESC
LIMIT 5;
```

Expected: most recent run should have `status = 'completed'` (not `running` or `pending`).

## 3. Trigger Manual Scan

Via API (do not hardcode org_id in application code):

```bash
curl -X POST https://api.auditgraph.ai/api/runs/trigger \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"cloud_connection_id": <connection_id>}'
```

Or via the newer discovery endpoint:

```bash
curl -X POST https://api.auditgraph.ai/api/discovery/run \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"connection_id": <connection_id>, "full_refresh": true}'
```

**Note:** The admin token must belong to a user in `<target_org_id>` with `admin` or
`security_admin` role. The org_id is derived from the JWT — it is never passed in
the request body.

## 4. Monitor Scan Progress

```sql
SELECT id, status, started_at, completed_at,
       total_identities
FROM discovery_runs
WHERE organization_id = <target_org_id>
ORDER BY started_at DESC
LIMIT 1;
```

Wait for `status = 'completed'` and `total_identities > 0`.
Typical scan duration: 2-10 minutes depending on tenant size.

## 5. Post-Scan Verification

### Verdict distribution

```sql
SELECT lineage_verdict, COUNT(*)
FROM identities i
JOIN discovery_runs dr ON i.discovery_run_id = dr.id
WHERE dr.organization_id = <target_org_id>
  AND i.deleted_at IS NULL
GROUP BY lineage_verdict
ORDER BY COUNT(*) DESC;
```

Expected:
- ORPHANED count should drop significantly (was ~671, expect <100 for active orgs)
- Active identities should show HEALTHY or AT_RISK, not ORPHANED

### Dashboard verification

- [ ] Navigate to CISO dashboard -- AGIRS score should have shifted after re-computation
- [ ] Navigate to Identity Inventory -- ORPHANED filter count should be lower
- [ ] Spot-check 3-5 previously-ORPHANED SPNs -- should now show HEALTHY or AT_RISK
- [ ] Non-Human Identities page should reflect updated verdict badges

### AGIRS recomputation

The AGIRS score is recomputed automatically at the end of each discovery run.
If it appears stale, verify the agirs_scores table was updated:

```sql
SELECT created_at, agirs_score, hiri_score, nhiri_score, gei_score
FROM agirs_scores
WHERE organization_id = <target_org_id>
ORDER BY created_at DESC
LIMIT 3;
```
