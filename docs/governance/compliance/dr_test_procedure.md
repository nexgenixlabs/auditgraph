# Disaster Recovery Test Execution Procedure — AuditGraph

**Version:** 1.0
**Effective Date:** 2026-03-03
**Owner:** Engineering Lead
**SOC 2 Controls:** A1.2, A1.3 | **HIPAA:** 164.308(a)(7)
**Cadence:** Quarterly (January, April, July, October)

---

## 1. Purpose

This procedure defines the step-by-step process for executing a disaster recovery drill, validating Point-in-Time Recovery (PITR), collecting evidence for compliance audits, and certifying AuditGraph's ability to meet its RPO (< 5 min) and RTO (< 30 min) targets.

## 2. DR Architecture Summary

```
Production                          Recovery
─────────                          ────────
Azure PostgreSQL Flexible Server    Azure PostgreSQL (PITR clone)
├── Continuous WAL archiving        ├── Restored to T-minus-N minutes
├── 35-day backup retention         ├── Read-write validation
├── Automated daily snapshots       └── Tenant isolation verification
│
Azure Container Apps                Azure Container Apps (staging slot)
├── auditgraph-api                  ├── Temporary deployment
├── auditgraph-web                  └── Health check validation
│
Azure Container Registry
└── Tagged images (commit SHA)      → Same images used for recovery
```

## 3. Pre-Drill Preparation

### 3.1 Schedule

| Quarter | Drill Window | Lead | Observer |
|---------|-------------|------|----------|
| Q1 (January) | 2nd Wednesday, 10:00-12:00 UTC | Engineering Lead | Security Lead |
| Q2 (April) | 2nd Wednesday, 10:00-12:00 UTC | On-Call SRE | CTO |
| Q3 (July) | 2nd Wednesday, 10:00-12:00 UTC | Engineering Lead | Compliance Officer |
| Q4 (October) | 2nd Wednesday, 10:00-12:00 UTC | On-Call SRE | Security Lead |

### 3.2 Pre-Drill Checklist

- [ ] Drill window communicated to team (1 week advance notice)
- [ ] Azure subscription has capacity for temporary resources
- [ ] Latest commit SHA for backend/frontend images recorded
- [ ] Current tenant count and sample data noted for validation
- [ ] Evidence collection template prepared (Section 8)
- [ ] Stopwatch/timer ready for RTO measurement

---

## 4. PITR Restore Drill — Step by Step

### Phase 1: Record Baseline (T-0)

**Objective:** Capture current production state for post-restore comparison.

```bash
# 1. Record current time (this becomes the recovery target)
RECOVERY_TARGET=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "Recovery target: $RECOVERY_TARGET"

# 2. Record current tenant count
az postgres flexible-server execute \
  --name auditgraph-db-dev \
  --resource-group auditgraph-dev-rg \
  --admin-user $DB_ADMIN_USER \
  --admin-password $DB_ADMIN_PASSWORD \
  --database-name auditgraph \
  --querytext "SELECT COUNT(*) as tenant_count FROM tenants;"

# 3. Record identity count per tenant (sample)
az postgres flexible-server execute \
  --name auditgraph-db-dev \
  --resource-group auditgraph-dev-rg \
  --admin-user $DB_ADMIN_USER \
  --admin-password $DB_ADMIN_PASSWORD \
  --database-name auditgraph \
  --querytext "
    SELECT t.name, COUNT(i.id) as identity_count
    FROM tenants t
    LEFT JOIN discovery_runs dr ON dr.organization_id = t.id
    LEFT JOIN identities i ON i.discovery_run_id = dr.id
    GROUP BY t.name;
  "

# 4. Record latest activity_log entry (for integrity verification)
az postgres flexible-server execute \
  --name auditgraph-db-dev \
  --resource-group auditgraph-dev-rg \
  --admin-user $DB_ADMIN_USER \
  --admin-password $DB_ADMIN_PASSWORD \
  --database-name auditgraph \
  --querytext "
    SELECT id, action_type, integrity_hash, created_at
    FROM activity_log ORDER BY id DESC LIMIT 1;
  "
```

**Record:** Tenant count, identity counts, latest activity_log ID + hash. Save output as `baseline-YYYY-MM-DD.txt`.

### Phase 2: Initiate PITR Restore (Start RTO Timer)

**Objective:** Create a point-in-time restore of the production database.

```bash
# START RTO TIMER NOW
RTO_START=$(date +%s)

# 5. Create PITR restore (5 minutes before baseline)
RESTORE_TIME=$(date -u -d "$RECOVERY_TARGET - 5 minutes" +"%Y-%m-%dT%H:%M:%SZ")

az postgres flexible-server restore \
  --resource-group auditgraph-dev-rg \
  --name auditgraph-db-dr-drill \
  --source-server auditgraph-db-dev \
  --restore-time "$RESTORE_TIME"

# This takes 5-15 minutes. Monitor progress:
az postgres flexible-server show \
  --name auditgraph-db-dr-drill \
  --resource-group auditgraph-dev-rg \
  --query "state" -o tsv
```

**Expected:** Server state transitions from `Creating` to `Ready` within 15 minutes.

### Phase 3: Validate Restored Database

**Objective:** Verify data integrity, tenant isolation, and completeness.

```bash
# 6. Connect to restored database and verify tenant count
az postgres flexible-server execute \
  --name auditgraph-db-dr-drill \
  --resource-group auditgraph-dev-rg \
  --admin-user $DB_ADMIN_USER \
  --admin-password $DB_ADMIN_PASSWORD \
  --database-name auditgraph \
  --querytext "SELECT COUNT(*) as tenant_count FROM tenants;"

# 7. Verify identity counts match baseline
az postgres flexible-server execute \
  --name auditgraph-db-dr-drill \
  --resource-group auditgraph-dev-rg \
  --admin-user $DB_ADMIN_USER \
  --admin-password $DB_ADMIN_PASSWORD \
  --database-name auditgraph \
  --querytext "
    SELECT t.name, COUNT(i.id) as identity_count
    FROM tenants t
    LEFT JOIN discovery_runs dr ON dr.organization_id = t.id
    LEFT JOIN identities i ON i.discovery_run_id = dr.id
    GROUP BY t.name;
  "

# 8. Verify RLS policies are intact
az postgres flexible-server execute \
  --name auditgraph-db-dr-drill \
  --resource-group auditgraph-dev-rg \
  --admin-user $DB_ADMIN_USER \
  --admin-password $DB_ADMIN_PASSWORD \
  --database-name auditgraph \
  --querytext "
    SELECT relname, relrowsecurity, relforcerowsecurity
    FROM pg_class
    WHERE relname IN (
      SELECT tablename FROM pg_tables WHERE schemaname = 'public'
    )
    AND relrowsecurity = true
    ORDER BY relname;
  "

# 9. Verify FORCE RLS on all expected tables
az postgres flexible-server execute \
  --name auditgraph-db-dr-drill \
  --resource-group auditgraph-dev-rg \
  --admin-user $DB_ADMIN_USER \
  --admin-password $DB_ADMIN_PASSWORD \
  --database-name auditgraph \
  --querytext "
    SELECT relname
    FROM pg_class
    WHERE relname IN (
      SELECT tablename FROM pg_tables WHERE schemaname = 'public'
    )
    AND relrowsecurity = true AND relforcerowsecurity = false;
  "
  # Expected: 0 rows (all RLS tables should also have FORCE)

# 10. Verify activity_log integrity hash chain
az postgres flexible-server execute \
  --name auditgraph-db-dr-drill \
  --resource-group auditgraph-dev-rg \
  --admin-user $DB_ADMIN_USER \
  --admin-password $DB_ADMIN_PASSWORD \
  --database-name auditgraph \
  --querytext "
    SELECT id, integrity_hash, created_at
    FROM activity_log ORDER BY id DESC LIMIT 5;
  "

# 11. Verify immutable trigger exists
az postgres flexible-server execute \
  --name auditgraph-db-dr-drill \
  --resource-group auditgraph-dev-rg \
  --admin-user $DB_ADMIN_USER \
  --admin-password $DB_ADMIN_PASSWORD \
  --database-name auditgraph \
  --querytext "
    SELECT tgname, tgenabled
    FROM pg_trigger
    WHERE tgname = 'trg_activity_log_immutable';
  "
```

### Phase 4: Deploy Application Against Restored DB

**Objective:** Verify the application starts and serves traffic with the restored database.

```bash
# 12. Deploy temporary backend pointing to restored DB
az containerapp create \
  --name auditgraph-api-dr-drill \
  --resource-group auditgraph-dev-rg \
  --environment auditgraph-env \
  --image $ACR_LOGIN_SERVER/auditgraph-backend:latest \
  --min-replicas 1 --max-replicas 1 \
  --env-vars \
    DB_HOST=auditgraph-db-dr-drill.postgres.database.azure.com \
    DB_PORT=5432 \
    DB_NAME=auditgraph \
    DB_USER=$DB_USER \
    DB_PASSWORD=$DB_PASSWORD \
    DB_ADMIN_USER=$DB_ADMIN_USER \
    DB_ADMIN_PASSWORD=$DB_ADMIN_PASSWORD \
    DB_SSLMODE=require \
    FLASK_ENV=production \
    APP_ENV=prod

# 13. Wait for readiness
DR_URL=$(az containerapp show --name auditgraph-api-dr-drill \
  --resource-group auditgraph-dev-rg \
  --query properties.configuration.ingress.fqdn -o tsv)

for i in $(seq 1 12); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$DR_URL/health/ready")
  if [ "$STATUS" = "200" ]; then
    echo "DR backend ready after $((i * 10))s"
    break
  fi
  echo "  Attempt $i: HTTP $STATUS"
  sleep 10
done

# STOP RTO TIMER
RTO_END=$(date +%s)
RTO_SECONDS=$((RTO_END - RTO_START))
echo "RTO: ${RTO_SECONDS}s (target: <1800s)"

# 14. Verify health endpoint
curl -s "https://$DR_URL/api/health" | python3 -m json.tool

# 15. Verify API responds with correct data
curl -s "https://$DR_URL/api/stats" \
  -H "Authorization: Bearer $TEST_TOKEN" | python3 -m json.tool
```

### Phase 5: Cleanup

```bash
# 16. Delete DR drill resources
az containerapp delete \
  --name auditgraph-api-dr-drill \
  --resource-group auditgraph-dev-rg \
  --yes

az postgres flexible-server delete \
  --name auditgraph-db-dr-drill \
  --resource-group auditgraph-dev-rg \
  --yes
```

---

## 5. Validation Checklist

Complete this checklist during each drill. All items must pass for the drill to be certified.

### Data Integrity
- [ ] Tenant count matches baseline (±0)
- [ ] Identity count per tenant matches baseline (±0 for restore point)
- [ ] Latest `activity_log` entries present and consistent
- [ ] `integrity_hash` chain intact on restored activity_log

### Security Controls
- [ ] All 44 RLS tables have `relrowsecurity = true`
- [ ] All 44 RLS tables have `relforcerowsecurity = true` (0 exceptions)
- [ ] `trg_activity_log_immutable` trigger exists and is enabled
- [ ] `auditgraph_app` user has NOBYPASSRLS on restored server
- [ ] `auditgraph_admin` user has BYPASSRLS on restored server

### Application Health
- [ ] `/health` returns 200 (liveness)
- [ ] `/health/ready` returns 200 (readiness — no migration in progress)
- [ ] `/api/health` returns 200 with DB connectivity confirmed
- [ ] `/api/stats` returns valid data with correct tenant scoping

### Recovery Metrics
- [ ] RPO achieved: data loss < 5 minutes from recovery target
- [ ] RTO achieved: total recovery time < 30 minutes
- [ ] No cross-tenant data leakage in restored instance

---

## 6. Failure Scenarios

If the drill fails at any step, document the failure and continue:

| Failure | Action | Escalation |
|---------|--------|------------|
| PITR restore times out | Retry with different restore point | Azure Support ticket |
| Tenant count mismatch | Check WAL archiving status | Security Lead |
| RLS policies missing | Check if migration ran on restore | Engineering Lead + P1 incident |
| App fails to start | Check DB connectivity, env vars | On-Call SRE |
| RTO exceeds 30 min | Document actual time, identify bottleneck | Engineering Lead |

---

## 7. RPO Verification

To verify RPO < 5 minutes:

1. Before drill: insert a test activity_log entry with known content at T-0
2. Restore to T-minus-5-minutes
3. Verify the test entry is NOT present (correct — it was after the restore point)
4. Insert another test entry at T-minus-6-minutes
5. Restore to T-minus-5-minutes
6. Verify that entry IS present (within RPO window)

```sql
-- Insert test marker (before restore)
INSERT INTO activity_log (action_type, description, organization_id, user_id)
VALUES ('dr_drill_marker', 'DR drill RPO test marker - YYYY-MM-DD', 1, 1);
```

---

## 8. Evidence Collection

After each drill, collect and store the following artifacts:

### 8.1 Evidence Checklist

- [ ] `baseline-YYYY-MM-DD.txt` — pre-drill production state
- [ ] `restore-YYYY-MM-DD.txt` — post-restore validation output
- [ ] `rto-measurement-YYYY-MM-DD.txt` — timer start/stop with calculated duration
- [ ] `validation-checklist-YYYY-MM-DD.pdf` — completed checklist (signed by drill lead + observer)
- [ ] `health-check-YYYY-MM-DD.json` — API health response from restored instance
- [ ] Screenshot of restored `/api/health` endpoint response

### 8.2 Evidence Storage

Store all evidence in:
```
docs/compliance/dr-evidence/
├── 2026-Q1/
│   ├── baseline.txt
│   ├── restore-validation.txt
│   ├── rto-measurement.txt
│   ├── checklist-signed.pdf
│   └── notes.md
├── 2026-Q2/
│   └── ...
```

### 8.3 Drill Report Template

```markdown
# DR Drill Report — YYYY-QN

**Date:** YYYY-MM-DD
**Drill Lead:** [Name]
**Observer:** [Name]
**Duration:** [Start time] - [End time]

## Results

| Metric | Target | Actual | Pass/Fail |
|--------|--------|--------|-----------|
| RPO | < 5 min | X min | PASS/FAIL |
| RTO | < 30 min | X min | PASS/FAIL |
| Data integrity | 100% | X% | PASS/FAIL |
| RLS intact | All 44 tables | X/44 | PASS/FAIL |
| Hash chain intact | Yes | Yes/No | PASS/FAIL |

## Issues Found
- [List any issues encountered]

## Action Items
- [ ] [Any follow-up tasks with owner and deadline]

## Certification
I certify that this DR drill was conducted according to procedure and the results
are accurately recorded.

Drill Lead: _________________ Date: _________
Observer:    _________________ Date: _________
```

---

## 9. Quarterly Calendar

| Month | Activity | Owner |
|-------|----------|-------|
| January | Q1 DR drill | Engineering Lead |
| February | Review Q1 results, action items | Security Lead |
| March | Update procedure if needed | Engineering Lead |
| April | Q2 DR drill | On-Call SRE |
| May | Review Q2 results, action items | Security Lead |
| June | Mid-year compliance evidence package | Compliance Officer |
| July | Q3 DR drill | Engineering Lead |
| August | Review Q3 results, action items | Security Lead |
| September | Update procedure if needed | Engineering Lead |
| October | Q4 DR drill | On-Call SRE |
| November | Review Q4 results, action items | Security Lead |
| December | Annual DR procedure review + SOC 2 evidence prep | Security Lead |

---

## 10. Related Documents

| Document | Purpose |
|----------|---------|
| `incident_response_plan.md` | IR workflow triggered by failed DR drill |
| `information_security_policy.md` | Parent security policy (Section 6.2) |
| `compliance_matrix.md` | SOC 2/HIPAA control mapping |
| `config.py` | Production hardening blueprint with DR architecture |
