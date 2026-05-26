# Week 3-4 Quick Reference

## 🎯 Quick Stats

| Metric | Value |
|--------|-------|
| **Status** | ✅ COMPLETE |
| **Time Spent** | 8 hours (6 sessions) |
| **Lines of Code** | ~2,000+ |
| **Noise Reduction** | 99% (181 → 9) |
| **API Endpoints** | 7 |
| **Database Tables** | 3 + 2 views |
| **Discovery Runs** | 5 |
| **Azure Cost** | ~$15/month |

---

## 🚀 How to Run Discovery
```bash
# 1. Navigate to backend
cd ~/projects/auditgraph/backend

# 2. Activate virtual environment
source venv/bin/activate

# 3. Run discovery (with auto-save and drift detection)
python app/test_discovery.py
```

**Expected Output:**
```
📋 Discovering Service Principals...
  Found 188 service principals
⚠️  Calculating Risk Levels...
  🚨 4 critical risks
🔑 Checking Credential Expiration...
  ✓ All valid 30+ days
🕐 Checking Last Activity...
  ⚪ No sign-in data: 9
💾 Saving to database...
  ✓ Run #5 created
🔄 Drift Detection...
  ✅ No changes detected
```

---

## 🗄️ Database Commands

### Connect to PostgreSQL
```bash
# Using psql
psql -h xxxxxx-db-dev.postgres.database.azure.com \
     -U auditgraph_admin \
     -d xxxxxx \
     -p 5432

# Password: Axxxxxxx
```

### Quick Queries
```sql
-- Get all discovery runs
SELECT id, started_at, status, total_identities, critical_count 
FROM discovery_runs 
ORDER BY id DESC;

-- Get latest identities
SELECT display_name, risk_level, credential_status, activity_status
FROM identities 
WHERE discovery_run_id = (SELECT MAX(id) FROM discovery_runs WHERE status = 'completed')
ORDER BY risk_level;

-- Get critical risks
SELECT display_name, risk_reasons 
FROM v_critical_identities;

-- Get drift between last two runs
-- (Use drift detector instead)
```

### Backup/Restore
```bash
# Backup database
pg_dump -h xxxx-db-dev.postgres.database.azure.com \
        -U auditgraph_admin -d auditgraph > backup.sql

# Restore database
psql -h xxx-db-dev.postgres.database.azure.com \
     -U auditgraph_admin -d auditgraph < backup.sql
```

---

## 🔌 API Commands

### Start API Server
```bash
cd ~/projects/auditgraph/backend
source venv/bin/activate
python app/api.py

# API available at: http://localhost:5001
```

### Test Endpoints
```bash
# Health check
curl http://localhost:5001/api/health

# Get all identities
curl http://localhost:5001/api/identities | python3 -m json.tool

# Get critical risks
curl http://localhost:5001/api/risks | python3 -m json.tool

# Get specific identity
curl http://localhost:5001/api/identities/ee1c8a8e-440f-45cf-bda6-57303bcacd16

# Get discovery runs
curl http://localhost:5001/api/runs | python3 -m json.tool

# Get drift report
curl http://localhost:5001/api/drift/5 | python3 -m json.tool

# Get stats
curl http://localhost:5001/api/stats | python3 -m json.tool
```

---

## 🧪 Test Drift Detection
```bash
# Run standalone drift detector
python app/test_drift.py

# Expected output:
# Comparing: Run #5 vs Run #4
# ✅ No changes detected - environment is stable
```

---

## 📁 Key Files

| File | Purpose | Lines |
|------|---------|-------|
| `app/engines/discovery/azure_discovery.py` | Main discovery engine | 500+ |
| `app/database.py` | Database operations | 200+ |
| `app/engines/drift_detector.py` | Change detection | 200+ |
| `app/api.py` | REST API | 300+ |
| `app/engines/discovery/credential_checker.py` | Credential monitoring | 150+ |
| `app/engines/discovery/activity_tracker.py` | Activity tracking | 150+ |
| `app/engines/discovery/models.py` | Data models | 200+ |
| `database_schema.sql` | DB schema | 200+ |

---

## 🔑 Environment Variables
```bash
# Azure Credentials (.env)
AZURE_TENANT_ID=xxxxx-23b8-xxxx-9d9e-1802369217af
AZURE_CLIENT_ID=xxxxx-40cc-xxxx-935b-04f822b269a0
AZURE_CLIENT_SECRET=REPLACE_ME
AZURE_SUBSCRIPTION_ID=xxxxx-6a21-4b79-xxxx-1e3976b58a33

# Database Configuration (.env)
DB_HOST=auditgraph-db-dev.postgres.database.azure.com
DB_PORT=5432
DB_NAME=xxxxxx
DB_USER=REPLACE_ME
DB_PASSWORD=REPLACE_ME
```

---

## 📊 Current State

### Discovery Run #5 (Latest)

| Metric | Value |
|--------|-------|
| Total Identities | 188 |
| Microsoft System | 179 (filtered) |
| Custom Identities | 9 |
| Critical Risks | 4 |
| High Risks | 0 |
| Medium Risks | 2 |
| Credentials Status | All valid 30+ days |
| Activity Status | No recent sign-ins |

### Critical Identities

| Name | Risk | Reason |
|------|------|--------|
| spn-overprivileged-owner | 🔴 Critical | Owner on subscription |
| spn-user-access-admin | 🔴 Critical | User Access Admin on subscription |
| spn-contributor-sub | 🔴 Critical | Contributor on subscription |
| spn-auditgraph-admin | 🔴 Critical | Owner on subscription |

### Database Stats

| Metric | Value |
|--------|-------|
| Discovery Runs | 5 |
| Identities Tracked | 45 |
| Role Assignments | 35 |
| Database Size | <10 MB |

---

## 🔧 Azure Resources

### PostgreSQL Server
```bash
# Server details
Name: auditgraph-db-dev
Location: Central US
SKU: Standard_B1ms
Version: PostgreSQL 14
Database: auditgraph

# Get connection string
az postgres flexible-server show \
  --name auditgraph-db-dev \
  --resource-group auditgraph-dev-rg
```

### Permissions Granted
```bash
# Service Principal: spn-auditgraph-discovery
Permissions:
  - Directory.Read.All (Azure AD)
  - Application.Read.All (Microsoft Graph)
  - AuditLog.Read.All (Microsoft Graph)
```

---

## 🐛 Troubleshooting

### Issue: "Module not found"
```bash
# Solution: Activate venv
cd ~/projects/auditgraph/backend
source venv/bin/activate
```

### Issue: "Database connection failed"
```bash
# Solution 1: Check firewall rules
az postgres flexible-server firewall-rule list \
  --name auditgraph-db-dev \
  --resource-group auditgraph-dev-rg

# Solution 2: Add your IP
az postgres flexible-server firewall-rule create \
  --resource-group auditgraph-dev-rg \
  --name auditgraph-db-dev \
  --rule-name AllowMyIP \
  --start-ip-address $(curl -4 -s ifconfig.me) \
  --end-ip-address $(curl -4 -s ifconfig.me)
```

### Issue: "API port already in use"
```bash
# Solution: Use different port
# Edit app/api.py line: app.run(port=5002)
# Or kill process on port 5001:
lsof -ti:5001 | xargs kill -9
```

### Issue: "Permission denied (Graph API)"
```bash
# Solution: Check permissions
az ad app permission list --id b29a04cb-40cc-4e26-935b-04f822b269a0

# Grant permissions if missing
az ad app permission add --id b29a04cb-40cc-4e26-935b-04f822b269a0 \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role

az ad app permission admin-consent --id b29a04cb-40cc-4e26-935b-04f822b269a0
```

---

## 📦 Dependencies
```bash
# Install all dependencies
pip install -r requirements.txt

# Key packages:
# - azure-identity
# - azure-mgmt-authorization
# - azure-mgmt-msi
# - psycopg2-binary
# - flask
# - flask-cors
# - requests
```

---

## 🔄 Git Commands
```bash
# Check status
git status

# Commit changes
git add .
git commit -m "Week 3-4: Description"
git push origin main

# View history
git log --oneline --graph --decorate

# View Week 3-4 commits
git log --since="2026-01-23" --oneline
```

---

## 📈 Performance Benchmarks

| Operation | Time |
|-----------|------|
| Discovery (188 identities) | ~5 seconds |
| Credential check (9 SPNs) | ~3 seconds |
| Activity check (9 SPNs) | ~2 seconds |
| Database save | ~1 second |
| Drift detection | <1 second |
| **Total Run Time** | **~10 seconds** |

| API Endpoint | Response Time |
|--------------|---------------|
| /api/health | <10ms |
| /api/identities | <100ms |
| /api/risks | <50ms |
| /api/runs | <100ms |
| /api/drift/<id> | <200ms |
| /api/stats | <50ms |

---

## 💰 Cost Breakdown

| Resource | Monthly Cost |
|----------|--------------|
| PostgreSQL Flexible Server (Standard_B1ms) | ~$10-15 |
| Storage (<10 MB) | <$1 |
| Network egress | <$1 |
| **Total** | **~$12-17** |

---

## 🎯 Quick Commands
```bash
# Full discovery + drift
python app/test_discovery.py

# Just drift detection
python app/test_drift.py

# Start API
python app/api.py

# Database query
python -c "from app.database import Database; db = Database(); print('Connected')"

# Check last run
python -c "from app.database import Database; db=Database(); print(db.get_latest_discovery_run())"
```

---

## 📚 Useful Links

**Documentation:**
- [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/overview)
- [Azure PostgreSQL](https://learn.microsoft.com/en-us/azure/postgresql/)
- [Flask Docs](https://flask.palletsprojects.com/)

**Internal Docs:**
- [Week 1-2 Summary](../week-1-2/WEEK-1-2-SUMMARY.md)
- [Week 3-4 Summary](WEEK-3-4-SUMMARY.md)
- [Lessons Learned](LESSONS-LEARNED.md)

**GitHub:**
- [Repository](https://github.com/AuditGraph/auditgraph)

---

## 🎓 Common Tasks

### Add New Discovery

1. Run discovery: `python app/test_discovery.py`
2. Check database: Query `discovery_runs` table
3. View drift: Automatic in output
4. Check via API: `curl http://localhost:5001/api/runs`

### Debug Discovery Issues

1. Check logs in terminal output
2. Verify Azure credentials: `az account show`
3. Test Graph API access: `az rest --method GET --url "https://graph.microsoft.com/v1.0/applications"`
4. Check database connection: Run query command above

### Update Database Schema

1. Modify `database_schema.sql`
2. Drop tables: `DROP TABLE role_assignments, identities, discovery_runs CASCADE;`
3. Recreate: `python apply_schema.py`
4. Re-run discovery to populate

---

**Last Updated:** January 23, 2026  
**Status:** Current  
**Next Update:** Week 5-6
