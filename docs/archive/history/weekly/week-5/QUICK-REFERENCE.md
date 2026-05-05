# Week 5 Quick Reference

## 🎯 Quick Stats

| Metric | Value |
|--------|-------|
| **Status** | ✅ COMPLETE |
| **Time Spent** | 10 hours (5 sessions) |
| **Lines of Code** | ~3,000+ |
| **Identities** | 16 (down from 197) |
| **Noise Reduction** | 92% |
| **Entra Roles** | 31 discovered |
| **Total Roles** | 42 (11 Azure + 31 Entra) |
| **Frontend Components** | 6 |
| **Backend Endpoints** | 3 |

---

## 🚀 How to Run

### Start Backend API
```bash
cd ~/projects/auditgraph/backend
source venv/bin/activate
python app/api.py

# API available at: http://localhost:5001
```

### Start Frontend
```bash
cd ~/projects/auditgraph/frontend
npm start

# Frontend available at: http://localhost:3000
```

### Run Discovery
```bash
cd ~/projects/auditgraph/backend
source venv/bin/activate
python -m app.engines.discovery.azure_discovery
```

---

## 📊 Current State

### Identity Breakdown
- **Total Discovered:** 197 identities
- **Filtered Out:** 181 Microsoft system SPNs (92%)
- **Actionable:** 16 identities saved to database
  - Service Principals: 13
  - Users: 3

### Risk Distribution
- **Critical:** 6 identities
- **High:** 0 identities
- **Medium:** 10 identities
- **Low:** 0 identities

### Role Tracking
- **Azure RBAC Roles:** 11
- **Entra ID Roles:** 31
- **Total Roles:** 42

---

## 🔑 Key Files

### Frontend
```
frontend/src/
├── pages/
│   ├── Dashboard.tsx           # Main dashboard
│   ├── Identities.tsx          # Identity list
│   └── IdentityDetail.tsx      # Detail view
├── components/
│   └── StatsCard.tsx           # Stat display
├── services/
│   └── api.ts                  # API client
└── types/
    └── index.ts                # TypeScript types
```

### Backend
```
backend/app/
├── database.py                 # UPDATED - Entra roles
└── engines/discovery/
    └── azure_discovery.py      # UPDATED - Major refactor
```

---

## 🗄️ Database Commands

### Connect to PostgreSQL
```bash
psql -h xxxxx-db-dev.postgres.database.azure.com \
     -U auditgraph_admin \
     -d auditgraph \
     -p 5432
# Password: AuditGrxxxxx
```

### Quick Queries
```sql
-- Get all identities
SELECT display_name, risk_level, identity_type 
FROM identities 
WHERE discovery_run_id = (SELECT MAX(id) FROM discovery_runs)
ORDER BY risk_level;

-- Get Entra roles
SELECT i.display_name, era.role_name
FROM identities i
JOIN entra_role_assignments era ON i.id = era.identity_db_id
ORDER BY i.display_name;

-- Count roles per identity
SELECT 
    i.display_name,
    COUNT(DISTINCT ra.id) as azure_roles,
    COUNT(DISTINCT era.id) as entra_roles,
    COUNT(DISTINCT ra.id) + COUNT(DISTINCT era.id) as total_roles
FROM identities i
LEFT JOIN role_assignments ra ON i.id = ra.identity_db_id
LEFT JOIN entra_role_assignments era ON i.id = era.identity_db_id
GROUP BY i.id, i.display_name
ORDER BY total_roles DESC;
```

---

## 📌 API Endpoints

### Backend API (Port 5001)
```bash
# Health check
curl http://localhost:5001/api/health

# Get statistics
curl http://localhost:5001/api/stats

# Get all identities
curl http://localhost:5001/api/identities

# Get specific identity
curl http://localhost:5001/api/identities/:id

# Get critical risks
curl http://localhost:5001/api/risks

# Get all discovery runs
curl http://localhost:5001/api/runs

# Get drift report
curl http://localhost:5001/api/drift/:run_id
```

---

## 🧪 Test Data

### Service Principals (13)
```
1. spn-auditgraph-admin          (CRITICAL - Owner)
2. spn-auditgraph-automation     (MEDIUM - Reader)
3. spn-auditgraph-discovery      (MEDIUM - Reader)
4. spn-backup-automation         (MEDIUM - no roles)
5. spn-contributor-sub           (CRITICAL - Contributor)
6. spn-devops-pipeline           (MEDIUM - no roles)
7. spn-monitoring-alerts         (MEDIUM - no roles)
8. spn-overprivileged-owner      (CRITICAL - Owner)
9. spn-reader-rg                 (MEDIUM - Reader)
10. spn-readonly-reporting       (MEDIUM - no roles)
11. spn-security-scanner         (MEDIUM - no roles)
12. spn-unused-orphan            (MEDIUM - orphaned)
13. spn-user-access-admin        (CRITICAL - User Access Admin)
```

### Users (3)
```
1. Admin User   (CRITICAL - 32 roles)
   - Entra: Global Admin, Priv Role Admin, +28 more
   - Azure: Owner, User Access Admin

2. Jane Smith (Test)             (CRITICAL - 2 roles)
   - Entra: Cloud App Administrator
   - Azure: Contributor

3. John Doe (Test)               (MEDIUM - 1 role)
   - Azure: Reader
```

---

## 🛠️ Common Commands

### Frontend Development
```bash
# Install dependencies
cd ~/projects/auditgraph/frontend
npm install

# Start dev server
npm start

# Build for production
npm run build

# Run TypeScript check
npm run type-check
```

### Backend Development
```bash
# Activate virtual environment
cd ~/projects/auditgraph/backend
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run discovery
python -m app.engines.discovery.azure_discovery

# Start API server
python app/api.py

# Python shell for testing
python
>>> from app.database import Database
>>> db = Database()
>>> db.get_latest_discovery_run()
```

---

## 🔧 Troubleshooting

### Issue: "Module not found"
```bash
# Solution: Activate venv
cd ~/projects/auditgraph/backend
source venv/bin/activate
```

### Issue: "Database connection failed"
```bash
# Solution: Check firewall rules
az postgres flexible-server firewall-rule list \
  --name auditgraph-db-dev \
  --resource-group auditgraph-dev-rg

# Add your IP if needed
az postgres flexible-server firewall-rule create \
  --resource-group auditgraph-dev-rg \
  --name auditgraph-db-dev \
  --rule-name AllowMyIP \
  --start-ip-address $(curl -4 -s ifconfig.me) \
  --end-ip-address $(curl -4 -s ifconfig.me)
```

### Issue: "Frontend not loading data"
```bash
# Solution 1: Check backend is running
curl http://localhost:5001/api/health

# Solution 2: Check CORS settings in app/api.py
# Should have: CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# Solution 3: Check browser console for errors
# Open DevTools → Console
```

### Issue: "Discovery returns 0 identities"
```bash
# Solution: Check Azure credentials
az account show

# Verify SPN permissions
az ad app permission list --id <client-id>

# Re-run with debug
python -m app.engines.discovery.azure_discovery
```

---

## 📊 Performance Benchmarks

| Operation | Time | Notes |
|-----------|------|-------|
| Discovery | ~11 seconds | 197 identities |
| Entra role discovery | ~3 seconds | 31 roles |
| User discovery | ~2 seconds | 3 users |
| Database save | ~1 second | 16 identities |
| API response | <100ms | Average |
| Frontend render | <2 seconds | Initial load |

---

## 💾 Backup & Recovery

### Backup Database
```bash
pg_dump -h auditxxxgraph-db-dev.postgres.database.azure.com \
        -U auditgraph_admin \
        -d auditgraph \
        > backup-$(date +%Y%m%d).sql
```

### Restore Database
```bash
psql -h auditgraph-db-dev.postgres.database.azure.com \
     -U auditgraph_admin \
     -d auditgraph \
     < backup-20260125.sql
```

---

## 🔍 Debugging

### Check Discovery Output
```bash
# Run discovery with full output
python -m app.engines.discovery.azure_discovery 2>&1 | tee discovery.log

# Check for errors
grep -i error discovery.log
grep -i warning discovery.log
```

### Check Database State
```bash
# Connect and inspect
psql -h auditgraph-db-dev.postgres.database.azure.com \
     -U auditgraph_admin -d auditgraph

-- Check last discovery run
SELECT * FROM discovery_runs ORDER BY id DESC LIMIT 1;

-- Check identity count
SELECT COUNT(*) FROM identities;

-- Check Entra roles
SELECT COUNT(*) FROM entra_role_assignments;
```

### Check API Health
```bash
# Test all endpoints
for endpoint in health stats identities risks runs; do
    echo "Testing /api/$endpoint..."
    curl -s http://localhost:5001/api/$endpoint | jq
done
```

---

## 📁 Project Structure

```
auditgraph/
├── backend/
│   ├── app/
│   │   ├── api.py
│   │   ├── database.py
│   │   └── engines/
│   │       └── discovery/
│   │           └── azure_discovery.py
│   ├── requirements.txt
│   └── venv/
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── pages/
│   │   ├── components/
│   │   ├── services/
│   │   └── types/
│   ├── package.json
│   └── node_modules/
├── docs/
│   └── weekly/
│       ├── week-1-2/
│       ├── week-3-4/
│       └── week-5/
└── .env
```

---

## 🎯 Quick Commands Reference

```bash
# DISCOVERY
python -m app.engines.discovery.azure_discovery

# API
python app/api.py

# FRONTEND
npm start

# DATABASE
psql -h xxxxxtgraph-db-dev.postgres.database.azure.com -U auditgraph_admin -d auditgraph

# GIT
git status
git add .
git commit -m "message"
git push origin main

# AZURE
az account show
az ad sp list --all
```

---

## 🔗 Useful Links

**Documentation:**
- [Week 5 Summary](WEEK-5-SUMMARY.md)
- [Week 5 Lessons Learned](LESSONS-LEARNED.md)
- [Week 3-4 Summary](../week-3-4/WEEK-3-4-SUMMARY.md)

**External:**
- [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/overview)
- [React Docs](https://react.dev/)
- [TypeScript Docs](https://www.typescriptlang.org/docs/)

---

**Last Updated:** January 25, 2026  
**Status:** Current  
**Next Update:** Week 6