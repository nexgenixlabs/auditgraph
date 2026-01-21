# AuditGraph Week 1-2 - Quick Reference

## 🎯 Quick Stats

| Metric | Value |
|--------|-------|
| **Status** | ✅ COMPLETE |
| **Time Spent** | 6 hours |
| **Lines of Code** | ~600 |
| **Identities Discovered** | 180 |
| **Critical Risks Found** | 4/4 (100%) |
| **Cost** | $1-2/month |

## 🚀 How to Run Discovery

```bash
# 1. Navigate to backend
cd /Users/sangabattula/projects/auditgraph/backend

# 2. Activate virtual environment
source venv/bin/activate

# 3. Load environment variables
set -a
source ../.env
set +a

# 4. Run discovery
python app/test_discovery.py
```

## 📁 Key Files

| File | Purpose | Lines |
|------|---------|-------|
| `app/engines/discovery/models.py` | Data models | 180 |
| `app/engines/discovery/azure_discovery.py` | Main engine | 300 |
| `app/test_discovery.py` | Test runner | 50 |

## 🔑 Environment Variables

```bash
AZURE_TENANT_ID=aaa1cba5-23b8-49d0-9d9e-1802369217af
AZURE_CLIENT_ID=b29a04cb-40cc-4e26-935b-04f822b269a0
AZURE_CLIENT_SECRET=y_F8Q~tHdkgE3tUqbtqvEZYxlscYX3EIJDeGFaYb
AZURE_SUBSCRIPTION_ID=34780384-6a21-4b79-ac90-1e3976b58a33
```

## 🎯 Test SPNs Created

| Name | Role | Risk | Status |
|------|------|------|--------|
| spn-overprivileged-owner | Owner | 🔴 CRITICAL | Found ✅ |
| spn-contributor-sub | Contributor | 🔴 CRITICAL | Found ✅ |
| spn-user-access-admin | User Access Admin | 🔴 CRITICAL | Found ✅ |
| spn-reader-rg | Reader | ✅ Acceptable | Found ✅ |
| spn-unused-orphan | None | 🟡 Medium | Found ✅ |

## 📊 Discovery Results

**Total Identities:** 180
- Custom SPNs: 8
- Microsoft System SPNs: 172

**Risk Breakdown:**
- 🔴 Critical: 4
- 🟠 High: 0
- 🟡 Medium: 173 (mostly orphaned MS SPNs)

## 🔄 Git Commands

```bash
# Commit work
git add .
git commit -m "Week 1-2 Complete: Discovery Engine"
git push origin main

# Create Week 3 branch
git checkout -b week3-enhanced-discovery
```

## 🧹 Cleanup Commands

```bash
# Delete test environment
az group delete --name rg-auditgraph-test --yes --no-wait

# Delete test SPNs
az ad sp delete --id <app-id>

# Stop local services
docker-compose down
```

## 📈 Week 3 Preview

**Focus:** Enhanced Discovery + Database Integration

**Goals:**
- [ ] Track last activity dates
- [ ] Check credential expiration
- [ ] Map resource access
- [ ] PostgreSQL integration
- [ ] Historical drift detection

**Time Budget:** 10 hours

## 🐛 Common Issues

### Issue: "Module not found"
```bash
# Solution: Activate venv
source venv/bin/activate
```

### Issue: "Authentication failed"
```bash
# Solution: Check .env file
cat ../.env
# Reload variables
set -a; source ../.env; set +a
```

### Issue: "Permission denied"
```bash
# Solution: Verify SPN has Reader + Directory.Read.All
az role assignment list --assignee <client-id>
```

## 📞 Contact

**Founder:** Bhupathi  
**Project:** AuditGraph  
**Timeline:** 10 weeks to MVP  
**Target:** 10 customers, $50K MRR by Dec 2026
