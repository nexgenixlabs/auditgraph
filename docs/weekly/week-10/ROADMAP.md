# Week 10-12: Non-Human Identity Security Dashboard

**Project:** AuditGraph - Cloud Identity Security Posture Management  
**Phase:** Non-Human Identity Module (Complete Redesign)  
**Timeline:** 3 weeks (30 hours total)  
**Status:** 📋 Planning Phase

---

## 🎯 Executive Summary

Transform AuditGraph into a **dedicated Non-Human Identity security platform** with enhanced risk intelligence, comprehensive access visibility, and actionable security insights specifically designed for service principals, managed identities, and application registrations.

---

## 🔍 Problem Statement

### **Current State (After Week 9):**
```
✅ Basic service principal discovery
✅ API permissions tracking
✅ Credential monitoring
✅ Role assignments
❌ Mixed with human users (confusing UX)
❌ Limited risk scoring (misses critical patterns)
❌ No app roles visibility
❌ No usage intelligence
❌ No ownership tracking
```

### **Target State (After Week 12):**
```
✅ Dedicated Non-Human Identity dashboard
✅ Enhanced risk scoring (permission + role + usage patterns)
✅ Complete access visibility (API perms + App roles + Azure roles)
✅ Usage intelligence (last used, source tracking)
✅ Ownership and accountability tracking
✅ Actionable security insights
✅ Compliance-ready reporting
```

---

## 📊 Architecture Overview

### **New Navigation Structure:**
```
┌─────────────────────────────────────────────────┐
│  AuditGraph - Identity Security Platform        │
├─────────────────────────────────────────────────┤
│  📊 Dashboard (Overview)                        │
│  🤖 Non-Human Identities  ← PRIMARY FOCUS      │
│  👥 Human Users                                 │
│  🔐 Key Vaults                                  │
│  💾 Storage Accounts                            │
│  ⚙️  Organization Config                        │
└─────────────────────────────────────────────────┘
```

---

## 🎯 Week 10: Backend Foundation & Enhanced Discovery

### **Phase 10A: App Roles Discovery (8 hours)**

#### **What are App Roles?**
```
App Roles = Custom roles defined INSIDE your application
- Different from Azure RBAC (Owner, Contributor)
- Different from API permissions (User.Read.All)
- Examples: "Admin", "Viewer", "DataProcessor", "ReportReader"
```

#### **Implementation:**

**1. Discovery Engine Enhancement**
- File: `backend/app/engines/discovery/azure_discovery.py`
- New method: `async def _discover_app_roles()`
- Microsoft Graph endpoint: `/servicePrincipals/{id}/appRoleAssignedTo`

**2. Database Schema**
```sql
CREATE TABLE sp_app_roles (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER NOT NULL,
    app_role_id VARCHAR(255),
    app_role_value VARCHAR(255),
    app_role_display_name TEXT,
    resource_display_name TEXT,
    principal_display_name TEXT,
    assigned_date TIMESTAMP,
    risk_level VARCHAR(20) DEFAULT 'medium',
    FOREIGN KEY (identity_db_id) REFERENCES identities(id) ON DELETE CASCADE
);
```

**3. API Enhancement**
- Endpoint: `GET /api/identities/{id}`
- Add: `app_roles` array in response
- Similar structure to `graph_permissions`

#### **Expected Outcome:**
```json
{
  "identity": { ... },
  "graph_permissions": [3 items],
  "app_roles": [
    {
      "app_role_value": "Admin",
      "app_role_display_name": "Application Administrator",
      "resource_display_name": "MyApp",
      "risk_level": "high"
    }
  ]
}
```

---

### **Phase 10B: Ownership Tracking (4 hours)**

#### **Why This Matters:**
```
Scenario: SPN with Owner role on subscription
Question: WHO is responsible for this identity?
Current: Unknown ❌
Target: "Created by: john.doe@company.com" ✅
```

#### **Implementation:**

**1. Discovery Enhancement**
- Fetch application owner from Microsoft Graph
- Endpoint: `/applications/{id}/owners`
- Store owner's display name, UPN, object ID

**2. Database Schema**
```sql
CREATE TABLE sp_ownership (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER NOT NULL,
    owner_object_id VARCHAR(255),
    owner_display_name VARCHAR(255),
    owner_upn VARCHAR(255),
    ownership_type VARCHAR(50) DEFAULT 'application',
    discovered_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (identity_db_id) REFERENCES identities(id) ON DELETE CASCADE
);
```

**3. API Enhancement**
- Add `owners` array to identity response
- Show in frontend as "Accountability" section

---

### **Phase 10C: Enhanced Risk Scoring (6 hours)**

#### **New Risk Matrix:**

| Scenario | Risk Level | Points | Reason |
|----------|-----------|--------|---------|
| Owner + API permissions | **CRITICAL** | 150 | Extreme privilege |
| No roles + API permissions | **HIGH** | 80 | Orphaned access |
| API permissions + never used | **HIGH** | 70 | Attack vector |
| Reader + No API | **LOW** | 10 | Least privilege ✅ |
| No roles + App roles | **MEDIUM** | 50 | Hidden permissions |
| Expired credentials + roles | **HIGH** | 75 | Security gap |

#### **Implementation:**

**1. Risk Calculation Algorithm**
```python
def calculate_enhanced_risk(identity, roles, permissions, app_roles, usage):
    """
    Points-based risk scoring system
    """
    points = 0
    reasons = []
    
    # Azure RBAC roles
    if has_owner_role(roles):
        points += 100
        reasons.append("Owner role on subscription")
    
    # API Permissions
    if has_write_permissions(permissions):
        points += 60
        reasons.append("Has write permissions to Graph API")
    elif has_read_all_permissions(permissions):
        points += 40
        reasons.append("Has read-all permissions")
    
    # Orphaned permissions (no roles but has API access)
    if len(roles) == 0 and len(permissions) > 0:
        points += 30
        reasons.append("API permissions without role justification")
    
    # App Roles
    if has_admin_app_roles(app_roles):
        points += 50
        reasons.append("Has administrative app roles")
    
    # Usage patterns
    if never_used(usage) and has_credentials(identity):
        points += 40
        reasons.append("Never used but has active credentials")
    elif not_used_90_days(usage):
        points += 20
        reasons.append("Dormant for 90+ days")
    
    # Expired credentials
    if has_expired_credentials(identity):
        points += 35
        reasons.append("Has expired credentials")
    
    # Convert points to risk level
    if points >= 120:
        return 'critical', reasons
    elif points >= 70:
        return 'high', reasons
    elif points >= 40:
        return 'medium', reasons
    else:
        return 'low', reasons
```

**2. Database Update**
- Update `identities.risk_level` based on new calculation
- Update `identities.risk_reasons` with detailed explanations
- Add `identities.risk_score` (integer points)

---

### **Phase 10D: Database Schema Updates (2 hours)**

#### **New Columns in `identities` table:**
```sql
ALTER TABLE identities 
ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS api_permission_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS app_role_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS owner_display_name VARCHAR(255),
ADD COLUMN IF NOT EXISTS last_activity_source VARCHAR(255),
ADD COLUMN IF NOT EXISTS days_since_last_use INTEGER;
```

#### **Indexes for Performance:**
```sql
CREATE INDEX idx_identities_risk_score ON identities(risk_score);
CREATE INDEX idx_identities_api_perm_count ON identities(api_permission_count);
CREATE INDEX idx_identities_app_role_count ON identities(app_role_count);
CREATE INDEX idx_identities_last_use ON identities(days_since_last_use);
```

---

## 🎯 Week 11: Frontend Dashboard & UI Components

### **Phase 11A: Separate Non-Human Identity Dashboard (8 hours)**

#### **New Route:**
- Path: `/non-human-identities`
- Component: `NonHumanIdentitiesDashboard.tsx`
- Features: Dedicated view, separate from human users

#### **Dashboard Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  🤖 Non-Human Identities                         [Trigger]  │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  📊 Summary Cards:                                           │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐  │
│  │ Total    │ Critical │ Orphaned │ Dormant  │ No Owner │  │
│  │ SPNs: 20 │ Risk: 8  │ Perms: 3 │ 90d+: 5  │ Unknown:2│  │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘  │
│                                                               │
│  🔍 Filters:                                                 │
│  [Risk: All ▼] [Roles: All ▼] [Permissions: 0 ▼]          │
│  [Last Used: All ▼] [Owner: All ▼]                         │
│                                                               │
│  📋 Identities Table:                                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Name │ Risk │ Roles │ Secrets │ API │ App │ Last │   │
│  │      │      │       │ /Certs  │Perms│Roles│ Used │   │
│  ├──────┼──────┼───────┼─────────┼─────┼─────┼──────┤   │
│  │ spn-1│ 🔴   │ 1     │ 1 / 0   │ 3   │ 0   │ 2d   │   │
│  │ spn-2│ 🟠   │ 0     │ 0 / 0   │ 1   │ 2   │Never │   │
│  └──────┴──────┴───────┴─────────┴─────┴─────┴──────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

### **Phase 11B: Enhanced Table Component (6 hours)**

#### **Column Definitions:**
```typescript
interface NonHumanIdentityTableRow {
  identity_name: string;
  identity_type: 'service_principal' | 'managed_identity';
  source: 'azure' | 'aws' | 'gcp';
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  risk_score: number;
  role_count: number;
  secrets_count: number;
  certificates_count: number;
  api_permission_count: number;
  app_role_count: number;
  owner_display_name: string | null;
  days_since_last_use: number | null;
  last_activity_source: string | null;
  created_date: string;
}
```

#### **Sortable Columns:**
- ✅ Risk Score (default sort)
- ✅ Last Used (date)
- ✅ Created Date
- ✅ Role Count
- ✅ API Permissions Count
- ✅ Name (alphabetical)

#### **Filterable Columns:**
- ✅ Risk Level (multi-select)
- ✅ Roles: 0, 1-2, 3+
- ✅ API Permissions: 0, 1-5, 6+
- ✅ Last Used: Never, 0-30d, 30-90d, 90d+
- ✅ Owner: Known, Unknown

---

### **Phase 11C: Enhanced Detail View (6 hours)**

#### **New Modal/Panel Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  spn-auditgraph-discovery                    [Risk: MEDIUM] │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Tabs: [Overview] [Permissions] [Credentials] [Activity]    │
│                                                               │
│  ┌─ Overview ──────────────────────────────────────────┐    │
│  │ Identity ID: xxx                                     │    │
│  │ Created: Jan 21, 2026                               │    │
│  │ Owner: john.doe@company.com                         │    │
│  │ Risk Score: 65 points (MEDIUM)                      │    │
│  └──────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─ Permissions Summary ─────────────────────────────┐      │
│  │ Azure RBAC Roles      │ 1  │ [View Details →]      │      │
│  │ Entra Directory Roles │ 0  │ [View Details →]      │      │
│  │ API Permissions       │ 3  │ [View Details →]      │      │
│  │ App Roles             │ 0  │ [View Details →]      │      │
│  └───────────────────────────────────────────────────┘      │
│                                                               │
│  ┌─ Credentials ────────────────────────────────────┐       │
│  │ Secrets                                           │       │
│  │ ├─ Secret 1: Expires Feb 15, 2026 (15 days) ⚠️   │       │
│  │                                                    │       │
│  │ Certificates                                       │       │
│  │ ├─ None                                           │       │
│  └────────────────────────────────────────────────────┘      │
│                                                               │
│  ┌─ Activity ──────────────────────────────────────┐        │
│  │ Last Used: 2 days ago                            │        │
│  │ Source: Azure DevOps Pipeline                    │        │
│  │ Pattern: Regular (every 6 hours)                 │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  [Disable Identity] [Remove Permissions] [View Audit Log]   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Week 12: Usage Intelligence & Advanced Features

### **Phase 12A: Sign-In Log Analysis (8 hours)**

#### **Microsoft Graph API Integration:**
```
Endpoint: /auditLogs/signIns
Filter: appId eq '{service_principal_app_id}'
Data: Last 90 days of sign-in activity
```

#### **Data Points to Capture:**
```typescript
interface SignInActivity {
  sign_in_date: string;
  source_ip: string;
  source_location: string;        // City, Country
  source_application: string;      // "Azure DevOps", "GitHub Actions"
  target_resource: string;         // What the SPN accessed
  status: 'success' | 'failure';
  failure_reason: string | null;
}
```

#### **Database Schema:**
```sql
CREATE TABLE sp_sign_in_logs (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER NOT NULL,
    sign_in_date TIMESTAMP NOT NULL,
    source_ip VARCHAR(45),
    source_location VARCHAR(255),
    source_application VARCHAR(255),
    target_resource VARCHAR(255),
    status VARCHAR(20),
    failure_reason TEXT,
    discovered_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (identity_db_id) REFERENCES identities(id) ON DELETE CASCADE
);
```

#### **Usage Intelligence Metrics:**
- Last sign-in date
- Sign-in frequency pattern (hourly, daily, weekly)
- Most common source application
- Geographic distribution
- Failed sign-in attempts (security indicator)

---

### **Phase 12B: Advanced Risk Patterns (4 hours)**

#### **Behavioral Anomaly Detection:**
```python
Patterns to Flag:
1. Sign-ins from unusual locations
2. Sign-ins outside business hours (for automated SPNs)
3. Failed sign-in spikes (potential attack)
4. New target resources accessed
5. Dormant SPN suddenly active
```

#### **Risk Alerts:**
```typescript
interface RiskAlert {
  alert_type: 'anomaly' | 'security' | 'compliance';
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  details: string;
  detected_at: string;
  resolved: boolean;
}
```

---

### **Phase 12C: Compliance Reporting (4 hours)**

#### **Pre-built Reports:**
```
1. Orphaned Identities Report
   - SPNs with permissions but no roles
   - SPNs with no owner
   - SPNs never used

2. High-Risk Identities Report
   - Critical risk score SPNs
   - SPNs with write permissions
   - SPNs with multiple privilege paths

3. Credential Hygiene Report
   - Expiring credentials (next 30 days)
   - Expired credentials
   - Long-lived credentials (>365 days)

4. Usage Analysis Report
   - Dormant identities (90+ days)
   - Never-used identities
   - Over-privileged unused identities
```

---

### **Phase 12D: Export & Integration (4 hours)**

#### **Export Formats:**
- CSV (for Excel)
- JSON (for automation)
- PDF (for executive reports)

#### **API Endpoints:**
```
GET /api/non-human-identities/export?format=csv
GET /api/reports/orphaned-identities
GET /api/reports/high-risk
GET /api/reports/credential-hygiene
```

---

## 📊 Success Metrics

### **Week 10:**
- ✅ App roles discovered for all SPNs
- ✅ Ownership tracked for all SPNs
- ✅ Enhanced risk scoring deployed
- ✅ Database schema complete

### **Week 11:**
- ✅ Separate dashboard launched
- ✅ Enhanced table with all columns
- ✅ Detail view redesigned
- ✅ Filtering & sorting working

### **Week 12:**
- ✅ Usage intelligence operational
- ✅ Behavioral patterns identified
- ✅ Compliance reports available
- ✅ Export functionality working

---

## 🎯 Implementation Timeline
```
Week 10 (20 hours):
├─ Day 1-2: App Roles Discovery (8h)
├─ Day 3: Ownership Tracking (4h)
├─ Day 4: Enhanced Risk Scoring (6h)
└─ Day 5: Database Updates (2h)

Week 11 (20 hours):
├─ Day 1-2: Dashboard Component (8h)
├─ Day 2-3: Table Enhancement (6h)
├─ Day 4-5: Detail View (6h)

Week 12 (20 hours):
├─ Day 1-2: Sign-In Analysis (8h)
├─ Day 3: Risk Patterns (4h)
├─ Day 4: Compliance Reports (4h)
└─ Day 5: Export & Polish (4h)
```

---

## 🚀 Next Steps

1. ✅ Review this roadmap
2. ✅ Approve or suggest modifications
3. ✅ Begin Week 10 implementation
4. ✅ Daily checkpoints and progress tracking

---

**Prepared by:** Bhupathi  
**Date:** January 31, 2026  
**Status:** Ready for Week 10 kickoff 🚀
