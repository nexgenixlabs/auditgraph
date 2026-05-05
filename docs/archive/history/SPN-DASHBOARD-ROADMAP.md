# AuditGraph SPN Dashboard - Scope & Roadmap

**Created:** January 30, 2026  
**Status:** ✅ APPROVED - Added to Product Scope  
**Priority:** HIGH - Unique differentiator

---

## 🎯 **Vision Statement**

> "SPNs are the most privileged, least visible identities in cloud. AuditGraph is the only tool that treats them as first-class security risks."

AuditGraph's SPN Dashboard provides honest, audit-ready intelligence on service principals - showing not just what access exists, but why it's dangerous, what can be touched, and what should be fixed first.

---

## 🏆 **Why This Is Unique**

### **What Competitors Do:**
- List service accounts
- Show permissions
- Generic "rotate secrets" advice
- Heavy setup, noisy UI
- Assume logs exist
- Built for IAM admins

### **What AuditGraph Does:**
- **Honest about missing data:** "Usage: Unknown (telemetry not available)"
- **Risk + Evidence:** Not just access, but "why dangerous + what auditors will ask"
- **Non-human identity focus:** SPNs as first-class security risks
- **Audit-ready:** Built for compliance teams
- **Zero-trust access reality:** Shows access itself as risk
- **Works without logs:** Doesn't require perfect telemetry

### **The Difference:**
Most tools answer: "What does this SPN have?"  
**AuditGraph answers:** "Why is this SPN dangerous, what can it touch, and what should we do?"

---

## 📊 **Core Features (Final Spec)**

### **1. Dashboard Summary Cards**

**Inventory:**
- Total SPNs
- Custom SPNs (non-Microsoft)
- Microsoft-managed SPNs (hidden by default)

**Risk:**
- Critical SPNs (Owner, User Access Administrator)
- High-risk SPNs
- SPNs with PHI access
- SPNs with RBAC write permissions

**Credential Hygiene:**
- Expired credentials
- Expiring in < 30 days
- Long-lived secrets (> 90 days)

**Usage Visibility:**
- SPNs used in last 30 days
- Unused > 90 days
- **Usage unknown (logs missing)** ← CRITICAL DIFFERENTIATOR

---

### **2. SPN Main Table**

**Columns:**
- SPN Name
- App ID
- Identity Type (Secret / Cert / Federated)
- Risk Level (Critical / High / Medium / Low)
- Critical Roles (Owner / UAA / Key Vault / etc.)
- PHI Access (Yes/No + count)
- Next Expiry (date or "Expired")
- Last Used (date / Never / Unknown)
- Usage Source (Entra Logs / None)
- Blast Radius (High / Medium / Low)

**Default Sort:**
1. Risk level
2. PHI access
3. Expired/expiring
4. Unknown usage

---

### **3. Filters**

**Risk Filters:**
- Has PHI access
- Has RBAC write permissions
- Critical roles (Owner, UAA)

**Credential Filters:**
- Expired credentials
- Expiring < 30 days
- Long-lived secrets

**Usage Filters:**
- Unused > 90 days
- Usage unknown

**Type Filters:**
- Authentication type (secret / cert / federated)
- Scope (subscription / resource group / resource)

---

### **4. SPN Drill-Down Panel (The Killer Feature)**

**Identity Details:**
- Display name, App ID, Object ID, Tenant ID
- Created date
- Owner (if known)
- Source: Azure

**Credentials Section:**
- **Secrets:** ID (masked), start date, expiry, status
- **Certificates:** Key ID/thumbprint, expiry, status
- **Federated Credentials:** Issuer, subject, audience
- **Recommendations:** Replace secret with federation, rotate now, etc.

**Access & Privilege:**
- **Azure RBAC:** Role, scope, scope type, inherited/direct
- **Entra Roles:** Directory roles (if any)
- **Privilege Flags:**
  - Can assign roles (RBAC write)
  - Can read secrets
  - Can modify IAM
  - Can access subscription root

**Sensitive Access (AuditGraph Special):**
- PHI/sensitive resources reachable
- **Path view:** `SPN → Role → Scope → PHI Storage/DB`
- Access type: Read / Write / Admin
- **This alone satisfies many audit questions**

**Usage Intelligence:**
- Last sign-in time
- Client application (if known)
- Target resource
- Source IP / location (if available)
- **Usage confidence:**
  - High → logs present
  - Low → partial
  - Unknown → telemetry missing
- **If logs missing:** "Usage data unavailable. Access still exists." ← TRANSPARENCY WINS

**Risk Summary (Auto-generated):**
- Why this SPN is risky
- What attackers could do
- What auditors will question
- **Example:** "This SPN has Owner on subscription, uses a 2-year-old secret, and can access PHI storage. Usage telemetry is unavailable."

**Recommendations (Actionable):**
- Split bootstrap vs deploy SPN
- Remove unused roles
- Rotate credentials
- Migrate to federated identity
- Restrict scope

---

## 🗓️ **Implementation Roadmap**

### **🚀 WEEK 9-10: Quick Wins (2 weeks)**
**Goal:** Show credential hygiene + basic SPN risk in demos

**Deliverables:**
1. ✅ **Credential expiry tracking** (no logs needed!)
   - Add `credentials` table with schema:
     ```sql
     CREATE TABLE credentials (
       id SERIAL PRIMARY KEY,
       identity_db_id INTEGER REFERENCES identities(id),
       credential_type TEXT CHECK (credential_type IN ('secret', 'certificate', 'federated')),
       key_id TEXT,
       display_name TEXT,
       start_datetime TIMESTAMP,
       end_datetime TIMESTAMP,
       created_at TIMESTAMP DEFAULT NOW(),
       UNIQUE(identity_db_id, key_id)
     );
     ```
   - Discover credentials via Microsoft Graph API
   - Store secrets/certs with expiry dates
   - Calculate credential risk (Expired / ExpiringSoon / Healthy / Unknown)

2. ✅ **SPN-specific columns on existing dashboard**
   - Identity Type (Secret / Cert / Federated / Multiple)
   - Next Expiry (earliest expiry across all credentials)
   - Credential Risk badge (red/yellow/green/gray)
   - Filter: "Expiring < 30 days"
   - Filter: "Expired credentials"

3. ✅ **Basic drill-down panel** (click SPN → see details)
   - Identity info (already have)
   - Credentials list with expiry
   - Roles (already have)
   - Simple recommendations based on credential age + roles

**Success Criteria:**
- Can identify all SPNs with expired credentials in < 30 seconds
- Can find SPNs with Owner role + expiring secrets in < 60 seconds
- Demo: "Here are your 3 most dangerous credential risks"

**Technical Notes:**
- Microsoft Graph endpoint: `GET /servicePrincipals/{id}` includes `passwordCredentials` and `keyCredentials`
- No additional permissions needed (already have Directory.Read.All)
- Works without sign-in logs

---

### **🎯 WEEK 11-12: Dedicated SPN Dashboard (2 weeks)**
**Goal:** Separate SPNs from users, add risk intelligence

**Deliverables:**
1. ✅ **New route: `/spns`**
   - Separate navigation tab in header
   - SPN-only view (filter out identity_type='user')
   - URL: `http://localhost:3000/spns`

2. ✅ **Summary cards (4 cards across top)**
   - **Total SPNs** (count custom only, hide Microsoft by default)
   - **Critical SPNs** (Owner / User Access Administrator roles)
   - **Expired Credentials** (count)
   - **Expiring < 30 Days** (count)

3. ✅ **Enhanced SPN table**
   - Add "Critical Roles" column (show top 2 most dangerous roles)
   - Add "Blast Radius" column (High/Medium/Low based on scope)
   - Calculate blast radius:
     - **High:** Subscription-level Owner/Contributor/UAA
     - **Medium:** Resource group-level write permissions
     - **Low:** Resource-level read-only

4. ✅ **Advanced filters**
   - Has RBAC write permissions (Contributor, Owner, UAA, etc.)
   - Has Key Vault access
   - Authentication type (secret/cert/federated)
   - Scope level (subscription/resource group/resource)
   - Risk level (critical/high/medium/low)

5. ✅ **Enhanced drill-down panel**
   - All sections from spec above
   - Auto-generated risk summary
   - Recommendations based on:
     - Credential age (> 90 days = recommend rotation)
     - Credential type (secret = recommend cert/federation)
     - Role scope (subscription = recommend restriction)
     - Unused status (> 90 days = recommend removal)

**Success Criteria:**
- Can demo: "Here are your 5 most dangerous SPNs and why they're dangerous" in < 2 minutes
- Can filter to "Critical SPNs with expired secrets" in 1 click
- Risk summary makes sense to non-technical auditor

**Demo Narrative:**
> "Most breaches happen through service principals. Watch this: [Click SPNs tab] Here are 47 SPNs. 5 are critical, 3 have expired credentials. [Click critical SPN] This one has Owner on your subscription, uses a 2-year-old secret, and we can't prove anyone's using it. [Show recommendations] Here's what to fix."

---

### **🔥 WEEK 13-14: Usage Intelligence (2 weeks, optional logs)**
**Goal:** Show "last used" when possible, honest when not

**Deliverables:**
1. ✅ **Sign-in log integration** (Entra service principal logs)
   - Add `identity_usage` table:
     ```sql
     CREATE TABLE identity_usage (
       id SERIAL PRIMARY KEY,
       identity_db_id INTEGER REFERENCES identities(id),
       last_seen_at TIMESTAMP,
       last_seen_source TEXT, -- 'entra_signin', 'azure_activity', 'unknown'
       last_used_client_app TEXT,
       last_used_resource TEXT,
       last_used_ip TEXT,
       last_used_location TEXT,
       usage_confidence TEXT CHECK (usage_confidence IN ('high', 'medium', 'low', 'unknown')),
       updated_at TIMESTAMP DEFAULT NOW(),
       UNIQUE(identity_db_id)
     );
     ```
   - Query Microsoft Graph: `GET /auditLogs/signIns?$filter=appId eq '{appId}'`
   - Parse last sign-in event
   - Calculate confidence:
     - **High:** Sign-in within 30 days
     - **Medium:** Sign-in 30-90 days ago
     - **Low:** Sign-in > 90 days ago
     - **Unknown:** No sign-in logs available

2. ✅ **Usage columns**
   - "Last Used" (date or "Never" or "Unknown")
   - "Usage Source" badge (Entra Logs / None)
   - "Usage Confidence" badge (High/Medium/Low/Unknown)
   - Sort by: Last used (oldest first to find unused)

3. ✅ **Telemetry health banner**
   - Show at top of SPN dashboard if > 10% have unknown usage
   - "⚠️ 15 SPNs have unknown usage (sign-in telemetry not enabled)"
   - Link to Microsoft docs: "How to enable service principal sign-in logs"
   - Button: "Dismiss" (hide banner for session)

4. ✅ **Usage-based filters**
   - "Unused > 90 days" (when usage known)
   - "Usage unknown" (when logs missing)
   - "Used within 30 days" (active SPNs)

**Success Criteria:**
- Shows last used date when available
- Honestly shows "Unknown" when logs missing
- Banner appears when logs are insufficient
- Can demo: "These 8 SPNs haven't been used in 90 days - candidates for removal"

**Important:** This feature gracefully degrades. Dashboard works perfectly without sign-in logs, just shows "Unknown" instead of dates.

**Technical Notes:**
- Requires Azure AD Premium P1 or P2 (for sign-in logs)
- Many orgs don't have this enabled
- AuditGraph's honesty here builds trust vs competitors who hide missing data

---

### **🎊 WEEK 15-16: PHI Access + Audit Export (2 weeks)**
**Goal:** Tie SPNs to sensitive data, make it audit-ready

**Deliverables:**
1. ✅ **PHI access mapping** (builds on Week 8 scope work)
   - Discover which Azure resources are tagged with PHI/sensitive data
   - Calculate which SPNs can access these resources
   - Show count: "PHI Resources: 3" in SPN table
   - In drill-down panel, show:
     - List of PHI resources accessible
     - Access path: `SPN → Owner role → Subscription → PHI Storage Account`
     - Access type: Read / Write / Admin

2. ✅ **Risk summary (auto-generated text)**
   - Template-based generation:
     ```python
     risk_summary = []
     if 'Owner' in roles or 'User Access Administrator' in roles:
         risk_summary.append("Has subscription-level admin access")
     if credential_age > 90:
         risk_summary.append(f"Uses {credential_age}-day-old secret")
     if phi_access_count > 0:
         risk_summary.append(f"Can access {phi_access_count} PHI resources")
     if usage_status == 'unknown':
         risk_summary.append("Usage telemetry unavailable")
     
     return f"⚠️ {'. '.join(risk_summary)}."
     ```
   - Show in drill-down panel
   - Example output: "⚠️ Has subscription-level admin access. Uses 180-day-old secret. Can access 3 PHI resources. Usage telemetry unavailable."

3. ✅ **Auditor-friendly explanations**
   - "What attackers could do" section:
     - "This SPN could read patient data from Storage Account 'phi-prod'"
     - "This SPN could create new admin accounts via User Access Administrator"
   - "What auditors will question" section:
     - "Why does automation need Owner on entire subscription?"
     - "How do you prove this SPN is still in use?"
     - "When was this credential last rotated?"

4. ✅ **Export: SPN Privilege Report**
   - CSV export with columns:
     - SPN Name, App ID, Object ID
     - Critical Roles, All Roles
     - Credential Type, Next Expiry, Days to Expiry
     - PHI Access (Yes/No), PHI Resources Count
     - Last Used, Usage Confidence
     - Risk Level, Risk Summary
   - PDF export (formatted report):
     - Executive summary (top risks)
     - Full SPN inventory table
     - Detailed findings for each critical SPN
     - Recommendations
   - Button: "Export for Audit" (generates timestamp + org name in filename)

**Success Criteria:**
- Can demo: "These 3 SPNs can access patient data" in < 30 seconds
- Export looks professional enough for external auditor
- Risk summary makes sense to non-technical stakeholder

---

## 📈 **Data Model (New Tables)**

### **`credentials` Table**
```sql
CREATE TABLE credentials (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER REFERENCES identities(id) ON DELETE CASCADE,
    credential_type TEXT CHECK (credential_type IN ('secret', 'certificate', 'federated')),
    key_id TEXT NOT NULL,
    display_name TEXT,
    start_datetime TIMESTAMP,
    end_datetime TIMESTAMP,
    thumbprint TEXT, -- for certificates
    issuer TEXT, -- for federated
    subject TEXT, -- for federated
    discovered_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(identity_db_id, key_id)
);

CREATE INDEX idx_credentials_identity ON credentials(identity_db_id);
CREATE INDEX idx_credentials_expiry ON credentials(end_datetime);
```

### **`identity_usage` Table**
```sql
CREATE TABLE identity_usage (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER REFERENCES identities(id) ON DELETE CASCADE,
    last_seen_at TIMESTAMP,
    last_seen_source TEXT CHECK (last_seen_source IN ('entra_signin', 'azure_activity', 'unknown')),
    last_used_client_app TEXT,
    last_used_resource TEXT,
    last_used_ip TEXT,
    last_used_location TEXT,
    usage_confidence TEXT CHECK (usage_confidence IN ('high', 'medium', 'low', 'unknown')),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(identity_db_id)
);

CREATE INDEX idx_identity_usage_identity ON identity_usage(identity_db_id);
CREATE INDEX idx_identity_usage_last_seen ON identity_usage(last_seen_at);
```

### **`phi_resources` Table** (Week 15-16)
```sql
CREATE TABLE phi_resources (
    id SERIAL PRIMARY KEY,
    resource_id TEXT UNIQUE NOT NULL,
    resource_name TEXT,
    resource_type TEXT, -- 'storage_account', 'database', 'key_vault', etc.
    tags JSONB,
    is_phi BOOLEAN DEFAULT FALSE,
    confidence TEXT CHECK (confidence IN ('high', 'medium', 'low')), -- based on tags/naming
    discovered_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE identity_phi_access (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER REFERENCES identities(id) ON DELETE CASCADE,
    phi_resource_id INTEGER REFERENCES phi_resources(id) ON DELETE CASCADE,
    access_type TEXT CHECK (access_type IN ('read', 'write', 'admin')),
    access_path TEXT, -- 'SPN → Owner → Subscription → PHI Storage'
    discovered_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(identity_db_id, phi_resource_id)
);
```

---

## 🎬 **Demo Narrative (After Week 12)**

**Setup (5 seconds):**
Navigate to `/spns` tab

**Opening (30 seconds):**
> "Most breaches happen through service principals - automated identities with permanent credentials and too much access. But they're invisible in most tools. AuditGraph treats SPNs as first-class security risks."

**Show (60 seconds):**
1. **Dashboard view:** "Here are your 47 SPNs. 5 are critical, 3 have expired credentials, 12 are expiring soon."
2. **Click critical SPN:** "This SPN has Owner on your subscription, uses a 2-year-old secret, and we can't prove anyone's using it. [Scroll to recommendations]"
3. **Show recommendations:** "Rotate secret, restrict scope, migrate to workload identity federation."
4. **Export:** "Here's an audit-ready report you can send to your compliance team."

**Close (30 seconds):**
> "In 2 minutes, you found your riskiest SPNs and know exactly what to fix. This is what HIPAA auditors will ask about - and now you have the answers."

**Key callout during demo:**
> "Notice we show 'Usage: Unknown' for some SPNs. We don't hide missing data - we're honest when logs aren't available. The access risk still exists."

---

## 🏗️ **Technical Implementation Notes**

### **Microsoft Graph API Calls**

**Get Service Principal with Credentials:**
```http
GET https://graph.microsoft.com/v1.0/servicePrincipals/{id}
?$select=id,appId,displayName,passwordCredentials,keyCredentials,createdDateTime
```

**Get Sign-in Logs:**
```http
GET https://graph.microsoft.com/v1.0/auditLogs/signIns
?$filter=appId eq '{appId}' and createdDateTime ge {30_days_ago}
&$orderby=createdDateTime desc
&$top=1
```

**Permissions Required:**
- `Application.Read.All` (already have)
- `Directory.Read.All` (already have)
- `AuditLog.Read.All` (for sign-in logs - Week 13-14)

### **Risk Calculation Logic**

**Credential Risk:**
```python
def calculate_credential_risk(credentials):
    now = datetime.utcnow()
    
    for cred in credentials:
        if cred.end_datetime < now:
            return 'expired'
    
    earliest_expiry = min(c.end_datetime for c in credentials if c.end_datetime)
    days_to_expiry = (earliest_expiry - now).days
    
    if days_to_expiry < 30:
        return 'expiring_soon'
    elif days_to_expiry < 90:
        return 'healthy'
    else:
        return 'healthy'
```

**Blast Radius:**
```python
def calculate_blast_radius(roles):
    high_roles = ['Owner', 'User Access Administrator', 'Contributor']
    
    for role in roles:
        if role.scope_type == 'subscription' and role.role_name in high_roles:
            return 'high'
    
    for role in roles:
        if role.scope_type == 'resource_group' and role.role_name in ['Owner', 'Contributor']:
            return 'medium'
    
    return 'low'
```

### **Frontend Components**

**New Components to Create:**
- `SPNDashboard.tsx` (main SPN page)
- `SPNTable.tsx` (table with SPN-specific columns)
- `SPNDrillDown.tsx` (right-side panel)
- `CredentialList.tsx` (credentials section in drill-down)
- `UsageTimeline.tsx` (usage history visualization - Week 13-14)
- `PHIAccessGraph.tsx` (access path visualization - Week 15-16)

---

## 🎯 **Success Metrics**

### **Product Metrics:**
- Time to identify most critical SPN: < 30 seconds
- Time to understand why SPN is risky: < 60 seconds
- Time to generate audit report: < 10 seconds

### **Demo Metrics:**
- Can explain value in < 2 minutes
- Non-technical person understands risk
- Auditor can use export without modification

### **Differentiation Metrics:**
- Only tool that shows "Usage: Unknown" honestly
- Only tool with audit-ready SPN reports
- Only tool connecting SPNs → PHI access

---

## 💼 **Business Value**

### **For Security Teams:**
- Find dangerous SPNs in minutes, not hours
- Prioritize fixes based on real risk
- Reduce blast radius of compromised credentials

### **For Compliance Teams:**
- Audit-ready SPN inventory
- Evidence of least-privilege attempts
- Clear audit trail for HIPAA/SOC2/PCI-DSS

### **For Leadership:**
- Quantify non-human identity risk
- Show progress on credential hygiene
- Demonstrate security maturity

### **ROI Calculation:**
- Manual SPN audit: 40 hours @ $150/hr = $6,000
- AuditGraph: 30 minutes = $75
- **Savings per audit cycle: $5,925**

---

## 🚀 **Go-to-Market Positioning**

### **Primary Message:**
"The only identity security tool that treats service principals as first-class risks"

### **Secondary Messages:**
- "Honest identity intelligence - we don't hide missing data"
- "Audit-ready in 2 minutes"
- "Built for healthcare compliance teams"

### **Competitive Positioning:**
- **vs Veza/Oasis/Saviynt:** They list SPNs, we explain risk
- **vs CrowdStrike/SentinelOne:** They detect compromise, we prevent it
- **vs Native Azure tools:** They show access, we show danger

### **Sales Narrative:**
1. **Problem:** SPNs are invisible, overprivileged, and cause breaches
2. **Consequence:** Auditors ask "prove this is secure" - you can't answer
3. **Solution:** AuditGraph shows which SPNs are dangerous and why
4. **Proof:** Live demo in 2 minutes
5. **Action:** 30-day trial with your Azure environment

---

## 📝 **Documentation Requirements**

**For Each Phase:**
- API endpoint documentation
- Database schema changes
- Frontend component specs
- Test scenarios
- Demo scripts

**User Documentation:**
- "Understanding SPN Risk" guide
- "Enabling Sign-in Logs" guide
- "Interpreting Risk Summary" guide
- "Preparing for HIPAA Audit" guide

---

## ✅ **Status: APPROVED & IN SCOPE**

This feature set is now officially part of AuditGraph's product roadmap. Implementation begins with Week 9 (credential expiry tracking).

**Next Actions:**
1. ✅ Commit Week 8 changes
2. ✅ Create Week 9 detailed plan
3. ✅ Update investor deck with SPN dashboard mockups
4. ✅ Add to demo script

---

**Document Owner:** AuditGraph Team  
**Last Updated:** January 30, 2026  
**Status:** Living Document - Update after each milestonegit add docs/