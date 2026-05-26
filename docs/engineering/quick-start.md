# Quick Start Guide

## Overview

This guide walks you through connecting your first cloud environment to AuditGraph and running your first identity security scan. By the end, you'll have a complete inventory of identities, risk scores, and actionable remediation priorities.

**Time to first scan: ~15 minutes**

---

## Prerequisites

### Platform Access

| Requirement | Details |
|-------------|---------|
| **AuditGraph account** | Sign up at `app.auditgraph.ai` or receive an invitation from your organization admin |
| **Browser** | Chrome, Firefox, Edge, or Safari (latest 2 versions) |
| **Role** | `admin` or `security_admin` to add connectors and trigger scans |

### Cloud Provider Credentials

You'll need read-only credentials for each cloud environment you want to monitor. AuditGraph never modifies your cloud environment — all API calls are read-only.

#### Azure (Recommended Starting Point)

Create an Azure AD app registration with these permissions:

| Permission Type | Permission | Purpose |
|----------------|-----------|---------|
| **Microsoft Graph (Application)** | `Directory.Read.All` | Read users, groups, service principals |
| **Microsoft Graph (Application)** | `Application.Read.All` | Read app registrations, credentials |
| **Microsoft Graph (Application)** | `RoleManagement.Read.Directory` | Read PIM eligible assignments |
| **Microsoft Graph (Application)** | `Policy.Read.All` | Read conditional access policies |
| **Microsoft Graph (Application)** | `AuditLog.Read.All` | Read sign-in logs (requires Azure AD P2) |
| **Azure RBAC** | `Reader` role on target subscriptions | Read RBAC role assignments and resources |

```
Azure Portal Setup:
1. Azure Active Directory → App registrations → New registration
2. Name: "AuditGraph Scanner" (or your preferred name)
3. Supported account types: "Accounts in this organizational directory only"
4. Add API permissions listed above → Grant admin consent
5. Certificates & secrets → New client secret → Copy the value immediately
6. Note: Application (client) ID, Directory (tenant) ID, Client secret value
```

#### AWS

Create an IAM user with read-only IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:List*",
        "iam:Get*",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Note: Access Key ID and Secret Access Key.

#### GCP

Create a service account with these roles:

- `roles/iam.securityReviewer`
- `roles/viewer`

Download the JSON key file.

---

## Step 1: Create Your Organization

When you first sign up at `app.auditgraph.ai`, you'll create your organization:

```
POST /api/auth/signup

{
  "organization_name": "Acme Corp",
  "admin_username": "admin@acme.com",
  "admin_password": "YourStr0ng!Password",
  "admin_display_name": "Jane Admin"
}
```

**Or via the UI:**

1. Navigate to `app.auditgraph.ai`
2. Click **Sign Up**
3. Enter your organization name, admin email, and password
4. Complete the onboarding wizard

**Password requirements:** 12+ characters, at least one uppercase, one lowercase, one digit, and one special character.

After signup, you'll be guided through onboarding stages:

```
welcome → password_change → authenticating → connections → active
```

---

## Step 2: Add a Cloud Connector

A connector links AuditGraph to your cloud environment using the credentials you prepared.

### Via the UI

1. Navigate to **Settings → Connections** (or follow the onboarding wizard)
2. Click **Add Connection**
3. Select your cloud provider (Azure, AWS, or GCP)
4. Enter your credentials:

| Field | Azure | AWS | GCP |
|-------|-------|-----|-----|
| **Label** | "Production Azure" | "Production AWS" | "Analytics GCP" |
| **Tenant/Account ID** | Directory (tenant) ID | Account ID | Project ID |
| **Client/Access ID** | Application (client) ID | Access Key ID | Client email |
| **Secret/Key** | Client secret value | Secret Access Key | Private key (JSON) |

5. Click **Test Connection** — AuditGraph validates credentials and confirms access
6. Click **Save**

### Via the API

```http
POST /api/client/connections
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "label": "Production Azure",
  "cloud": "azure",
  "azure_directory_id": "abc-123-def-456",
  "client_id": "your-app-id",
  "client_secret": "your-client-secret"
}
```

**Important:** Credentials are encrypted immediately using Fernet (AES-128-CBC + HMAC-SHA256) and stored with an `enc:` prefix. The plaintext secret is never stored and never returned in API responses.

### Test Before Saving

```http
POST /api/client/connections/test
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "cloud": "azure",
  "azure_directory_id": "abc-123-def-456",
  "client_id": "your-app-id",
  "client_secret": "your-client-secret"
}
```

A successful test returns the tenant name and subscription count, confirming AuditGraph can reach your environment.

---

## Step 3: Run Your First Discovery

Discovery scans your cloud environment and builds the identity inventory.

### Trigger a Scan

**Via the UI:** Click **Run Discovery** on the dashboard or in Settings → Connections.

**Via the API:**

```http
POST /api/runs/trigger
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "connection_id": 1,
  "scan_mode": "deep"
}
```

### Scan Modes

| Mode | Duration | What It Covers |
|------|----------|---------------|
| **Quick** | 1-2 min | Identities, credentials, basic permissions |
| **Standard** | 3-5 min | Quick + RBAC role assignments, Entra roles, ownership |
| **Deep** | 5-10 min | Standard + PIM eligible assignments, conditional access policies, resources, app registrations |

**Recommendation:** Use `deep` for your first scan to get the complete picture.

### What Happens During Discovery

```
Stage 1: Authentication
  └── Acquire OAuth token from cloud provider

Stage 2: Identity Scanning
  └── Enumerate all users, service principals, managed identities

Stage 3: Data Extraction
  └── Fetch credentials, ownership, group memberships

Stage 4: Entitlement Mapping
  └── Collect RBAC assignments, Entra roles, IAM policies

Stage 5: Resource Mapping (Deep mode)
  └── Inventory subscriptions, storage accounts, key vaults

Stage 6: Risk Scoring
  └── Compute per-identity risk score, blast radius, tier classification

Stage 7: Graph Construction
  └── Build identity access graph with nodes and edges

Post-Discovery:
  └── Drift detection → Anomaly detection → AGIRS computation → Notifications
```

### Monitor Progress

```http
GET /api/runs?limit=1
Authorization: Bearer eyJ...
```

The run progresses through states: `pending` → `running` → `completed` (or `failed`).

---

## Step 4: Review Your AGIRS Score

After discovery completes, navigate to the **CISO Dashboard** to see your organization's identity risk posture.

### Understanding the AGIRS Score

AGIRS (AuditGraph Identity Risk Score) is a composite score from 0-100:

```
AGIRS = 0.40 × HIRI + 0.40 × NHIRI + 0.20 × GEI

Where:
  HIRI  = Human Identity Risk Index (ghost accounts, dormant privileged, over-privileged)
  NHIRI = Non-Human Identity Risk Index (orphaned SPNs, expired credentials, zombie NHI)
  GEI   = Governance Effectiveness Index (ownership, PIM adoption, access reviews)
```

### Grade Scale

| Score | Grade | Status | Interpretation |
|-------|-------|--------|---------------|
| 80-100 | A | Resilient | Strong identity hygiene. Minor improvements possible. |
| 60-79 | B | Controlled | Good posture with specific areas needing attention. |
| 45-59 | C | Elevated | Significant risk factors present. Prioritize remediation. |
| 30-44 | D | High | Serious identity risk. Immediate action recommended. |
| 0-29 | F | Critical | Severe exposure. Critical remediation required. |

### Key Metrics to Check First

| Metric | What It Means | Where to Find It |
|--------|--------------|-----------------|
| **Ghost Accounts** | Disabled users with active role assignments | CISO Dashboard → HIRI breakdown |
| **Orphaned SPNs** | Service principals with no human owner | CISO Dashboard → NHIRI breakdown |
| **Over-Privileged** | Identities with broader access than needed | CISO Dashboard → Top Risks |
| **High Blast Radius** | Identities that can reach many resources | CISO Dashboard → Blast Radius panel |
| **Expired Credentials** | SPNs with expired secrets or certificates | SPN Dashboard → Credential Risk |

---

## Step 5: Investigate Top Risks

### Drill Into Risk Factors

From the CISO Dashboard, click on any risk factor count to see the affected identities. For example, clicking "44 Ghost Accounts" navigates to the Identities page filtered to show only ghost accounts.

### Review an Individual Identity

1. Click on any identity row to open the detail page
2. Review the **Overview** tab for risk score, tier, and risk factors
3. Check the **Access Graph** tab to visualize what this identity can access
4. Review the **Credentials** tab for expiration dates and rotation status

### Priority Investigation Order

| Priority | Risk Factor | Why It's Urgent |
|----------|-------------|----------------|
| **P0** | Zombie identities | Disabled + privileged = potential compromise indicator |
| **P0** | High blast radius + stale | Dormant identity with broad access = easy lateral movement |
| **P1** | Ghost accounts | Active permissions on disabled accounts = unnecessary exposure |
| **P1** | Orphaned NHI with T0/T1 roles | No owner = no accountability for privileged access |
| **P2** | Dormant privileged users | Standing privilege without recent use = unnecessary risk |

---

## Step 6: Start Remediation

### Automated Recommendations

AuditGraph generates remediation recommendations for each identity. Navigate to any identity's **Remediation** tab to see:

- Specific actions (e.g., "Remove Global Administrator role")
- CLI commands for Azure/AWS/GCP
- Estimated risk reduction

### Remediation Center

The **Remediation Center** page aggregates all recommendations across your environment, ranked by risk reduction impact.

### Example: Removing a Ghost Account's Roles

```bash
# AuditGraph identified: user@company.com (disabled) has Reader on sub-123
# Recommended action:

az role assignment delete \
  --assignee "user@company.com" \
  --role "Reader" \
  --scope "/subscriptions/sub-123"
```

### Verify Remediation

After making changes in your cloud environment:

1. Trigger a new discovery scan
2. Check that the AGIRS score improved
3. Verify the remediated identity no longer appears in the risk list

---

## Configure Ongoing Monitoring

### Discovery Schedule

AuditGraph automatically runs discovery scans on a configurable schedule:

| Environment | Recommended Interval | Scan Mode |
|-------------|---------------------|-----------|
| Production | Every 12 hours | Deep |
| Development/Staging | Every 24 hours | Standard |
| Large (1000+ identities) | Every 12-24 hours | Standard (weekly Deep) |

Configure via **Settings → Discovery** or:

```http
POST /api/settings
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "discovery_interval_hours": 12
}
```

### Enable Notifications

Set up Slack or Teams alerts for critical events:

1. Navigate to **Settings → Integrations**
2. Add your Slack webhook URL or Teams webhook URL
3. Enable event types: `scan_complete`, `anomaly_detected`, `drift_detected`

### Enable P2 Telemetry (Azure AD P2 Required)

If your Azure AD tenant has P2 licensing, enable P2 telemetry for enhanced behavioral analysis:

1. Navigate to **Settings → P2 Telemetry**
2. Toggle **Enable P2 Sign-In Log Ingestion**
3. AuditGraph will ingest sign-in logs for 95% confidence activity classification (vs. 40% heuristic without P2)

---

## Common Mistakes

### 1. Insufficient Permissions

**Symptom:** Discovery completes but shows 0 identities or missing data.

**Fix:** Verify the app registration has `Directory.Read.All` (Application permission, not Delegated) and admin consent has been granted.

### 2. Wrong Directory ID

**Symptom:** Connection test fails with "invalid tenant" error.

**Fix:** Ensure the Directory (tenant) ID in the connector matches the Azure AD tenant where the app registration was created.

### 3. Expired Client Secret

**Symptom:** Discovery fails after previously working.

**Fix:** Azure client secrets expire. Check **Settings → Connections** for credential status. Rotate via:

```http
POST /api/connectors/1/rotate-credentials
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "client_secret": "new-secret-value"
}
```

### 4. Using Deep Scan on Very Large Environments

**Symptom:** Discovery takes 30+ minutes or times out.

**Fix:** For environments with 5,000+ identities, start with `standard` mode. Use `deep` mode weekly.

### 5. Not Running Discovery After Remediation

**Symptom:** AGIRS score doesn't reflect changes you made in the cloud.

**Fix:** Trigger a new discovery scan. AGIRS is recomputed from the latest snapshot, not in real-time.

### 6. Forgetting to Assign SPN Owners

**Symptom:** NHIRI score is low despite fixing credentials.

**Fix:** The Governance Effectiveness Index (GEI) penalizes orphaned service principals. Assign owners in Azure AD or via AuditGraph's ownership attestation feature.

---

## Next Steps

| Goal | Resource |
|------|----------|
| Understand the risk scoring model | [Risk Scoring Model](risk-scoring.md) |
| Set up additional cloud connectors | [Connectors](connectors.md) |
| Configure compliance monitoring | [Compliance Mapping](compliance.md) |
| Review security best practices | [Best Practices](best-practices.md) |
| Integrate with your SIEM/SOAR | [Security Features](security-features.md) |
| Explore the full API | [API Reference](api-reference.md) |

---

## References

- [Introduction](introduction.md) -- Platform overview
- [Architecture](architecture.md) -- How AuditGraph works
- [Connectors](connectors.md) -- Connector setup details
- [Discovery Engine](discovery-engine.md) -- Scan modes and pipeline
- [Risk Scoring Model](risk-scoring.md) -- AGIRS methodology
- [Best Practices](best-practices.md) -- Operational recommendations
