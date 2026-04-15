# Section 5 -- Connectors

## Overview

Connectors are the bridge between AuditGraph and your cloud environments. Each connector represents an isolated cloud boundary — an Azure Tenant, AWS Account, or GCP Project — and authenticates with the cloud provider's APIs to discover identities, entitlements, and resources.

All discovery data, identities, and risk calculations are scoped at the connector level, ensuring strict separation between environments even within the same organization. An organization can connect multiple environments of the same provider (e.g., separate production and development Azure tenants) with full data isolation between each connector.

```
Organization (Acme Corp)
│
├── Azure Connector: "Production Tenant"
│   └── Azure Tenant abc-123-def
│
├── Azure Connector: "Development Tenant"
│   └── Azure Tenant ghi-456-jkl
│
├── AWS Connector: "Production Account"
│   └── AWS Account 123456789012
│
└── GCP Connector: "Analytics Project"
    └── GCP Project analytics-prod
```

---

## Azure Connector

### Permission Requirements

The Azure connector requires a service principal (app registration) with the following API permissions:

**Microsoft Graph API (Application permissions):**

| Permission | Purpose |
|-----------|---------|
| `User.Read.All` | Discover human users and their directory attributes |
| `Application.Read.All` | Discover service principals, app registrations, and credentials |
| `Directory.Read.All` | Read Entra directory roles and group memberships |
| `RoleManagement.Read.Directory` | Read PIM eligible assignments and role activations |
| `Policy.Read.All` | Read conditional access policies |
| `AuditLog.Read.All` | Read sign-in logs for activity tracking (including servicePrincipalSignIns for AI agent dormancy detection) |
| `GroupMember.Read.All` | Read group memberships for role mapping |

**Azure Resource Manager (RBAC):**

| Role | Scope | Purpose |
|------|-------|---------|
| `Reader` | Subscription or Management Group | Read RBAC role assignments and resource metadata |

### Setup Steps

```
1. Register an application in Azure Entra ID
   Azure Portal → App Registrations → New Registration
   Name: "AuditGraph Discovery"
   Supported account types: Single tenant

2. Create a client secret
   App Registration → Certificates & secrets → New client secret
   Description: "AuditGraph"
   Expiry: 24 months (rotate before expiry)

3. Grant API permissions
   App Registration → API permissions → Add a permission
   Microsoft Graph → Application permissions → Add each permission above
   Click "Grant admin consent for {tenant}"

4. Assign RBAC role
   Subscriptions → {subscription} → Access Control (IAM) → Add role assignment
   Role: Reader
   Assign to: "AuditGraph Discovery" application

5. Add connector in AuditGraph
   Settings → Connectors → Add Cloud Connection
   Cloud: Azure
   Azure Directory ID: {tenant_id}
   Client ID: {application_id}
   Client Secret: {secret_value}
```

### What Gets Discovered

| Category | Items |
|----------|-------|
| **Human Identities** | All users with Azure RBAC or Entra directory roles |
| **Service Principals** | Custom and Microsoft system SPNs (filtered separately) |
| **Managed Identities** | System-assigned and user-assigned |
| **App Registrations** | Applications with permissions, credentials, and owners |
| **Role Assignments** | Azure RBAC at subscription, resource group, and resource level |
| **Entra Roles** | Directory roles (Global Admin, Exchange Admin, etc.) |
| **Credentials** | Secrets, certificates, federated credentials with expiration |
| **PIM** | Eligible role assignments and activation history |
| **Conditional Access** | Policy discovery and coverage calculation |
| **Storage Accounts** | With security configuration and SAS audit |
| **Key Vaults** | With item-level expiry tracking and diagnostic logging |
| **Subscriptions** | For hierarchical scope visualization |

---

## AWS Connector

### Permission Requirements

The AWS connector requires an IAM user with programmatic access:

| Permission | Purpose |
|-----------|---------|
| `iam:ListUsers` | Discover IAM users |
| `iam:ListRoles` | Discover IAM roles |
| `iam:ListAccessKeys` | Check credential status |
| `iam:GetAccessKeyLastUsed` | Activity tracking |
| `iam:ListUserPolicies` | Inline policy discovery |
| `iam:ListAttachedUserPolicies` | Managed policy discovery |
| `iam:ListRolePolicies` | Role inline policies |
| `iam:GetPolicy` | Policy document retrieval |
| `iam:GetPolicyVersion` | Policy version details |
| `iam:ListMFADevices` | MFA status check |
| `iam:GetLoginProfile` | Console access check |
| `iam:ListGroupsForUser` | Group membership |

**Recommended IAM Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:List*",
        "iam:Get*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Setup Steps

```
1. Create an IAM user in AWS
   IAM Console → Users → Create user
   Name: "auditgraph-discovery"
   Access type: Programmatic access only

2. Attach the read-only IAM policy

3. Generate access keys
   IAM Console → Users → auditgraph-discovery → Security credentials
   Create access key → Application running outside AWS

4. Add connector in AuditGraph
   Settings → Connectors → Add Cloud Connection
   Cloud: AWS
   Access Key ID: {access_key_id}
   Secret Access Key: {secret_access_key}
```

### What Gets Discovered

| Category | Items |
|----------|-------|
| **IAM Users** | All IAM users with access keys and MFA status |
| **IAM Roles** | Roles with trust relationships and policies |
| **Service-Linked Roles** | AWS-managed service roles |
| **Access Keys** | Key status, creation date, last used |
| **Policies** | Inline and attached policies with dangerous action detection |

### Dangerous Actions Tracked

AuditGraph flags IAM policies containing these high-risk actions:

```
*              (wildcard)
iam:*          (full IAM control)
iam:CreateUser
iam:AttachUserPolicy
iam:CreateAccessKey
sts:AssumeRole
kms:*          (full KMS control)
```

---

## GCP Connector

### Permission Requirements

The GCP connector requires a service account with the following roles:

| Role | Purpose |
|------|---------|
| `roles/iam.securityReviewer` | Read IAM policies and service accounts |
| `roles/viewer` | Read project resources and metadata |

### Setup Steps

```
1. Create a service account in GCP
   IAM & Admin → Service accounts → Create
   Name: "auditgraph-discovery"

2. Grant roles
   IAM & Admin → IAM → Grant access
   Member: auditgraph-discovery@{project}.iam.gserviceaccount.com
   Roles: Security Reviewer, Viewer

3. Create a key
   Service accounts → auditgraph-discovery → Keys → Add Key
   Key type: JSON

4. Add connector in AuditGraph
   Settings → Connectors → Add Cloud Connection
   Cloud: GCP
   Project ID: {project_id}
   Service Account Key: {json_key_content}
```

### What Gets Discovered

| Category | Items |
|----------|-------|
| **Service Accounts** | All service accounts with key metadata |
| **IAM Bindings** | Project-level role assignments |
| **Roles** | Predefined and custom roles |
| **Keys** | Service account key creation time and type |

### Privileged Roles Tracked

```
roles/owner
roles/editor
roles/iam.securityAdmin
roles/iam.serviceAccountAdmin
roles/iam.serviceAccountKeyAdmin
roles/resourcemanager.organizationAdmin
```

---

## Credential Security

### How Credentials Are Stored

Cloud connector credentials are encrypted at rest using Fernet symmetric encryption:

```
User enters:     client_secret = "my-secret-value"
Stored in DB:    metadata.client_secret = "enc:gAAAAABk...base64..."
                                          │
                                          └── Fernet-encrypted
```

- Credentials are encrypted immediately on creation (before database write)
- Credentials are decrypted only at discovery time (in the scheduler)
- Credentials are never included in API responses
- Credentials are never written to logs (redaction filter catches them)

### Credential Rotation

AuditGraph supports in-place credential rotation without disrupting discovery:

```
POST /api/connectors/{connection_id}/rotate-credentials
{
  "client_secret": "new-secret-value"
}

Response:
{
  "success": true,
  "message": "Credentials rotated successfully",
  "connection_id": 1,
  "rotated_at": "2026-03-16T14:30:00Z"
}
```

The rotation endpoint:
1. Encrypts the new credential
2. Updates the stored encrypted value
3. Logs a `CREDENTIAL_ROTATED` security event
4. Does not interrupt running discovery

### Recommended Rotation Schedule

| Cloud | Credential Type | Recommended Rotation |
|-------|----------------|---------------------|
| Azure | Client secret | Every 6 months (before 12-month expiry) |
| AWS | Access key | Every 90 days |
| GCP | Service account key | Every 90 days |

---

## Connector Lifecycle

```
┌──────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐
│ Created  │────►│  Testing  │────►│ Connected │────►│ Disabled  │
│ (pending)│     │           │     │           │     │           │
└──────────┘     └─────┬─────┘     └─────┬─────┘     └───────────┘
                       │                 │
                       ▼                 ▼
                 ┌───────────┐     ┌───────────┐
                 │   Error   │     │  Deleted  │
                 │           │     │           │
                 └───────────┘     └───────────┘
```

| State | Description |
|-------|-------------|
| `pending` | Connector created but not yet tested |
| `connected` | Credentials validated, ready for discovery |
| `error` | Connection test failed (invalid credentials, permissions, or network) |
| `disabled` | Manually disabled by administrator |
| `deleted` | Connector removed (discovery data retained per retention policy) |

---

## Connector Data Isolation

Data from different connectors is strictly isolated:

1. **Database level**: Every `discovery_run` has a `cloud_connection_id` foreign key
2. **Query level**: `_latest_run_ids()` scopes queries to a specific connector
3. **Frontend level**: `ConnectionContext` sends `connection_id` as a query parameter
4. **Organization level**: Row Level Security prevents cross-organization access

This means:
- Production Azure tenant data never mixes with development Azure tenant data
- Azure identities never appear in AWS connector views
- Deleting a connector does not delete data from other connectors

---

## References

- [Discovery Engine](discovery-engine.md) -- What happens after a connector runs
- [Security Architecture](security-architecture.md) -- Credential encryption details
- [Operations](operations.md) -- Connector troubleshooting
- [Best Practices](best-practices.md) -- Connector configuration recommendations
