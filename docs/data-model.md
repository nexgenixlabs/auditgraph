# Platform Data Model

## Overview

AuditGraph's data model captures the complete identity and access landscape across cloud environments. The model is designed around three principles:

1. **Snapshot-based**: Each discovery run produces a point-in-time snapshot. Historical data is retained for trend analysis and drift detection.
2. **Tenant-isolated**: Every table with customer data enforces Row Level Security (RLS) via `organization_id`. Cross-tenant access is architecturally impossible.
3. **Graph-native**: Identity-to-resource relationships are stored as structured edges, enabling access graph visualization and attack path analysis.

---

## Entity Relationship Diagram

```
┌──────────────────┐
│  organizations   │
│  (tenant root)   │
└────────┬─────────┘
         │ 1:N
         ├──────────────────────────┐
         │                          │
         ▼                          ▼
┌──────────────────┐     ┌──────────────────┐
│ cloud_connections │     │     users        │
│ (connectors)     │     │ (platform users) │
└────────┬─────────┘     └──────────────────┘
         │ 1:N
         ▼
┌──────────────────┐
│  discovery_runs  │──────────────────────────────────────────┐
│  (snapshots)     │                                          │
└────────┬─────────┘                                          │
         │ 1:N                                                │
         ▼                                                    ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   identities     │     │  risk_summary    │     │  drift_reports   │
│ (60+ columns)    │     │ (AGIRS scores)   │     │ (change deltas)  │
└────────┬─────────┘     └──────────────────┘     └──────────────────┘
         │ 1:N
         ├──────────────────────────┬──────────────────────────┐
         │                          │                          │
         ▼                          ▼                          ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ role_assignments │     │   credentials    │     │    anomalies     │
│ (RBAC bindings)  │     │ (secrets, certs) │     │ (detected events)│
└──────────────────┘     └──────────────────┘     └──────────────────┘
         │
         ├──────────────────────────┬──────────────────────────┐
         ▼                          ▼                          ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ entra_role_      │     │ graph_api_       │     │ pim_eligible_    │
│ assignments      │     │ permissions      │     │ assignments      │
│ (directory roles)│     │ (app consents)   │     │ (JIT access)     │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

---

## Core Entities

### Organization

The root tenant entity. All customer data is scoped to an organization via `organization_id` (integer).

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Organization identifier |
| `name` | TEXT NOT NULL | Display name (e.g., "Acme Corp") |
| `slug` | TEXT UNIQUE | URL-safe identifier for subdomain routing |
| `plan` | TEXT | Subscription tier: `free`, `trial`, `pro`, `enterprise` |
| `onboarding_stage` | TEXT | Current stage: `welcome`, `password_change`, `authenticating`, `connections`, `active` |
| `created_at` | TIMESTAMPTZ | Creation timestamp |
| `license_activated_at` | TIMESTAMPTZ | When the license was activated |
| `license_expires_at` | TIMESTAMPTZ | License expiration date |

**Key relationships:**
- 1:N → `cloud_connections`
- 1:N → `users`
- 1:N → `settings`
- 1:N → `risk_summary`

**Tenant isolation:** The `organizations` table itself has NO RLS policy (it must be readable by the system for login routing). All child tables enforce RLS via `organization_id`.

---

### Cloud Connection (Connector)

Represents a link to a specific cloud environment (Azure tenant, AWS account, or GCP project).

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Connection identifier |
| `organization_id` | INTEGER NOT NULL | Owning organization (FK, RLS-enforced) |
| `label` | TEXT | Human-readable name (e.g., "Production Azure") |
| `cloud` | TEXT NOT NULL | Provider: `azure`, `aws`, `gcp` |
| `status` | TEXT | Connection state: `pending`, `connected`, `failed`, `disabled` |
| `azure_directory_id` | TEXT | Azure AD tenant ID |
| `client_id` | TEXT | Application/access key ID |
| `client_secret` | TEXT | Encrypted credential (Fernet, `enc:` prefix) |
| `aws_access_key_id` | TEXT | AWS access key |
| `aws_secret_access_key` | TEXT | Encrypted AWS secret key |
| `gcp_project_id` | TEXT | GCP project identifier |
| `gcp_service_account_key` | TEXT | Encrypted GCP JSON key |
| `discovery_enabled` | BOOLEAN | Whether scheduled discovery is active |
| `discovery_interval_minutes` | INTEGER | Per-connection scan interval |
| `last_discovery_at` | TIMESTAMPTZ | Last successful discovery timestamp |
| `created_at` | TIMESTAMPTZ | Creation timestamp |

**Credential security:**
- All secrets are encrypted immediately on receipt using Fernet (AES-128-CBC + HMAC-SHA256)
- Encrypted values carry an `enc:` prefix for identification
- Credentials are decrypted only at discovery time, used for API calls, then discarded
- API responses never return credential values

---

### Discovery Run (Snapshot)

Each discovery execution produces a run — a point-in-time snapshot of all identity and access data.

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Run identifier |
| `organization_id` | INTEGER NOT NULL | Owning organization (RLS-enforced) |
| `cloud_connection_id` | INTEGER NOT NULL | Source connector (FK) |
| `status` | TEXT | Run state: `pending`, `running`, `completed`, `failed` |
| `scan_mode` | TEXT | Scan depth: `quick`, `standard`, `deep` |
| `started_at` | TIMESTAMPTZ | Start timestamp |
| `completed_at` | TIMESTAMPTZ | Completion timestamp |
| `total_identities` | INTEGER | Count of discovered identities |
| `critical_count` | INTEGER | Identities with critical risk |
| `high_count` | INTEGER | Identities with high risk |
| `medium_count` | INTEGER | Identities with medium risk |
| `low_count` | INTEGER | Identities with low risk |
| `error_message` | TEXT | Error details if status is `failed` |
| `snapshot_hash` | TEXT | SHA-256 hash of snapshot data |
| `snapshot_signature` | TEXT | HMAC signature for integrity verification |
| `last_heartbeat` | TIMESTAMPTZ | Zombie detection heartbeat (20-second interval) |

**Snapshot integrity:** Each completed run is cryptographically hashed (SHA-256) and signed (HMAC) to ensure integrity. This enables tamper detection and supports audit validation of historical identity data.

**Querying by latest run:** The helper function `_latest_run_ids()` returns the most recent completed run IDs for the current organization and connection, scoping all identity queries to the freshest data.

---

### Identity

The central entity representing any principal in a cloud environment. A single table holds all identity types across all cloud providers.

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Internal database ID |
| `identity_id` | TEXT NOT NULL | Cloud provider ID (Azure object ID, AWS ARN, GCP email) |
| `display_name` | TEXT | Human-readable name |
| `identity_category` | TEXT | Type classification (see below) |
| `cloud` | TEXT | Provider: `azure`, `aws`, `gcp` |
| `risk_level` | TEXT | Computed: `critical`, `high`, `medium`, `low` |
| `risk_score` | INTEGER | Computed: 0-100 (higher = more risk) |
| `tier` | TEXT | Privilege tier: `T0`, `T1`, `T2`, `T3` |
| `activity_status` | TEXT | Computed: `active`, `inactive`, `stale`, `never_used`, `recently_created` |
| `last_sign_in` | TIMESTAMPTZ | Most recent sign-in (from Graph API or P2 telemetry) |
| `created_date` | TIMESTAMPTZ | Identity creation date in cloud |
| `account_enabled` | BOOLEAN | Whether the identity is enabled |
| `owner_count` | INTEGER | Number of assigned owners |
| `credential_count` | INTEGER | Number of credentials (secrets + certificates) |
| `blast_radius_score` | FLOAT | Computed: 0-100 (resource exposure) |
| `primary_subscription_id` | TEXT | Most-privileged subscription |
| `additional_subscription_count` | INTEGER | Cross-subscription access count |
| `discovery_run_id` | INTEGER NOT NULL | Source snapshot (FK) |
| `spn_app_id` | TEXT | Azure application ID (for SPN cross-linking) |
| `spn_type` | TEXT | Azure: `Application`, `ManagedIdentity`, `Legacy` |
| `is_microsoft` | BOOLEAN | Whether this is a Microsoft-managed identity |

**Identity categories:**

| Category | Description | Cloud |
|----------|------------|-------|
| `human_user` | Interactive user account | Azure, AWS, GCP |
| `guest` | External/B2B guest user | Azure |
| `service_principal` | Application identity | Azure |
| `managed_identity_system` | System-assigned managed identity | Azure |
| `managed_identity_user` | User-assigned managed identity | Azure |
| `microsoft_internal` | Microsoft first-party service principal | Azure |

**Tenant scoping:** The `identities` table does NOT have an `organization_id` column. Tenant isolation is achieved through `discovery_run_id` — each run belongs to an organization, and queries join through runs to enforce scoping.

---

### Role Assignment (RBAC)

Azure RBAC, AWS IAM policies, and GCP IAM bindings.

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Assignment identifier |
| `identity_db_id` | INTEGER NOT NULL | FK to `identities.id` |
| `identity_id` | TEXT | Cloud provider identity ID |
| `role_name` | TEXT | Role display name (e.g., "Owner", "Contributor") |
| `role_id` | TEXT | Role definition ID |
| `scope` | TEXT | Resource scope (e.g., `/subscriptions/{id}/resourceGroups/{name}`) |
| `scope_type` | TEXT | Scope classification: `subscription`, `resource_group`, `resource`, `management_group` |
| `subscription_id` | TEXT | Extracted subscription ID from scope |
| `subscription_name` | TEXT | Subscription display name |
| `source` | TEXT | Assignment source: `rbac`, `entra`, `aws_iam`, `gcp_iam` |
| `discovery_run_id` | INTEGER NOT NULL | Source snapshot |

**Scope hierarchy:** Azure RBAC roles are inherited downward:
```
Management Group → Subscription → Resource Group → Resource
```

AuditGraph tracks the actual assignment scope and computes effective access during graph construction.

---

### Entra Role Assignment

Azure AD directory roles (Global Administrator, Security Reader, etc.).

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Assignment identifier |
| `identity_db_id` | INTEGER NOT NULL | FK to `identities.id` |
| `identity_id` | TEXT | Cloud provider identity ID |
| `role_name` | TEXT | Directory role name (e.g., "Global Administrator") |
| `role_id` | TEXT | Role template ID |
| `assignment_type` | TEXT | `active` or `eligible` (PIM) |
| `scope` | TEXT | Always `directory` for Entra roles |
| `scope_type` | TEXT | Always `entra` |
| `discovery_run_id` | INTEGER NOT NULL | Source snapshot |

---

### Credential

Secrets, certificates, and access keys associated with identities.

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Credential identifier |
| `identity_db_id` | INTEGER NOT NULL | FK to `identities.id` |
| `identity_id` | TEXT | Cloud provider identity ID |
| `credential_type` | TEXT | `client_secret`, `certificate`, `access_key`, `service_account_key` |
| `key_id` | TEXT | Credential identifier in cloud provider |
| `display_name` | TEXT | Credential description |
| `created_at` | TIMESTAMPTZ | When the credential was created |
| `expiration` | TIMESTAMPTZ | Expiration date (null = never expires) |
| `status` | TEXT | Computed: `valid`, `expiring_soon`, `expired`, `warning` |
| `discovery_run_id` | INTEGER NOT NULL | Source snapshot |

**Credential status classification:**
- `expired`: Past expiration date
- `expiring_soon`: Within 30 days of expiration
- `warning`: Within 90 days of expiration
- `valid`: More than 90 days until expiration

---

### Graph API Permission

Application and delegated permissions consented to Azure AD app registrations.

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Permission identifier |
| `identity_db_id` | INTEGER NOT NULL | FK to `identities.id` |
| `identity_id` | TEXT | Cloud provider identity ID |
| `permission_name` | TEXT | Permission scope (e.g., `Mail.ReadWrite`) |
| `permission_type` | TEXT | `Application` or `Delegated` |
| `resource_app_id` | TEXT | Target API (e.g., Microsoft Graph) |
| `is_high_risk` | BOOLEAN | Whether this is a dangerous permission |
| `discovery_run_id` | INTEGER NOT NULL | Source snapshot |

**High-risk permissions** (tracked via `HIGH_RISK_PERMISSION_GUIDS`):
- `RoleManagement.ReadWrite.Directory`
- `Application.ReadWrite.All`
- `AppRoleAssignment.ReadWrite.All`
- `Directory.ReadWrite.All`
- `Mail.ReadWrite` (Application)
- And 5 others

---

### Risk Summary

Persisted AGIRS scores computed after each discovery run.

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Summary identifier |
| `organization_id` | INTEGER NOT NULL | Owning organization (RLS-enforced) |
| `discovery_run_id` | INTEGER | Source run (null for manual computations) |
| `agirs_score` | FLOAT | Composite score: 0-100 |
| `agirs_tier` | TEXT | Letter grade: A, B, C, D, F |
| `hiri_score` | FLOAT | Human Identity Risk Index |
| `nhiri_score` | FLOAT | Non-Human Identity Risk Index |
| `gei_score` | FLOAT | Governance Effectiveness Index |
| `total_identities` | INTEGER | Total identity count |
| `critical_count` | INTEGER | Critical risk count |
| `high_count` | INTEGER | High risk count |
| `hiri_breakdown` | JSONB | Detailed HIRI factors (H1-H5 counts) |
| `nhiri_breakdown` | JSONB | Detailed NHIRI factors (N1-N5 counts) |
| `gei_breakdown` | JSONB | GEI component scores |
| `dangerous_identities` | JSONB | Top identities by blast radius |
| `computed_at` | TIMESTAMPTZ | Computation timestamp |

**AGIRS formula:** `0.40 × HIRI + 0.40 × NHIRI + 0.20 × GEI`

**Persistence:** Risk summaries are computed by `RiskSummaryEngine` at the end of each discovery run and persisted for historical trending. The CISO Dashboard reads from this table rather than recomputing on each page load.

---

### App Registration

Azure AD application registrations with permission analysis and risk scoring.

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Registration identifier |
| `organization_id` | INTEGER NOT NULL | Owning organization (RLS-enforced) |
| `discovery_run_id` | INTEGER NOT NULL | Source snapshot |
| `app_id` | TEXT NOT NULL | Azure application (client) ID |
| `display_name` | TEXT | Application display name |
| `sign_in_audience` | TEXT | `AzureADMyOrg`, `AzureADMultipleOrgs`, `AzureADandPersonalMicrosoftAccount` |
| `app_permissions` | JSONB | Application (daemon) permissions |
| `delegated_permissions` | JSONB | Delegated (user context) permissions |
| `high_risk_permissions` | JSONB | Flagged dangerous permissions |
| `secret_count` | INTEGER | Number of client secrets |
| `certificate_count` | INTEGER | Number of certificates |
| `has_expired_credentials` | BOOLEAN | Whether any credentials are expired |
| `owner_count` | INTEGER | Number of assigned owners |
| `owners` | JSONB | Owner details array |
| `linked_spn_id` | TEXT | Associated service principal ID |
| `risk_score` | INTEGER | 10-factor risk score (0-100) |
| `risk_level` | TEXT | `critical`, `high`, `medium`, `low` |
| `redirect_uris` | JSONB | Configured redirect URIs |
| `is_multi_tenant` | BOOLEAN | Whether the app accepts external tenants |

**Risk scoring factors** (10 factors, cumulative):
1. Ownerless (+40)
2. Multi-tenant + application permissions (+30)
3. Expired credentials (+25)
4. High-risk Graph API permissions (+20 each)
5. Excessive permissions (+15)
6. No credentials (abandoned) (+10)
7. Wildcard redirect URIs (+10)
8. Delegated + application mix (+5)
9. Multiple owners (+5 if >3)
10. Long-lived secrets (+5 if >2 years)

---

### Azure Resources

Storage accounts and key vaults discovered via Azure Resource Manager.

#### Storage Accounts

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Resource identifier |
| `organization_id` | INTEGER NOT NULL | Owning organization (RLS-enforced) |
| `discovery_run_id` | INTEGER NOT NULL | Source snapshot |
| `resource_id` | TEXT | Full ARM resource ID |
| `name` | TEXT | Storage account name |
| `subscription_id` | TEXT | Subscription ID |
| `resource_group` | TEXT | Resource group name |
| `location` | TEXT | Azure region |
| `kind` | TEXT | `StorageV2`, `BlobStorage`, etc. |
| `sku_name` | TEXT | `Standard_LRS`, `Premium_LRS`, etc. |
| `https_only` | BOOLEAN | Whether HTTPS is enforced |
| `min_tls_version` | TEXT | Minimum TLS version |
| `public_network_access` | TEXT | `Enabled`, `Disabled` |
| `allow_blob_public_access` | BOOLEAN | Whether anonymous blob access is allowed |
| `network_default_action` | TEXT | `Allow` or `Deny` |
| `encryption_key_source` | TEXT | `Microsoft.Storage` or `Microsoft.Keyvault` |
| `infrastructure_encryption` | BOOLEAN | Double encryption enabled |
| `diagnostic_logging_enabled` | BOOLEAN | Whether diagnostic logs are configured |
| `risk_score` | INTEGER | Points-based CIS compliance score |
| `risk_level` | TEXT | Computed risk level |

#### Key Vaults

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Resource identifier |
| `organization_id` | INTEGER NOT NULL | Owning organization (RLS-enforced) |
| `discovery_run_id` | INTEGER NOT NULL | Source snapshot |
| `resource_id` | TEXT | Full ARM resource ID |
| `name` | TEXT | Key vault name |
| `vault_uri` | TEXT | `https://{name}.vault.azure.net/` |
| `subscription_id` | TEXT | Subscription ID |
| `sku_name` | TEXT | `standard` or `premium` |
| `soft_delete_enabled` | BOOLEAN | Whether soft-delete is on |
| `purge_protection_enabled` | BOOLEAN | Whether purge protection is on |
| `rbac_authorization` | BOOLEAN | Using RBAC vs access policies |
| `public_network_access` | TEXT | `Enabled`, `Disabled` |
| `network_default_action` | TEXT | `Allow` or `Deny` |
| `private_endpoint_connections` | JSONB | Private endpoints |
| `key_expiry_items` | JSONB | Keys with expiration tracking |
| `secret_expiry_items` | JSONB | Secrets with expiration tracking |
| `certificate_expiry_items` | JSONB | Certificates with expiration tracking |
| `risk_score` | INTEGER | Points-based CIS compliance score |
| `risk_level` | TEXT | Computed risk level |

---

### Security Event

Structured security events generated by the platform for audit trail and SIEM integration.

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Event identifier |
| `organization_id` | INTEGER NOT NULL | Owning organization (RLS-enforced) |
| `event_type` | TEXT | Event classification (see below) |
| `severity` | TEXT | `critical`, `high`, `medium`, `low`, `info` |
| `message` | TEXT | Human-readable description |
| `details` | JSONB | Structured event metadata |
| `source_ip` | TEXT | Request origin IP |
| `user_id` | INTEGER | Acting user (if applicable) |
| `timestamp` | TIMESTAMPTZ | Event timestamp |

**Event types:**
- `LOGIN_SUCCESS` / `LOGIN_FAILED` / `ACCOUNT_LOCKOUT`
- `RLS_VIOLATION` / `TENANT_CONTEXT_VIOLATION`
- `RATE_LIMIT_EXCEEDED`
- `INPUT_VALIDATION_FAILED`
- `SLOW_QUERY`
- `CIRCUIT_BREAKER_OPENED` / `CIRCUIT_BREAKER_CLOSED`
- `ENCRYPTION_ERROR`
- `SUSPICIOUS_INPUT`

---

## Supporting Entities

### PIM Eligible Assignments

Privileged Identity Management (Azure AD P2) just-in-time access.

| Column | Type | Description |
|--------|------|-------------|
| `identity_db_id` | INTEGER NOT NULL | FK to `identities.id` |
| `role_name` | TEXT | Eligible role name |
| `scope` | TEXT | Assignment scope |
| `start_time` | TIMESTAMPTZ | Eligibility start |
| `end_time` | TIMESTAMPTZ | Eligibility end |
| `discovery_run_id` | INTEGER NOT NULL | Source snapshot |

### PIM Activations

Records of PIM role activations.

| Column | Type | Description |
|--------|------|-------------|
| `identity_db_id` | INTEGER NOT NULL | FK to `identities.id` |
| `role_name` | TEXT | Activated role |
| `activated_at` | TIMESTAMPTZ | Activation timestamp |
| `duration_minutes` | INTEGER | Activation duration |
| `justification` | TEXT | Provided justification |
| `discovery_run_id` | INTEGER NOT NULL | Source snapshot |

### Conditional Access Policies

Azure AD conditional access policy configurations.

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Policy identifier |
| `organization_id` | INTEGER NOT NULL | Owning organization (RLS-enforced) |
| `policy_id` | TEXT | Azure AD policy ID |
| `display_name` | TEXT | Policy name |
| `state` | TEXT | `enabled`, `disabled`, `enabledForReportingButNotEnforced` |
| `conditions` | JSONB | Policy conditions (users, apps, locations) |
| `grant_controls` | JSONB | Grant controls (MFA, compliant device, etc.) |
| `discovery_run_id` | INTEGER NOT NULL | Source snapshot |

### Drift Report

Changes detected between consecutive discovery runs.

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Report identifier |
| `organization_id` | INTEGER NOT NULL | Owning organization (RLS-enforced) |
| `discovery_run_id` | INTEGER NOT NULL | Current run |
| `previous_run_id` | INTEGER | Previous run for comparison |
| `new_identities` | JSONB | Identities added since last run |
| `removed_identities` | JSONB | Identities removed since last run |
| `new_roles` | JSONB | New role assignments |
| `removed_roles` | JSONB | Removed role assignments |
| `credential_changes` | JSONB | Credential additions/expirations |
| `created_at` | TIMESTAMPTZ | Report timestamp |

### Anomaly

Behavioral anomalies detected by the anomaly detection engine.

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Anomaly identifier |
| `organization_id` | INTEGER NOT NULL | Owning organization (RLS-enforced) |
| `identity_db_id` | INTEGER | Affected identity (FK) |
| `identity_id` | TEXT | Cloud provider identity ID |
| `anomaly_type` | TEXT | Detection type (see below) |
| `severity` | TEXT | `critical`, `high`, `medium`, `low` |
| `description` | TEXT | Human-readable explanation |
| `details` | JSONB | Structured anomaly data |
| `resolved` | BOOLEAN | Whether the anomaly has been addressed |
| `resolution_notes` | TEXT | Investigator notes |
| `discovery_run_id` | INTEGER | Source run |
| `created_at` | TIMESTAMPTZ | Detection timestamp |

**Anomaly types:**
- `permission_escalation` — Unexpected role addition
- `risk_score_spike` — Sudden risk score increase
- `dormant_reactivation` — Stale identity suddenly active
- `credential_surge` — Multiple credentials added rapidly
- `off_hours_pim` — PIM activation outside business hours
- `excessive_pim_usage` — Abnormal PIM activation frequency
- `impossible_travel` — Sign-in from geographically impossible locations (P2)
- `auth_failure_burst` — Multiple authentication failures (P2)

---

## Tenant Isolation Model

### Row Level Security (RLS)

Every table containing customer data has a strict RLS policy:

```sql
CREATE POLICY tenant_strict_sel ON table_name
  FOR SELECT TO auditgraph_app
  USING (organization_id = current_setting('app.current_tenant_id', true)::integer);

CREATE POLICY tenant_strict_ins ON table_name
  FOR INSERT TO auditgraph_app
  WITH CHECK (organization_id = current_setting('app.current_tenant_id', true)::integer);
```

### Dual Database Users

| User | RLS Behavior | Purpose |
|------|-------------|---------|
| `auditgraph_app` | NOBYPASSRLS — all queries filtered by `organization_id` | All request-scoped operations |
| `auditgraph_admin` | BYPASSRLS — can access all data | System operations, DDL, cross-tenant analytics |

### Context Flow

```
HTTP Request
  → auth_middleware extracts org_id from JWT
  → Database(organization_id=org_id) connects as auditgraph_app
  → SET LOCAL app.current_tenant_id = org_id
  → All queries automatically filtered by RLS
  → Connection returned to pool with RESET
```

### Safety Layers

1. **SET LOCAL**: Context is transaction-scoped; cannot leak across requests
2. **Checkout RESET**: Connection pool resets context when checking out connections
3. **Return RESET**: Context is cleared when returning connections to pool
4. **Teardown hook**: Flask `teardown_appcontext` ensures cleanup
5. **Admin guard**: Blocks `Database()` calls without tenant context inside request handlers

---

## Snapshot Model

### How Snapshots Work

Each discovery run creates a complete snapshot — a full copy of all identity and access data at that point in time.

```
Run 107 (March 15, 12:00)          Run 108 (March 16, 00:00)
├── 248 identities                  ├── 250 identities (+2 new)
├── 1,204 role assignments          ├── 1,210 role assignments (+6)
├── 462 credentials                 ├── 460 credentials (-2 expired)
├── 156 Entra role assignments      ├── 158 Entra role assignments
└── AGIRS: 72.08                    └── AGIRS: 71.50 (-0.58)
                                    └── Drift report: 2 new, 0 removed,
                                        6 new roles, 2 credential changes
```

### Latest Run Resolution

The query pattern `_latest_run_ids()` returns the most recent completed run IDs for the current organization and connection:

```sql
SELECT dr.id FROM discovery_runs dr
JOIN cloud_connections cc ON dr.cloud_connection_id = cc.id
WHERE dr.organization_id = %s
  AND dr.status = 'completed'
  AND cc.id IS NOT NULL
ORDER BY dr.completed_at DESC
LIMIT 1
```

All identity queries use `WHERE discovery_run_id IN (latest_run_ids)` to scope to the current snapshot.

### Historical Access

Previous snapshots are retained per the data retention policy (default: 90 days). This enables:
- **Drift detection**: Compare run N with run N-1
- **Trend analysis**: Track AGIRS score over time
- **Forensic investigation**: Reconstruct identity state at any past point

---

## Graph Construction

### Building the Access Graph

After identity discovery, AuditGraph constructs an access graph representing identity-to-resource relationships.

```
Identity Node
  ├── [has_role] → Role Assignment Node
  │     └── [scoped_to] → Subscription → Resource Group → Resource
  ├── [has_entra_role] → Entra Role Node
  ├── [has_permission] → Graph API Permission Node
  ├── [has_credential] → Credential Node
  ├── [owned_by] → Owner Node
  └── [federated_via] → Federated Trust Node
```

### Node Types (13 Total)

| Node Type | Description | Data Source |
|-----------|------------|-------------|
| `identity` | The principal (user, SPN, managed identity) | `identities` table |
| `risk_summary` | Identity risk score and factors | Computed from identity attributes |
| `blast_radius` | Resource exposure visualization | Computed from role scope analysis |
| `owner` | Human owner of an identity | `identities` table (owner relationship) |
| `federated_trust` | External trust relationships | Credential and trust analysis |
| `role` | RBAC or Entra role assignment | `role_assignments` / `entra_role_assignments` |
| `permission` | Graph API permission | `graph_api_permissions` |
| `credential` | Secret or certificate | `credentials` |
| `scope` | Generic scope node | Scope parsing |
| `subscription` | Azure subscription | Extracted from role scope |
| `resource_group` | Azure resource group | Extracted from role scope |
| `resource` | Individual Azure resource | `azure_storage_accounts` / `azure_key_vaults` |
| `entra_directory` | Entra role directory scope | `entra_role_assignments` |

### Visualization Modes

| Mode | Purpose | Layout |
|------|---------|--------|
| **Executive** | High-level blast radius overview | Summary cards with risk factors |
| **Technical** | Full ARM tree with all relationships | Hierarchical: Identity → Subscription → RG → Resource |
| **Attack Path** | Escalation chains and lateral movement | Directed graph with 5 attack chain types |

---

## Table Inventory

AuditGraph uses 54+ PostgreSQL tables. Here is the complete inventory by category:

### Identity & Access (14 tables)

| Table | RLS | Purpose |
|-------|-----|---------|
| `identities` | Via run | Cloud identities (all types, all providers) |
| `role_assignments` | Via run | RBAC / IAM role bindings |
| `entra_role_assignments` | Via run | Azure AD directory roles |
| `graph_api_permissions` | Via run | App consent permissions |
| `credentials` | Via run | Secrets, certificates, keys |
| `pim_eligible_assignments` | Via run | PIM eligible roles |
| `pim_activations` | Via run | PIM activation records |
| `identity_subscription_access` | Via run | Multi-subscription junction |
| `app_registrations` | Yes | Azure AD app registrations |
| `sa_attestations` | Yes | Service account governance attestations |
| `ca_policies` | Yes | Conditional access policies |
| `graph_attack_findings` | Yes | Attack path analysis results |
| `identity_groups` | Yes | Custom identity groupings |
| `custom_risk_rules` | Yes | User-defined risk rules |

### Risk & Analytics (6 tables)

| Table | RLS | Purpose |
|-------|-----|---------|
| `risk_summary` | Yes | Persisted AGIRS scores per run |
| `anomalies` | Yes | Detected behavioral anomalies |
| `drift_reports` | Yes | Inter-run change reports |
| `risk_score_history` | Yes | Per-identity risk trends |
| `compliance_scores` | Yes | Framework compliance scores |
| `compliance_metrics` | Yes | Detailed compliance metrics |

### Resources (2 tables)

| Table | RLS | Purpose |
|-------|-----|---------|
| `azure_storage_accounts` | Yes | Storage account inventory |
| `azure_key_vaults` | Yes | Key vault inventory |

### Operations (10 tables)

| Table | RLS | Purpose |
|-------|-----|---------|
| `discovery_runs` | Yes | Discovery run history |
| `cloud_connections` | Yes | Cloud provider connectors |
| `settings` | Yes | Organization configuration |
| `activity_log` | Yes | Audit trail |
| `security_events` | Yes | Security event log |
| `notifications` | Yes | In-app notifications |
| `soar_playbooks` | Yes | SOAR automation playbooks |
| `soar_actions` | Yes | SOAR action history |
| `remediation_playbooks` | Yes | Remediation templates |
| `remediation_actions` | Yes | Remediation execution tracking |

### Platform (8 tables)

| Table | RLS | Purpose |
|-------|-----|---------|
| `organizations` | No | Tenant root (no RLS — needed for routing) |
| `users` | Yes | Platform user accounts |
| `api_keys` | Yes | API key management |
| `sso_auth_codes` | No | One-time SSO codes (60s TTL) |
| `refresh_tokens` | Yes | JWT refresh tokens |
| `dashboard_preferences` | Yes | Per-user dashboard layout |
| `copilot_conversations` | Yes | AI copilot chat history |
| `saved_views` | Yes | Saved identity query filters |

### P2 Telemetry (3 tables)

| Table | RLS | Purpose |
|-------|-----|---------|
| `workload_signin_events` | Yes | Azure AD sign-in logs |
| `workload_activity_stats` | Yes | Aggregated activity statistics |
| `workload_anomaly_events` | Yes | Behavioral anomaly events |

---

## References

- [Architecture](architecture.md) -- System architecture overview
- [Security Architecture](security-architecture.md) -- RLS and tenant isolation details
- [Discovery Engine](discovery-engine.md) -- How data is collected
- [Risk Scoring Model](risk-scoring.md) -- AGIRS computation from data model
- [Identity Graph](identity-graph.md) -- Graph construction and visualization
- [API Reference](api-reference.md) -- Querying the data model
