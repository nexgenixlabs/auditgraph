# Compliance Mapping

## Overview

AuditGraph maps identity and access findings to major compliance frameworks, enabling organizations to demonstrate continuous compliance through automated evidence collection, posture scoring, and gap analysis.

This section documents how AuditGraph controls align to each supported framework, what evidence is generated, and how to use the platform for audit preparation.

---

## Supported Frameworks

| Framework | Version | Coverage | Focus Area |
|-----------|---------|----------|------------|
| [SOC 2 Type II](#soc-2-type-ii) | 2017 | 18 controls | Access control, monitoring, encryption |
| [ISO 27001](#iso-27001) | 2022 | 14 controls | Information security management |
| [NIST 800-53](#nist-800-53) | Rev 5 | 22 controls | Federal security and privacy |
| [NIST CSF](#nist-cybersecurity-framework) | 2.0 | 12 functions | Risk management framework |
| [CIS Benchmarks](#cis-benchmarks) | v2.0 | 33 checks | Azure, AWS, GCP hardening |
| [Azure Security Benchmark](#azure-security-benchmark) | v3 | 16 controls | Azure-specific best practices |
| [AWS Security Best Practices](#aws-security-best-practices) | Current | 12 controls | AWS IAM and resource security |
| [HIPAA](#hipaa) | 2013 | 10 controls | Healthcare data protection |
| [PCI-DSS](#pci-dss) | v4.0 | 8 controls | Payment card data security |
| [SOX](#sox-it-controls) | Section 404 | 6 controls | Financial IT controls |
| [GDPR/CCPA](#gdpr--ccpa) | Current | 5 controls | Data privacy and access rights |

---

## SOC 2 Type II

SOC 2 evaluates controls across five Trust Services Criteria. AuditGraph provides automated evidence for access control, monitoring, and change management.

### Control Mapping

| SOC 2 Criteria | Control | AuditGraph Feature | Evidence Source |
|---------------|---------|-------------------|----------------|
| **CC6.1** | Logical access security | RBAC (8 client roles, 4 portal roles) | `GET /api/auth/me` (permissions), user role audit |
| **CC6.2** | Access provisioning | JIT provisioning (SSO/SAML), onboarding stages | `users` table, `sso_auth_codes`, activity log |
| **CC6.3** | Access removal | Ghost account detection, drift monitoring | HIRI H1 factor, `drift_reports` table |
| **CC6.4** | Privileged access restriction | PIM adoption tracking, T0/T1 tier classification | GEI PIM component, `pim_eligible_assignments` |
| **CC6.5** | Authentication mechanisms | JWT auth, OIDC/SAML SSO, MFA via CA policies | `ca_policies`, SSO configuration |
| **CC6.6** | Encryption of data in transit | TLS 1.3, HSTS (1-year max-age, preload) | Security headers, health endpoint |
| **CC6.7** | Encryption of data at rest | Fernet field-level encryption | Encrypted `client_secret` fields (`enc:` prefix) |
| **CC6.8** | Access reviews | Quarterly access review framework | `compliance_metrics` table, review history |
| **CC7.1** | Monitoring | Anomaly detection (8 types), security events | `anomalies` table, `security_events` table |
| **CC7.2** | Change detection | Drift detection between discovery runs | `drift_reports`, `GET /api/drift/history` |
| **CC7.3** | Incident response | SOAR playbooks, automated response | `soar_playbooks`, `soar_actions` tables |
| **CC8.1** | Change management | Activity logging, admin audit trail | `activity_log`, `admin_audit_log` |

### Evidence Generation

AuditGraph automatically generates SOC 2 evidence packages:

```
SOC 2 Evidence Package
├── Access Control Report
│   ├── Current RBAC assignments (all users with roles)
│   ├── Privileged access inventory (T0/T1 identities)
│   ├── Ghost account count (should be 0)
│   └── Access review completion rate
├── Change Detection Report
│   ├── 90-day drift history
│   ├── Role assignment changes
│   └── Credential lifecycle events
├── Monitoring Report
│   ├── Anomaly detection summary
│   ├── Security event log (12+ event types)
│   └── SOAR action history
└── Encryption Report
    ├── Credential encryption verification
    ├── TLS configuration
    └── Key rotation history
```

---

## ISO 27001

ISO 27001:2022 defines controls in Annex A. AuditGraph maps to identity and access management controls.

### Control Mapping

| ISO 27001 Control | Description | AuditGraph Feature | Metric |
|-------------------|-------------|-------------------|--------|
| **A.5.15** | Access control policy | RBAC enforcement, least privilege monitoring | Over-privileged count (HIRI H3) |
| **A.5.16** | Identity management | Identity lifecycle tracking, activity status | Total identities, activity_status field |
| **A.5.17** | Authentication information | Password policy (12+ chars, complexity), credential rotation | Password policy check, credential expiry |
| **A.5.18** | Access rights provisioning | JIT provisioning, PIM, onboarding stages | GEI PIM Adoption score |
| **A.5.24** | Information security incident | Anomaly detection, SOAR response | Anomaly count, SOAR action success rate |
| **A.5.25** | Assessment of events | Risk scoring (AGIRS), blast radius computation | AGIRS score, blast_radius_score |
| **A.8.2** | Privileged access rights | T0/T1 tier classification, PIM tracking | Privileged identity count, PIM coverage % |
| **A.8.3** | Information access restriction | RLS tenant isolation, scope-based RBAC | RLS policy count (44 tables) |
| **A.8.4** | Access to source code | Not applicable (AuditGraph monitors cloud IAM) | — |
| **A.8.5** | Secure authentication | OIDC JWKS verification, SAML signed assertions | SSO configuration status |
| **A.8.9** | Configuration management | Conditional access policies, security settings | CA policy coverage % |
| **A.8.15** | Logging | Activity log, security events, audit trail | Activity log entry count |
| **A.8.16** | Monitoring activities | Scheduled discovery, drift detection, anomalies | Discovery frequency, anomaly detection rate |
| **A.8.24** | Use of cryptography | Fernet/MultiFernet encryption, key rotation | Encryption key count, rotation date |

---

## NIST 800-53

NIST Special Publication 800-53 Rev 5 defines security and privacy controls for federal information systems.

### Control Mapping

| NIST 800-53 Control | Family | AuditGraph Feature | Evidence |
|---------------------|--------|-------------------|----------|
| **AC-2** | Account Management | Identity discovery, lifecycle tracking, ghost detection | Identity inventory, H1 ghost count |
| **AC-2(3)** | Disable Accounts | Zombie identity detection (H5/N3) | Zombie count, disabled + privileged list |
| **AC-2(4)** | Automated Audit | Activity logging, security event tracking | `activity_log`, `security_events` |
| **AC-3** | Access Enforcement | RBAC, RLS, scope-based authorization | Role assignment inventory, RLS policies |
| **AC-5** | Separation of Duties | Multi-SPN strategy, T0/T1 segregation | SPN-per-workload analysis |
| **AC-6** | Least Privilege | Over-privilege detection (H3), scope analysis | Over-privileged %, subscription-level role count |
| **AC-6(1)** | Authorized Access | PIM eligible assignments, JIT activation | PIM coverage %, activation logs |
| **AC-6(5)** | Privileged Accounts | T0/T1 tier classification, standing privilege audit | T0 identity count, PIM adoption % |
| **AC-6(9)** | Log Privileged Functions | Admin audit log, PIM activation justification | `admin_audit_log`, `pim_activations` |
| **AC-6(10)** | Prohibit Non-Privileged Users | Role-based UI restrictions, decorator enforcement | RBAC middleware, `require_role()` |
| **AC-17** | Remote Access | Conditional access policies, MFA enforcement | CA policy inventory, MFA coverage % |
| **AU-2** | Audit Events | 12+ security event types, activity log | Event type catalog, log retention policy |
| **AU-3** | Content of Audit Records | Structured JSON events with user/tenant/IP/timestamp | Event schema documentation |
| **AU-6** | Audit Review | CISO Dashboard, anomaly detection, drift review | AGIRS trend, anomaly stats |
| **IA-2** | Identification and Authentication | JWT, OIDC, SAML, API keys | Auth mechanism inventory |
| **IA-4** | Identifier Management | Unique identity tracking (identity_id per cloud) | Identity deduplication |
| **IA-5** | Authenticator Management | Credential expiry tracking, rotation monitoring | Expired credential count, rotation schedule |
| **RA-3** | Risk Assessment | AGIRS scoring model, per-identity risk analysis | AGIRS score, risk factor breakdown |
| **RA-5** | Vulnerability Monitoring | CIS benchmark checks, resource security scanning | CIS compliance %, resource risk scores |
| **SC-12** | Cryptographic Key Establishment | Fernet key management, MultiFernet rotation | Encryption key configuration |
| **SC-13** | Cryptographic Protection | AES-128-CBC + HMAC-SHA256 (Fernet), TLS 1.3 | Encryption algorithm inventory |
| **SI-4** | System Monitoring | Anomaly detection, health monitoring, circuit breakers | Anomaly engine, health endpoints |

---

## NIST Cybersecurity Framework

The NIST CSF 2.0 organizes controls into six core functions.

### Function Mapping

| CSF Function | Category | AuditGraph Capability |
|-------------|----------|----------------------|
| **IDENTIFY** | Asset Management | Identity discovery across Azure, AWS, GCP |
| **IDENTIFY** | Risk Assessment | AGIRS scoring, blast radius computation |
| **IDENTIFY** | Governance | GEI score, ownership coverage, access reviews |
| **PROTECT** | Access Control | RBAC, PIM, conditional access monitoring |
| **PROTECT** | Data Security | Fernet encryption, credential masking, RLS |
| **PROTECT** | Identity Management | Lifecycle tracking, provisioning/deprovisioning |
| **DETECT** | Anomalies & Events | 8 anomaly types, behavioral analysis |
| **DETECT** | Continuous Monitoring | Scheduled discovery (12h), drift detection |
| **DETECT** | Detection Processes | SOAR playbooks, automated alerting |
| **RESPOND** | Response Planning | Remediation playbooks, SOAR integration |
| **RESPOND** | Communications | Slack/Teams notifications, security events |
| **RECOVER** | Recovery Planning | Credential rotation API, remediation center |

---

## CIS Benchmarks

AuditGraph evaluates cloud resources against CIS (Center for Internet Security) benchmark controls.

### Azure CIS Benchmark (v2.0)

#### Identity & Access (7 checks)

| CIS Control | Description | AuditGraph Check | Severity |
|-------------|-------------|------------------|----------|
| **1.1** | Ensure MFA is enabled for all privileged users | CA policy analysis for T0/T1 identities | Critical |
| **1.2** | Ensure MFA is enabled for all users | CA policy all-user coverage check | High |
| **1.3** | Ensure guest users are reviewed monthly | External guest tracking (HIRI H4) | Medium |
| **1.4** | Ensure no custom Owner roles | RBAC custom role analysis | Medium |
| **1.5** | Ensure PIM is configured for privileged roles | GEI PIM Adoption component | High |
| **1.6** | Ensure access reviews are configured | GEI Access Reviews component | Medium |
| **1.7** | Ensure service principal credentials are rotated | Credential expiry tracking (NHIRI N4) | High |

#### Storage Account Security (13 checks)

| CIS Control | Description | Field Checked | Pass Criteria |
|-------------|-------------|--------------|---------------|
| **3.1** | Require secure transfer | `https_only` | `true` |
| **3.2** | Enable storage account encryption | `encryption_key_source` | Not null |
| **3.3** | Disable anonymous blob access | `allow_blob_public_access` | `false` |
| **3.4** | Use customer-managed keys | `encryption_key_source` | `Microsoft.Keyvault` |
| **3.5** | Enable soft delete for blobs | `blob_soft_delete_enabled` | `true` |
| **3.6** | Require minimum TLS 1.2 | `min_tls_version` | `TLS1_2` |
| **3.7** | Enable infrastructure encryption | `infrastructure_encryption` | `true` |
| **3.8** | Restrict default network access | `network_default_action` | `Deny` |
| **3.9** | Enable trusted Microsoft services | `network_bypass` | Contains `AzureServices` |
| **3.10** | Disable public network access | `public_network_access` | `Disabled` |
| **3.11** | Enable private endpoint connections | `private_endpoint_connections` | Non-empty |
| **3.12** | Enable blob versioning | `blob_versioning_enabled` | `true` |
| **3.14** | Enable diagnostic logging | `diagnostic_logging_enabled` | `true` |

#### Key Vault Security (10 checks)

| CIS Control | Description | Field Checked | Pass Criteria |
|-------------|-------------|--------------|---------------|
| **8.1** | Enable soft delete | `soft_delete_enabled` | `true` |
| **8.2** | Enable purge protection | `purge_protection_enabled` | `true` |
| **8.3** | Use RBAC authorization | `rbac_authorization` | `true` |
| **8.4** | Restrict default network access | `network_default_action` | `Deny` |
| **8.5** | Disable public network access | `public_network_access` | `Disabled` |
| **8.6** | Enable private endpoint connections | `private_endpoint_connections` | Non-empty |
| **8.7** | Set key expiration dates | `key_expiry_items` | All keys have expiry |
| **8.8** | Set secret expiration dates | `secret_expiry_items` | All secrets have expiry |
| **8.9** | Set certificate expiration dates | `certificate_expiry_items` | All certs have expiry |
| **8.10** | Enable key rotation reminders | `key_rotation_compliance` | Rotation within 90 days |

### AWS CIS Benchmark

| CIS Control | Description | AuditGraph Check |
|-------------|-------------|------------------|
| **1.4** | Ensure no root access keys | IAM root account key check |
| **1.5** | Ensure MFA is enabled for root | Root MFA status |
| **1.10** | Ensure unused credentials are disabled | Dormant IAM user detection |
| **1.12** | Ensure credentials unused for 90 days are disabled | Activity status = stale |
| **1.14** | Ensure access keys are rotated every 90 days | Key age > 90 days |
| **1.16** | Ensure IAM policies are attached only to groups/roles | Direct user policy attachment |

### GCP CIS Benchmark

| CIS Control | Description | AuditGraph Check |
|-------------|-------------|------------------|
| **1.1** | Ensure service account has no admin privileges | Over-privileged SA detection |
| **1.4** | Ensure service account keys are rotated within 90 days | Key age tracking |
| **1.5** | Ensure no default service account is used | Default SA identification |
| **1.6** | Ensure user-managed service account keys are managed | Key inventory |

---

## Azure Security Benchmark

The Azure Security Benchmark (ASB) v3 provides Azure-specific security guidance.

### Control Mapping

| ASB Control | Category | AuditGraph Feature |
|-------------|----------|-------------------|
| **IM-1** | Use centralized identity | SSO/OIDC integration monitoring |
| **IM-2** | Protect identity and authentication systems | JWT security, OIDC JWKS verification |
| **IM-3** | Manage application identities safely | SPN dashboard, app registration audit |
| **IM-4** | Authenticate server and services | Managed identity tracking |
| **IM-6** | Use strong authentication controls | CA policy MFA coverage |
| **IM-7** | Restrict resource access based on conditions | Conditional access policy inventory |
| **IM-8** | Restrict exposure of credentials | Credential encryption, rotation monitoring |
| **PA-1** | Protect and limit highly privileged users | T0/T1 classification, PIM tracking |
| **PA-2** | Restrict administrative access to business-critical systems | Blast radius analysis, scope mapping |
| **PA-3** | Manage access lifecycle | Ghost detection, dormant monitoring |
| **PA-4** | Set up emergency access | Break-glass account identification |
| **PA-7** | Follow just enough administration principle | Over-privilege detection, role right-sizing |
| **LT-1** | Enable logging | Activity log, security events |
| **LT-3** | Enable logging for security investigation | P2 telemetry, sign-in logs |
| **LT-4** | Enable network logging | Resource network access tracking |
| **DS-2** | Ensure data encryption in transit | TLS enforcement, HSTS headers |

---

## AWS Security Best Practices

### Control Mapping

| AWS Best Practice | AuditGraph Feature |
|-------------------|-------------------|
| **IAM.1** | Require MFA for console access | CA policy equivalent monitoring |
| **IAM.2** | Do not use root account access keys | Root account key detection |
| **IAM.3** | Rotate IAM access keys regularly | Key age tracking, rotation alerts |
| **IAM.4** | Remove unused IAM credentials | Dormant user detection (90-day threshold) |
| **IAM.5** | Enable MFA for privileged IAM users | Privileged access monitoring |
| **IAM.6** | Use IAM roles instead of long-term credentials | Role vs user access analysis |
| **IAM.7** | Minimize wildcard permissions | Over-privilege detection |
| **IAM.8** | Remove unnecessary IAM policies | Unused policy identification |
| **IAM.9** | Use groups for permissions | Direct user policy attachment check |
| **IAM.10** | Review cross-account access | Trust relationship analysis |
| **IAM.11** | Ensure access keys are used | Unused access key detection |
| **IAM.12** | Monitor for policy changes | Drift detection for IAM changes |

---

## HIPAA

HIPAA requires administrative, physical, and technical safeguards for protected health information (PHI).

### Control Mapping

| HIPAA Section | Requirement | AuditGraph Feature |
|---------------|-------------|-------------------|
| **164.312(a)(1)** | Access control | RBAC enforcement, RLS tenant isolation |
| **164.312(a)(2)(i)** | Unique user identification | JWT subject claims, identity_id tracking |
| **164.312(a)(2)(iii)** | Automatic logoff | JWT TTL (30/60 min access, 7-day refresh) |
| **164.312(a)(2)(iv)** | Encryption at rest | Fernet field encryption for credentials |
| **164.312(b)** | Audit controls | Activity log, security events, admin audit |
| **164.312(c)(1)** | Integrity | Snapshot SHA-256 hash + HMAC signature |
| **164.312(d)** | Person or entity authentication | JWT, OIDC, SAML, API key auth |
| **164.312(e)(1)** | Transmission security | TLS 1.3, HSTS enforcement |
| **164.308(a)(3)** | Workforce security | Password policy (12+ chars, complexity) |
| **164.308(a)(5)** | Security awareness | Risk scoring, remediation recommendations |

---

## PCI-DSS

PCI-DSS v4.0 requirements relevant to identity and access management.

### Control Mapping

| PCI-DSS Requirement | Description | AuditGraph Feature |
|---------------------|-------------|-------------------|
| **7.1** | Limit access to system components | Least privilege monitoring, over-privilege detection |
| **7.2** | Ensure appropriate access based on need-to-know | Role-based access analysis, blast radius |
| **7.3** | Manage access via an access control system | RBAC inventory, scope-based authorization |
| **8.2** | Identify users and authenticate access | JWT authentication, unique user IDs |
| **8.3** | Secure all authentication factors | Password policy, credential encryption |
| **8.4** | Implement MFA for all access | CA policy MFA coverage monitoring |
| **8.6** | Manage service accounts properly | SPN governance, ownership tracking |
| **10.2** | Implement audit trail mechanisms | Activity log, security event logging |

---

## SOX IT Controls

Sarbanes-Oxley Section 404 IT General Controls (ITGC) related to identity.

### Control Mapping

| SOX ITGC | Description | AuditGraph Feature |
|----------|-------------|-------------------|
| **AC-01** | Logical access provisioning | Identity lifecycle, onboarding tracking |
| **AC-02** | Privileged access management | T0/T1 classification, PIM monitoring |
| **AC-03** | Access removal (termination) | Ghost account detection (H1), zombie detection (H5) |
| **AC-04** | Periodic access review | Access review framework, GEI scoring |
| **AC-05** | Password management | Password policy enforcement (12+ chars) |
| **CM-01** | Change management | Drift detection, activity logging |

---

## GDPR / CCPA

Data privacy regulations with identity and access implications.

### Control Mapping

| Regulation | Article | AuditGraph Feature |
|-----------|---------|-------------------|
| **GDPR Art. 5** | Data minimization | Least privilege monitoring, over-privilege reduction |
| **GDPR Art. 25** | Data protection by design | RLS tenant isolation, Fernet encryption |
| **GDPR Art. 30** | Records of processing | Activity log, discovery run history |
| **GDPR Art. 32** | Security of processing | AGIRS scoring, continuous monitoring |
| **CCPA 1798.150** | Security procedures | Encryption at rest, access controls |

---

## Compliance Scoring

### How Scores Are Computed

AuditGraph computes compliance scores per framework based on control pass rates:

```
Framework Score = (Controls Passing / Total Controls) × 100

Where each control is evaluated as:
  PASS:    All criteria met
  PARTIAL: Some criteria met (scores 50%)
  FAIL:    Criteria not met (scores 0%)
  N/A:     Not applicable to this environment (excluded from total)
```

### Identity Posture Metrics

AuditGraph tracks 14 identity posture metrics that map across frameworks:

| Metric | Description | Frameworks |
|--------|-------------|------------|
| `mfa_coverage` | % of identities covered by MFA policies | SOC 2, NIST, CIS, PCI-DSS |
| `pim_adoption` | % of T0/T1 identities using PIM | SOC 2, ISO 27001, NIST |
| `ghost_account_pct` | % of identities that are ghost accounts | SOC 2, NIST, SOX |
| `orphaned_spn_pct` | % of SPNs without owners | ISO 27001, Azure ASB |
| `over_privileged_pct` | % of identities over-privileged | NIST, CIS, PCI-DSS |
| `credential_rotation_compliance` | % of credentials rotated on schedule | CIS, AWS Best Practices |
| `dormant_privileged_count` | Count of dormant privileged identities | NIST, SOX |
| `external_guest_count` | Count of external guests with roles | CIS, GDPR |
| `access_review_completion` | % of access reviews completed on time | SOC 2, SOX, ISO 27001 |
| `ca_policy_coverage` | % of identities under conditional access | Azure ASB, CIS |
| `encryption_compliance` | Whether all credentials are encrypted | HIPAA, PCI-DSS, GDPR |
| `logging_coverage` | Whether audit logging is enabled | SOC 2, HIPAA, PCI-DSS |
| `resource_cis_compliance` | % of resources passing CIS checks | CIS, Azure ASB |
| `ownership_coverage` | % of SPNs with assigned owners | ISO 27001, Azure ASB |

### Root Cause Categories

When compliance gaps are identified, AuditGraph classifies them into 7 root cause categories:

| Category | Description | Example |
|----------|-------------|---------|
| `identity_hygiene` | Inactive, ghost, or zombie identities | 44 ghost accounts retaining role assignments |
| `privilege_management` | Over-privileged or standing T0 access | 73 identities with broader access than needed |
| `credential_management` | Expired or unrotated credentials | 5 SPNs with expired client secrets |
| `governance_gaps` | Missing ownership, reviews, or PIM | 16 orphaned SPNs with no human owner |
| `configuration_drift` | Security settings changed unexpectedly | New T0 role assignment detected in drift |
| `resource_security` | Resource misconfigurations (CIS) | Storage account with public blob access enabled |
| `monitoring_gaps` | Missing telemetry or detection | No P2 sign-in log ingestion configured |

---

## Using AuditGraph for Audit Preparation

### Pre-Audit Checklist

```
1. Run Deep Discovery
   POST /api/runs/trigger
   { "connection_id": 1, "scan_mode": "deep" }

2. Review AGIRS Score
   GET /api/risk/summary/full
   Target: Grade B (score >= 80) before audit

3. Check Compliance Dashboard
   GET /api/compliance/scores
   Review pass/fail per framework

4. Generate Evidence Report
   GET /api/reports/data
   Download comprehensive PDF with all metrics

5. Review Open Anomalies
   GET /api/anomalies?resolved=false
   Resolve or document all open findings

6. Verify Drift Baseline
   GET /api/drift/history
   Ensure no unexpected changes in the last 30 days
```

### Evidence Endpoints

| Endpoint | Evidence Type |
|----------|--------------|
| `GET /api/risk/summary/full` | AGIRS score, risk factor breakdown, identity counts |
| `GET /api/compliance/scores` | Framework-specific compliance scores |
| `GET /api/compliance/metrics` | Detailed compliance metric values |
| `GET /api/identities?risk_level=critical` | Critical risk identity inventory |
| `GET /api/drift/history` | Change detection history |
| `GET /api/anomalies/stats` | Anomaly detection summary |
| `GET /api/activity?limit=500` | Audit trail (180-day retention) |
| `GET /api/resources/stats` | Resource security compliance summary |
| `GET /api/reports/data` | Comprehensive report data for PDF generation |

### Audit Evidence Export

Auditors require evidence in specific formats. AuditGraph supports four export methods:

#### 1. PDF Reports

Generate comprehensive audit reports directly from the platform.

**Executive Summary (1-page):**
- AGIRS posture score with visual gauge
- 6-metric grid (ghost accounts, orphaned SPNs, over-privileged, dormant privileged, blast radius, credential risk)
- Executive narrative summary

**Full Audit Report (multi-page):**
- Cover page with organization name, date, scan metadata
- Executive summary section
- Compliance scorecard per framework
- Top 10 critical risk identities with detail
- Remediation playbook with CLI commands
- Evidence appendix with data hashes

```
Via the UI:  Reports → Select Report Type → Download PDF
Via the API: GET /api/reports/data → client-side PDF generation (jsPDF)
```

#### 2. JSON Export

Every API endpoint returns structured JSON suitable for ingestion by audit tools, GRC platforms, and SIEM systems.

**Key endpoints for JSON evidence:**

| Evidence Need | Endpoint | Format |
|---------------|----------|--------|
| Complete risk posture | `GET /api/risk/summary/full` | JSON (scores, breakdowns, counts) |
| Identity inventory | `GET /api/identities?limit=500` | JSON (paginated, filterable) |
| Compliance scores | `GET /api/compliance/scores` | JSON (per-framework pass rates) |
| Compliance metrics | `GET /api/compliance/metrics` | JSON (14 posture metrics) |
| Change history | `GET /api/drift/history` | JSON (per-run delta reports) |
| Anomaly log | `GET /api/anomalies` | JSON (filterable by type, severity) |
| Audit trail | `GET /api/activity?limit=500` | JSON (180-day retention) |
| Resource compliance | `GET /api/resources/stats` | JSON (CIS pass/fail counts) |

**Example: Extracting SOC 2 evidence via API:**

```bash
# 1. Risk posture snapshot
curl -H "Authorization: Bearer $TOKEN" \
  https://api.auditgraph.ai/api/risk/summary/full > risk_posture.json

# 2. All critical identities
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.auditgraph.ai/api/identities?risk_level=critical&limit=500" > critical_identities.json

# 3. 90-day drift history
curl -H "Authorization: Bearer $TOKEN" \
  https://api.auditgraph.ai/api/drift/history > drift_history.json

# 4. Audit trail
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.auditgraph.ai/api/activity?limit=500" > audit_trail.json
```

#### 3. CSV Export

The Identities page and SPN Dashboard support direct CSV download from the UI.

**CSV exports include:**

| Export | Columns | Access |
|--------|---------|--------|
| **Identity List** | display_name, identity_category, cloud, risk_level, risk_score, tier, activity_status, owner_count, credential_count, blast_radius_score | Identities page → Export CSV |
| **SPN Inventory** | display_name, risk_level, blast_radius, critical_roles, credential_risk, next_expiry, activity_status, owner_count | SPN Dashboard → Export CSV |
| **SPN Privilege Report** | Per-SPN: all RBAC roles, Entra roles, permissions, credentials, owners, recommendations | SPN Detail → Download PDF |

CSV exports respect the current filter state — if you filter to "critical risk, Azure only," the CSV contains only matching rows.

#### 4. API Key Access

For automated evidence collection, create a dedicated API key:

```http
POST /api/api-keys
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "name": "SOC2 Audit Evidence Collector",
  "role": "viewer",
  "expires_at": "2026-06-30T00:00:00Z"
}
```

**Response (key shown only once):**

```json
{
  "id": 5,
  "name": "SOC2 Audit Evidence Collector",
  "key": "ag_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p",
  "role": "viewer",
  "expires_at": "2026-06-30T00:00:00Z"
}
```

Use the API key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: ag_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p" \
  https://api.auditgraph.ai/api/risk/summary/full
```

**Best practices for audit API keys:**
- Use `viewer` role (read-only, least privilege)
- Set expiration to the audit window end date
- Create a dedicated key per auditor or GRC tool
- Review usage via `GET /api/api-keys` (tracks `last_used_at`)
- Revoke immediately after audit completes

#### Evidence Integrity

All discovery snapshots include integrity metadata:

| Field | Purpose |
|-------|---------|
| `snapshot_hash` | SHA-256 hash of the complete discovery snapshot |
| `snapshot_signature` | HMAC signature for tamper detection |
| `computed_at` | Timestamp of risk computation |
| `discovery_run_id` | Traceable link to the source scan |

Auditors can verify that evidence data has not been modified since discovery by comparing the `snapshot_hash` against the raw snapshot data.

---

### Continuous Compliance

Rather than point-in-time audits, AuditGraph enables continuous compliance monitoring:

| Activity | Frequency | Metric |
|----------|-----------|--------|
| Identity discovery | Every 12 hours | Total identities, risk distribution |
| Drift detection | After each scan | Change count, severity |
| Anomaly detection | After each scan | Open anomaly count |
| AGIRS computation | After each scan | Score trend (improving/declining) |
| CIS benchmark evaluation | After each scan | Resource compliance % |
| Compliance scoring | After each scan | Framework pass rates |

### Recommended Governance Targets

| Metric | Target | Grade Impact |
|--------|--------|-------------|
| AGIRS Score | >= 80 (Grade B) | Direct composite score |
| Ghost accounts | 0 | HIRI H1 component |
| Over-privileged identities | < 10% | HIRI H3 component |
| SPN ownership coverage | >= 90% | GEI Ownership component |
| PIM adoption for T0 | 100% | GEI PIM component |
| Credential rotation compliance | >= 95% | NHIRI N4 component |
| CIS resource compliance | >= 85% | Resource security posture |

---

## References

- [Risk Scoring Model](risk-scoring.md) -- AGIRS methodology and risk factors
- [Security Architecture](security-architecture.md) -- Platform security controls
- [Security Posture](security-posture.md) -- Platform self-assessment
- [Security Features](security-features.md) -- Feature-level security documentation
- [Best Practices](best-practices.md) -- Operational security recommendations
- [Data Model](data-model.md) -- Compliance-related tables and schemas
