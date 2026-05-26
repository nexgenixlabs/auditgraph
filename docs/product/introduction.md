# Section 1 -- Introduction

## What Is AuditGraph

AuditGraph is a Cloud Identity Security platform that discovers, maps, and scores every identity across your cloud environments. It builds a real-time access graph connecting identities to their effective permissions, resources, and risk factors.

### Agentless Architecture

AuditGraph operates using an agentless architecture. The platform connects to cloud environments using secure provider APIs (Azure, AWS, GCP) and does not require any software deployment inside customer infrastructure. This approach reduces operational overhead, minimizes security risk, and enables rapid onboarding without changes to customer environments.

The platform answers a fundamental question that most organizations cannot answer today:

> **Who can access what, why do they have that access, and what is the blast radius if that identity is compromised?**

AuditGraph connects to your cloud environments through secure connectors, runs automated discovery scans, and produces a complete identity risk posture covering human users, service principals, managed identities, API keys, and federated credentials.

```
                        ┌──────────────────────────┐
                        │      AuditGraph          │
                        │   Identity Security       │
                        │       Platform            │
                        └─────────┬────────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
        ┌─────▼─────┐     ┌──────▼──────┐     ┌──────▼──────┐
        │   Azure    │     │    AWS      │     │    GCP      │
        │  Tenant    │     │  Account    │     │  Project    │
        └─────┬─────┘     └──────┬──────┘     └──────┬──────┘
              │                   │                   │
        ┌─────▼─────┐     ┌──────▼──────┐     ┌──────▼──────┐
        │ Identities │     │ Identities  │     │ Identities  │
        │  Roles     │     │  Policies   │     │  Bindings   │
        │  Creds     │     │  Keys       │     │  Keys       │
        │  Resources │     │  Resources  │     │  Resources  │
        └───────────┘     └─────────────┘     └─────────────┘
```

---

## Why Identity Security Matters

Cloud breaches are identity breaches. According to industry research, over 80% of cloud security incidents involve compromised or misconfigured identities. The attack surface has expanded dramatically:

| Challenge | Impact |
|-----------|--------|
| **Explosion of non-human identities** | Service principals, managed identities, and API keys outnumber human users 10:1 in most enterprises. These identities often have broad permissions and no oversight. |
| **Privilege sprawl** | Over-provisioned access accumulates over time. Users retain roles from past projects. Service accounts receive Owner permissions during setup and never get scoped down. |
| **Credential risk** | Expired credentials, long-lived secrets, and ownerless service principals create persistent attack vectors that traditional IAM tools miss. |
| **Identity drift** | Permissions change continuously. New role assignments, credential additions, and configuration changes happen daily without centralized tracking. |
| **Cross-cloud complexity** | Organizations using Azure, AWS, and GCP manage identities across incompatible IAM systems with no unified view of effective access. |
| **Audit fatigue** | Security teams cannot manually audit thousands of identities. Without automation, privileged access reviews become checkbox exercises. |

AuditGraph addresses each of these challenges through continuous automated discovery, graph-based access analysis, and quantitative risk scoring.

---

## Problems AuditGraph Solves

### 1. Visibility Gap

Most organizations do not know how many identities exist in their cloud environments, much less what each identity can access. The platform discovers every identity — human and non-human — and maps effective permissions across all connected environments.

### 2. Privilege Over-Provisioning

AuditGraph identifies identities with excessive permissions relative to their actual usage. A service principal with Global Administrator that has not signed in for 90 days represents quantifiable risk. The platform scores and prioritizes these findings.

### 3. Non-Human Identity Risk

Service principals, managed identities, and API keys are the fastest-growing and least-governed identity category. AuditGraph tracks credential expiry, ownership status, activity patterns, and blast radius for every non-human identity.

### 4. Identity Drift Detection

AuditGraph compares consecutive discovery snapshots to detect changes: new role assignments, removed permissions, credential additions, and configuration modifications. Drift detection runs automatically after every discovery scan.

### 5. Compliance Evidence

Security frameworks (SOC 2, ISO 27001, NIST 800-53, CIS Benchmarks) require evidence of access governance. AuditGraph produces compliance scorecards, audit trails, and exportable reports that map directly to framework controls.

### 6. Attack Path Analysis

AuditGraph computes privilege escalation chains showing how an attacker could move from an initial compromise to critical resources. Five escalation types are analyzed: direct escalation, ownership chains, PIM abuse, lateral movement, and credential exposure.

---

## Key Product Capabilities

| Capability | Description |
|------------|-------------|
| **Multi-Cloud Discovery** | Automated scanning of Azure, AWS, and GCP environments through secure connectors |
| **Identity Graph** | Visual representation of identity-to-resource access relationships with role and permission edges |
| **Risk Scoring (AGIRS)** | Proprietary composite scoring model combining human risk, non-human risk, and governance effectiveness |
| **Blast Radius Analysis** | Per-identity impact assessment: what can an attacker reach if this identity is compromised |
| **Attack Path Computation** | Automated detection of privilege escalation chains across identity relationships |
| **Drift Detection** | Snapshot comparison detecting permission changes, credential additions, and configuration modifications |
| **Anomaly Detection** | Behavioral analysis detecting permission escalation, risk score spikes, dormant reactivation, and credential surges |
| **Compliance Mapping** | Automated scoring against SOC 2, ISO 27001, NIST 800-53, and CIS Benchmark controls |
| **Remediation Engine** | Actionable fix recommendations with CLI commands, risk reduction estimates, and auto-execution |
| **SOAR Integration** | Automated response playbooks triggered by anomalies and drift events |
| **AI Copilot** | Natural language security analysis powered by Claude for investigating identities and interpreting risk |
| **Executive Reporting** | One-page posture summaries and detailed audit reports in PDF format |

---

## What AuditGraph Does NOT Do

AuditGraph monitors and analyzes identity security posture. It is not a replacement for operational security tooling. Understanding these boundaries prevents scope confusion during vendor evaluation and audit.

### AuditGraph does NOT replace:

| Category | What AuditGraph Does | What You Still Need |
|----------|---------------------|---------------------|
| **IAM Provisioning** | Discovers and audits existing access | An IAM system to provision and deprovision access (SailPoint, Saviynt, Azure AD, Okta) |
| **SIEM / Log Aggregation** | Generates structured security events in JSON format | A SIEM to aggregate logs from all sources (Splunk, Datadog, Sentinel) |
| **Endpoint Security** | Detects identity-based risk (credential exposure, privilege escalation) | EDR/XDR for device-level protection (CrowdStrike, Defender for Endpoint) |
| **Network Security** | Maps identity-to-resource access paths | Firewalls, NSGs, and network monitoring tools for traffic-level security |
| **Secrets Management** | Tracks credential expiry and rotation compliance | A vault for storing and distributing secrets (Azure Key Vault, HashiCorp Vault, AWS Secrets Manager) |
| **Vulnerability Scanning** | Scans IAM configurations and CIS benchmarks | A vulnerability scanner for OS/application CVEs (Qualys, Tenable, Trivy) |
| **Ticketing / ITSM** | Generates remediation recommendations with CLI commands | A ticket system for tracking remediation workflows (Jira, ServiceNow) |
| **MFA / Authentication** | Monitors MFA coverage via conditional access policies | An identity provider that enforces MFA (Azure AD, Okta, Duo) |

### AuditGraph does NOT:

- **Modify your cloud environment** — All API calls are read-only. The only exception is opt-in auto-remediation, which requires explicit admin approval and simulates actions by default before execution.
- **Store your data** — AuditGraph stores identity metadata (names, roles, credential expiry dates). It does not read or store file contents, email, chat messages, application data, or network traffic.
- **Replace access reviews** — AuditGraph identifies who needs review and quantifies risk. Human decision-makers still approve or revoke access.
- **Guarantee compliance** — AuditGraph maps controls to frameworks and generates evidence. It does not certify or attest compliance — that requires an independent auditor.
- **Provide real-time blocking** — AuditGraph scans on a configurable schedule (default 12 hours). It is not an inline enforcement point. For real-time access decisions, use conditional access policies and PIM.

### Where AuditGraph Fits in Your Security Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Operations                           │
│                                                                  │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│   │   SIEM   │  │  SOAR    │  │Ticketing │  │   EDR/XDR    │  │
│   │ (Splunk) │  │(Cortex)  │  │ (Jira)   │  │(CrowdStrike) │  │
│   └────▲─────┘  └────▲─────┘  └────▲─────┘  └──────────────┘  │
│        │              │              │                            │
│        │   Events     │  Playbooks   │  Remediations              │
│        │              │              │                            │
│   ┌────┴──────────────┴──────────────┴─────┐                    │
│   │            AuditGraph                    │                    │
│   │   Identity Posture + Risk Analysis       │                    │
│   └────────────────┬─────────────────────────┘                    │
│                    │  Read-Only                                    │
│        ┌───────────┼───────────┐                                  │
│        ▼           ▼           ▼                                  │
│   ┌─────────┐ ┌─────────┐ ┌─────────┐                           │
│   │  Azure  │ │   AWS   │ │   GCP   │                           │
│   │  AD/ARM │ │   IAM   │ │   IAM   │                           │
│   └─────────┘ └─────────┘ └─────────┘                           │
│                                                                  │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐                      │
│   │ Key Vault│  │  Okta    │  │ Network  │                      │
│   │ (Secrets)│  │  (IdP)   │  │ (FW/NSG) │                      │
│   └──────────┘  └──────────┘  └──────────┘                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## How AuditGraph Differs from Traditional IAM Tools

Traditional IAM tools focus on provisioning and access request workflows. They answer "how do I grant access" but not "what access exists and is it appropriate."

| Dimension | Traditional IAM | AuditGraph |
|-----------|----------------|------------|
| **Focus** | Access provisioning and request workflows | Access visibility, risk analysis, and governance |
| **Identity Types** | Primarily human users | Human users, service principals, managed identities, API keys |
| **Analysis Model** | Role-based access control lists | Graph-based effective access with blast radius |
| **Risk Quantification** | Binary (compliant / non-compliant) | Continuous scoring (0-100) with weighted risk factors |
| **Drift Detection** | Manual periodic reviews | Automated snapshot comparison after every scan |
| **Cross-Cloud** | Single cloud or directory | Unified view across Azure, AWS, and GCP |
| **Non-Human Identities** | Limited or no coverage | First-class coverage with credential tracking and ownership governance |
| **Remediation** | Manual ticket workflows | Automated fix recommendations with CLI commands and risk reduction estimates |
| **Time to Value** | Weeks to months of configuration | First discovery scan completes within minutes of connector setup |

---

## Identity Concepts

### Human Identities vs Non-Human Identities

AuditGraph categorizes every discovered identity into one of two primary classes:

**Human Identities** are accounts that represent people. They authenticate interactively and are subject to MFA, conditional access policies, and access reviews.

| Category | Description | Examples |
|----------|-------------|---------|
| `human_user` | Standard user accounts in the cloud directory | Employees, contractors |
| `guest` | External users invited to the directory | Vendors, partners, consultants |

**Non-Human Identities (NHI)** are accounts that represent applications, services, and automated processes. They authenticate programmatically and often have persistent credentials.

| Category | Description | Examples |
|----------|-------------|---------|
| `service_principal` | Application identities registered in the directory | Custom apps, third-party SaaS integrations |
| `managed_identity_system` | System-assigned identities tied to a specific Azure resource | VM-assigned identities, Function App identities |
| `managed_identity_user` | User-assigned identities that can be shared across resources | Shared workload identities |
| `iam_user` | AWS IAM users with programmatic access | CI/CD service users, automation accounts |
| `iam_role` | AWS IAM roles assumed by services | Lambda execution roles, ECS task roles |
| `gcp_service_account` | GCP service accounts with key-based authentication | Compute Engine SAs, Cloud Function SAs |

AuditGraph also identifies `microsoft_internal` identities (first-party Microsoft service principals) and separates them from customer-managed identities to prevent false-positive risk findings.

### The Identity Graph Concept

An identity graph is a directed graph where:

- **Nodes** represent entities: identities, roles, permissions, credentials, subscriptions, resource groups, and resources
- **Edges** represent relationships: "has role," "scoped to," "owns," "trusts," "has credential"

```
    ┌──────────┐     has role      ┌────────────┐
    │ Identity ├────────────────►  │    Role     │
    └──────────┘                   └──────┬─────┘
                                          │ scoped to
                                          ▼
                                   ┌────────────┐
                                   │Subscription│
                                   └──────┬─────┘
                                          │ contains
                                          ▼
                                   ┌────────────┐
                                   │  Resource   │
                                   │   Group     │
                                   └──────┬─────┘
                                          │ contains
                                          ▼
                                   ┌────────────┐
                                   │  Resource   │
                                   │ (Key Vault) │
                                   └────────────┘
```

Graph traversal enables powerful analysis:

- **Effective access**: Follow edges from an identity to determine all resources it can reach
- **Blast radius**: Count the resources, subscriptions, and critical assets reachable from a single identity
- **Attack paths**: Find multi-hop escalation chains through ownership, PIM eligibility, and credential exposure
- **Orphan detection**: Identify identities with no incoming ownership edges

### Privilege Risk Analysis

AuditGraph assigns a **tier** to every identity based on its effective privilege level:

| Tier | Meaning | Examples |
|------|---------|---------|
| **T0** | Tenant-wide control | Global Administrator, Privileged Role Administrator |
| **T1** | Subscription-wide control | Subscription Owner, User Access Administrator |
| **T2** | Resource group control | Resource Group Contributor, Key Vault Administrator |
| **T3** | Single resource access | Storage Blob Reader, specific resource role assignments |

Higher-tier identities have larger blast radius. The combination of tier, activity status, credential health, and ownership determines the identity's overall risk score.

---

## Platform Flow Overview

For executive stakeholders, the following diagram illustrates how AuditGraph operates end-to-end:

```
Cloud Environment (Azure / AWS / GCP)
        ↓
Connector (secure, read-only API access)
        ↓
Discovery Engine (identity & entitlement scanning)
        ↓
Identity Graph (access relationship mapping)
        ↓
Risk Engine (AGIRS scoring)
        ↓
CISO Dashboard & Reports
```

Each stage is fully automated. After initial connector setup, discovery runs on a configurable schedule and requires no manual intervention.

---

## Platform Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Organization                                │
│                                                                     │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│   │  Azure        │  │  AWS         │  │  GCP         │            │
│   │  Connector    │  │  Connector   │  │  Connector   │            │
│   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘            │
│          │                  │                  │                     │
│          ▼                  ▼                  ▼                     │
│   ┌──────────────────────────────────────────────────┐             │
│   │              Discovery Engine                     │             │
│   │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │             │
│   │  │ Identity  │ │ Entitle- │ │ Resource         │ │             │
│   │  │ Discovery │ │ ment     │ │ Discovery        │ │             │
│   │  └──────────┘ └──────────┘ └──────────────────┘ │             │
│   └──────────────────────┬───────────────────────────┘             │
│                          │                                          │
│          ┌───────────────┼───────────────┐                         │
│          ▼               ▼               ▼                         │
│   ┌────────────┐  ┌────────────┐  ┌──────────────┐                │
│   │  Access     │  │   Risk     │  │  Compliance  │                │
│   │  Graph      │  │   Engine   │  │  Engine      │                │
│   └────────────┘  └────────────┘  └──────────────┘                │
│                                                                     │
│   ┌──────────────────────────────────────────────────┐             │
│   │  Post-Discovery Pipeline                          │             │
│   │  ┌────────┐ ┌──────────┐ ┌──────────┐ ┌───────┐ │             │
│   │  │ Drift  │ │ Anomaly  │ │ Attack   │ │ SOAR  │ │             │
│   │  │ Detect │ │ Detect   │ │ Paths    │ │       │ │             │
│   │  └────────┘ └──────────┘ └──────────┘ └───────┘ │             │
│   └──────────────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────────────┘
```

Each organization in AuditGraph can connect multiple cloud environments. Each connector represents a cloud boundary (Azure Tenant, AWS Account, GCP Project). Discovery runs execute per-connector, and data is isolated at the connector level through the platform's Row Level Security model.

---

## Next Steps

- [Architecture](architecture.md) -- Detailed platform architecture and data model
- [Connectors](connectors.md) -- Set up your first cloud connector
- [Risk Scoring Model](risk-scoring.md) -- Understand how AuditGraph quantifies risk
