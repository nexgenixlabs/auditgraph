# Section 7 -- Identity Graph

## Overview

AuditGraph builds a directed access graph for every discovered identity. The graph connects identities to their roles, permissions, credentials, and resources, enabling powerful analysis of effective access, blast radius, and privilege escalation paths.

---

## Graph Structure

### Nodes

The identity graph uses 13 node types:

| Node Type | Description | Example |
|-----------|-------------|---------|
| `identity` | The identity being analyzed | Service principal "prod-automation" |
| `risk_summary` | Aggregated risk score and factors | Risk: 85 (Critical), Tier: T0 |
| `blast_radius` | Impact assessment summary | 12 subscriptions, 307 resources reachable |
| `owner` | Identity that owns this entity | User "jane@company.com" |
| `federated_trust` | External trust relationship | GitHub Actions OIDC federation |
| `role` | Azure RBAC or Entra directory role | Owner, Global Administrator |
| `permission` | Microsoft Graph API permission | Directory.ReadWrite.All |
| `credential` | Secret, certificate, or federated credential | Client secret expiring 2026-09-15 |
| `scope` | Generic access scope | Management group or tenant scope |
| `subscription` | Azure subscription | "prod-sub" (abc-123) |
| `resource_group` | Azure resource group | "prod-rg" |
| `resource` | Specific cloud resource | Key Vault "prod-kv", Storage "prod-storage" |
| `entra_directory` | Entra ID directory role scope | Global Admin directory scope |

### Edges

Edges represent relationships between nodes:

| Edge Type | From | To | Meaning |
|-----------|------|-----|---------|
| `has_role` | identity | role | Identity holds this role |
| `scoped_to` | role | subscription/resource_group/resource | Role applies at this scope |
| `has_permission` | identity | permission | Identity has this API permission |
| `has_credential` | identity | credential | Identity has this credential |
| `owns` | owner | identity | Owner manages this identity |
| `trusts` | identity | federated_trust | Identity trusts external issuer |
| `contains` | subscription | resource_group | Subscription contains RG |
| `contains` | resource_group | resource | RG contains resource |
| `directory_role` | identity | entra_directory | Identity has directory role |

---

## Identity Types

### Human Identities

```
┌──────────────────────────────────────────────────────────────────┐
│  Human User: jane@company.com                                    │
│  Category: human_user                                            │
│  Activity: active (last sign-in: 2 hours ago)                    │
│  Risk: 45 (Medium) | Tier: T1                                   │
│                                                                  │
│  Entra Roles:                                                    │
│    └── Exchange Administrator                                    │
│                                                                  │
│  Azure RBAC:                                                     │
│    ├── Owner → prod-sub                                          │
│    │              ├── prod-rg (Contributor)                       │
│    │              │     ├── prod-kv [Get, List, Set]              │
│    │              │     └── prod-storage [Read, Write]            │
│    │              └── data-rg                                     │
│    │                    └── analytics-db [Reader]                 │
│    └── Reader → dev-sub                                          │
│                                                                  │
│  Credentials:                                                    │
│    └── (none - human, uses interactive auth)                     │
└──────────────────────────────────────────────────────────────────┘
```

### Service Principals

```
┌──────────────────────────────────────────────────────────────────┐
│  Service Principal: prod-automation-sp                            │
│  Category: service_principal                                     │
│  Activity: stale (last sign-in: 120 days ago)                    │
│  Risk: 85 (Critical) | Tier: T0                                 │
│                                                                  │
│  Entra Roles:                                                    │
│    └── Global Administrator                                      │
│                                                                  │
│  Azure RBAC:                                                     │
│    ├── Owner → prod-sub                                          │
│    └── Contributor → staging-sub                                 │
│                                                                  │
│  MS Graph Permissions:                                           │
│    ├── Directory.ReadWrite.All (Application)                     │
│    ├── User.ReadWrite.All (Application)                          │
│    └── Mail.Read (Delegated)                                     │
│                                                                  │
│  Credentials:                                                    │
│    ├── Client Secret (expires: 2026-09-15, status: warning)      │
│    └── Certificate (expires: 2027-01-20, status: good)           │
│                                                                  │
│  Owners:                                                         │
│    └── (none — ORPHANED)                                         │
│                                                                  │
│  Federated Trust:                                                │
│    └── GitHub Actions (issuer: token.actions.githubusercontent)  │
│                                                                  │
│  Blast Radius: 90.0 (Critical)                                   │
│    2 subscriptions, 45 resource groups, 307 resources            │
│    Including: 4 Key Vaults, 45 Storage Accounts                  │
└──────────────────────────────────────────────────────────────────┘
```

### Managed Identities

```
┌──────────────────────────────────────────────────────────────────┐
│  Managed Identity: prod-vm-identity                              │
│  Category: managed_identity_system                               │
│  Activity: active                                                │
│  Risk: 30 (Low) | Tier: T3                                      │
│                                                                  │
│  Azure RBAC:                                                     │
│    └── Storage Blob Data Reader → prod-rg/prod-storage           │
│                                                                  │
│  Credentials:                                                    │
│    └── (system-managed — no manual rotation needed)              │
│                                                                  │
│  Blast Radius: 1.0 (Low)                                        │
│    1 resource group, 1 resource                                  │
└──────────────────────────────────────────────────────────────────┘
```

### API Keys (AWS)

```
┌──────────────────────────────────────────────────────────────────┐
│  IAM User: cicd-deployer                                         │
│  Category: iam_user                                              │
│  Activity: active (key last used: 3 hours ago)                   │
│  Risk: 65 (High) | Tier: T1                                     │
│                                                                  │
│  IAM Policies:                                                   │
│    ├── AdministratorAccess (attached managed)                    │
│    └── custom-deploy-policy (inline)                             │
│        Actions: s3:*, ec2:*, iam:PassRole                        │
│                                                                  │
│  Access Keys:                                                    │
│    ├── AKIA...ABC (created: 2025-06-01, status: active)         │
│    └── AKIA...DEF (created: 2024-01-15, status: active)         │
│                                                                  │
│  MFA: NOT ENABLED                                                │
│                                                                  │
│  Dangerous Actions:                                              │
│    ├── iam:PassRole                                              │
│    ├── s3:* (wildcard)                                           │
│    └── ec2:* (wildcard)                                          │
└──────────────────────────────────────────────────────────────────┘
```

---

## How Relationships Are Represented

The graph uses a hierarchical ARM tree model for Azure:

```
Identity
    │
    ├── Entra Branch (Directory Roles)
    │   ├── Global Administrator
    │   ├── Privileged Role Administrator
    │   └── Exchange Administrator
    │
    ├── ARM Branch (Azure RBAC)
    │   ├── Subscription: prod-sub
    │   │   ├── [Owner]
    │   │   ├── Resource Group: prod-rg
    │   │   │   ├── [Contributor]
    │   │   │   ├── Key Vault: prod-kv [Get, List]
    │   │   │   └── Storage: prod-blob [Read, Write]
    │   │   └── Resource Group: data-rg
    │   │       └── SQL DB: analytics [Reader]
    │   └── Subscription: staging-sub
    │       └── [Reader]
    │
    ├── Permissions Branch
    │   ├── Directory.ReadWrite.All (Application)
    │   └── User.ReadWrite.All (Application)
    │
    ├── Credentials Branch
    │   ├── Client Secret (expires: 2026-09-15)
    │   └── Certificate (expires: 2027-01-20)
    │
    └── Ownership Branch
        └── (owner: jane@company.com)
```

---

## Graph Traversal for Privilege Analysis

### Effective Access Analysis

To determine what an identity can access, traverse from the identity node through role edges to scope nodes:

```
Query: What resources can prod-automation-sp access?

Traversal:
  prod-automation-sp
    → has_role: Owner
      → scoped_to: prod-sub
        → contains: prod-rg
          → contains: prod-kv        ✓ Full access
          → contains: prod-storage    ✓ Full access
        → contains: data-rg
          → contains: analytics-db    ✓ Full access
    → has_role: Contributor
      → scoped_to: staging-sub
        → contains: staging-rg
          → contains: staging-kv      ✓ Contributor access

Result: 2 subscriptions, 3 resource groups, 4 resources
```

### Blast Radius Calculation

Blast radius counts the total scope reachable from an identity:

```
Blast Radius Assessment:
  Subscriptions reachable:  2
  Resource groups reachable: 3
  Resources reachable:       4
  Key Vaults:                2 (high-value)
  Storage Accounts:          1

  Blast Radius Label: "Subscription" (multi-subscription access)
  Blast Radius Score: 90.0 (T0 × subscription × stale × cross-sub)
```

### Attack Path Analysis

AuditGraph computes five types of privilege escalation chains:

| Path Type | Description | Example |
|-----------|-------------|---------|
| **Direct Escalation** | Identity can directly modify its own permissions | SPN with `RoleManagement.ReadWrite.Directory` can self-promote to Global Admin |
| **Ownership Chain** | Identity owns another identity with higher privileges | User owns SPN that has Global Admin |
| **PIM Abuse** | Identity has PIM eligibility for high-privilege roles | User eligible for Global Admin activation |
| **Lateral Movement** | Identity can move between subscriptions or tenants | SPN with Owner on sub A, cross-sub access |
| **Credential Exposure** | Identity's credentials are accessible to others | SPN secret stored in Key Vault accessible by another identity |

```
Attack Path Example: Ownership Chain

  attacker@hacked.com (Guest, Reader)
    │
    │ OWNS
    ▼
  dev-automation-sp (Service Principal)
    │
    │ HAS ROLE: User Access Administrator
    ▼
  prod-sub (Subscription)
    │
    │ CAN ASSIGN: Owner role to self
    ▼
  prod-sub (Subscription, Owner)
    │
    │ FULL CONTROL
    ▼
  All resources in prod-sub

  Risk: A compromised guest account can escalate to
        subscription Owner through the ownership chain.
```

---

## Visualization Modes

### Executive Mode

Designed for security leaders. Shows a summarized view:

```
┌──────────────────────────────────────────────────────────┐
│  prod-automation-sp                                      │
│  Risk: 85 (Critical) | Tier: T0 | Stale                │
│                                                          │
│  ┌────────────────────────────────────────────┐         │
│  │  BLAST RADIUS                               │         │
│  │  Subscriptions: 2                           │         │
│  │  Resources: 307                             │         │
│  │  Key Vaults: 4                              │         │
│  │  Privileged Roles: 3                        │         │
│  │                                             │         │
│  │  Severity: CRITICAL                         │         │
│  └────────────────────────────────────────────┘         │
│                                                          │
│  ┌────────────────────────────────────────────┐         │
│  │  KEY RISKS                                  │         │
│  │  • T0 Privilege (Global Administrator)      │         │
│  │  • Stale (120 days no activity)            │         │
│  │  • No owner assigned                       │         │
│  │  • Credential expiring in 30 days          │         │
│  └────────────────────────────────────────────┘         │
│                                                          │
│  ┌────────────────────────────────────────────┐         │
│  │  RECOMMENDED ACTIONS                        │         │
│  │  1. Assign an owner                        │         │
│  │  2. Remove Global Administrator role       │         │
│  │  3. Rotate expiring credential             │         │
│  │  4. Scope down to least privilege          │         │
│  └────────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────────┘
```

### Technical Mode

Designed for engineers and auditors. Shows the full hierarchical ARM tree with role badges:

```
┌──────────────┐
│   Identity   │ prod-automation-sp (T0, Critical)
└──────┬───────┘
       │
       ├──────────────────────────────┐
       │                              │
       ▼                              ▼
┌──────────────┐              ┌──────────────┐
│  Entra Dir   │              │ Subscription │ prod-sub
│  Global Admin│              │   [Owner]    │
└──────────────┘              └──────┬───────┘
                                     │
                              ┌──────┴───────┐
                              │              │
                              ▼              ▼
                       ┌──────────┐   ┌──────────┐
                       │ prod-rg  │   │ data-rg  │
                       │[Contrib] │   └────┬─────┘
                       └────┬─────┘        │
                            │              ▼
                       ┌────┴────┐   ┌──────────┐
                       │         │   │analytics │
                       ▼         ▼   │   [Read] │
                 ┌─────────┐ ┌────┐ └──────────┘
                 │ prod-kv │ │blob│
                 │[Get,Set]│ │[RW]│
                 └─────────┘ └────┘
```

### Attack Path Mode

Shows privilege escalation chains as directed graphs:

```
┌──────────────┐     OWNS      ┌──────────────┐
│ guest@ext.com├──────────────►│ dev-auto-sp  │
│ (Guest)      │               │ (SPN)        │
└──────────────┘               └──────┬───────┘
                                      │
                                      │ HAS ROLE: UAA
                                      ▼
                               ┌──────────────┐
                               │ prod-sub     │
                               │ (Sub)        │
                               └──────┬───────┘
                                      │
                                      │ CAN ASSIGN: Owner
                                      ▼
                               ┌──────────────┐
                               │ prod-sub     │
                               │ [Owner]      │
                               └──────────────┘

  Path Severity: CRITICAL
  Steps: 3 hops
  Narrative: Guest user owns a service principal with
             User Access Administrator on production.
```

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/identities/{id}/graph-data` | Full access graph with nodes, edges, and blast radius |
| `GET /api/identities/{id}/attack-paths` | Computed attack paths for an identity |
| `GET /api/identities/{id}/blast-radius` | Blast radius detail |
| `GET /api/identities/{id}/effective-access` | Effective access summary |
| `GET /api/graph/visualization` | Full graph visualization data |
| `GET /api/graph/blast-radius` | Organization-wide blast radius summary |

---

## References

- [Introduction](introduction.md) -- Identity concepts and privilege tiers
- [Risk Scoring Model](risk-scoring.md) -- How blast radius feeds into AGIRS
- [Discovery Engine](discovery-engine.md) -- How graph data is collected
- [API Reference](api-reference.md) -- Graph API endpoint details
