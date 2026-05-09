# AuditGraph by NexGenix Labs

> **The Identity Security Platform That Sees What Others Miss**

---

## About NexGenix Labs

NexGenix Labs builds next-generation cybersecurity products that solve real enterprise pain — not checkbox compliance. We believe identity is the new perimeter, and every organization deserves enterprise-grade identity security without enterprise-grade complexity.

**Our Vision:** Make cloud identity security accessible, actionable, and autonomous — so every organization can protect their most critical attack surface: identity.

**Our Mission:** Eliminate identity blind spots across every cloud, every identity type, every permission — before attackers exploit them.

**Our Approach:** We don't just scan — we understand. AuditGraph maps the full identity universe (human, machine, guest, federated) across Azure, AWS, and GCP, scores risk with context, and tells you exactly what to fix and why.

---

## What is AuditGraph?

AuditGraph is a **Cloud Identity Security & Governance Platform** that discovers, analyzes, and remediates identity risks across multi-cloud environments.

Think of it as a **security X-ray for every identity in your cloud** — users, service principals, managed identities, app registrations, guest accounts, federated credentials — all mapped into a living graph that shows who has access to what, why it's risky, and what to do about it.

```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│   "We don't just find identities.                                   │
│    We find the ones that can bring your business down."              │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Why AuditGraph?

### The Problem

Every major breach in the last 5 years started with one thing: **a compromised identity.**

- **SolarWinds** — compromised service account with over-privileged access
- **Colonial Pipeline** — stolen VPN credentials (no MFA)
- **Uber (2022)** — social engineering → MFA fatigue → admin access
- **Okta (2023)** — service account token stolen from support case
- **Microsoft (2024)** — legacy test OAuth app with no MFA → email compromise

The pattern is clear: **identities are the #1 attack vector**, and most organizations can't answer basic questions:

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│   Questions CISOs Can't Answer Today:                            │
│                                                                   │
│   1. How many service principals have Global Admin access?       │
│   2. Which identities have credentials expiring this week?       │
│   3. If this one identity is compromised, what's the blast       │
│      radius?                                                     │
│   4. Which identities haven't been used in 90 days but still     │
│      have privileged access?                                     │
│   5. Are any federated credentials pointing to untrusted         │
│      issuers?                                                    │
│   6. What's our identity posture score — and is it improving?    │
│                                                                   │
│   AuditGraph answers all of these. In real time.                 │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### The Market Gap

| What Exists Today | What's Missing |
|-------------------|----------------|
| CSPM tools that scan cloud configs | Deep identity relationship mapping |
| IGA platforms that manage access requests | Real-time risk scoring with blast radius |
| PAM tools that vault passwords | Non-human identity (SPN/MI) lifecycle |
| CIEM tools that right-size permissions | Attack path + blast radius combined analysis |
| Native tools (Entra PM) that show permissions | Cross-cloud identity correlation |

**No single product today combines:** discovery + graph analysis + risk scoring + attack paths + blast radius + remediation + compliance — specifically for identities.

AuditGraph does.

---

## What AuditGraph Does

### The Identity Security Lifecycle

```
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐         ║
║   │          │    │          │    │          │    │          │         ║
║   │ DISCOVER │───▶│ ANALYZE  │───▶│  SCORE   │───▶│ REMEDIATE│         ║
║   │          │    │          │    │          │    │          │         ║
║   └──────────┘    └──────────┘    └──────────┘    └──────────┘         ║
║        │               │               │               │                ║
║   Every identity  Attack paths    AGIRS risk      Automated             ║
║   across every    Blast radius    scoring         fix actions           ║
║   cloud           Drift           (0-100)         SOAR routing          ║
║   provider        Anomalies       Lineage         Approval              ║
║                   Correlations    verdicts         workflows             ║
║                                                                          ║
║   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐         ║
║   │          │    │          │    │          │    │          │         ║
║   │ MONITOR  │◀───│ COMPLY   │◀───│  REPORT  │◀───│ GOVERN   │         ║
║   │          │    │          │    │          │    │          │         ║
║   └──────────┘    └──────────┘    └──────────┘    └──────────┘         ║
║        │               │               │               │                ║
║   Continuous      SOC 2, NIST    CISO boards      Access               ║
║   drift           HIPAA, PCI     PDF exports       reviews              ║
║   detection       CIS Controls   Scheduled         Role mining          ║
║   Anomaly         MITRE ATT&CK   delivery          Policy gen           ║
║   alerts                                                                 ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## Product Architecture

### High-Level System Architecture

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           AUDITGRAPH PLATFORM                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  ┌────────────────────────────────────────────────────────────────────┐      ║
║  │                    PRESENTATION LAYER                              │      ║
║  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐ │      ║
║  │  │   CISO     │  │  SecOps    │  │  Auditor   │  │   Admin    │ │      ║
║  │  │ Dashboard  │  │  Command   │  │ Compliance │  │  Console   │ │      ║
║  │  │            │  │  Center    │  │  Reports   │  │            │ │      ║
║  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘ │      ║
║  │        React 19 + TypeScript + Tailwind CSS + @xyflow/react      │      ║
║  └──────────────────────────────┬─────────────────────────────────────┘      ║
║                                 │ HTTPS (JWT + CSRF)                         ║
║  ┌──────────────────────────────▼─────────────────────────────────────┐      ║
║  │                      API GATEWAY LAYER                             │      ║
║  │  ┌────────┐ ┌────────┐ ┌──────────┐ ┌────────┐ ┌──────────────┐ │      ║
║  │  │  Auth   │ │  RBAC  │ │  Input   │ │  Rate  │ │    Tenant    │ │      ║
║  │  │Middleware│ │Enforce │ │Sanitizer │ │Limiter │ │  Scope Guard │ │      ║
║  │  └────────┘ └────────┘ └──────────┘ └────────┘ └──────────────┘ │      ║
║  │              Flask + FastAPI Hybrid (610 endpoints)                │      ║
║  └──────────────────────────────┬─────────────────────────────────────┘      ║
║                                 │                                            ║
║  ┌──────────────────────────────▼─────────────────────────────────────┐      ║
║  │                     ENGINE LAYER (66 engines)                      │      ║
║  │                                                                    │      ║
║  │  ┌─────────────────────────────────────────────────────────────┐  │      ║
║  │  │              DISCOVERY PIPELINE (13 phases)                 │  │      ║
║  │  │  Azure RBAC ─▶ Entra Roles ─▶ SPNs ─▶ Credentials ─▶     │  │      ║
║  │  │  Graph Perms ─▶ App Roles ─▶ Users ─▶ Risk Calc ─▶       │  │      ║
║  │  │  Credential Check ─▶ Activity ─▶ Save ─▶ Complete         │  │      ║
║  │  └─────────────────────────────────────────────────────────────┘  │      ║
║  │                                                                    │      ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │      ║
║  │  │  Risk    │ │  Attack  │ │  Blast   │ │  Anomaly │            │      ║
║  │  │ Scoring  │ │  Path    │ │  Radius  │ │Detection │            │      ║
║  │  │ (AGIRS)  │ │  Engine  │ │  Engine  │ │  Engine  │            │      ║
║  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │      ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │      ║
║  │  │  Drift   │ │  Lineage │ │  Role    │ │  SOAR    │            │      ║
║  │  │ Detector │ │  Engine  │ │  Mining  │ │ Orchestr │            │      ║
║  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │      ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │      ║
║  │  │ Security │ │ AI       │ │ Ghost    │ │Compliance│            │      ║
║  │  │ Copilot  │ │ Advisor  │ │ Detector │ │Benchmark │            │      ║
║  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │      ║
║  └──────────────────────────────┬─────────────────────────────────────┘      ║
║                                 │                                            ║
║  ┌──────────────────────────────▼─────────────────────────────────────┐      ║
║  │                       DATA LAYER                                   │      ║
║  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │      ║
║  │  │ PostgreSQL 16│  │   Neo4j 5    │  │    Redis     │            │      ║
║  │  │  207 tables  │  │ Trust graph  │  │   Caching    │            │      ║
║  │  │  525 RLS     │  │ Attack paths │  │   Sessions   │            │      ║
║  │  │  policies    │  │ Relationships│  │              │            │      ║
║  │  └──────────────┘  └──────────────┘  └──────────────┘            │      ║
║  └──────────────────────────────┬─────────────────────────────────────┘      ║
║                                 │                                            ║
║  ┌──────────────────────────────▼─────────────────────────────────────┐      ║
║  │                    CLOUD INTEGRATIONS                              │      ║
║  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │      ║
║  │  │    Azure     │  │     AWS      │  │     GCP      │            │      ║
║  │  │  Graph API   │  │  IAM API     │  │  IAM API     │            │      ║
║  │  │  ARM API     │  │  CloudTrail  │  │  Audit Logs  │            │      ║
║  │  │  Entra ID    │  │  STS         │  │  Admin API   │            │      ║
║  │  │  Key Vault   │  │  KMS         │  │  Secret Mgr  │            │      ║
║  │  └──────────────┘  └──────────────┘  └──────────────┘            │      ║
║  └────────────────────────────────────────────────────────────────────┘      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### Security Architecture

```
╔══════════════════════════════════════════════════════════════════════╗
║                     ZERO TRUST SECURITY MODEL                        ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  AUTHENTICATION                    AUTHORIZATION                     ║
║  ┌─────────────────┐              ┌─────────────────┐               ║
║  │ JWT Dual-Secret  │              │ 7-Tier RBAC      │               ║
║  │ ┌─────┐ ┌─────┐ │              │                   │               ║
║  │ │Admin│ │Client│ │              │ Owner             │               ║
║  │ │ Key │ │ Key  │ │              │  └─ Admin         │               ║
║  │ └─────┘ └─────┘ │              │      └─ SecAdmin  │               ║
║  │                   │              │          └─ Analyst│              ║
║  │ httpOnly Cookies  │              │              └─ Compliance      ║
║  │ CSRF Double-Submit│              │                  └─ Reader     ║
║  │ SAML / OIDC / SSO│              │                      └─ Viewer ║
║  └─────────────────┘              └─────────────────┘               ║
║                                                                      ║
║  TENANT ISOLATION                  DATA PROTECTION                   ║
║  ┌─────────────────┐              ┌─────────────────┐               ║
║  │ PostgreSQL RLS   │              │ Fernet Encryption│               ║
║  │ (525 policies)   │              │ (secrets at rest) │              ║
║  │                   │              │                   │               ║
║  │ @requires_org_id │              │ MultiFernet       │               ║
║  │ @cross_org audit │              │ (key rotation)    │               ║
║  │                   │              │                   │               ║
║  │ Sentinel values   │              │ Zero-after-use   │               ║
║  │ Fail-closed auth  │              │ (AG-116 pattern)  │              ║
║  └─────────────────┘              └─────────────────┘               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

### Risk Scoring Architecture (AGIRS)

```
╔══════════════════════════════════════════════════════════════════════╗
║            AGIRS — AuditGraph Identity Risk Score (0-100)             ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  ┌───────────────────────────────────────────────┐                  ║
║  │                                               │                  ║
║  │              AGIRS COMPOSITE                  │                  ║
║  │          ┌─────────────────────┐              │                  ║
║  │          │    Final Score      │              │                  ║
║  │          │    (0 — 100)        │              │                  ║
║  │          └────────┬────────────┘              │                  ║
║  │                   │                           │                  ║
║  │     ┌─────────────┼─────────────┐            │                  ║
║  │     │             │             │            │                  ║
║  │  ┌──▼──┐      ┌───▼───┐    ┌───▼───┐       │                  ║
║  │  │HIRI │      │ NHIRI │    │  GEI  │       │                  ║
║  │  │ 40% │      │  40%  │    │  20%  │       │                  ║
║  │  └──┬──┘      └───┬───┘    └───┬───┘       │                  ║
║  │     │             │            │             │                  ║
║  │  Human          Non-Human    Governance      │                  ║
║  │  Identity       Identity     Effectiveness   │                  ║
║  │  Risk Index     Risk Index   Index            │                  ║
║  │                                               │                  ║
║  │  - Ghost users  - Orphaned SPNs  - Control   │                  ║
║  │  - Dormant      - Expired creds    health     │                  ║
║  │  - Over-priv    - Ownerless apps - Compliance │                  ║
║  │  - Guest risk   - Zombie MIs     - Policy     │                  ║
║  │  - Zombie accts - Fed misconfig    adherence  │                  ║
║  │                                               │                  ║
║  └───────────────────────────────────────────────┘                  ║
║                                                                      ║
║  RISK LEVELS:                                                        ║
║  ████████████████████ CRITICAL (80-100)                              ║
║  ████████████████     HIGH     (60-79)                               ║
║  ████████████         MEDIUM   (40-59)                               ║
║  ████████             LOW      (0-39)                                ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## Product Modules — Deep Dive

### Module 1: Identity Discovery Engine

**What it does:** Continuously discovers every identity across Azure, AWS, and GCP — users, service principals, managed identities, app registrations, guest accounts, federated credentials.

**Why we built it:** Native cloud tools show you _your_ identities. They don't show you the relationships between them, the credentials attached, the permissions inherited, or the blast radius if compromised.

**Why this technology:**
| Choice | Why |
|--------|-----|
| Microsoft Graph API | Deepest Entra ID data — SPNs, app roles, OAuth permissions, federated creds |
| Azure ARM SDK | Subscription-scoped RBAC discovery across management groups |
| boto3 (AWS) | IAM users, roles, policies, access keys, CloudTrail events |
| GCP IAM API | Service accounts, IAM bindings, org-level policies |
| 13-phase pipeline | Deterministic ordering ensures complete, consistent snapshots |

```
DISCOVERY PIPELINE (13 phases)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Phase 1  ▓▓  Create discovery run record
Phase 2  ▓▓▓▓  Azure RBAC role assignments (ARM)
Phase 3  ▓▓▓▓  Entra ID directory roles (Graph)
Phase 4  ▓▓▓▓▓▓▓▓  Service principals + pagination (Graph)
Phase 5  ▓▓▓▓▓▓  SPN credentials (secrets, certs, federated)
Phase 6  ▓▓▓▓▓▓  Microsoft Graph API permissions
Phase 7  ▓▓▓▓  Custom app role assignments
Phase 8  ▓▓▓▓▓▓▓▓  Users with RBAC or Entra roles
Phase 9  ▓▓▓▓▓▓▓▓▓▓  Risk level calculation
Phase 10 ▓▓▓▓  Credential expiration check
Phase 11 ▓▓▓▓▓▓  Activity / sign-in status
Phase 12 ▓▓▓▓  Save to PostgreSQL
Phase 13 ▓▓  Complete with summary stats
```

---

### Module 2: Attack Path & Blast Radius Analysis

**What it does:** Maps every possible privilege escalation route and calculates what an attacker could reach if any single identity is compromised.

**Why we built it:** Knowing _who has what access_ isn't enough. You need to know _what happens if they're compromised_ — which subscriptions, resource groups, key vaults, and secrets are reachable through transitive permissions.

**Why this technology:**
| Choice | Why |
|--------|-----|
| Neo4j graph database | Native graph traversal — attack paths are graph problems, not table problems |
| @xyflow/react | Interactive, zoomable attack path visualization for security teams |
| Custom fingerprinting | SHA-256 deduplication prevents duplicate findings across snapshots |

```
ATTACK PATH EXAMPLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Compromised           Privilege              Target
  Identity              Escalation             Resources
                        Path

  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐
  │ Guest    │───▶│ User Admin   │───▶│ Global Admin      │
  │ Account  │    │ Role (Entra) │    │ Role Assignment   │
  └──────────┘    └──────┬───────┘    └────────┬─────────┘
                         │                      │
                         ▼                      ▼
                  ┌──────────────┐    ┌──────────────────┐
                  │ Reset any    │    │ All subscriptions │
                  │ user password│    │ All key vaults    │
                  └──────────────┘    │ All storage accts │
                                      └──────────────────┘
  BLAST RADIUS: 12 subscriptions, 47 resource groups,
                340 resources, 8 key vaults
```

---

### Module 3: AI Security Copilot

**What it does:** Natural language security investigation — ask questions about your identity posture and get instant, contextual answers powered by AI.

**Why we built it:** Security teams spend hours manually correlating data across dashboards. Copilot lets them ask "Which service principals have Global Admin and haven't been used in 90 days?" and get an answer in seconds.

**Why this technology:**
| Choice | Why |
|--------|-----|
| Claude Sonnet 4.5 | Best-in-class reasoning for complex security analysis |
| 18 intent patterns | Structured query routing — not raw LLM, but guided intelligence |
| 5 investigation tools | attack_paths, blast_radius, escalation_paths, timeline, forensics |
| Per-org rate limits | Free: 10/day, Trial: 100/day, Pro: 1,000/day |

**Sample queries:**
- "Show me the riskiest identities in our production subscription"
- "Which service principals have credentials expiring this week?"
- "What's the blast radius if john.doe@company.com is compromised?"
- "List all privilege escalation paths from guest accounts to Global Admin"

---

### Module 4: SOAR & Remediation Engine

**What it does:** Automated security orchestration — detects issues, generates fix recommendations, routes to ticketing systems, and optionally executes remediations directly.

**Why we built it:** Finding risks is only half the battle. If fixing them requires manual work across 5 different tools, nothing gets fixed. AuditGraph closes the loop.

**Why this technology:**
| Choice | Why |
|--------|-----|
| 586-class fix recommendation engine | Every finding type maps to a specific, actionable remediation |
| ServiceNow + Jira integration | Meet security teams where they work |
| Slack + Teams + PagerDuty | Real-time alerting to the right channel |
| Approval workflows | Humans in the loop for destructive actions (role removal, identity disable) |
| Direct Azure execution | Remove role assignments, rotate credentials, enable PIM — without leaving AuditGraph |

---

### Module 5: Compliance & Governance

**What it does:** Maps your identity posture to regulatory frameworks (SOC 2, NIST, HIPAA, PCI-DSS, CIS, MITRE ATT&CK) and generates audit-ready evidence.

**Why we built it:** Every compliance framework has identity requirements. But mapping technical findings to control IDs is painful manual work. AuditGraph automates it.

**Frameworks supported:**
```
┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│  SOC 2 Type II          NIST 800-53           HIPAA              │
│  ┌──────────────┐       ┌──────────────┐      ┌──────────────┐  │
│  │ CC6.1 Logical│       │ AC-6 Least   │      │ 164.312      │  │
│  │ CC6.3 RBAC   │       │ IA-5 AuthN   │      │ Access       │  │
│  │ CC7.2 Monitor│       │ AC-2 Account │      │ Controls     │  │
│  └──────────────┘       └──────────────┘      └──────────────┘  │
│                                                                   │
│  PCI-DSS v4             CIS Controls v8       MITRE ATT&CK v14  │
│  ┌──────────────┐       ┌──────────────┐      ┌──────────────┐  │
│  │ Req 7 Access │       │ CIS 5 Account│      │ T1078 Valid  │  │
│  │ Req 8 Identify│      │ CIS 6 Access │      │ T1098 Manip  │  │
│  │ Req 10 Log   │       │ CIS 16 AppSec│      │ T1136 Create │  │
│  └──────────────┘       └──────────────┘      └──────────────┘  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

### Module 6: Drift Detection & Anomaly Engine

**What it does:** Continuously monitors identity changes between discovery runs — new privileged access, removed permissions, credential rotations, suspicious activity patterns.

**Why we built it:** Point-in-time scans miss what happens _between_ scans. AuditGraph detects privilege drift (someone gained admin access), ghost identities (disabled but still has roles), and behavioral anomalies (login from unusual location).

---

### Module 7: Identity Graph & Correlation

**What it does:** Builds a living graph of relationships between identities — who owns what, who can impersonate whom, which identities are linked across clouds.

**Why we built it:** Flat identity lists don't show risk. A service principal with "Reader" looks safe — until you see it owns an app registration that has "Application.ReadWrite.All" which can grant itself Global Admin. That's a graph problem.

**Why this technology:**
| Choice | Why |
|--------|-----|
| Neo4j | Purpose-built for relationship queries — 1000x faster than SQL JOINs for graph traversal |
| @xyflow/react | Interactive, draggable graph visualization in the browser |
| 12-signal lineage engine | Combines activity, permissions, ownership, credentials, drift, anomalies into a single verdict per identity |

---

## Technology Choices — Why We Chose What We Chose

| Technology | Why This | Why Not Alternatives |
|------------|----------|---------------------|
| **Python 3.11** | Richest Azure/AWS/GCP SDK ecosystem, async support, security libraries | Go (weaker Azure SDK), Java (verbose, slower iteration) |
| **Flask + FastAPI** | Flask for mature middleware + FastAPI for modern async routes — hybrid bridge | Django (too opinionated), Express (wrong ecosystem) |
| **React 19 + TypeScript** | Component ecosystem, type safety, massive talent pool | Vue (smaller ecosystem), Angular (over-engineered for this) |
| **Tailwind CSS** | Utility-first = fast iteration, consistent design, no CSS sprawl | Bootstrap (dated look), Material UI (too opinionated) |
| **PostgreSQL 16** | RLS for multi-tenancy, JSONB for flexible schemas, battle-tested at scale | MySQL (no RLS), MongoDB (no ACID for financial/compliance data) |
| **Neo4j** | Native graph traversal — attack paths are graph problems | JanusGraph (complex ops), SQL recursive CTEs (too slow at scale) |
| **Fernet encryption** | Symmetric, fast, supports key rotation via MultiFernet | AES-GCM (more complex key management), RSA (wrong use case) |
| **Azure Container Apps** | Serverless containers, auto-scaling, managed TLS, Azure-native | AKS (over-engineered), ECS (wrong cloud), bare VMs (ops burden) |
| **APScheduler** | Lightweight, in-process job scheduling, perfect for discovery pipeline | Celery (needs Redis/RabbitMQ broker), Airflow (too heavy) |
| **Claude Sonnet 4.5** | Best reasoning for security analysis, tool use support, safe outputs | GPT-4 (weaker tool use), Gemini (less accurate for security) |
| **Recharts** | Simple, composable React charts — perfect for dashboards | D3 (too low-level), Chart.js (less React-native) |
| **@xyflow/react** | Purpose-built for interactive node graphs — attack paths, identity graphs | vis.js (less maintained), Cytoscape (heavier) |

---

## Current Market Issues & Competitor Gaps

### Market Problems We Solve

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                    │
│  PROBLEM 1: Identity Blind Spots                                  │
│  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄                                  │
│  80% of organizations don't know how many service principals      │
│  exist in their Azure tenant. Microsoft Entra shows them —        │
│  but doesn't score risk, detect ghosts, or map blast radius.     │
│                                                                    │
│  PROBLEM 2: Non-Human Identity Neglect                            │
│  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄                               │
│  Machine identities outnumber humans 45:1. Most CIEM tools        │
│  focus on users. AuditGraph treats SPNs, MIs, and app regs as    │
│  first-class citizens with dedicated risk scoring.                │
│                                                                    │
│  PROBLEM 3: No Actionable Remediation                             │
│  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄                               │
│  Finding 500 "high risk" identities is useless without            │
│  prioritization, blast radius context, and one-click fix.         │
│  AuditGraph ranks by impact and executes fixes directly.          │
│                                                                    │
│  PROBLEM 4: Compliance-to-Code Gap                                │
│  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄                                │
│  Auditors ask "show me SOC 2 CC6.1 evidence." Engineers stare.   │
│  AuditGraph maps every technical finding to control IDs           │
│  automatically.                                                    │
│                                                                    │
│  PROBLEM 5: Tool Sprawl                                           │
│  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄                                   │
│  Today's identity security requires 4-6 tools:                    │
│  IGA + CIEM + PAM + CSPM + SIEM + ticketing.                     │
│  AuditGraph consolidates identity security into one platform.     │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### Competitor Gap Analysis

```
                          FEATURE COVERAGE HEATMAP
                    (darker = stronger coverage)

                    Audit  Entra  Crowd  Ermet  Opal  Saviy  Wiz
                    Graph  PM     Strike Tenable       nt
                    ─────  ─────  ─────  ─────  ─────  ─────  ─────
SPN Deep Analysis   █████  ██░░░  ░░░░░  ██░░░  ░░░░░  ██░░░  ██░░░
Blast Radius        █████  ░░░░░  ██░░░  █████  ░░░░░  ░░░░░  █████
Attack Paths        █████  ██░░░  █████  █████  ░░░░░  ░░░░░  █████
Lineage Engine      █████  ░░░░░  ░░░░░  ░░░░░  ░░░░░  ░░░░░  ░░░░░
Risk Forecasting    █████  ░░░░░  ░░░░░  ░░░░░  ░░░░░  ░░░░░  ░░░░░
Remediation Exec    █████  ██░░░  ██░░░  █████  █████  █████  ██░░░
CISO Dashboard      █████  ██░░░  ░░░░░  ██░░░  ░░░░░  ██░░░  ██░░░
AI Copilot          █████  ██░░░  █████  ██░░░  ░░░░░  ██░░░  █████
Self-Hosted         █████  ░░░░░  ░░░░░  ░░░░░  █████  █████  ░░░░░
Price/Value         █████  ███░░  ██░░░  ██░░░  ███░░  █░░░░  ██░░░

LEGEND: █████ = Excellent  ███░░ = Good  ██░░░ = Partial  ░░░░░ = Missing
```

**AuditGraph's Unfair Advantages:**
1. **Lineage Engine** — 12-signal verdict assembly. No competitor has this.
2. **SPN/MI as First-Class Citizens** — Not an afterthought.
3. **Blast Radius + Attack Path Combined** — "How can it be compromised?" + "What's the damage?"
4. **Self-Hosted Option** — Critical for regulated industries.
5. **610 API Endpoints** — Deepest integration surface in the market.
6. **Price** — 60-80% less than enterprise incumbents.

---

## Billing Plans

```
╔══════════════════════════════════════════════════════════════════════════╗
║                         AUDITGRAPH PRICING                              ║
╠════════════════╦════════════════╦════════════════╦═══════════════════╣
║     FREE       ║     TRIAL      ║      PRO       ║   ENTERPRISE      ║
╠════════════════╬════════════════╬════════════════╬═══════════════════╣
║                ║                ║                ║                    ║
║  $0/month      ║  $0 for 30     ║  $500/month    ║  Custom pricing   ║
║                ║  days          ║  platform fee  ║                    ║
║  + $69/sub     ║  + $0/sub      ║  + $69/sub     ║  Volume discounts ║
║                ║  (all waived)  ║  per cloud sub ║  Dedicated support║
║                ║                ║                ║                    ║
╠════════════════╬════════════════╬════════════════╬═══════════════════╣
║ LIMITS         ║ LIMITS         ║ LIMITS         ║ LIMITS             ║
║ 1 cloud sub    ║ 5 cloud subs   ║ Unlimited      ║ Unlimited          ║
║ 50 identities  ║ 500 identities ║ Unlimited      ║ Unlimited          ║
║                ║                ║                ║                    ║
╠════════════════╬════════════════╬════════════════╬═══════════════════╣
║ FEATURES       ║ FEATURES       ║ FEATURES       ║ FEATURES           ║
║                ║                ║                ║                    ║
║ Discovery      ║ Everything     ║ Everything     ║ Everything         ║
║ Risk scoring   ║ in Pro         ║ in Free plus:  ║ in Pro plus:       ║
║ Basic dashboard║ for 30 days    ║                ║                    ║
║ Anomaly detect ║                ║ SOAR automation║ SCIM provisioning  ║
║                ║ AI Copilot:    ║ API keys       ║ Custom integrations║
║ AI Copilot:    ║ 100 queries/day║ Advanced query ║ Dedicated CSM      ║
║ 10 queries/day ║                ║ Custom risk    ║ SLA guarantees     ║
║                ║                ║ AI Copilot:    ║ On-prem deployment ║
║                ║                ║ 1000 queries   ║ Priority support   ║
║                ║                ║ SSO/OIDC       ║ White-label option ║
║                ║                ║ Scheduled rpts ║                    ║
║                ║                ║ Compliance exp ║ AI Copilot:        ║
║                ║                ║                ║ Unlimited          ║
║                ║                ║                ║                    ║
╠════════════════╩════════════════╩════════════════╩═══════════════════╣
║                                                                       ║
║  COMMITMENT DISCOUNTS (on total bill):                                ║
║  ┌─────────────────────────────────────────────────────┐             ║
║  │  1-year commitment ........... 15% off              │             ║
║  │  3-year commitment ........... 25% off              │             ║
║  │  5-year commitment ........... 35% off              │             ║
║  └─────────────────────────────────────────────────────┘             ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
```

### Pricing Examples

| Scenario | Cloud Subs | Plan | Monthly Cost | Annual (1yr) | Annual (3yr) |
|----------|-----------|------|-------------|-------------|-------------|
| Startup (1 Azure sub) | 1 | Free | $69 | $703 | $621 |
| SMB (5 Azure subs) | 5 | Pro | $845 | $8,618 | $7,605 |
| Mid-Market (20 subs) | 20 | Pro | $1,880 | $19,176 | $16,920 |
| Enterprise (50 subs) | 50 | Pro | $3,950 | $40,290 | $35,550 |
| Large Enterprise (200 subs) | 200 | Enterprise | Custom | Custom | Custom |

---

## ROI — Return on Investment

### Cost of Identity Breaches (Industry Data)

| Metric | Value | Source |
|--------|-------|--------|
| Average cost of a data breach | $4.88M | IBM Cost of a Data Breach 2024 |
| Average cost when stolen credentials involved | $4.81M | IBM 2024 |
| Average time to detect credential breach | 292 days | IBM 2024 |
| % of breaches involving compromised identities | 80%+ | Verizon DBIR 2024 |
| Average cost of identity-related incident | $2.1M | Gartner 2024 |

### AuditGraph ROI Model

```
╔══════════════════════════════════════════════════════════════════════╗
║                    ROI CALCULATION — MID-MARKET                      ║
║                    (20 cloud subscriptions, Pro plan)                 ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  ANNUAL COST                                                         ║
║  ┌────────────────────────────────────────────────────────────┐      ║
║  │  AuditGraph Pro (20 subs, 1yr commit) .... $19,176/year   │      ║
║  └────────────────────────────────────────────────────────────┘      ║
║                                                                      ║
║  RISK REDUCTION (conservative estimates)                             ║
║  ┌────────────────────────────────────────────────────────────┐      ║
║  │                                                            │      ║
║  │  Breach probability reduction ........... 40-60%          │      ║
║  │  Average breach cost ................... $4.88M           │      ║
║  │  Expected annual loss (without AG) ..... $244K            │      ║
║  │  (assuming 5% chance of breach/year)                      │      ║
║  │                                                            │      ║
║  │  Expected annual loss (with AG) ........ $98K             │      ║
║  │  (assuming 2% chance after remediation)                   │      ║
║  │                                                            │      ║
║  │  ANNUAL RISK SAVINGS ................... $146K            │      ║
║  │                                                            │      ║
║  └────────────────────────────────────────────────────────────┘      ║
║                                                                      ║
║  OPERATIONAL SAVINGS                                                 ║
║  ┌────────────────────────────────────────────────────────────┐      ║
║  │                                                            │      ║
║  │  Manual identity audit time saved ...... 200 hrs/year     │      ║
║  │  Engineer hourly rate .................. $85/hr           │      ║
║  │  Time savings value .................... $17,000          │      ║
║  │                                                            │      ║
║  │  Compliance audit prep time saved ...... 80 hrs/year      │      ║
║  │  Compliance specialist rate ............ $120/hr          │      ║
║  │  Compliance savings value .............. $9,600           │      ║
║  │                                                            │      ║
║  │  Tool consolidation savings ............ $30,000/year     │      ║
║  │  (replacing 2-3 point tools)                              │      ║
║  │                                                            │      ║
║  │  TOTAL OPERATIONAL SAVINGS ............. $56,600          │      ║
║  │                                                            │      ║
║  └────────────────────────────────────────────────────────────┘      ║
║                                                                      ║
║  ┌────────────────────────────────────────────────────────────┐      ║
║  │                                                            │      ║
║  │  TOTAL ANNUAL VALUE .................... $202,600         │      ║
║  │  AUDITGRAPH ANNUAL COST ............... $19,176           │      ║
║  │                                                            │      ║
║  │  ══════════════════════════════════════════════════        │      ║
║  │  ROI ................................... 957%              │      ║
║  │  PAYBACK PERIOD ........................ 35 days          │      ║
║  │  ══════════════════════════════════════════════════        │      ║
║  │                                                            │      ║
║  └────────────────────────────────────────────────────────────┘      ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

### ROI by Company Size

| Company Size | Subs | Annual Cost | Risk Savings | Ops Savings | Total Value | ROI |
|-------------|------|------------|-------------|------------|------------|-----|
| Startup | 1 | $703 | $12K | $5K | $17K | 2,318% |
| SMB | 5 | $8,618 | $49K | $18K | $67K | 677% |
| Mid-Market | 20 | $19,176 | $146K | $57K | $203K | 957% |
| Enterprise | 50 | $40,290 | $488K | $120K | $608K | 1,409% |

---

## Business Strategy

### Go-to-Market Motion

```
╔══════════════════════════════════════════════════════════════════════╗
║                        GTM STRATEGY                                   ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  PHASE 1: LAND (Months 1-6)                                        ║
║  ┌────────────────────────────────────────────────────────────┐      ║
║  │  Target: Azure-heavy mid-market (500-5000 identities)     │      ║
║  │  Motion: Product-led growth + direct sales                 │      ║
║  │  Channel: Free tier → Trial → Pro conversion              │      ║
║  │  Goal: 10 paying customers, $100K ARR                     │      ║
║  └────────────────────────────────────────────────────────────┘      ║
║                                                                      ║
║  PHASE 2: EXPAND (Months 6-12)                                      ║
║  ┌────────────────────────────────────────────────────────────┐      ║
║  │  Target: Enterprise (5000+ identities), regulated orgs    │      ║
║  │  Motion: Solution selling + POC-driven                    │      ║
║  │  Channel: Direct + MSP/MSSP partners                      │      ║
║  │  Goal: 50 customers, $500K ARR, Azure Marketplace listing │      ║
║  └────────────────────────────────────────────────────────────┘      ║
║                                                                      ║
║  PHASE 3: SCALE (Year 2+)                                           ║
║  ┌────────────────────────────────────────────────────────────┐      ║
║  │  Target: Multi-cloud enterprises, global deployments      │      ║
║  │  Motion: Channel-led + analyst-validated                  │      ║
║  │  Channel: MSPs + Marketplace + Analyst referrals          │      ║
║  │  Goal: 200+ customers, $2M ARR, Gartner recognition      │      ║
║  └────────────────────────────────────────────────────────────┘      ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

### Ideal Customer Profile (ICP)

| Attribute | Ideal Target |
|-----------|-------------|
| **Company size** | 200-5,000 employees |
| **Cloud usage** | Azure-primary, may have AWS/GCP |
| **Identity count** | 500-10,000 (users + SPNs + MIs) |
| **Industry** | Finance, healthcare, government, SaaS, technology |
| **Compliance needs** | SOC 2, HIPAA, PCI-DSS, NIST |
| **Pain point** | Failed audit, breach scare, compliance deadline, tool sprawl |
| **Decision maker** | CISO, VP Security, Director of Cloud Security |
| **Budget holder** | CISO or CTO |
| **Technical champion** | Cloud security engineer, IAM team lead |

### Sales Process

```
Day 1 ──────── Day 3 ──────── Day 7 ──────── Day 14 ──────── Day 30
  │               │               │               │               │
  ▼               ▼               ▼               ▼               ▼
Connect         First          Risk            Decision        Close
Azure           Discovery      Review          Meeting
Tenant          Complete       with CISO

Free Tier ──── Trial ──────── Trial ──────── Pro ──────────── Annual
Self-Serve     Activation     Value Demo     Conversion       Commitment
```

---

## Product Feature Inventory

### 74 Pages, 66 Engines, 610 API Endpoints

| Module | Pages | Engines | Key Differentiator |
|--------|-------|---------|-------------------|
| **CISO Dashboard** | 4 | 3 | Executive-ready posture scoring (AGIRS) |
| **Identity Explorer** | 12 | 8 | SPN/MI deep analysis, credential tracking |
| **Attack Intelligence** | 5 | 6 | Graph-based attack paths + blast radius |
| **Risk & Compliance** | 10 | 7 | Multi-framework compliance automation |
| **Remediation** | 3 | 4 | Direct execution + SOAR + approval workflows |
| **Drift & Anomaly** | 3 | 4 | Continuous change detection |
| **Governance** | 5 | 4 | Access reviews, role mining, policy generation |
| **Reporting** | 3 | 2 | PDF exports, scheduled delivery |
| **AI Copilot** | 1 | 3 | Natural language security investigation |
| **Billing & Admin** | 12 | 2 | Multi-tenant SaaS, MSP support |
| **Auth & Settings** | 8 | 1 | SSO/OIDC/SAML, API keys |
| **Data Security** | 4 | 3 | Key vault, storage, SAS token analysis |
| **Graph Visualization** | 4 | 3 | Interactive identity relationship mapping |

---

## NexGenix Labs — Company Summary

| | |
|---|---|
| **Company** | NexGenix Labs |
| **Product** | AuditGraph |
| **Category** | Cloud Identity Security & Governance (CIEM + IGA) |
| **Founded** | 2025 |
| **Stage** | Product-ready, pre-revenue |
| **Stack** | Python + React + PostgreSQL + Neo4j + Azure |
| **Codebase** | 288K LOC, 675 files, 66 engines, 207 DB tables |
| **Differentiation** | Deepest non-human identity analysis, lineage engine, blast radius, self-hosted option |
| **Target Market** | Azure-heavy mid-market to enterprise, regulated industries |
| **Business Model** | SaaS (platform fee + per-subscription) with self-hosted option |
| **Pricing** | $69/sub/month + $500 platform fee (Pro), free tier available |

---

*Built by NexGenix Labs. Securing identities others ignore.*
