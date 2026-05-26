# AuditGraph — Hiring, Skills & Go-to-Market Playbook

> **Product:** AuditGraph — Cloud Identity Security & Governance Platform
> **Codebase:** ~288K LOC | 291 Python files | 267 TypeScript files | 610 API endpoints | 207 DB tables | 55 engines
> **Stack:** Python 3.11 (Flask + FastAPI) | React 19 + TypeScript | PostgreSQL 16 + Neo4j | Azure / AWS / GCP | Docker + Azure Container Apps

---

## 1. Current Technical Landscape

| Dimension | Metric |
|-----------|--------|
| Backend LOC | 195,307 (Python) |
| Frontend LOC | 84,032 (TypeScript/TSX) |
| SQL Migrations | 103 files, 207 tables |
| API Endpoints | 610 |
| Analysis Engines | 55 (risk, anomaly, blast radius, attack path, drift, RBAC hygiene, etc.) |
| Frontend Pages | 74 pages, 132 components, 9 custom hooks |
| Scheduled Jobs | 12 (APScheduler) |
| Test Files | 78 (pytest + Jest) |
| Cloud Providers | Azure (primary), AWS, GCP |
| CI/CD | GitHub Actions — 7-stage security pipeline |
| Compliance Refs | SOC 2 Type II, HIPAA, PCI-DSS, NIST 800-53 |

---

## 2. Engineering Roles Needed

### 2a. Immediate Hires (Core Team)

#### Senior Backend / Platform Engineer
| | |
|---|---|
| **Count** | 1–2 |
| **Experience** | 7–10 years |
| **Must-have** | Python 3.9+ (async, generators, decorators), Flask or FastAPI, PostgreSQL (RLS, JSONB, window functions, CTEs), REST API design, Azure SDK / Microsoft Graph API |
| **Nice-to-have** | Neo4j / graph databases, APScheduler / Celery, OpenTelemetry, multi-tenant SaaS architecture |
| **Owns** | Discovery pipeline (13-phase), 55 analysis engines, database schema, background jobs, API layer |
| **Day-1 tasks** | Extend discovery pipeline to AWS/GCP, optimize query performance, add new risk signals |

#### Senior Full-Stack Engineer
| | |
|---|---|
| **Count** | 1–2 |
| **Experience** | 5–8 years |
| **Must-have** | React 18/19, TypeScript, Tailwind CSS, Python (Flask/FastAPI), PostgreSQL, REST APIs |
| **Nice-to-have** | Recharts / D3.js / graph visualization (@xyflow/react), PDF generation (jsPDF), DOMPurify/XSS prevention |
| **Owns** | End-to-end feature delivery — backend API + frontend UI, CISO dashboard, identity detail views, reporting |
| **Day-1 tasks** | Build new dashboard views, wire remaining UI to live data, improve UX flows |

#### Cloud Security / IAM Engineer
| | |
|---|---|
| **Count** | 1 |
| **Experience** | 5–8 years |
| **Must-have** | Azure AD / Entra ID, Azure RBAC, Microsoft Graph API, OAuth 2.0 / OIDC / SAML, identity governance concepts (PIM, JIT, least privilege) |
| **Nice-to-have** | AWS IAM, GCP IAM, attack path modeling, MITRE ATT&CK, CIS Controls, NIST 800-53 |
| **Owns** | Risk scoring algorithms, compliance framework mappings, privilege tier classification (T0–T3), anomaly detection logic, federated credential analysis |
| **Day-1 tasks** | Tune risk scoring, add new compliance frameworks, validate attack path engine |

#### DevOps / Infrastructure Engineer
| | |
|---|---|
| **Count** | 1 |
| **Experience** | 5–7 years |
| **Must-have** | Docker, Azure Container Apps / AKS, GitHub Actions CI/CD, PostgreSQL administration, Bicep or Terraform |
| **Nice-to-have** | Trivy / Checkov / Gitleaks, OpenTelemetry, Azure Monitor, multi-environment deployment (dev/qa/stg/prod), SBOM generation |
| **Owns** | CI/CD pipelines, container builds, infrastructure-as-code, database backups, monitoring/alerting, security scanning pipeline |
| **Day-1 tasks** | Harden production deployment, set up staging environment, implement blue/green deployments |

---

### 2b. Growth Hires (Scale Team — Months 3–6)

#### Mid-Level Backend Engineer
| | |
|---|---|
| **Count** | 1–2 |
| **Experience** | 3–5 years |
| **Must-have** | Python, PostgreSQL, REST APIs |
| **Owns** | Engine feature work, API endpoints, test coverage, migration authoring |

#### Mid-Level Frontend Engineer
| | |
|---|---|
| **Count** | 1 |
| **Experience** | 3–5 years |
| **Must-have** | React, TypeScript, Tailwind CSS |
| **Owns** | New UI pages, component library, accessibility, performance optimization |

#### QA / Test Engineer
| | |
|---|---|
| **Count** | 1 |
| **Experience** | 3–5 years |
| **Must-have** | pytest, Jest/React Testing Library, API testing (Postman/Newman), SQL |
| **Owns** | Test coverage (currently ~40–50%), regression suites, E2E test framework, load testing |

---

### 2c. Team Size Summary

| Phase | Headcount | Roles |
|-------|-----------|-------|
| **Now (MVP → First Customers)** | 4–6 engineers | 1–2 Sr Backend, 1–2 Sr Full-Stack, 1 Cloud Security, 1 DevOps |
| **Growth (Months 3–6)** | 7–9 engineers | + 1–2 Mid Backend, 1 Mid Frontend, 1 QA |
| **Scale (Months 6–12)** | 10–14 engineers | + SRE, Data Engineer, additional domain specialists |

---

## 3. Non-Engineering Roles Needed

### 3a. Immediate (Pre-Launch / First Customers)

#### Technical Product Manager (TPM)
| | |
|---|---|
| **Count** | 1 |
| **Experience** | 5–8 years, B2B SaaS / cybersecurity products |
| **Must-have** | Roadmap ownership, user story authoring, sprint planning, stakeholder communication, basic understanding of cloud security / IAM |
| **Nice-to-have** | Prior work on GRC / CSPM / CIEM products, Jira/Linear, data-driven decision making |
| **Owns** | Product roadmap, feature prioritization, release planning, customer feedback loops, competitive analysis |
| **Why critical** | Bridge between engineering, customers, and business — ensures you build what sells |

#### Solutions Engineer / Sales Engineer (SE)
| | |
|---|---|
| **Count** | 1 |
| **Experience** | 4–7 years, cybersecurity / cloud sales engineering |
| **Must-have** | Azure AD / Entra fluency, demo delivery, POC management, technical objection handling, RFP/RFI responses |
| **Nice-to-have** | CISSP / AZ-500 / SC-300 certification, prior CSPM/CIEM/IGA vendor experience |
| **Owns** | Customer demos, POC execution, technical win, security questionnaire responses, integration guidance |
| **Why critical** | This product requires technical selling — CISOs and security teams need to see value in their environment |

#### Head of Sales / Business Development
| | |
|---|---|
| **Count** | 1 |
| **Experience** | 7–10+ years, B2B cybersecurity SaaS |
| **Must-have** | Enterprise sales motion (MEDDPICC or similar), CISO-level relationships, channel/partner strategy, pipeline management |
| **Nice-to-have** | Identity security market knowledge, existing network in cloud security buyer community |
| **Owns** | Revenue targets, sales pipeline, pricing strategy, partnership deals, first 10 customers |
| **Why critical** | Identity security is sold to security leadership — you need someone who speaks their language |

### 3b. Growth Phase (Months 3–6)

#### Customer Success Manager (CSM)
| | |
|---|---|
| **Count** | 1 |
| **Experience** | 3–5 years, B2B SaaS |
| **Owns** | Onboarding, adoption, retention, expansion, customer health scoring |

#### Marketing Lead (Product Marketing)
| | |
|---|---|
| **Count** | 1 |
| **Experience** | 5+ years, cybersecurity product marketing |
| **Owns** | Positioning, messaging, content (whitepapers, case studies), analyst relations (Gartner, Forrester), event strategy |

#### Compliance / GRC Analyst
| | |
|---|---|
| **Count** | 1 (can be fractional/contractor) |
| **Experience** | 3–5 years |
| **Owns** | SOC 2 Type II audit prep, ISO 27001, customer security questionnaires, data processing agreements |

---

## 4. Skills Matrix — Technology Map

```
ROLE                        Python  React/TS  PostgreSQL  Azure   Graph API  Security  Docker/CI  Neo4j
─────────────────────────── ──────  ────────  ──────────  ──────  ─────────  ────────  ─────────  ─────
Sr Backend Engineer         █████   ░░░░░     █████       ████░   ████░      ███░░     ███░░      ██░░░
Sr Full-Stack Engineer      ████░   █████     ████░       ██░░░   ██░░░      ██░░░     ██░░░      ░░░░░
Cloud Security Engineer     ███░░   ░░░░░     ██░░░       █████   █████      █████     ██░░░      ██░░░
DevOps Engineer             ██░░░   ░░░░░     ████░       ████░   ░░░░░      ███░░     █████      ░░░░░
Mid Backend Engineer        ████░   ░░░░░     ███░░       ██░░░   ██░░░      ██░░░     ██░░░      ░░░░░
Mid Frontend Engineer       ░░░░░   █████     ██░░░       ░░░░░   ░░░░░      █░░░░     █░░░░      ░░░░░
QA Engineer                 ███░░   ███░░     ███░░       ██░░░   █░░░░      ██░░░     ███░░      ░░░░░

█ = Required expertise level (each block ≈ 20%)
```

---

## 5. Go-to-Market — Next Steps to Sell

### Phase 1: Product Readiness (Weeks 1–4)

| # | Action | Owner | Details |
|---|--------|-------|---------|
| 1 | **Multi-tenant hardening** | Backend Eng | RLS audit complete (525 policies); validate tenant isolation for enterprise SLAs |
| 2 | **SOC 2 Type II readiness** | Compliance + DevOps | Audit logging exists; need formal controls documentation, evidence collection, auditor engagement |
| 3 | **Production environment** | DevOps | Azure Container Apps deployed; need HA, auto-scaling, backup/DR strategy, SLA targets |
| 4 | **Security penetration test** | External vendor | Third-party pentest before enterprise customers — they will ask for the report |
| 5 | **Customer-facing documentation** | TPM + SE | API docs, integration guides, admin guides, deployment prerequisites |
| 6 | **Demo environment** | SE + DevOps | Isolated demo tenant with realistic synthetic data (not customer data) |

### Phase 2: Market Entry (Weeks 4–12)

| # | Action | Owner | Details |
|---|--------|-------|---------|
| 7 | **Ideal Customer Profile (ICP)** | Sales + TPM | Mid-market to enterprise, Azure-heavy, 500+ identities, regulated industries (finance, healthcare, gov) |
| 8 | **Pricing model** | Sales + TPM | Per-identity or per-tenant tiered pricing; billing module already in codebase (`app/billing/`) |
| 9 | **Competitive positioning** | Marketing | Position vs. Microsoft Entra Permissions Management, CrowdStrike CIEM, Ermetic/Tenable, Opal, ConductorOne |
| 10 | **Sales collateral** | Marketing + SE | One-pager, pitch deck, ROI calculator, security whitepaper |
| 11 | **First 5 design partners** | Sales | Offer free/discounted access for feedback; target existing network contacts |
| 12 | **POC playbook** | SE | 14-day POC: Day 1 connect tenant → Day 3 first discovery → Day 7 risk review → Day 14 decision |

### Phase 3: Scale (Months 3–12)

| # | Action | Owner | Details |
|---|--------|-------|---------|
| 13 | **AWS + GCP discovery GA** | Backend Eng | Engines exist but need production hardening for multi-cloud customers |
| 14 | **SIEM/SOAR integrations** | Backend Eng | Splunk, Sentinel, ServiceNow, Jira — export findings and remediation tickets |
| 15 | **Marketplace listings** | DevOps + Sales | Azure Marketplace (primary), AWS Marketplace — drives inbound and simplifies procurement |
| 16 | **Analyst briefings** | Marketing | Gartner (CIEM MQ), Forrester (Identity Governance Wave), KuppingerCole |
| 17 | **Case studies** | CSM + Marketing | 2–3 published customer success stories with quantified outcomes |
| 18 | **Channel partnerships** | Sales | MSPs, MSSPs, consulting partners (Deloitte, Accenture, Big 4) |
| 19 | **Certifications** | Compliance | SOC 2 Type II report, ISO 27001, potentially FedRAMP (for gov) |

---

## 6. Competitive Landscape

### 6a. Summary

| Competitor | Category | AuditGraph Differentiator |
|------------|----------|--------------------------|
| **Microsoft Entra Permissions Management** | Native CIEM | Deeper SPN/MI analysis, cross-cloud identity graph, remediation workflows |
| **CrowdStrike CIEM (Falcon Identity)** | Platform add-on | Standalone focus, lower cost, purpose-built for identity governance |
| **Ermetic (Tenable Cloud Security)** | Cloud identity | Attack path + blast radius analysis, lineage engine, CISO-ready reporting |
| **Opal / ConductorOne** | Access governance | Real-time discovery (not just governance), risk scoring, anomaly detection |
| **Saviynt / SailPoint** | IGA platforms | Cloud-native, faster deployment, modern UX, identity-specific (not broad IGA) |
| **Zscaler CIEM** | Network-first CIEM | Identity-first approach, deeper Entra role analysis, no network dependency |
| **Wiz CIEM** | CNAPP add-on | Dedicated identity focus, lineage engine, remediation workflows (not just visibility) |
| **Authomize (Delinea)** | Identity threat | Broader cloud coverage, lower cost, open architecture |

### 6b. Feature Comparison Map

| Capability | AuditGraph | Entra PM | CrowdStrike | Ermetic/Tenable | Opal | Saviynt | Wiz | Zscaler |
|------------|:----------:|:--------:|:-----------:|:---------------:|:----:|:-------:|:---:|:-------:|
| **DISCOVERY & INVENTORY** | | | | | | | | |
| Azure AD / Entra identity discovery | Y | Y | Y | Y | P | Y | Y | Y |
| Service Principal deep analysis | Y | P | N | P | N | P | P | N |
| Managed Identity discovery | Y | Y | N | Y | N | P | Y | P |
| Federated credential detection | Y | P | N | P | N | N | P | N |
| Guest / B2B identity tracking | Y | Y | Y | P | N | Y | P | P |
| AWS IAM discovery | P | Y | Y | Y | Y | Y | Y | Y |
| GCP IAM discovery | P | Y | N | Y | P | Y | Y | Y |
| Credential expiry tracking | Y | P | N | P | N | P | N | N |
| **RISK & SCORING** | | | | | | | | |
| Identity risk scoring (CVSS-aligned) | Y | P | Y | Y | N | P | Y | P |
| Privilege tier classification (T0–T3) | Y | N | P | P | N | Y | N | N |
| Anomaly detection | Y | P | Y | Y | N | P | Y | P |
| Drift detection | Y | N | P | Y | N | P | Y | N |
| Risk forecasting | Y | N | N | N | N | N | N | N |
| **ATTACK PATH & GRAPH** | | | | | | | | |
| Attack path analysis | Y | P | Y | Y | N | N | Y | P |
| Blast radius calculation | Y | N | P | Y | N | N | Y | N |
| Identity relationship graph (Neo4j) | Y | N | N | P | N | N | P | N |
| Lineage engine (12-signal verdicts) | Y | N | N | N | N | N | N | N |
| **GOVERNANCE & REMEDIATION** | | | | | | | | |
| Access reviews / recertification | Y | Y | N | P | Y | Y | N | N |
| Remediation workflows | Y | P | P | Y | Y | Y | P | N |
| SOAR integration | Y | P | P | Y | N | Y | P | P |
| Policy generation | Y | P | N | P | Y | Y | N | N |
| Role mining / right-sizing | Y | Y | N | Y | Y | Y | P | P |
| **COMPLIANCE & REPORTING** | | | | | | | | |
| SOC 2 / HIPAA / PCI-DSS mapping | Y | P | P | Y | N | Y | P | P |
| NIST 800-53 controls mapping | Y | P | P | Y | N | Y | P | P |
| MITRE ATT&CK alignment | Y | N | Y | Y | N | N | Y | N |
| CIS Controls v8 mapping | Y | N | P | Y | N | Y | P | N |
| CISO executive dashboard | Y | P | N | P | N | P | P | N |
| Scheduled PDF/email reports | Y | P | N | P | N | Y | N | N |
| **ARCHITECTURE** | | | | | | | | |
| Multi-tenant (RLS isolation) | Y | Y | Y | Y | P | Y | Y | Y |
| Self-hosted / on-prem option | Y | N | N | N | N | Y | N | N |
| API-first (610+ endpoints) | Y | P | P | P | P | P | P | P |
| AI/Copilot investigation | Y | P | Y | P | N | P | Y | N |
| Open architecture (no vendor lock) | Y | N | N | N | Y | N | N | N |
| **PRICING** | | | | | | | | |
| Estimated annual (1000 identities) | $15–30K | $36K+ | $50K+ (bundle) | $40K+ | $24K+ | $80K+ | $60K+ (bundle) | $40K+ (bundle) |
| Standalone purchase | Y | Y | N (Falcon req) | Y | Y | Y | N (CNAPP req) | N (ZIA/ZPA req) |

**Legend:** Y = Full support | P = Partial / limited | N = Not available

### 6c. AuditGraph Unique Strengths

1. **Lineage Engine** — 12-signal verdict assembly with confidence scoring. No competitor has this.
2. **SPN/MI Deep Dive** — Most competitors treat service principals as second-class. AuditGraph discovers credentials, federated configs, Graph permissions, app roles, and ownership chains.
3. **Blast Radius + Attack Path** — Combined graph analysis showing both "how can this identity be compromised" and "what's the damage if it is."
4. **Price-to-Value** — 60–80% lower than enterprise incumbents (Saviynt, CrowdStrike bundles) with comparable or deeper identity-specific coverage.
5. **Self-Hosted Option** — Critical for regulated industries (banking, gov, healthcare) that can't send identity data to a third-party SaaS.
6. **Open API Surface** — 610+ endpoints vs competitors' limited APIs — enables custom integrations and automation.

---

## 7. Budget Estimation (Annual — India Hiring)

*All salaries in USD, based on India market rates (Bangalore/Hyderabad/Pune tier-1 cities, 2025–26).*

| Role | Count | India Salary (USD/yr) | Total |
|------|-------|-----------------------|-------|
| Sr Backend Engineer | 2 | $18K–$28K | $36K–$56K |
| Sr Full-Stack Engineer | 1 | $16K–$25K | $16K–$25K |
| Cloud Security / IAM Engineer | 1 | $18K–$30K | $18K–$30K |
| DevOps Engineer | 1 | $15K–$24K | $15K–$24K |
| Technical Product Manager | 1 | $16K–$25K | $16K–$25K |
| Solutions Engineer | 1 | $14K–$22K | $14K–$22K |
| Head of Sales (India/APAC) | 1 | $20K–$30K + commission | $20K–$30K |
| **Engineering subtotal** | **5** | | **$85K–$135K** |
| **GTM subtotal** | **3** | | **$50K–$77K** |
| **Total Year 1** | **8** | | **$135K–$212K** |

### India vs US Cost Comparison

| | US Market | India Market | Savings |
|---|-----------|-------------|---------|
| Engineering (5) | $780K–$970K | $85K–$135K | ~85–88% |
| GTM (3) | $420K–$545K | $50K–$77K | ~85–88% |
| **Total (8)** | **$1.2M–$1.5M** | **$135K–$212K** | **~85%** |

### India Hiring Notes
- **Tier-1 cities** (Bangalore, Hyderabad, Pune): Best talent pool for Azure/cloud security skills
- **Tier-2 cities** (Chennai, Kochi, Jaipur): 20–30% lower cost, good for mid-level roles
- **Hiring platforms**: Naukri, LinkedIn India, Instahyre, Cutshort, AngelList India
- **Key advantage**: India has a massive Azure talent pool due to Microsoft's large India presence
- **Consideration**: Head of Sales targeting US/EU enterprise customers may need to be US-based ($130K–$170K) for timezone/relationship reasons — keep one GTM hire in-market
- **Equity**: Can further reduce cash burn; Indian engineers increasingly value ESOP participation

---

## 8. Hiring Priority — Sequenced

```
MONTH 1          MONTH 2          MONTH 3          MONTH 4          MONTH 5-6
─────────        ─────────        ─────────        ─────────        ─────────
Sr Backend   →   DevOps Eng   →   Solutions Eng →  Mid Backend  →   QA Engineer
Sr Full-Stack→   Cloud Sec Eng→   Head of Sales →  Mid Frontend →   CSM
TPM          →                →                →   Marketing    →   Compliance
```

**First 3 hires** (immediately): Sr Backend + Sr Full-Stack + TPM — this gives you product velocity and direction.

**Next 2** (month 2): DevOps + Cloud Security — production hardening and domain credibility.

**Next 2** (month 3): Solutions Engineer + Head of Sales — start selling.

---

## 9. Key Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Single-person backend knowledge | Bus factor = 1 | Hire Sr Backend ASAP; this doc + TDD provide onboarding material |
| No SOC 2 report | Enterprise deal blocker | Start audit prep now (3–6 month process) |
| Test coverage ~40–50% | Regression risk at scale | QA hire + coverage targets (>80% critical paths) |
| Azure-only discovery mature | Limits TAM | AWS/GCP engines exist — need hardening investment |
| No marketplace listing | Missed inbound channel | Azure Marketplace listing is low effort, high ROI |
| Pricing not validated | Revenue risk | Design partner feedback before fixing pricing |

---

*Generated from AuditGraph codebase analysis — May 2026*
