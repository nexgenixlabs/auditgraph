# AuditGraph — Current Roadmap

> Last updated: 2026-05-02

---

## Completed (Phases 1-86+)

### Core Identity Engine
- Identity discovery (Azure AD: users, SPNs, managed identities, guests)
- CVSS-aligned risk scoring (5 dimensions, privilege-modulated)
- AGIRS composite model (HIRI 40% + NHIRI 40% + GEI 20%)
- Blast radius scoring (0-100, 7 base + 15 additive bonuses)
- Posture Score aggregation (0-100, band-weighted)

### CISO Dashboard
- Executive posture report (1-page PDF)
- Privilege exposure, anomalies, blast radius widgets
- Risk velocity charts, trend sparklines
- Cloud context banner with provider status

### Identity Governance
- Service Account governance (attestation, policy enforcement)
- Identity lifecycle (active/inactive/stale/dormant/never_used)
- PIM tracking (eligible roles, activations, overuse)
- Access reviews and role mining

### Attack Paths & Simulation
- 5 escalation chain types (direct, ownership, PIM abuse, lateral, credential)
- What-If risk simulation (fix prioritization, delta preview)
- ReactFlow directed chain visualization

### Change Control Center
- Drift detection (persisted reports, 5 change types)
- Anomaly detection (6 types: permission escalation, risk spike, dormant reactivation, etc.)
- SOAR integration (playbooks, condition matching, cooldown, 4 action handlers)

### AI Agent Governance
- AI agent pattern detection (configurable patterns JSON)
- Agent classifier service
- Blast radius policy engine

### Security & Compliance
- Multi-tenant RLS (strict policies, dual DB users, auto-fill triggers)
- SSO/SAML (python3-saml, JIT provisioning, replay protection, HMAC codes)
- SOC 2 Type II mapping (35 controls, 33 satisfied)
- HIPAA safeguards (18 controls, 16 satisfied)
- SQL injection defense (schema-derived allowlists)

### Platform & SaaS
- Multi-tenant SaaS (subdomain routing, tenant isolation, superadmin)
- Admin portal (4 roles: superadmin/poweradmin/billing/reader)
- Client portal RBAC (admin/security_admin/compliance/reader)
- API key management (ag_ prefix, SHA-256 hashed, role-scoped)
- AI Security Copilot (Claude API, conversation history)
- Data retention & archival (6 cleanup methods, daily scheduler)

### Deployment & Ops
- Azure Container Apps (backend + frontend + admin)
- CI/CD via GitHub Actions (ACR build, Bicep infra)
- Scheduled discovery (APScheduler, per-tenant loops)
- Slack/Teams notification dispatcher
- Real-time monitoring & health (Prometheus metrics, system health page)

### Web Presence
- docs-site (18-page documentation site)
- Jira project: AG at nexgenixlabs.atlassian.net
- Confluence space: Auditgraph (spaceId: 21856259)

---

## In Progress

- P2 Telemetry pipeline stabilization (sign-in log ingestion, behavioral anomalies)
- Resource inventory collector & scope extractor engines
- Pipeline health monitoring
- Privilege drift event tracking
- Identity reachability mapping

---

## Backlog / Remaining

### Near-Term
- OpenAPI spec generation
- Terraform export integration
- Enhanced conditional access analysis
- Compliance auto-remediation (full Azure API integration, not simulated)
- Identity group risk rollup

### Cloud Expansion
- **AWS**: IAM discovery depth (policies, roles, SCPs, access keys)
- **GCP**: IAM discovery (service accounts, roles, org policies)
- Timeline: TBD (stubs exist in `backend/app/engines/discovery/`)

### Platform Maturity
- ML-based anomaly detection (replace heuristic thresholds)
- Cross-tenant analytics for MSP view
- Webhook event streaming
- Custom risk rules engine (user-defined)
- SSO group sync automation

---

## Infrastructure Decisions

| Component | Choice | Notes |
|-----------|--------|-------|
| Database | PostgreSQL | Azure PostgreSQL Flexible Server (prod) |
| Backend | Python Flask | Gunicorn, 2 workers, --preload |
| Frontend | React 19 + TypeScript | Tailwind CSS, Vite |
| Hosting | Azure Container Apps | eastus, static IP |
| CI/CD | GitHub Actions | ACR build, Bicep deploy |
| Auth | JWT (PyJWT + bcrypt) | SAML SSO optional |
| AI | Anthropic Claude API | Copilot service |
