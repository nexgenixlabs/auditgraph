# AuditGraph Documentation

**Cloud Identity Security Platform**

AuditGraph provides deep visibility into human and non-human identities, access relationships, privilege risk, and identity drift across Azure, AWS, and GCP environments.

---

## Directory Structure

```
docs/
├── architecture/     — System design, data models, graph construction
├── engineering/      — Dev setup, API docs, runbooks, scoring reference
├── product/          — Roadmap, features, positioning, demos
├── governance/       — Compliance frameworks, policies, scoring SSOT
├── security/         — Threat models, tenant isolation, hardening
├── verification/     — AG-* security fix audit trails
├── weekly/recap/     — Current SSOT snapshots (5 docs)
└── archive/          — Historical, stale, duplicate, and merged docs
```

---

## Getting Started

| Doc | Path | Audience |
|-----|------|----------|
| Introduction | [product/introduction.md](product/introduction.md) | All |
| Quick Start | [engineering/quick-start.md](engineering/quick-start.md) | All |
| Dev Environment | [engineering/DEV_ENVIRONMENT.md](engineering/DEV_ENVIRONMENT.md) | Engineers |
| Current Roadmap | [product/ROADMAP_CURRENT.md](product/ROADMAP_CURRENT.md) | All |
| Status Snapshot | [product/STATUS_SNAPSHOT.md](product/STATUS_SNAPSHOT.md) | All |

---

## Architecture

| Doc | Path |
|-----|------|
| Platform Architecture | [architecture/platform-overview.md](architecture/platform-overview.md) |
| Architecture SSOT | [architecture/ARCHITECTURE_SSOT.md](architecture/ARCHITECTURE_SSOT.md) |
| Data Model | [architecture/data-model.md](architecture/data-model.md) |
| Identity Graph | [architecture/identity-graph.md](architecture/identity-graph.md) |
| Discovery Engine | [architecture/discovery-engine.md](architecture/discovery-engine.md) |
| Data Tiers | [architecture/DATA_TIERS.md](architecture/DATA_TIERS.md) |
| Builder State Matrix | [architecture/BUILDER_STATE_MATRIX.md](architecture/BUILDER_STATE_MATRIX.md) |

---

## Engineering

| Doc | Path |
|-----|------|
| Dev Environment | [engineering/DEV_ENVIRONMENT.md](engineering/DEV_ENVIRONMENT.md) |
| API Reference | [engineering/api-reference.md](engineering/api-reference.md) |
| Operations & Deployment | [engineering/operations.md](engineering/operations.md) |
| Connectors | [engineering/connectors.md](engineering/connectors.md) |
| DB Migration Guide | [engineering/database-migration-guide.md](engineering/database-migration-guide.md) |
| DB Provisioning Runbook | [engineering/DB_PROVISIONING_RUNBOOK.md](engineering/DB_PROVISIONING_RUNBOOK.md) |
| Scoring Reference | [engineering/SCORING_REFERENCE.md](engineering/SCORING_REFERENCE.md) |
| Best Practices | [engineering/best-practices.md](engineering/best-practices.md) |
| Auth Architecture | [engineering/auth-architecture.md](engineering/auth-architecture.md) |
| Regression Test Matrix | [engineering/REGRESSION_TEST_MATRIX.md](engineering/REGRESSION_TEST_MATRIX.md) |
| Discovery Pipeline Fixes | [engineering/discovery_pipeline_fixes.md](engineering/discovery_pipeline_fixes.md) |
| Runbooks | [engineering/runbooks/](engineering/runbooks/) |

---

## Product

| Doc | Path |
|-----|------|
| Current Roadmap | [product/ROADMAP_CURRENT.md](product/ROADMAP_CURRENT.md) |
| Status Snapshot | [product/STATUS_SNAPSHOT.md](product/STATUS_SNAPSHOT.md) |
| Product Textbook | [product/AuditGraph_Product_Textbook.md](product/AuditGraph_Product_Textbook.md) |
| Competitive Positioning | [product/competitive_positioning.md](product/competitive_positioning.md) |
| Prod Readiness Audit | [product/prodready.md](product/prodready.md) |
| Demo Script (Backend) | [product/DEMO_SCRIPT.md](product/DEMO_SCRIPT.md) |
| Pilot Demo Script | [product/pilot_demo_script.md](product/pilot_demo_script.md) |
| Security Marketing Kit | [product/security_marketing_kit.md](product/security_marketing_kit.md) |
| FAQ | [product/faq.md](product/faq.md) |
| Glossary | [product/glossary.md](product/glossary.md) |
| Gate Closure Log | [product/GATE_CLOSURE_LOG.md](product/GATE_CLOSURE_LOG.md) |

---

## Governance

| Doc | Path |
|-----|------|
| Compliance Overview | [governance/compliance-overview.md](governance/compliance-overview.md) |
| SOC 2 Type II | [governance/compliance/SOC2.md](governance/compliance/SOC2.md) |
| HIPAA | [governance/compliance/HIPAA.md](governance/compliance/HIPAA.md) |
| CIS Benchmarks | [governance/compliance/CIS.md](governance/compliance/CIS.md) |
| Information Security Policy | [governance/compliance/information_security_policy.md](governance/compliance/information_security_policy.md) |
| MFA Policy | [governance/compliance/mfa_policy.md](governance/compliance/mfa_policy.md) |
| Incident Response Plan | [governance/compliance/incident_response_plan.md](governance/compliance/incident_response_plan.md) |
| DR Test Procedure | [governance/compliance/dr_test_procedure.md](governance/compliance/dr_test_procedure.md) |
| Compliance Matrix | [governance/compliance_matrix.md](governance/compliance_matrix.md) |
| Risk Scoring (AGIRS) | [governance/risk-scoring.md](governance/risk-scoring.md) |
| Security Posture Assessment | [governance/security-posture.md](governance/security-posture.md) |
| Security Architecture Whitepaper | [governance/security_architecture_whitepaper.md](governance/security_architecture_whitepaper.md) |

---

## Security

| Doc | Path |
|-----|------|
| Security Overview | [security/overview.md](security/overview.md) |
| Security Architecture | [security/security-architecture.md](security/security-architecture.md) |
| Security Features | [security/security-features.md](security/security-features.md) |
| Data Protection | [security/data-protection.md](security/data-protection.md) |
| Tenant Isolation (AG-94) | [security/tenant-isolation.md](security/tenant-isolation.md) |
| Vendor Security FAQ | [security/vendor-security-faq.md](security/vendor-security-faq.md) |
| SQL Identifier Safety | [security/sql-identifier-safety.md](security/sql-identifier-safety.md) |
| SSO/SAML Security | [security/sso-saml-security.md](security/sso-saml-security.md) |

---

## Verification (Security Fix Audit Trails)

| Doc | Path |
|-----|------|
| AG-72 Memberships Fix | [verification/AG-72_verify_20260427.md](verification/AG-72_verify_20260427.md) |
| AG-93 SQL Injection Fix | [verification/AG-93_fix_20260427.md](verification/AG-93_fix_20260427.md) |
| AG-94 Cross-Tenant Fix | [verification/AG-94_fix_20260427.md](verification/AG-94_fix_20260427.md) |
| AG-95 SSO/SAML Audit | [verification/AG-95_audit_20260428.md](verification/AG-95_audit_20260428.md) |
| AG-95 SSO/SAML Fix | [verification/AG-95_fix_20260428.md](verification/AG-95_fix_20260428.md) |
| AG-95-v2 Encryption | [verification/AG-95-v2_fix_20260428.md](verification/AG-95-v2_fix_20260428.md) |
| AG-129 Audit | [verification/AG-129_audit_20260428.md](verification/AG-129_audit_20260428.md) |
| AG-129 Org ID Fix | [verification/AG-129_fix_20260428.md](verification/AG-129_fix_20260428.md) |
| AG-132 Cross-Tenant Leak | [verification/AG-132_fix_20260428.md](verification/AG-132_fix_20260428.md) |

---

## Weekly SSOT Snapshots

| Doc | Path |
|-----|------|
| Executive Summary | [weekly/recap/00-executive-summary.md](weekly/recap/00-executive-summary.md) |
| Database Schema | [weekly/recap/01-database-schema.md](weekly/recap/01-database-schema.md) |
| API Endpoints | [weekly/recap/02-api-endpoints.md](weekly/recap/02-api-endpoints.md) |
| Feature Inventory | [weekly/recap/03-feature-inventory.md](weekly/recap/03-feature-inventory.md) |
| Frontend & Deployment | [weekly/recap/04-frontend-and-deployment.md](weekly/recap/04-frontend-and-deployment.md) |

---

## Archive

Historical, stale, duplicate, and pre-merge originals are preserved in `archive/`:
- `archive/history/` — build logs, phase logs, weekly summaries (weeks 1-11)
- `archive/stale/` — superseded docs (newui.md, Hosting_strategy.md, etc.)
- `archive/duplicates/` — backend copy of tenant-isolation.md
- `archive/merged/` — originals before SCORING merge

---

## External References

- **docs-site/content/**: Published documentation site mirror (18 files, maintained separately)
- **Jira**: Project AG at nexgenixlabs.atlassian.net
- **Confluence**: Space "Auditgraph" (spaceId: 21856259)

---

## Platform URLs

| Environment | URL |
|-------------|-----|
| Client Portal | `https://app.auditgraph.ai` |
| Admin Portal | `https://admin.auditgraph.ai` |
| API | `https://api.auditgraph.ai` |
| Dev API | `https://dev.api.auditgraph.ai` |
| Dev App | `https://dev.app.auditgraph.ai` |
| Demo | `https://demo.auditgraph.ai` |

---

*AuditGraph — Cloud Identity Security Platform*
