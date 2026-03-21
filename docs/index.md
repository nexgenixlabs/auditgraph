# AuditGraph Documentation

**Cloud Identity Security Platform**

AuditGraph provides deep visibility into human and non-human identities, access relationships, privilege risk, and identity drift across Azure, AWS, and GCP environments.

---

## Documentation

### Getting Started

| Section | Description | Audience |
|---------|-------------|----------|
| [Introduction](introduction.md) | Platform overview, key capabilities, identity security concepts | All |
| [Quick Start Guide](quick-start.md) | Step-by-step onboarding, first scan, interpreting results | All |

### Architecture

| Section | Description | Audience |
|---------|-------------|----------|
| [Architecture](architecture.md) | Platform architecture, discovery pipeline, connector model | Engineers, Architects |
| [Identity Graph](identity-graph.md) | Access graph model, relationship mapping, privilege analysis | Analysts, Auditors |
| [Platform Data Model](data-model.md) | Database schema, entity relationships, tenant isolation | Engineers, Architects |

### Security

| Section | Description | Audience |
|---------|-------------|----------|
| [Security Overview](security/overview.md) | Executive-level platform security model and vendor assessment guide | CISOs, Security Leaders |
| [Data Protection](security/data-protection.md) | Tenant isolation, encryption, credential storage, API hardening | Security Leaders, Auditors |
| [Security Architecture](security-architecture.md) | Authentication, RBAC, tenant isolation, encryption | Security Leaders, Engineers |
| [Security Features](security-features.md) | Rate limiting, encryption, circuit breakers, event logging | Engineers, Security Leaders |
| [Vendor Security FAQ](security/vendor-security-faq.md) | Common vendor assessment questions with concise answers | CISOs, Auditors, Procurement |
| [Security Posture](security-posture.md) | Platform security maturity, compliance, data protection | Security Leaders, Auditors |

### Governance

| Section | Description | Audience |
|---------|-------------|----------|
| [Risk Scoring Model](risk-scoring.md) | AGIRS, HIRI, NHIRI, GEI scoring models | Security Leaders, Analysts |
| [Compliance Mapping](compliance.md) | SOC 2, ISO 27001, NIST, CIS, HIPAA, PCI-DSS framework mapping | Security Leaders, Auditors |
| [Best Practices](best-practices.md) | Connector setup, risk remediation, least privilege, monitoring | All |

### Operations

| Section | Description | Audience |
|---------|-------------|----------|
| [Connectors](connectors.md) | Cloud connector setup, permissions, credential management | Engineers, DevOps |
| [Discovery Engine](discovery-engine.md) | Discovery pipeline, scan modes, scheduling | Engineers, Analysts |
| [Operations](operations.md) | Deployment, configuration, monitoring, troubleshooting | DevOps, Engineers |

### Reference

| Section | Description | Audience |
|---------|-------------|----------|
| [API Reference](api-reference.md) | Endpoint inventory, authentication, request/response examples | Engineers, DevOps |
| [Glossary](glossary.md) | Identity security terminology and AuditGraph-specific definitions | All |
| [FAQ](faq.md) | Common questions and answers | All |

---

## Quick Links

- **Getting Started**: [Quick Start Guide](quick-start.md) > [Connectors](connectors.md) > [Discovery Engine](discovery-engine.md)
- **Security Review**: [Security Overview](security/overview.md) > [Data Protection](security/data-protection.md) > [Security Posture](security-posture.md)
- **Risk Analysis**: [Risk Scoring Model](risk-scoring.md) > [Identity Graph](identity-graph.md) > [Best Practices](best-practices.md)
- **Integration**: [API Reference](api-reference.md) > [Connectors](connectors.md) > [Operations](operations.md)
- **Vendor Assessment**: [Security Overview](security/overview.md) > [Vendor Security FAQ](security/vendor-security-faq.md) > [Data Protection](security/data-protection.md)

---

## Platform URLs

| Environment | URL |
|-------------|-----|
| Client Portal | `https://app.auditgraph.ai` |
| Admin Portal | `https://admin.auditgraph.ai` |
| API | `https://api.auditgraph.ai` |
| Documentation | `https://docs.auditgraph.ai` |

---

*AuditGraph v1.0 -- Cloud Identity Security Platform*
