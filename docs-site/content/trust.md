# AuditGraph Trust Center

> AuditGraph is built by NexgenixLabs to help security teams understand identity risk in their own cloud. We hold ourselves to the same standards we apply to your environment. This page consolidates our compliance posture, security architecture, sub-processors, and how to request audit artifacts.

**Last updated:** 2026-06-01

---

## Compliance posture

| Program | Status | How to obtain |
|---|---|---|
| **SOC 2 Type II** | Type 1 attestation Q2 2026; Type II observation period underway, full report Q3 2026 target | Available under NDA via `security@auditgraph.ai` |
| **ISO 27001** | Planned | Roadmap available on request |
| **HIPAA** | Business Associate Agreement available on request for customers with PHI in scope | `compliance@auditgraph.ai` |
| **GDPR** | Data Processing Addendum available on request | `compliance@auditgraph.ai` |
| **CIS Foundations Benchmark** | AuditGraph's own platform alignment is documented; controls map maintained internally | See `docs/governance/compliance/CIS.md` (customer copy on request) |

Our SOC 2 control catalog covers 35 controls across Security (CC6), Availability (A1), Confidentiality (C1), Processing Integrity (PI1), Monitoring (CC7), Change Management (CC8), and Risk Assessment (CC3). 33 of 35 are fully satisfied, 2 are in partial status with documented compensating controls — all tracked against the Q3 2026 Type II target.

We do not overstate certification. Where a program is "planned" or "in progress," we say so.

---

## Security architecture

AuditGraph follows a **Zero Trust** model. Every request is authenticated, authorized, and explicitly scoped to both `organization_id` (tenant) and `cloud_connection_id` (connector). Trust is never inherited from network position, prior session, or shared infrastructure.

### Defense-in-depth layers

1. **Network** — HTTPS/TLS, HSTS, security headers, CORS allowlist
2. **Authentication** — JWT (portal-specific signing keys), OIDC, SAML, API Keys (SHA-256 hashed, `ag_` prefix)
3. **Authorization** — Role-Based Access Control (8 roles), portal-scoped permissions, feature flags
4. **Tenant isolation** — PostgreSQL Row-Level Security on every tenant-scoped table, dual DB user pattern (app user has `NOBYPASSRLS`, admin user is reserved for system-level DDL)
5. **Data protection** — Field-level encryption (Fernet / MultiFernet) for application secrets, structured log redaction for tokens and credentials
6. **API protection** — Rate limiting on authentication endpoints, request size limits, input validation, idempotency keys for mutating operations
7. **Operational safety** — Circuit breakers on outbound calls, retry-with-backoff on cloud APIs, security event logging

### Tenant isolation specifics

- 44 of 54 application tables carry `tenant_id NOT NULL` with strict RLS policies. No null-context bypass — every query must declare a tenant context.
- A trigger (`trg_auto_tenant_id`) auto-populates `tenant_id` from session context on insert and raises if both context and explicit value are absent.
- Cross-tenant access by a superadmin is gated by an explicit `X-Tenant-Id` header override and logged to the activity audit trail.
- The host-to-tenant guard in `auth_middleware` verifies the subdomain slug against the JWT's tenant claim on every request.

Full architecture reference: `/#/security-architecture` (sidebar: Security → Security Architecture).

---

## Encryption

| Surface | Standard |
|---|---|
| Data at rest (database) | AES-256 via PostgreSQL transparent disk encryption (Azure Database for PostgreSQL) |
| Application secrets | Fernet (AES-128 in CBC mode + HMAC-SHA256) with MultiFernet key rotation |
| Data in transit | TLS 1.2+ enforced on every endpoint; HSTS preload-eligible policy |
| Production secret store | Azure Key Vault, RBAC-scoped, no secret material exported to logs or backups |
| Customer-provided cloud credentials | Read-only scopes only; encrypted at rest; never exported |

---

## Penetration testing

- **Frequency:** annual third-party penetration test plus continuous internal scanning
- **Most recent external test:** 2026-05-08
- **Findings:** all findings tracked in our remediation register with severity, owner, and target close date; executive summary available on request (NDA)
- **Continuous scanning:** quarterly internal red-team exercises, SAST + container image scanning on every PR via the `pr-gate.yml` and `container-infra-scan.yml` workflows, secret scanning on every commit

To request the executive summary: `security@auditgraph.ai`.

---

## Incident response

We maintain a documented Incident Response Plan with a severity matrix (Sev-0 through Sev-3), defined escalation paths, and customer-notification SLAs.

| Event | Customer notification SLA |
|---|---|
| Confirmed data exposure affecting customer data | Within 24 hours |
| Confirmed security breach (no data exposure yet confirmed) | Within 72 hours |
| Sev-0 platform outage | Status-page update within 15 minutes |

- **Monitoring:** 24/7 on-call rotation, alerting on auth anomalies, RLS policy violations, scheduler failures, and outbound-error spikes
- **Tabletop exercises:** quarterly, covering credential compromise, ransomware against operational tooling, and supply-chain incidents
- **Post-incident:** every Sev-0 / Sev-1 incident produces a public-facing root-cause analysis when customer data or service is affected

**Public incident archive:** none to date.

Source policy: `docs/governance/compliance/incident_response_plan.md`.

---

## Vulnerability disclosure

We welcome coordinated disclosure from independent security researchers.

- **Report to:** `security@auditgraph.ai` (PGP key available on request)
- **Coordinated-disclosure window:** 90 days from acknowledgement; we will not pursue legal action against good-faith research that adheres to this window and does not exfiltrate customer data
- **Acknowledgement target:** within 2 business days of report receipt
- **Hall of Fame:** researchers who report verified findings are listed publicly (with permission) on our security page

In scope: `*.auditgraph.ai` web properties, public API, the docs site. Out of scope: third-party services we use (report directly to those vendors).

---

## Sub-processors

We use a small, deliberately chosen set of sub-processors. Customers are notified 30 days before any material change to this list.

| Sub-processor | Purpose | Customer data hosted | Region |
|---|---|---|---|
| Microsoft Azure | Compute, Azure Database for PostgreSQL, Azure Key Vault, Azure Container Registry, Container Apps | All customer tenant data, metadata, audit logs | US (Central US) primary; EU available on request |
| Anthropic | Argus AI security analyst (optional; can be disabled per tenant) | Anonymized identity/role context for analyst queries — no PII, no credentials | US |
| Ollama (self-hosted alternative for Argus) | Open-source LLM provider, deployed in customer-controlled or AuditGraph-controlled compute | Same scope as Anthropic; never leaves the deployment boundary | Customer-elected |
| SendGrid | Transactional email (notifications, password reset, scheduled reports) | Customer email addresses, notification subject lines and excerpts | US |
| GitHub | Source code repository, CI/CD workflow execution | No customer data; product source and build artifacts only | US |

Argus AI analysis is **opt-in per tenant**. When disabled, no customer data is sent to any LLM provider.

---

## Customer data rights

| Right | How |
|---|---|
| Access | Self-serve export via the Evidence Center (JSON or CSV) at any time |
| Correction | Update via Settings or contact `support@auditgraph.ai` |
| Deletion (account-wide) | Settings → Data Lifecycle → Permanent deletion; all tenant data deleted within 30 days of confirmation |
| Portability | JSON or CSV export of all your identity, risk, run, and audit data |
| Restriction | Per-feature opt-outs (e.g., disable Argus, disable scheduled reports, disable email notifications) |
| Residency | US (Central US) default; EU region available on request for Enterprise plans |

You retain ownership of all data ingested from your cloud environments. We process it solely to provide the Service.

Source: `docs/security/data-protection.md`.

---

## Request documents

The following artifacts are available to customers and prospects evaluating AuditGraph:

| Document | Access |
|---|---|
| SOC 2 Type 1 attestation report (Q2 2026) | NDA — `security@auditgraph.ai` |
| Penetration test executive summary (most recent: 2026-05-08) | NDA — `security@auditgraph.ai` |
| Data Processing Addendum (DPA) | `compliance@auditgraph.ai` |
| Business Associate Agreement (BAA, HIPAA) | `compliance@auditgraph.ai` |
| Security FAQ for vendor diligence | Public: [`/#/security-vendor-faq`](#/security-vendor-faq) |
| Information Security Policy (executive summary) | On request |
| Sub-processor list | This page; updated as changes occur |

---

## Contact

| Purpose | Address |
|---|---|
| Security disclosures and incident reports | `security@auditgraph.ai` |
| Privacy questions and data-subject requests | `privacy@auditgraph.ai` |
| Compliance, audit artifacts, DPA / BAA requests | `compliance@auditgraph.ai` |
| General support | `support@auditgraph.ai` |

We aim to acknowledge security reports within 2 business days and respond substantively within 5.
