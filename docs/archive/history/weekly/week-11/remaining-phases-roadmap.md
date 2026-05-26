# AuditGraph: Remaining Phases Roadmap (Phase 52+)

> Forward-looking technical roadmap for the AuditGraph identity security audit platform. Each proposed phase builds on the existing foundation of 51 completed phases, which include multi-cloud identity discovery, risk scoring, compliance frameworks, anomaly detection, SOAR integration, multi-tenancy, and a full React/TypeScript frontend.

---

## What Already Exists (Context for Roadmap)

Before proposing new phases, here is a summary of capabilities that are already built and should NOT be duplicated:

| Capability | Existing Phase(s) |
|------------|-------------------|
| JWT authentication with RBAC (admin/auditor/viewer) | Phase 31 |
| API key management with role scoping | Phase 42 |
| Multi-tenancy with superadmin role | Phases 45-46 |
| Compliance frameworks (SOC 2, NIST, HIPAA, CIS) | Phases 32, 50, 51 |
| Anomaly detection (6 types) | Phase 40 |
| SOAR with Slack/Teams/PagerDuty/ServiceNow/Jira | Phase 43 |
| Webhook notifications (7 event types) | Phase 28 |
| In-app notification center | Phase 30 |
| Email notifications | Phases 14, 18 |
| Drift detection and history | Phases 14, 16 |
| Remediation playbooks and tracking | Phases 12, 21 |
| Access review campaigns | Phase 36 |
| Role mining and optimization | Phase 37 |
| Identity lifecycle tracking | Phase 35 |
| Risk simulation ("What If") | Phase 49 |
| Export pipeline (CSV/JSON for identities, compliance, drift, risk-summary) | Phase 33 |
| Dashboard customization | Phase 44 |
| Dark mode | Phases 22-24 |
| Global search (Cmd+K) | Phase 27 |
| Advanced query builder | Phase 39 |
| Onboarding wizard | Phase 48 |
| Azure AD full discovery (production) | Core |
| AWS/GCP discovery (placeholder stubs) | Core |

---

## Phase Categories

| Category | Phases | Focus Area |
|----------|--------|------------|
| **API & Developer Experience** | 52 | OpenAPI documentation, SDK generation |
| **Cloud Depth** | 53-54 | Full AWS/GCP IAM support |
| **Enterprise Authentication** | 55, 60 | SCIM provisioning, SSO/SAML |
| **Governance Workflows** | 57, 62, 66 | Approval workflows, certification, entitlements |
| **Automation** | 58 | Auto-remediation with guardrails |
| **Intelligence & Analytics** | 59, 67, 74 | ML anomaly detection, ITDR, intelligence dashboard |
| **Integration** | 56, 61 | PAM, SIEM export |
| **Security Architecture** | 63-65 | Service accounts, federation, Zero Trust |
| **Operations** | 68, 72-73 | Monitoring, retention, advanced reporting |
| **Platform Evolution** | 69-71 | Mobile, plugins, CA simulation |

---

## Phase 52: OpenAPI/Swagger Documentation

### Description

Auto-generate and serve interactive API documentation from the existing Flask routes. Integrate Flask-RESTX or Flasgger to produce an OpenAPI 3.0 specification. The `/api/docs` endpoint serves Swagger UI, and `/api/openapi.json` provides the machine-readable specification. All 80+ existing endpoints are annotated with request/response schemas, authentication requirements, and example payloads.

### Priority: **High**
### Estimated Complexity: **Medium**
### Dependencies: None (builds on existing routes in `main.py`)

### Business Value

API documentation is essential for external integrations, partner onboarding, and developer experience. Currently, API consumers must read source code to understand endpoints. OpenAPI documentation enables self-service integration, reduces support burden, and is a prerequisite for an API marketplace or partner ecosystem. It also enables auto-generation of client SDKs in Python, JavaScript, Go, and other languages.

### What Would Be Built

- OpenAPI 3.0 specification for all 96+ endpoints
- Swagger UI served at `/api/docs`
- Request/response JSON Schema definitions
- Authentication documentation (JWT + API key flows)
- Example requests and responses for every endpoint
- SDK generation configuration (openapi-generator)
- Postman collection export

---

## Phase 53: AWS IAM Deep Integration

### Description

Replace the placeholder `AWSDiscoveryEngine` stub with a production implementation that discovers and analyzes AWS IAM identities. Coverage includes:
- IAM users, roles, groups, and policies (managed + inline)
- Service accounts and access key rotation status
- STS assumed role sessions
- AWS SSO (Identity Center) users and permission sets
- Resource-based policies (S3, KMS, Lambda, etc.)
- CloudTrail-based activity analysis for usage status
- Cross-account role trust relationships
- Permission boundaries analysis
- Mapping AWS findings to the existing risk scoring, compliance, and anomaly detection engines

### Priority: **High**
### Estimated Complexity: **Large**
### Dependencies: Core multi-cloud foundation (already exists), `BaseDiscoveryEngine` class (already exists in `backend/app/engines/discovery/base.py`)

### Business Value

AWS is the most widely used cloud platform. Full AWS IAM support dramatically expands the addressable market and enables organizations with hybrid Azure/AWS environments to get a unified identity security view. AWS IAM is the #1 target in cloud breaches -- full visibility is critical. This is the single highest-impact feature for market expansion.

### What Would Be Built

- `AWSDiscoveryEngine` implementation with boto3
- IAM user discovery (access keys, MFA status, last activity, console login)
- IAM role discovery (trust policies, attached policies, assume-role chains)
- Policy analysis (admin-equivalent detection, wildcard permissions)
- Service-linked role tracking
- Cross-account trust mapping
- Risk scoring adapted for AWS IAM concepts
- Credential health: access key age, rotation status, unused keys
- AWS-specific columns/fields in identity detail
- Integration with existing drift, anomaly, and compliance engines

### Key API Additions

```
GET /api/identities?cloud=aws          -- Filter to AWS identities
GET /api/identities/<id>               -- AWS-specific fields in detail response
```

---

## Phase 54: GCP IAM Deep Integration

### Description

Replace the placeholder `GCPDiscoveryEngine` stub with a production implementation covering:
- GCP IAM members (users, service accounts, groups)
- IAM policy bindings at organization, folder, project, and resource levels
- Service account key rotation and usage
- Workload Identity Federation configurations
- Cloud Audit Logs integration for activity tracking
- Custom roles analysis and recommendation
- Cross-project access analysis
- Organization-level policy inheritance analysis

### Priority: **High**
### Estimated Complexity: **Large**
### Dependencies: Core multi-cloud foundation (already exists), `BaseDiscoveryEngine` class (already exists)

### Business Value

Completes the multi-cloud trifecta (Azure + AWS + GCP), making AuditGraph a true multi-cloud identity security platform. GCP's IAM model has unique concepts (service account impersonation chains, Workload Identity) that require specialized discovery. Necessary for enterprises with GCP workloads and for competitive positioning against cloud-specific tools.

### What Would Be Built

- `GCPDiscoveryEngine` implementation with google-cloud-iam
- Service account discovery (keys, impersonation chains, Workload Identity)
- IAM binding discovery (org, folder, project, resource levels)
- Custom role analysis and least-privilege recommendations
- Workload Identity Federation mapping
- Service account key age and rotation tracking
- GCP-specific risk scoring for privilege patterns
- Integration with existing drift, anomaly, and compliance engines

---

## Phase 55: SCIM Provisioning Integration

### Description

Implement SCIM 2.0 (System for Cross-domain Identity Management) client support to integrate with identity providers for automated user provisioning and deprovisioning. Features include:
- SCIM client that connects to IdP SCIM endpoints (Okta, Azure AD, OneLogin, etc.)
- Monitor provisioning events (user creation, attribute updates, deactivation)
- Correlate SCIM events with discovered identities to detect provisioning drift
- Alert on deprovisioned users that still have active cloud access (ghost accounts)
- SCIM event timeline in identity lifecycle view
- SCIM health monitoring dashboard widget

### Priority: **Medium**
### Estimated Complexity: **Large**
### Dependencies: Phase 35 (Identity Lifecycle), Phase 31 (Authentication)

### Business Value

SCIM integration bridges the gap between HR-driven provisioning systems and actual cloud access. Detecting when a deprovisioned employee still has active service principal access is a critical security finding that manual processes frequently miss. This addresses one of the most common audit findings: orphaned accounts from terminated employees.

### What Would Be Built

- SCIM 2.0 client implementation
- IdP connector configurations (Okta, Azure AD, OneLogin)
- Provisioning event ingestion and storage
- Ghost account detection engine
- Lifecycle correlation dashboard
- SCIM configuration UI in Settings

---

## Phase 56: Privileged Access Management (PAM) Integration

### Description

Integrate with leading PAM solutions (CyberArk, BeyondTrust, HashiCorp Vault, AWS Secrets Manager) to:
- Correlate PAM-managed credentials with discovered identities
- Identify identities with privileged access NOT managed by PAM (coverage gaps)
- Monitor PAM session activity and correlate with PIM activations
- Alert on PAM bypass (direct credential usage without PAM checkout)
- Dashboard widget showing PAM coverage metrics
- PAM-managed badge in identity table

### Priority: **Medium**
### Estimated Complexity: **Large**
### Dependencies: Phase 42 (API Key Management for PAM system authentication), Phase 40 (Anomaly Detection for PAM bypass detection)

### Business Value

PAM is a critical control for privileged access security. PAM coverage gaps are a top audit finding. This integration quantifies PAM adoption and identifies the highest-risk unmanaged privileged identities, directly supporting PAM program expansion justification. Addresses the question: "Which of our privileged identities are NOT managed by our PAM solution?"

### What Would Be Built

- CyberArk Privileged Cloud API integration
- BeyondTrust API integration
- HashiCorp Vault API integration
- PAM coverage analysis engine (privileged identities not in PAM)
- PAM bypass detection via anomaly correlations
- PAM coverage dashboard widget
- Compliance control: "All Tier-0 accounts in PAM"
- PAM configuration UI in Settings

---

## Phase 57: Identity Governance Workflows

### Description

Build configurable approval and review workflows for identity governance actions:
- Access request workflow: users request access, managers/security approve
- Deprovisioning workflow: triggered by lifecycle state changes, requiring multi-party approval
- Role change workflow: role modifications require review before execution
- Exception workflow: temporary elevated access with automatic expiration
- Workflow templates for common patterns
- Workflow audit trail integrated with Activity Log (Phase 17)
- Email notifications at each workflow step via existing EmailService
- Workflow status dashboard

### Priority: **Medium**
### Estimated Complexity: **Large**
### Dependencies: Phase 31 (RBAC), Phase 36 (Access Reviews), Phase 17 (Activity Log)

### Business Value

Governance workflows transform AuditGraph from an audit/monitoring tool into an active governance platform. Automated workflows ensure consistent policy enforcement, reduce manual coordination overhead, and provide complete audit trails for compliance evidence. This is a foundational capability for Identity Governance and Administration (IGA).

### What Would Be Built

- `workflows` and `workflow_steps` tables
- Workflow engine with configurable steps and approvers
- Workflow templates (access request, deprovisioning, role change)
- Multi-level approval chains
- Automatic escalation for unresponsed approvals
- Workflow completion tracking and SLA measurement
- Integration with SOAR (Phase 43) for automated actions
- Workflow configuration UI

---

## Phase 58: Compliance Auto-Remediation

### Description

Extend the existing SOAR and compliance gap analysis systems to support automated remediation of compliance failures:
- Define remediation actions per compliance control (e.g., "disable identity", "rotate credential")
- Auto-remediation mode with approval gates (propose + auto-execute after approval timeout)
- Dry-run mode showing what would be remediated before execution
- Integration with Azure AD Graph API for executing changes (disable user, revoke session, rotate key)
- Rollback capability for auto-remediation actions (undo within configurable window)
- Dashboard showing auto-remediation activity, success rates, and MTTR impact
- Guardrails: max identities per batch, require approval for high-risk actions

### Priority: **Medium**
### Estimated Complexity: **Large**
### Dependencies: Phase 12 (Remediation Engine), Phase 32 (Compliance Frameworks), Phase 43 (SOAR Integration), Phase 50 (Gap Analysis)

### Business Value

Auto-remediation reduces the time between detection and resolution from days/weeks to minutes. For high-confidence, low-risk remediations (e.g., disabling a never-used service principal with expired credentials), automation eliminates the human bottleneck entirely. This is the natural evolution of the remediation + compliance stack and represents significant operational efficiency gains.

### What Would Be Built

- Execution engine for remediation actions (Azure Graph API, ARM API)
- Remediation action library (disable, rotate, revoke, demote)
- Guardrail framework (approval requirements by risk level)
- Rollback capability with time-limited undo window
- Dry-run simulation mode
- Execution audit trail in Activity Log
- Auto-remediation policy configuration UI
- Remediation velocity and MTTR dashboard

---

## Phase 59: Advanced ML-Based Anomaly Detection

### Description

Augment the existing rule-based anomaly detector (Phase 40) with machine learning models:
- Baseline behavioral profiles per identity using historical discovery run data
- Unsupervised anomaly detection (Isolation Forest, Local Outlier Factor) on access patterns
- Time-series anomaly detection on risk score trajectories
- Peer group analysis: compare an identity's permissions to similar identities and flag outliers
- Anomaly confidence scoring with explainability (which features drove the anomaly)
- Model training pipeline using historical data stored across discovery runs
- A/B comparison of ML vs. rule-based detection rates
- Configurable sensitivity thresholds

### Priority: **Low**
### Estimated Complexity: **Large**
### Dependencies: Phase 40 (Anomaly Detection), Phase 41 (Risk Trend Analytics)

### Business Value

ML-based detection catches subtle behavioral anomalies that rule-based systems miss (e.g., gradual privilege creep that stays below fixed thresholds). Peer group analysis identifies identities that are outliers compared to their role, reducing false positives while catching novel attack patterns. This is a key differentiating capability against competitors.

### What Would Be Built

- Behavioral baseline model per identity
- Isolation Forest / DBSCAN anomaly detectors
- Peer group clustering and outlier scoring
- Explainability engine (feature importance per anomaly)
- Model training and evaluation pipeline
- ML anomaly results integrated with existing anomaly UI
- Sensitivity configuration in Settings

---

## Phase 60: SSO/SAML Integration

### Description

Support enterprise SSO for AuditGraph platform authentication:
- SAML 2.0 Service Provider implementation (pysaml2 or python3-saml)
- OIDC (OpenID Connect) relying party support
- Integration with major IdPs: Okta, Azure AD, OneLogin, Ping Identity, Google Workspace
- JIT (Just-In-Time) user provisioning from SAML attributes
- Role mapping from IdP groups to AuditGraph roles (admin/auditor/viewer)
- Single logout support
- SSO configuration UI in Settings
- Fallback to local auth when SSO is unavailable

### Priority: **High**
### Estimated Complexity: **Medium**
### Dependencies: Phase 31 (Authentication)

### Business Value

Enterprise customers require SSO for security policy compliance and user experience. Without SSO, AuditGraph requires separate credentials, creating a security risk (another password for users to manage) and a UX friction point. SSO is frequently a procurement requirement for enterprise sales and is essential for enterprise-grade deployments.

### What Would Be Built

- SAML 2.0 SP implementation
- OIDC RP implementation
- IdP metadata import/export
- Attribute-to-role mapping engine
- JIT user provisioning
- SSO configuration and testing UI in Settings
- Multi-IdP support (different tenants can use different IdPs)

---

## Phase 61: SIEM Export Integration

### Description

Build native export integrations for major SIEM platforms:
- Splunk HEC (HTTP Event Collector) integration
- Microsoft Sentinel (Log Analytics Workspace) integration via Azure Monitor
- Elastic/OpenSearch direct indexing
- Syslog (CEF format) export for legacy SIEMs
- Configurable export frequency (real-time via webhook, batch on schedule)
- Event normalization to common schemas (CEF, OCSF)
- Export filtering (only critical/high severity events, specific event types)
- Export health monitoring and failure alerting
- Dashboard templates for each SIEM (pre-built queries and visualizations)

### Priority: **Medium**
### Estimated Complexity: **Medium**
### Dependencies: Phase 28 (Webhooks -- provides the event infrastructure foundation), Phase 15 (Settings)

### Business Value

Security operations teams live in their SIEM. Exporting identity security events to the SIEM enables correlation with network, endpoint, and application security data. This integration makes AuditGraph data actionable within existing SOC workflows rather than requiring analysts to context-switch to a separate tool.

### What Would Be Built

- Syslog forwarder (CEF/LEEF format)
- Splunk HEC connector
- Sentinel/Azure Monitor connector
- Elastic bulk API connector
- OCSF event schema normalization
- Export filter configuration UI
- SIEM dashboard template packages

---

## Phase 62: Role-Based Access Certification

### Description

Extend access review campaigns (Phase 36) with role-centric certification:
- Certify roles (not just identities): review all identities assigned to a specific role
- Role owner assignment and notification
- Automatic campaign generation for high-risk roles on configurable schedules
- Attestation workflow: role owners attest that each assignment is still needed
- Automatic role removal for uncertified assignments (with approval gates)
- Certification dashboard with compliance metrics
- Integration with governance workflows (Phase 57)
- Certification history and trending

### Priority: **Medium**
### Estimated Complexity: **Medium**
### Dependencies: Phase 36 (Access Reviews), Phase 37 (Role Mining)

### Business Value

Role-based certification is a more efficient approach than identity-based reviews for environments with many identities sharing common roles. It aligns with how permissions are actually managed (by role, not by individual) and is a specific requirement in SOX and HIPAA compliance programs. Addresses the question: "Is everyone who has the Global Administrator role still authorized for it?"

### What Would Be Built

- Role-centric campaign type in access reviews
- Role owner assignment database and UI
- Scheduled campaign auto-generation
- Attestation recording and tracking
- Automatic revocation (configurable post-deadline)
- Role certification dashboard
- Historical certification reports

---

## Phase 63: Service Account Governance

### Description

Specialized governance capabilities for non-human identities (service principals, managed identities, service accounts):
- Service account ownership assignment and tracking (extending Phase 10B)
- Credential rotation policy enforcement with automated alerts
- Service account lifecycle management (creation approval, periodic revalidation, decommissioning)
- Dependency mapping: which applications/services depend on each service account
- Service account risk scoring calibrated for non-human identity patterns
- Service account inventory report for auditors
- Integration with CI/CD systems to detect service accounts created by pipelines
- Dormant service account identification and decommissioning workflows

### Priority: **High**
### Estimated Complexity: **Medium**
### Dependencies: Phase 12 (Remediation), Phase 35 (Identity Lifecycle), Phase 38 (Identity Groups)

### Business Value

Service accounts are the fastest-growing identity type and the most common attack vector (per Microsoft and CrowdStrike reports). They lack the natural governance that human identities receive through HR processes. Specialized service account governance addresses the largest unmanaged risk surface in most organizations and is a top audit finding in nearly every security assessment.

### What Would Be Built

- Service account ownership registry
- Credential rotation policy engine
- Lifecycle state management (provisioned, active, dormant, decommissioned)
- Dependency mapping database and visualization
- Non-human-specific risk scoring adjustments
- Service account inventory export
- Decommissioning workflow integration

---

## Phase 64: External Identity Federation Management

### Description

Discover and analyze external identity federation configurations:
- Enumerate Azure AD B2B (external collaboration) settings
- Detect cross-tenant access policies and their risk implications
- Identify externally federated identities and their access scope
- Monitor changes to federation trust relationships via drift detection
- Risk scoring for federation configurations (allow-list vs. broad trust)
- Dashboard showing external identity exposure metrics
- Alerts on federation configuration changes
- External guest identity inventory and access review integration

### Priority: **Medium**
### Estimated Complexity: **Medium**
### Dependencies: Phase 45 (Multi-Tenant), Phase 14 (Drift Detection)

### Business Value

External identity federation is a frequently overlooked attack surface. A misconfigured B2B policy or overly broad cross-tenant trust can expose an entire organization to external threats. This phase provides visibility into a risk area that most identity security tools ignore but that represents significant exposure in organizations with extensive partner/vendor relationships.

### What Would Be Built

- B2B configuration discovery
- Cross-tenant access policy analysis
- External identity inventory
- Federation trust risk scoring
- Federation change monitoring via drift
- External exposure dashboard widget
- Access review integration for guest identities

---

## Phase 65: Zero Trust Posture Assessment

### Description

Evaluate the organization's identity-centric Zero Trust maturity:
- Zero Trust assessment framework with maturity levels (Traditional, Advanced, Optimal)
- Pillar-based scoring aligned with CISA Zero Trust Maturity Model: Identity, Devices, Network, Applications, Data, Infrastructure
- Identity-specific metrics: MFA adoption, conditional access coverage, least-privilege adherence, session management
- Gap analysis with specific recommendations per pillar
- Benchmark comparison against industry standards
- Executive-friendly Zero Trust dashboard with maturity radar chart
- Improvement roadmap generation based on current maturity gaps
- Integration with existing compliance framework engine for automated scoring

### Priority: **Medium**
### Estimated Complexity: **Medium**
### Dependencies: Phase 32 (Compliance Frameworks), Phase 9 (Conditional Access), Phase 50 (Gap Analysis)

### Business Value

Zero Trust is the dominant security architecture paradigm. Organizations need to measure and demonstrate their Zero Trust maturity to leadership, cyber insurers, and regulators. A Zero Trust posture assessment provides a strategic roadmap and quantifiable progress metrics. This capability aligns with federal mandates (EO 14028) and industry best practices.

### What Would Be Built

- Zero Trust maturity model data definitions
- Pillar-based scoring engine
- Maturity radar chart visualization
- Gap analysis and recommendation engine
- CISA maturity model alignment
- Executive Zero Trust dashboard
- Improvement roadmap generator

---

## Phase 66: Entitlement Management

### Description

Build a comprehensive entitlement catalog and management system:
- Auto-discover all entitlements (roles, permissions, API grants, app roles) across cloud providers
- Entitlement catalog with categorization, risk classification, and ownership
- Entitlement analytics: most/least used, most granted, highest risk
- Entitlement request and approval workflows (integrating with Phase 57)
- Entitlement bundles (predefined permission sets for common job functions)
- Entitlement comparison across identities
- Entitlement cleanup recommendations based on usage data from Role Mining (Phase 37)
- Time-limited entitlement grants with automatic revocation

### Priority: **Low**
### Estimated Complexity: **Large**
### Dependencies: Phase 37 (Role Mining), Phase 57 (Governance Workflows), Phases 53/54 (AWS/GCP for multi-cloud coverage)

### Business Value

Entitlement management is the foundation of least-privilege access. By cataloging all entitlements and their usage, organizations can systematically reduce over-provisioning. This capability is central to Identity Governance and Administration (IGA) platforms and represents a significant market positioning upgrade for AuditGraph.

### What Would Be Built

- Entitlement catalog database and ingestion
- Entitlement analytics engine
- Request and approval workflow integration
- Entitlement bundle templates
- Cross-identity entitlement comparison
- Usage-based cleanup recommendations
- Time-limited grant management

---

## Phase 67: Identity Threat Detection and Response (ITDR)

### Description

Real-time identity threat detection using streaming event analysis:
- Ingest Azure AD sign-in logs, audit logs, and risk events in near-real-time
- Detect identity-based attack patterns: credential stuffing, token theft, lateral movement, impossible travel
- Correlate with existing anomaly data (Phase 40) for enriched threat context
- Threat timeline reconstruction for incident response
- Integration with Microsoft Security Graph for risk event enrichment
- Automated response actions via SOAR (Phase 43)
- MITRE ATT&CK mapping for detected threats
- Threat hunting query interface

### Priority: **Medium**
### Estimated Complexity: **Large**
### Dependencies: Phase 40 (Anomaly Detection), Phase 43 (SOAR), Phase 61 (SIEM Export)

### Business Value

ITDR is the next evolution of identity security (Gartner-defined category). Moving from periodic discovery to real-time threat detection positions AuditGraph as a detection and response platform, not just an audit tool. This addresses the most sophisticated identity-based attacks that occur between scheduled discovery runs, closing the detection gap from hours to minutes.

### What Would Be Built

- Sign-in log streaming ingestion (Azure AD, AWS CloudTrail, GCP Audit)
- Threat pattern detection engine (impossible travel, credential stuffing, etc.)
- MITRE ATT&CK mapping database
- Threat timeline visualization
- SOAR integration for automated response
- Threat hunting query interface
- Real-time alert pipeline (WebSocket + notification)

---

## Phase 68: Real-Time Monitoring and Alerting Improvements

### Description

Enhance the monitoring infrastructure for production reliability:
- Prometheus metrics endpoint (`/metrics`) with key platform health indicators
- Grafana dashboard templates for operational monitoring
- Health check improvements: database connectivity, scheduler status, integration health
- Alert rules for: discovery failures, SOAR action failures, database connection issues
- Performance monitoring: API response time tracking, slow query detection
- Uptime monitoring integration (PagerDuty, Opsgenie)
- SLA dashboard showing platform availability and performance metrics

### Priority: **Medium**
### Estimated Complexity: **Small**
### Dependencies: None

### Business Value

Production reliability is non-negotiable for a security platform. Monitoring and alerting ensure that the platform itself is healthy and that any degradation is detected before it impacts security visibility. This is a prerequisite for SLA commitments in enterprise contracts and for operational maturity.

### What Would Be Built

- `/metrics` Prometheus endpoint
- Grafana dashboard JSON templates
- Enhanced health check endpoints
- API latency tracking middleware
- Alert rule definitions
- SLA dashboard page

---

## Phase 69: Mobile App / Responsive Dashboard

### Description

Create a mobile-optimized experience for AuditGraph:
- Progressive Web App (PWA) configuration for mobile installation
- Responsive layouts for all existing pages (starting with Dashboard, Identities, Notifications)
- Push notifications for critical security events (via service worker)
- Mobile-optimized identity search and detail views
- Offline capability for recently viewed data
- Touch-optimized interactions (swipe to dismiss notifications, etc.)
- Mobile-specific dashboard layout with priority widgets

### Priority: **Low**
### Estimated Complexity: **Medium**
### Dependencies: Phase 44 (Dashboard Customization), Phase 30 (Notifications)

### Business Value

Security leaders and on-call analysts need access to identity security data outside the office. A mobile experience ensures that critical alerts can be reviewed and acknowledged from anywhere, reducing response time for off-hours incidents. PWA approach avoids the overhead of native app development.

### What Would Be Built

- PWA manifest and service worker
- Responsive Tailwind breakpoints for all pages
- Mobile-optimized Dashboard widget layout
- Touch-friendly data tables with horizontal scroll
- Push notification support
- Offline data caching

---

## Phase 70: Plugin/Extension Architecture

### Description

Build a plugin system that enables third-party extensions:
- Plugin manifest format defining capabilities, configuration, and lifecycle hooks
- Plugin types: custom discovery engines, risk scorers, compliance frameworks, report generators, integrations
- Plugin marketplace/registry for discovering and installing plugins
- Sandboxed execution environment for untrusted plugins
- Plugin configuration UI in Settings
- Plugin versioning, updates, and dependency management
- SDK and documentation for plugin developers
- Example plugins for common extensions (custom compliance framework, custom discovery engine)

### Priority: **Low**
### Estimated Complexity: **Large**
### Dependencies: Phases 53/54 (multi-cloud as plugin proof-of-concept), Phase 52 (API documentation)

### Business Value

A plugin architecture transforms AuditGraph from a product into a platform. It enables partners and customers to extend functionality without core code changes, creates an ecosystem for community contributions, and supports rapid feature development through modular architecture. The existing engine pattern (discovery engines, anomaly detector, SOAR engine, risk rule engine) provides a natural plugin interface.

### What Would Be Built

- Plugin API specification (lifecycle hooks, configuration schema)
- Plugin loader and execution framework
- Plugin registry and management UI
- Sandboxing for untrusted plugins
- Plugin SDK with examples
- Plugin marketplace concept

---

## Phase 71: Conditional Access Policy Simulation

### Description

Extend the existing Conditional Access discovery (Phase 9) with policy simulation:
- "What If" simulator for CA policies: test how a sign-in attempt would be evaluated against all active policies
- Policy conflict detection and resolution recommendations
- Coverage gap analysis: identify user/app combinations not covered by any policy
- Policy optimization recommendations (consolidate redundant policies, remove overlapping rules)
- Policy comparison across tenants for multi-tenant deployments
- Visual policy flow diagram showing evaluation order and decision points

### Priority: **Medium**
### Estimated Complexity: **Medium**
### Dependencies: Phase 9 (Conditional Access discovery), Phase 49 (Risk Simulation pattern)

### Business Value

Conditional Access policies are the primary control plane for Azure AD authentication security. Misconfigured policies are a top cause of both security gaps and user friction. Policy simulation prevents "deploy and pray" by validating policy behavior before production deployment. This extends the successful "What If" pattern from Phase 49 to the CA policy domain.

### What Would Be Built

- CA policy evaluation simulator
- Policy conflict detection engine
- Coverage gap analysis
- Policy optimization recommender
- Visual policy flow diagram
- Cross-tenant policy comparison

---

## Phase 72: Data Retention and Archival

### Description

Implement configurable data retention and archival policies:
- Configurable retention periods per data type (discovery runs, activity logs, notifications, anomalies, drift reports)
- Automatic archival of old data to compressed storage (S3, Azure Blob Storage)
- Archived data search and retrieval for compliance investigations
- Database size monitoring and growth projections
- Retention policy configuration UI in Settings
- Compliance-aware retention (ensure data is kept for regulatory minimum periods: SOC 2 = 1 year, HIPAA = 6 years)
- Data export before deletion for compliance evidence

### Priority: **Medium**
### Estimated Complexity: **Medium**
### Dependencies: Phase 15 (Settings), Phase 17 (Activity Log)

### Business Value

Without retention policies, the database grows unbounded, degrading query performance and increasing infrastructure costs. Compliance regulations specify both minimum retention periods (must keep data) and maximum retention periods (data privacy -- must delete data). Proper data lifecycle management is essential for production deployments and regulatory compliance.

### What Would Be Built

- `retention_policies` table (entity type, retention period, archive destination)
- Archival job (compress and upload to S3/Azure Blob)
- Retrieval API (restore archived data for review)
- Auto-cleanup of expired data
- Retention configuration UI in Settings
- Database size monitoring dashboard widget

---

## Phase 73: Advanced Reporting and Scheduling

### Description

Enhance the report generation system (Phase 13) with:
- Report templates: executive summary, detailed audit, compliance evidence, risk assessment, service account inventory
- Report scheduling with custom recipients per report type
- Report versioning and comparison (diff between two point-in-time reports)
- Custom report builder: configurable sections, data sources, and time ranges
- Report distribution lists managed in Settings
- Report formats: PDF (existing), Excel/XLSX, HTML email body
- Report API for programmatic generation and retrieval
- Report history and archive

### Priority: **Low**
### Estimated Complexity: **Medium**
### Dependencies: Phase 13 (Report Generation), Phase 18 (Scheduled Reports)

### Business Value

Different stakeholders need different reports. The CISO wants an executive summary; the auditor wants detailed evidence; the compliance manager wants framework-specific reports. A flexible reporting system serves all stakeholders from a single platform and eliminates hours of manual report customization.

### What Would Be Built

- Report template engine
- Custom report builder UI
- Multi-format export (PDF, XLSX, HTML)
- Scheduled delivery with distribution lists
- Report versioning and comparison
- Report API for automation

---

## Phase 74: Identity Intelligence Dashboard

### Description

Build an intelligence-focused dashboard aggregating insights across all platform capabilities:
- Threat intelligence feed integration (known compromised credentials, malicious IPs)
- Identity-to-threat correlation: map discovered identities to known threat intelligence
- Attack path visualization: show potential lateral movement paths from compromised identities
- Risk concentration mapping: identify organizational units with highest aggregate risk
- Peer benchmarking: anonymous comparison of security posture against similar organizations
- Intelligence briefing: auto-generated narrative summary of the week's top security highlights
- MITRE ATT&CK identity technique coverage mapping

### Priority: **Low**
### Estimated Complexity: **Large**
### Dependencies: Phase 40 (Anomaly Detection), Phase 41 (Risk Trends), Phase 67 (ITDR)

### Business Value

Intelligence transforms data into actionable insight. By correlating internal identity data with external threat intelligence and providing strategic analysis, this dashboard becomes the primary decision-making tool for security leadership. It represents the capstone of the analytics and intelligence capabilities built across earlier phases.

### What Would Be Built

- Threat intelligence feed connectors (STIX/TAXII, Have I Been Pwned)
- IoC matching engine
- Attack path graph analysis
- Risk concentration heatmap
- Auto-generated intelligence briefings
- MITRE ATT&CK coverage mapping
- Executive intelligence dashboard page

---

## Roadmap Prioritization Matrix

| Phase | Name | Priority | Complexity | Key Dependencies |
|-------|------|----------|------------|-----------------|
| 52 | OpenAPI/Swagger Docs | High | Medium | None |
| 53 | AWS IAM Deep Integration | High | Large | Core multi-cloud |
| 54 | GCP IAM Deep Integration | High | Large | Core multi-cloud |
| 55 | SCIM Provisioning | Medium | Large | Phase 35 |
| 56 | PAM Integration | Medium | Large | Phase 42 |
| 57 | Identity Governance Workflows | Medium | Large | Phases 31, 36 |
| 58 | Compliance Auto-Remediation | Medium | Large | Phases 12, 32, 43, 50 |
| 59 | ML-Based Anomaly Detection | Low | Large | Phase 40 |
| 60 | SSO/SAML Integration | High | Medium | Phase 31 |
| 61 | SIEM Export Integration | Medium | Medium | Phase 28 |
| 62 | Role-Based Access Certification | Medium | Medium | Phases 36, 37 |
| 63 | Service Account Governance | High | Medium | Phases 12, 35, 38 |
| 64 | External Identity Federation | Medium | Medium | Phase 45 |
| 65 | Zero Trust Posture Assessment | Medium | Medium | Phases 32, 50 |
| 66 | Entitlement Management | Low | Large | Phases 37, 57 |
| 67 | Identity Threat Detection (ITDR) | Medium | Large | Phases 40, 43 |
| 68 | Real-Time Monitoring | Medium | Small | None |
| 69 | Mobile App / Responsive | Low | Medium | Phases 30, 44 |
| 70 | Plugin/Extension Architecture | Low | Large | Phases 52, 53/54 |
| 71 | CA Policy Simulation | Medium | Medium | Phase 9 |
| 72 | Data Retention & Archival | Medium | Medium | Phase 15 |
| 73 | Advanced Reporting | Low | Medium | Phases 13, 18 |
| 74 | Identity Intelligence Dashboard | Low | Large | Phases 40, 41, 67 |

---

## Recommended Implementation Order

Based on priority, business value, dependency chains, and effort-to-impact ratio, the recommended implementation order is:

### Tier 1: Immediate (High Priority, High Impact)

| Order | Phase | Name | Rationale |
|-------|-------|------|-----------|
| 1 | 52 | OpenAPI/Swagger Docs | Low risk, high value for developer experience and integrations |
| 2 | 60 | SSO/SAML Integration | Enterprise procurement requirement; blocks enterprise sales |
| 3 | 63 | Service Account Governance | Addresses largest unmanaged risk surface in most organizations |
| 4 | 53 | AWS IAM Deep Integration | Largest market expansion opportunity; most-requested feature |
| 5 | 68 | Real-Time Monitoring | Small effort; essential for production reliability and SLA commitments |

### Tier 2: Near-Term (Medium Priority, Strategic Value)

| Order | Phase | Name | Rationale |
|-------|-------|------|-----------|
| 6 | 54 | GCP IAM Deep Integration | Completes multi-cloud story; necessary for enterprise positioning |
| 7 | 61 | SIEM Export Integration | Enables SOC workflow integration; drives day-to-day adoption |
| 8 | 72 | Data Retention & Archival | Required for production sustainability and compliance |
| 9 | 62 | Role-Based Access Certification | Extends existing access review capability with high compliance value |
| 10 | 71 | CA Policy Simulation | High-value Azure-specific capability with proven "What If" pattern |

### Tier 3: Medium-Term (Strategic Growth)

| Order | Phase | Name | Rationale |
|-------|-------|------|-----------|
| 11 | 65 | Zero Trust Posture Assessment | Market-aligned; federal mandate alignment |
| 12 | 55 | SCIM Provisioning | Bridges HR and cloud access; addresses orphaned accounts |
| 13 | 57 | Identity Governance Workflows | Platform evolution toward full IGA capability |
| 14 | 64 | External Identity Federation | Addresses overlooked attack surface |
| 15 | 58 | Compliance Auto-Remediation | Closes the loop from detection to automated resolution |
| 16 | 67 | Identity Threat Detection (ITDR) | Industry trend alignment; real-time detection |

### Tier 4: Long-Term (Platform Evolution)

| Order | Phase | Name | Rationale |
|-------|-------|------|-----------|
| 17 | 56 | PAM Integration | Complex integration with high governance value |
| 18 | 73 | Advanced Reporting | Enhanced stakeholder communication |
| 19 | 69 | Mobile App / Responsive | Extended reach; improves on-call workflows |
| 20 | 59 | ML-Based Anomaly Detection | Differentiation capability; reduces false positives |
| 21 | 66 | Entitlement Management | Full IGA capability; requires governance workflows first |
| 22 | 74 | Identity Intelligence Dashboard | Capstone analytics capability |
| 23 | 70 | Plugin/Extension Architecture | Platform ecosystem play; long-term investment |

---

## Architecture Considerations

### For AWS/GCP Integration (Phases 53-54)

The existing `BaseDiscoveryEngine` class in `backend/app/engines/discovery/base.py` defines the `discover()` and `test_connection()` interfaces. AWS and GCP engines should follow this pattern. Key considerations:

- Use the existing `cloud` column in the `identities` table (currently only `azure`)
- Map AWS/GCP identity types to the normalized `identity_type_normalized` field (`app`, `workload`, `human`, `system`)
- Ensure risk scoring works cross-cloud (the `_compute_risk_score` function may need cloud-aware adjustments for AWS policies vs. Azure roles)
- Extend the query builder field allowlist (`QUERY_FIELD_MAP`) for cloud-specific attributes
- Update the identity table UI columns for cloud-specific data
- Ensure drift detection and anomaly detection work across cloud providers

### For SSO Integration (Phase 60)

The current JWT auth system in `backend/app/api/auth.py` should be extended rather than replaced. SSO should produce the same JWT tokens used by the existing system, ensuring all downstream authorization logic (roles, tenants, API key dual-auth) continues to work. The `AuthContext` on the frontend should transparently support SSO-issued tokens.

### For SIEM Export (Phase 61)

The existing webhook infrastructure (Phase 28) provides a solid foundation. SIEM-specific integrations can be implemented as specialized webhook handlers with format transformation (CEF, OCSF) rather than entirely new infrastructure. The `WebhookService.EVENT_TYPES` list already covers the 7 event types that should be exported.

### For Plugin Architecture (Phase 70)

The existing engine pattern (discovery engines, anomaly detector, SOAR engine, risk rule engine) provides a natural plugin interface. Each engine type can be abstracted into a plugin interface with well-defined lifecycle hooks:
- `DiscoveryPlugin`: implements `discover()` and `test_connection()`
- `AnomalyPlugin`: implements `analyze(current_run_id, previous_run_id, settings)`
- `CompliancePlugin`: provides framework definition with controls and evaluation logic
- `IntegrationPlugin`: implements SOAR action handlers

---

## Success Metrics

Each phase should be evaluated against these criteria:

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **User Adoption** | >50% of active users interact with the feature within 30 days | Frontend analytics |
| **API Usage** | New endpoints receive >100 calls/day within 60 days | API key usage tracking, request logs |
| **Risk Reduction** | Measurable decrease in MTTD or MTTR | Before/after comparison of remediation metrics |
| **Compliance Impact** | Improvement in compliance scores for affected frameworks | Compliance trend tracking (Phase 51) |
| **Customer Demand** | Feature satisfies >3 customer/prospect requests | Customer feedback tracking |
| **Error Rate** | <0.1% error rate on new endpoints | Application monitoring |
| **Performance** | P95 response time <500ms for new API endpoints | Performance monitoring |
| **Code Quality** | 0 critical/high security issues in new code | Security scanning |

---

## Summary

| Metric | Value |
|--------|-------|
| Total proposed phases | 23 (Phase 52-74) |
| High priority phases | 5 (Phases 52, 53, 54, 60, 63) |
| Medium priority phases | 12 |
| Low priority phases | 6 |
| Large complexity items | 9 |
| Medium complexity items | 12 |
| Small complexity items | 2 |
| Estimated total effort | 35-45 engineering weeks |

---

*Document generated: February 2026*
*AuditGraph -- Identity Security Posture Management Platform*
