# Section 13 -- FAQ

## Data Protection

### How does AuditGraph protect customer data?

AuditGraph implements defense-in-depth data protection:

1. **Encryption in transit**: All communication uses HTTPS/TLS with HSTS enforcement (1-year max-age)
2. **Encryption at rest**: Cloud connector credentials are encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
3. **Tenant isolation**: PostgreSQL Row Level Security on 44 tables ensures one customer cannot access another's data -- even if application-level checks are bypassed
4. **Dual database users**: The app user (NOBYPASSRLS) cannot bypass RLS. Only the admin user (BYPASSRLS) can access cross-tenant data, and it's restricted to system operations
5. **Log redaction**: Passwords, tokens, API keys, and secrets are automatically redacted from all log output
6. **Security headers**: HSTS, Content-Security-Policy, X-Frame-Options, and other headers protect the web interface

### How are credentials stored?

Cloud connector credentials (client secrets, access keys, service account keys) are:

1. **Encrypted immediately** on receipt using Fernet symmetric encryption
2. **Stored with an `enc:` prefix** to distinguish from plaintext
3. **Never returned in API responses** -- the API returns connection metadata but masks all credentials
4. **Decrypted only when needed** -- the scheduler decrypts credentials at discovery time, uses them for API calls, then discards the plaintext
5. **Key rotation supported** -- MultiFernet allows old encrypted values to be decrypted after a key rotation

User passwords are hashed with bcrypt and never stored in plaintext.

### Is customer data shared between tenants?

No. Row Level Security (RLS) enforces strict tenant isolation at the database layer. Every query executed by the application user is automatically filtered by `organization_id`. Even if a software bug bypasses application-level authorization, the database itself prevents cross-tenant data access.

---

## Discovery

### How often should discovery run?

| Environment | Recommended Frequency | Scan Mode |
|-------------|----------------------|-----------|
| Production cloud environments | Every 12 hours | Deep |
| Development/staging environments | Every 24 hours | Standard |
| Large environments (1000+ identities) | Every 12-24 hours | Standard with weekly Deep |

The default scheduled interval is 12 hours. You can also configure per-connection intervals via `discovery_interval_minutes` and trigger manual scans at any time.

For environments with frequent identity changes (daily deployments, CI/CD-driven SPN creation), consider enabling continuous discovery (5-minute polling with per-connection intervals).

### What data does AuditGraph collect from my cloud environment?

AuditGraph reads identity and access configuration data. It does **not** read:

- File contents or blob data
- Email messages or chat messages
- Application data or databases
- Network traffic or logs (except sign-in logs if Azure AD P2 is enabled)

Specifically, AuditGraph collects:

| Data Category | Examples |
|--------------|---------|
| **Identities** | User accounts, service principals, managed identities, IAM users/roles |
| **Entitlements** | Azure RBAC role assignments, Entra directory roles, IAM policies, GCP bindings |
| **Credentials** | Secret/certificate expiration dates, key creation times (not the actual secrets) |
| **Resources** | Storage account names, Key Vault names, subscription IDs (metadata only) |
| **Ownership** | App registration owners, service account attestations |
| **Activity** | Last sign-in timestamps, sign-in logs (if P2 enabled) |
| **Configuration** | Conditional access policies, PIM eligible assignments |

### Does discovery modify anything in my cloud environment?

No. All AuditGraph API calls are read-only. The connector permissions are exclusively `Read` and `List` operations. AuditGraph does not create, modify, or delete any resources in your cloud environment.

The only exception is the auto-remediation feature, which is opt-in, requires explicit admin approval, and simulates actions by default before executing real changes.

### What happens if discovery fails?

If a discovery run fails:

1. The run is marked as `failed` with an error message
2. The previous successful snapshot remains the active dataset
3. If the failure is due to a transient API error, the circuit breaker may open and retry after the recovery timeout (60 seconds)
4. A `scan_failed` notification is sent (if configured)
5. The scheduler will attempt discovery again on the next scheduled interval

Failed runs do not corrupt or remove existing data.

---

## Risk Scoring

### How are risk scores calculated?

AuditGraph uses a proprietary composite model called AGIRS (AuditGraph Identity Risk Score):

```
AGIRS = 0.40 x HIRI + 0.40 x NHIRI + 0.20 x GEI

Where:
  HIRI  = Human Identity Risk Index (measures human user risk)
  NHIRI = Non-Human Identity Risk Index (measures SPN/managed identity risk)
  GEI   = Governance Effectiveness Index (measures governance maturity)
```

Each component starts at 100 and deducts points based on the severity and prevalence of risk factors. For example, HIRI deducts points for ghost accounts (3 points each), dormant privileged users (5 points each), and over-privileged identities (4 points each).

See [Risk Scoring Model](risk-scoring.md) for the complete methodology with formulas and examples.

### What does a low AGIRS score mean?

A low AGIRS score (below 45, Grade F) indicates severe identity risk:

- A large percentage of identities are over-privileged
- Many ghost accounts retain active role assignments
- Service principals lack ownership
- Governance processes (PIM, access reviews) are not in place

The top risks panel on the CISO Dashboard shows which specific risk factors have the biggest impact on your score and the estimated improvement from remediating each one.

### Can risk scores be customized?

The AGIRS model uses fixed weights based on security research. However:

- Custom risk rules can adjust per-identity risk scores based on your criteria
- Identity groups can tag identities for custom tracking
- The advanced query builder can filter identities by any combination of risk factors
- Risk findings can be acknowledged or suppressed if they are accepted risks

---

## Platform

### How does AuditGraph scale?

AuditGraph is designed for enterprise-scale cloud environments:

| Dimension | Capability |
|-----------|-----------|
| **Identities per connector** | Tested with 10,000+ identities per Azure tenant |
| **Connectors per organization** | No hard limit. Organizations commonly have 5-20 connectors |
| **Concurrent discovery** | Discovery runs execute per-connector with connection pooling |
| **Database** | PostgreSQL with connection pooling (configurable 2-20 connections) |
| **API** | Pagination on all list endpoints (max 500 per page) |

For very large environments (50,000+ identities across all connectors), consider:
- Increasing the database connection pool (`DB_POOL_MAX`)
- Using standard scan mode for daily scans, deep mode weekly
- Spreading connectors across separate organizations if tenant isolation is desired

### What cloud providers does AuditGraph support?

| Provider | Status | Depth |
|----------|--------|-------|
| **Microsoft Azure** | Production | Full: identities, RBAC, Entra roles, credentials, PIM, CA, resources, app registrations |
| **Amazon Web Services** | Production | IAM users, roles, policies, access keys, trust relationships |
| **Google Cloud Platform** | Production | Service accounts, IAM bindings, project-level roles, keys |

Azure has the deepest coverage due to the richness of its identity and access management APIs (Microsoft Graph + Azure Resource Manager).

### Does AuditGraph require agents to be installed?

No. AuditGraph is agentless. It connects to cloud provider APIs using standard authentication credentials (Azure service principal, AWS IAM user, GCP service account). No software needs to be installed in your cloud environment.

### Can I use AuditGraph with a single cloud provider?

Yes. AuditGraph supports any combination of cloud providers. You can connect only Azure, only AWS, or any mix. The platform dynamically shows only the connected cloud providers in the sidebar and dashboards.

---

## Security

### Is AuditGraph SOC 2 compliant?

AuditGraph implements controls aligned with SOC 2 Type II requirements:

- Access controls (RBAC with 8-role hierarchy)
- Encryption at rest (Fernet) and in transit (TLS)
- Audit logging (security events, activity log)
- Change detection (drift reports, anomaly detection)
- Data retention policies (configurable per data type)

Formal SOC 2 Type II audit certification is in progress.

### How does AuditGraph handle SSO?

AuditGraph supports two SSO protocols:

- **OIDC (OpenID Connect)**: Supports Azure AD, Okta, Google Workspace. JWKS signature verification with RS256.
- **SAML 2.0**: Supports any SAML-compliant IdP. Requires signed assertions.

Both protocols support:
- JIT (Just-in-Time) user provisioning
- IdP group-to-AuditGraph role mapping
- Force-SSO mode (disables local password login)
- Per-organization SSO configuration

### Can AuditGraph be self-hosted?

AuditGraph is currently offered as a SaaS platform hosted on Azure. The backend runs in Azure Container Apps with PostgreSQL Flexible Server.

For organizations with strict data residency requirements, contact the AuditGraph team to discuss deployment options.

### How do I report a security vulnerability?

Report security vulnerabilities to security@auditgraph.ai. Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment

---

## Integration

### Can I integrate AuditGraph with my SIEM?

Yes. AuditGraph produces structured security events in JSON format that can be forwarded to any SIEM:

```json
{
  "event_type": "LOGIN_FAILED",
  "severity": "medium",
  "timestamp": "2026-03-16T14:30:00.000Z",
  "details": { "username": "admin", "ip_address": "10.0.0.1" }
}
```

In production, logs are output in structured JSON format suitable for log aggregation (Splunk, Datadog, Azure Monitor, etc.).

### Can I automate responses to findings?

Yes. AuditGraph provides multiple automation options:

1. **SOAR Playbooks**: Configure automated response playbooks that execute when anomalies or drift events are detected
2. **Webhooks**: Send events to your own automation systems
3. **Slack/Teams**: Real-time notifications for configurable event types
4. **API**: Full REST API for building custom integrations
5. **Remediation Engine**: Auto-generated CLI commands for common remediations

### Does AuditGraph support SCIM provisioning?

Yes. AuditGraph implements SCIM 2.0 endpoints for user provisioning:

- `GET/POST /api/scim/v2/Users` -- List and create users
- `GET/PUT/PATCH/DELETE /api/scim/v2/Users/{id}` -- User lifecycle management
- `GET /api/scim/v2/ServiceProviderConfig` -- Provider configuration
- `GET /api/scim/v2/Schemas` -- Schema definitions

This allows identity providers (Azure AD, Okta) to automatically provision and deprovision AuditGraph user accounts.

---

## Billing

### How is AuditGraph priced?

AuditGraph pricing is per-cloud-provider with tiered plans:

| Plan | Azure | AWS | GCP |
|------|-------|-----|-----|
| **Pro** | $199/mo | $249/mo | $229/mo |

Plans include all core features (identity discovery, risk scoring, compliance, drift detection, anomaly detection, remediation, AI copilot). Extended data retention is available as a paid add-on ($149/month).

### Is there a free trial?

Yes. New organizations receive a 14-day free trial with full access to all features. No credit card required.

---

## References

- [Introduction](introduction.md) -- Platform overview
- [Risk Scoring Model](risk-scoring.md) -- Detailed scoring methodology
- [Connectors](connectors.md) -- Connector setup
- [Security Architecture](security-architecture.md) -- Security controls
- [API Reference](api-reference.md) -- Integration details
