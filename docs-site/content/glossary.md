# Glossary

This glossary defines identity security terminology used throughout the AuditGraph platform. Terms are organized alphabetically for quick reference.

---

## Access Graph

A directed graph representing the relationships between identities, roles, permissions, credentials, and resources in a cloud environment.

**Example:**
A service principal node connects via a "has role" edge to an Owner role node, which connects via a "scoped to" edge to a subscription node containing resource group and resource nodes.

**AuditGraph Implementation:**
AuditGraph constructs access graphs from discovery data using 13 node types and multiple edge types. Three visualization modes are available: Executive (blast radius summary), Technical (full ARM tree with all relationships), and Attack Path (escalation chains). See [Identity Graph](identity-graph.md).

---

## AGIRS (AuditGraph Identity Risk Score)

A proprietary composite score (0-100) that quantifies an organization's overall identity risk posture across all connected cloud environments. A higher score indicates lower risk.

**Formula:**

```
AGIRS = 0.40 × HIRI + 0.40 × NHIRI + 0.20 × GEI
```

**Example:**
An organization with HIRI 74.2, NHIRI 68.5, and GEI 75.0 receives an AGIRS score of 72.08 (Grade C — Elevated).

**AuditGraph Implementation:**
AGIRS is computed by the `RiskSummaryEngine` after each discovery run and persisted in the `risk_summary` table. The CISO Dashboard displays the current score, grade (A through F), and trend compared to the previous scan. See [Risk Scoring Model](risk-scoring.md).

---

## Attack Path

A computed privilege escalation chain showing how an attacker could move from an initial compromise to critical resources through a sequence of identity relationships.

**Example:**
An attacker compromises a service principal with User Access Administrator on a subscription, uses that role to grant themselves Owner, then accesses a Key Vault containing production secrets.

**AuditGraph Implementation:**
AuditGraph computes five attack path types: direct escalation, ownership chains, PIM abuse, lateral movement, and credential exposure. Attack paths are visualized in the Access Graph's Attack Path mode as directed flows with severity badges. See [Identity Graph](identity-graph.md).

---

## Blast Radius

A measure of the potential impact if a single identity is compromised. Quantifies how many resources, subscriptions, and critical assets an attacker could reach through an identity's effective permissions.

**Formula:**

```
Blast Radius = TierWeight × ScopeMultiplier × DormancyMultiplier × ExposureMultiplier
```

**Example:**
A service principal with Owner on two subscriptions (containing 150 resources and 3 Key Vaults) has a blast radius score of 90 out of 100.

**AuditGraph Implementation:**
Blast radius is computed per identity during risk scoring, factoring in privilege tier (T0-T3), scope breadth (subscription vs. resource group), dormancy status, and credential exposure. The CISO Dashboard highlights identities with the highest blast radius. See [Risk Scoring Model](risk-scoring.md).

---

## Conditional Access

Azure AD policies that enforce access controls based on conditions such as user location, device compliance, sign-in risk level, and application sensitivity. Commonly used to require MFA.

**Example:**
A conditional access policy requires MFA for all users accessing the Azure portal from outside the corporate network.

**AuditGraph Implementation:**
AuditGraph discovers conditional access policies during deep scans and evaluates coverage: which identities are protected by MFA, which are excluded, and which have no conditional access protection. CA coverage is a factor in the GEI governance score and appears in the Dashboard's Conditional Access card.

---

## Connector

A configured link between AuditGraph and a cloud environment (Azure tenant, AWS account, or GCP project). Connectors store encrypted credentials and define the scan scope.

**Example:**
An organization creates two connectors: "Production Azure" (deep scan every 12 hours) and "Staging AWS" (standard scan every 24 hours).

**AuditGraph Implementation:**
Connectors are stored in the `cloud_connections` table with Fernet-encrypted credentials. Each connector has an independent discovery schedule, scan mode, and status. AuditGraph supports Azure, AWS, and GCP connectors. See [Connectors](connectors.md).

---

## Credential Exposure

A risk condition where an identity's authentication credentials (secrets, certificates, access keys) are expired, expiring soon, long-lived, or otherwise vulnerable.

**Example:**
A service principal has a client secret that expired 6 months ago and was never rotated. The secret is still the only configured credential.

**AuditGraph Implementation:**
AuditGraph discovers all credentials during identity scanning and classifies each as `valid`, `expiring_soon` (within 30 days), `warning` (within 90 days), or `expired`. Credential risk contributes to the NHIRI score via factor N4. The SPN Dashboard provides a dedicated credential risk view. See [Risk Scoring Model](risk-scoring.md).

---

## Data Trust Zone

A CISO-asserted scope rule that assigns a data classification (PHI / PCI / PII / SOURCE / HR / FINANCIAL / CONFIDENTIAL) to every resource under a named scope. Replaces the read-data approach that would have broken AuditGraph's no-data-plane guarantee.

**Scope types:** `resource_name_pattern` (e.g. `*phi*`, `*claims*`) · `resource_group` · `resource_group_pattern` · `subscription` · `subscription_pattern`. Narrow patterns earn confidence 100; broad scopes earn 100 only when the resource name corroborates the class, otherwise 60 (Medium).

**AuditGraph Implementation:**
Backed by the `data_trust_zones` table with soft-delete (`revoked_at`). The post-discovery scheduler step `_run_data_trust_zones_classification` applies the [6-tier classification engine](breach-cost-methodology). Customer-facing name is "Data Trust Zones"; internal table is `data_trust_zones`. See [Data Trust Zones screen](screen-data-trust-zones).

---

## Discovery Run

A single execution of the identity discovery pipeline against a cloud connector. Each run produces a point-in-time snapshot of all identity and access data.

**Example:**
A deep discovery run against an Azure connector takes 8 minutes and discovers 248 identities with 1,204 role assignments.

**AuditGraph Implementation:**
Discovery runs progress through states: `pending` → `running` → `completed` (or `failed`). Each completed run triggers the post-discovery pipeline: drift detection, anomaly detection, AGIRS computation, and notifications. Runs include a SHA-256 hash and HMAC signature for snapshot integrity verification. See [Discovery Engine](discovery-engine.md).

---

## GEI (Governance Effectiveness Index)

A scoring component (0-100) that measures the maturity and effectiveness of an organization's identity governance practices. Part of the AGIRS composite score at 20% weight.

**Components:**

| Component | Weight | Measures |
|-----------|--------|----------|
| Ownership Coverage | 25% | Percentage of SPNs with assigned human owners |
| PIM Adoption | 25% | Percentage of T0/T1 identities using PIM |
| Access Reviews | 25% | Whether access reviews are configured and completed |
| Monitoring (P2) | 25% | Whether P2 telemetry is enabled for behavioral analysis |

**Example:**
An organization with 65% SPN ownership, 72% PIM adoption, active access reviews, and P2 telemetry enabled receives a GEI of 75.

**AuditGraph Implementation:**
GEI is computed from governance indicators discovered during deep scans. Each component scores independently. GEI appears in the CISO Dashboard alongside HIRI and NHIRI as an AGIRS pillar. See [Risk Scoring Model](risk-scoring.md).

---

## Ghost Account

A disabled user account that still retains active role assignments or permissions in the cloud environment. Ghost accounts represent unnecessary attack surface because a compromised or reactivated account would immediately have privileged access.

**Example:**
A former employee's Azure AD account was disabled during offboarding, but their Contributor role assignment on a production subscription was never removed.

**AuditGraph Implementation:**
Detected through HIRI factor H1 during identity discovery. AuditGraph identifies accounts where `account_enabled = false` but active role assignments exist. Each ghost account deducts 3 points from the HIRI score. The remediation recommendation is to remove all role assignments from disabled accounts. See [Risk Scoring Model](risk-scoring.md).

---

## HIRI (Human Identity Risk Index)

A scoring component (0-100) that measures risk from human user accounts. Part of the AGIRS composite score at 40% weight. HIRI starts at 100 and deducts points for each risk factor.

**Risk Factors:**

| Factor | Description | Weight |
|--------|-------------|--------|
| H1 | Ghost accounts (disabled users with roles) | 3 points each |
| H2 | Dormant privileged users (T0/T1, inactive 90+ days) | 5 points each |
| H3 | Over-privileged identities (broader access than needed) | 4 points each |
| H4 | External guests with privileged roles | 4 points each |
| H5 | Zombie identities (disabled + privileged + stale) | 7 points each |

**Example:**
An organization with 44 ghost accounts (H1) and 5 dormant privileged users (H2) receives: HIRI = max(0, 100 - (44 × 3) - (5 × 5)) = max(0, 100 - 132 - 25) = 0.

**AuditGraph Implementation:**
HIRI is computed from human identity attributes discovered during scanning. The breakdown (H1-H5 counts and per-factor deductions) is persisted in the `risk_summary` table as `hiri_breakdown` JSONB. See [Risk Scoring Model](risk-scoring.md).

---

## Identity Drift

Changes in identity configurations, role assignments, or credentials detected between consecutive discovery snapshots. Drift indicates that the cloud environment has changed since the last scan.

**Example:**
Between two discovery runs, a new Global Administrator role was assigned to a service principal, and two new client secrets were added to an app registration.

**AuditGraph Implementation:**
Drift detection runs automatically after each discovery scan by comparing the current snapshot with the previous one. Five change categories are tracked: new identities, removed identities, new roles, removed roles, and credential changes. Critical drift events (T0/T1 role additions) trigger Slack/Teams notifications and SOAR playbooks. See [Discovery Engine](discovery-engine.md).

---

## Identity Graph

The complete graph data structure representing all identities, their relationships, and effective access paths in a cloud environment. A superset of the access graph that includes risk metadata, ownership, and trust relationships.

**Example:**
An identity graph for a medium enterprise contains 248 identity nodes, 1,200+ role edges, 460 credential nodes, and computed blast radius values for every identity.

**AuditGraph Implementation:**
The identity graph is constructed during the graph construction stage of the discovery pipeline using 13 node types (identity, role, permission, credential, subscription, resource_group, resource, owner, federated_trust, risk_summary, blast_radius, scope, entra_directory). Node positions are pre-computed server-side. See [Identity Graph](identity-graph.md).

---

## Managed Identity

An Azure identity automatically managed by the platform, eliminating the need for credential management. Managed identities authenticate to Azure services without storing secrets.

**Types:**

| Type | Description |
|------|-------------|
| System-assigned | Tied to a single Azure resource; deleted when the resource is deleted |
| User-assigned | Independent resource that can be shared across multiple Azure resources |

**Example:**
An Azure Function App uses a system-assigned managed identity to read secrets from Key Vault without storing any credentials.

**AuditGraph Implementation:**
AuditGraph discovers managed identities as `managed_identity_system` or `managed_identity_user` categories. Managed identities generally have lower credential risk than service principals (no secrets to expire) but can still be over-privileged. They are included in NHIRI scoring.

---

## NHIRI (Non-Human Identity Risk Index)

A scoring component (0-100) that measures risk from non-human identities: service principals, managed identities, and API keys. Part of the AGIRS composite score at 40% weight. NHIRI starts at 100 and deducts points for each risk factor, with a 1.3x scope multiplier for identities with cross-subscription access.

**Risk Factors:**

| Factor | Description | Weight |
|--------|-------------|--------|
| N1 | Orphaned SPNs (no human owner + T0/T1 role) | 5 points each |
| N2 | Dormant NHI (inactive 90+ days) | 2 points each |
| N3 | Zombie NHI (disabled + privileged + stale) | 6 points each |
| N4 | Expired credentials | 4 points each |
| N5 | Ownerless app registrations | 3 points each |

**Example:**
An organization with 16 orphaned SPNs (N1) and 2 dormant NHI (N2) receives: NHIRI = max(0, 100 - (16 × 5) - (2 × 2)) = max(0, 100 - 80 - 4) = 16.

**AuditGraph Implementation:**
NHIRI is computed from non-human identity attributes. The "phantom breakdown" (orphaned, dormant, zombie, expired credentials, ownerless apps) is persisted in `risk_summary` as `nhiri_breakdown` JSONB. See [Risk Scoring Model](risk-scoring.md).

---

## Non-Human Identity (NHI)

Any cloud identity that represents an application, service, or automated process rather than a person. NHIs authenticate programmatically and typically use long-lived credentials.

**Categories:**

| Category | Cloud | Examples |
|----------|-------|---------|
| Service Principal | Azure | Custom apps, third-party SaaS integrations |
| Managed Identity (System) | Azure | VM-assigned identities, Function App identities |
| Managed Identity (User) | Azure | Shared workload identities |
| IAM User (programmatic) | AWS | CI/CD service users, automation accounts |
| IAM Role | AWS | Lambda execution roles, ECS task roles |
| Service Account | GCP | Compute Engine SAs, Cloud Function SAs |

**Example:**
A CI/CD pipeline uses a service principal with Contributor access to deploy applications to an Azure subscription.

**AuditGraph Implementation:**
AuditGraph tracks all NHI types and evaluates them via the NHIRI scoring component. The SPN Dashboard provides a dedicated view for non-human identity management including blast radius, credential risk, and ownership status.

---

## Potential Exposure Impact

The dollar figure shown on the Executive Posture hero card. Previously called "Estimated Exposure" — renamed in 2026 to better describe what the number is (a benchmark, not an actuarial loss model).

**Formula:**
```
total = (count_PHI × per_asset_PHI)
      + (count_PCI × per_asset_PCI)
      + (count_PII × per_asset_PII)
```

Defaults from IBM Cost of a Data Breach 2024: PHI $720K, PCI $1.2M, PII $540K. Overridable per tenant in Settings → Exposure Defaults.

**Why AI doesn't add a line:**
A GPT deployment is not inherently worth a fixed dollar; its value is bounded by the data it can reach. AI workloads inherit *attribution* from the data they can reach but don't contribute to the headline. See [Reach Attribution](#reach-attribution).

See [methodology page](breach-cost-methodology) for the full derivation.

---

## Reach Attribution

The cached classified-data exposure each identity (or AI model deployment) can reach via RBAC. Stored on `identities.reachable_classified_exposure` and `azure_ai_model_deployments.reachable_classified_exposure`, refreshed by the `_run_reach_attribution` scheduler step after every discovery.

**Example:**
> `SVC_Forensit` holds Reader at subscription scope. Of the 286 PHI buckets in that subscription, all 286 fall under its scope. Its reach is `286 × $720K = $205.9M` (less the rounding shown on screen).

**Why it matters:**
Identifies over-privileged identities by *what they could blow up*, not by their role name alone. When 5+ identities show the same reach number, that's the audit finding: one over-broad role assignment is concentrating the risk. Surfaces on the Executive Posture "Top Reach by Identity" panel.

For AI models the attribution method (`mi_principal_id` / `name_match` / `rbac_upper_bound` / `unresolved`) is recorded so the UI can show provenance honestly.

---

## Over-Privileged Identity

An identity with broader access permissions than required for its actual function. Over-provisioning is the most common identity risk in cloud environments.

**Example:**
A developer's service principal was granted subscription-level Owner during initial setup but only needs Contributor on a single resource group for deployments.

**AuditGraph Implementation:**
Detected through HIRI factor H3 (for human users) during identity discovery. AuditGraph identifies over-provisioning by comparing privilege tier with activity patterns and scope breadth. Each over-privileged identity deducts 4 points from the HIRI score. The remediation engine generates right-sizing recommendations with specific CLI commands. See [Risk Scoring Model](risk-scoring.md).

---

## Privilege Escalation

The process by which an attacker gains higher-level permissions than initially available, typically by exploiting identity relationships, role assignments, or credential exposure.

**Example:**
An attacker compromises a service principal with User Access Administrator role, then uses that role to assign themselves Global Administrator, gaining full tenant control.

**AuditGraph Implementation:**
AuditGraph computes privilege escalation paths through attack path analysis. Five escalation types are detected: direct escalation (role grants higher privilege), ownership chains (owner of privileged identity), PIM abuse (eligible for dangerous role), lateral movement (cross-subscription access), and credential exposure (leaked or shared secrets). See [Identity Graph](identity-graph.md).

---

## Privileged Identity Management (PIM)

An Azure AD feature that provides just-in-time (JIT) privileged access, requiring users to activate roles with a justification and time limit rather than having standing privileged access.

**Example:**
Instead of permanently holding Global Administrator, a security engineer has a PIM eligible assignment. When needed, they activate the role for 4 hours with a justification. The activation is logged and the role deactivates automatically.

**AuditGraph Implementation:**
AuditGraph discovers PIM eligible assignments and activation history during deep scans. PIM adoption is a component of the GEI governance score. The platform flags overuse patterns (excessive activations, off-hours activations) as anomalies. PIM data appears in the Identity Detail PIM tab and CISO Dashboard.

---

## Service Principal

An Azure AD identity that represents an application or service. Service principals authenticate using client secrets or certificates and are the most common non-human identity type in Azure environments.

**Example:**
An app registration named "Prod Deployment Pipeline" has an associated service principal with Contributor access to production subscriptions and two client secrets (one expiring in 30 days).

**AuditGraph Implementation:**
AuditGraph discovers service principals via Microsoft Graph API and evaluates them for risk: credential expiry, ownership status, privilege level, activity patterns, and blast radius. The SPN Dashboard provides a dedicated management view. App registrations are audited separately with a 10-factor risk scoring model. See [Connectors](connectors.md).

---

## Zombie Identity

A disabled identity that retains privileged role assignments and has been inactive for an extended period. Zombies represent the highest-priority remediation targets because they combine three risk factors: disabled status, privilege, and staleness.

**Example:**
A service principal was disabled 6 months ago but still has Global Administrator and Owner on two subscriptions. No sign-in activity has been recorded since it was disabled.

**AuditGraph Implementation:**
Detected through HIRI factor H5 (human zombies, 7 points each) and NHIRI factor N3 (non-human zombies, 6 points each). Zombie detection is the highest-severity finding and mapped to P0 remediation priority (24-hour response target). Zombie identities are flagged in the CISO Dashboard's top risks panel. See [Risk Scoring Model](risk-scoring.md) and [Best Practices](best-practices.md).

---

## References

- [Risk Scoring Model](risk-scoring.md) -- AGIRS, HIRI, NHIRI, GEI formulas and scoring
- [Identity Graph](identity-graph.md) -- Graph model, node types, visualization modes
- [Discovery Engine](discovery-engine.md) -- Discovery pipeline, scan modes, drift detection
- [Connectors](connectors.md) -- Cloud connector setup and credential management
- [Security Architecture](security-architecture.md) -- Authentication, RBAC, tenant isolation
- [Best Practices](best-practices.md) -- Remediation priorities and governance targets
