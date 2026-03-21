# Section 12 -- Best Practices

## Connector Configuration

### Least Privilege for Connectors

Grant connectors only the permissions they need:

| Cloud | Recommended | Avoid |
|-------|-------------|-------|
| Azure | `Reader` RBAC + Graph API read-only permissions | `Contributor`, `Owner`, or write permissions |
| AWS | `iam:List*` + `iam:Get*` | `iam:*` or `AdministratorAccess` |
| GCP | `roles/iam.securityReviewer` + `roles/viewer` | `roles/owner` or `roles/editor` |

### Credential Management

| Practice | Recommendation |
|----------|---------------|
| **Secret expiry** | Set Azure client secrets to 12 months. Create calendar reminders at 6 months. |
| **Rotation** | Rotate credentials every 6 months (Azure) or 90 days (AWS/GCP). Use AuditGraph's credential rotation API. |
| **Dedicated service principal** | Create a dedicated app registration for AuditGraph. Do not share credentials with other services. |
| **Monitor expiry** | Check `GET /api/connectors/expiring-credentials` regularly. AuditGraph alerts when credentials are approaching expiry. |

### Multi-Connector Strategy

```
Recommended structure for a mid-size enterprise:

Organization: Acme Corp
├── Azure Connector: "Production Tenant"    (deep scan every 12h)
├── Azure Connector: "Development Tenant"   (standard scan every 24h)
├── AWS Connector: "Production Account"     (standard scan every 12h)
├── AWS Connector: "Staging Account"        (quick scan every 24h)
└── GCP Connector: "Analytics Project"      (standard scan every 12h)
```

- Use **deep** scans for production environments (includes PIM, CA policies, resources)
- Use **standard** scans for non-production (credentials and permissions but not resource inventory)
- Use **quick** scans for large environments where frequent identity checks are needed

---

## Identity Risk Remediation

### Triage Framework

Prioritize remediation using AGIRS (AuditGraph Identity Risk Score) risk factors:

| Priority | Risk Factor | Action | Timeline |
|----------|-------------|--------|----------|
| **P0** | Zombie identities (H5, N3) | Disable immediately, investigate for compromise | 24 hours |
| **P0** | High blast radius + stale | Disable or remove roles | 24 hours |
| **P1** | Ghost accounts (H1) | Remove role assignments from disabled accounts | 72 hours |
| **P1** | Orphaned NHI with T0/T1 roles (N1) | Assign owner, scope down permissions | 72 hours |
| **P2** | Dormant privileged (H2) | Review with identity owner, remove if unnecessary | 1 week |
| **P2** | External guests with privilege (H4) | Verify business need, remove if expired | 1 week |
| **P3** | Over-privileged identities (H3) | Right-size permissions to least privilege | 2 weeks |
| **P3** | Expired credentials (N4) | Rotate or remove | 2 weeks |
| **P4** | Dormant NHI (N2) | Review in quarterly access review | Next quarter |

### Using AuditGraph for Remediation

1. **Start with the CISO Dashboard**: Review the AGIRS score and top risks
2. **Drill into risk factors**: Click on risk factor counts to see affected identities
3. **Use the Identity Detail page**: Review each identity's access graph, blast radius, and risk factors
4. **Check remediation recommendations**: AuditGraph generates actionable recommendations with CLI commands
5. **Execute remediations**: Use the Remediation Center to track actions or execute directly
6. **Monitor AGIRS improvement**: After remediation, the next discovery scan updates the AGIRS score

### Example: Remediating an Over-Privileged Service Principal

```
Identity: prod-automation-sp
Risk: 85 (Critical) | Tier: T0 | Blast Radius: 90
Issue: Global Administrator + Owner on 2 subscriptions

Step 1: Open Identity Detail
  Navigate to Identity Graph to see full access scope

Step 2: Review effective access
  Technical mode shows all subscriptions and resources reachable

Step 3: Determine minimum required access
  This SPN deploys to prod-rg only → needs Contributor on prod-rg

Step 4: Execute remediation
  a. Remove Global Administrator (Entra role)
     az ad app update --id {app-id} --remove-directory-roles
  b. Remove subscription-level Owner
     az role assignment delete --assignee {sp-id} --role Owner --scope /subscriptions/{sub-id}
  c. Add scoped Contributor
     az role assignment create --assignee {sp-id} --role Contributor --scope /subscriptions/{sub-id}/resourceGroups/prod-rg

Step 5: Verify
  Trigger a discovery run. AGIRS should improve.
```

---

## Least Privilege Enforcement

### Principles

| Principle | Implementation |
|-----------|---------------|
| **No standing T0 access** | Use PIM (Privileged Identity Management) for Global Admin. Require activation + justification. |
| **Scope to resource group** | Avoid subscription-level Owner/Contributor. Scope RBAC to the narrowest resource group. |
| **Time-bound access** | Use PIM eligible assignments with activation duration limits (e.g., 4 hours max). |
| **Separation of duties** | Different SPNs for different workloads. No single SPN should access production + staging. |
| **Owner assignment** | Every service principal must have a human owner. Ownerless SPNs are tracked by NHIRI. |

### Governance Targets

| Metric | Target | Measured By |
|--------|--------|-------------|
| AGIRS Score | >= 80 (Grade B) | Risk Summary |
| T0 identities with PIM | 100% | GEI: PIM Adoption |
| SPN ownership coverage | >= 90% | GEI: Ownership Coverage |
| Ghost account count | 0 | HIRI: H1 factor |
| Over-privileged identities | < 10% of total | HIRI: H3 factor |

### Step-by-Step: Implementing Least Privilege

```
Phase 1: Visibility (Week 1-2)
  ├── Connect all cloud environments
  ├── Run deep discovery scans
  ├── Review AGIRS score and risk factors
  └── Identify all T0 and T1 identities

Phase 2: Quick Wins (Week 3-4)
  ├── Remove ghost account role assignments
  ├── Assign owners to orphaned SPNs
  ├── Rotate expired credentials
  └── Disable zombie identities

Phase 3: Right-Sizing (Month 2-3)
  ├── Enable PIM for all T0 identities
  ├── Scope subscription-level roles to resource groups
  ├── Remove unnecessary Global Administrator assignments
  └── Implement conditional access for privileged access

Phase 4: Continuous Governance (Ongoing)
  ├── Scheduled deep scans (every 12 hours)
  ├── Anomaly detection alerts
  ├── Quarterly access reviews for all SPNs
  └── Monthly AGIRS trend review
```

---

## Credential Rotation

### Rotation Schedule

| Credential Type | Rotation Frequency | Monitoring |
|-----------------|-------------------|------------|
| AuditGraph connector secrets (Azure) | Every 6 months | `GET /api/connectors/expiring-credentials` |
| AuditGraph connector keys (AWS) | Every 90 days | Dashboard alerts |
| Application secrets in monitored environment | Per org policy | AuditGraph credential discovery |
| Platform encryption keys | Annually or after incident | Manual process |
| JWT signing secrets | Annually or after incident | Manual process |

### Rotation Procedure (AuditGraph Connector)

```
1. Generate new credential in cloud provider console
   (Azure: App Registration → Certificates & secrets → New)

2. Update AuditGraph connector
   POST /api/connectors/{id}/rotate-credentials
   { "client_secret": "new-secret-value" }

3. Verify connectivity
   POST /api/client/connections/test
   { "cloud": "azure", "client_id": "...", "client_secret": "new-secret-value" }

4. Remove old credential from cloud provider console

5. Confirm discovery runs successfully
   POST /api/runs/trigger
   { "connection_id": 1, "scan_mode": "quick" }
```

---

## Monitoring Identity Drift

### What to Monitor

| Drift Type | Risk Level | Response |
|-----------|------------|----------|
| New T0/T1 role assignment | Critical | Investigate immediately |
| New credential added to SPN | High | Verify with SPN owner |
| Role removed from identity | Informational | Confirm intentional |
| New identity appeared | Low | Normal onboarding |
| Identity removed | Informational | Normal offboarding |

### Setting Up Drift Alerts

```
1. Configure notification channel
   Settings → Integrations → Add Slack/Teams webhook

2. Enable drift notifications
   Toggle: "Drift Detected" event → ON

3. Configure severity threshold (optional)
   Only alert on critical/high drift events

4. Review drift reports
   GET /api/drift/history
   Click into each report to see detailed changes
```

### Drift Review Cadence

| Frequency | Activity |
|-----------|----------|
| **Real-time** | Slack/Teams alerts for critical drift (T0/T1 role changes) |
| **Daily** | Review drift summary in CISO Dashboard |
| **Weekly** | Review full drift history for the past week |
| **Monthly** | AGIRS trend review, compare current vs previous month |
| **Quarterly** | Full access review of all service principals |

### Anomaly Response Playbook

```
When an anomaly is detected:

1. Review anomaly in AuditGraph
   GET /api/anomalies/{id}
   Check: type, severity, affected identity, timestamp

2. Assess impact
   Is the affected identity T0/T1?
   What is the blast radius?
   Was this during business hours?

3. Investigate
   Check identity timeline: GET /api/identities/{id}/timeline
   Check attack paths: GET /api/identities/{id}/attack-paths
   Check recent sign-in logs (if P2 telemetry enabled)

4. Respond
   If unauthorized: disable identity immediately
   If legitimate: acknowledge anomaly, update SOAR playbook
   If unclear: escalate to identity owner

5. Document
   Resolve anomaly with notes
   PATCH /api/anomalies/{id}
   { "resolved": true, "resolution_notes": "..." }
```

---

## Summary

| Practice | Key Action | Metric |
|----------|-----------|--------|
| Connector configuration | Least privilege, rotation schedule, deep scans for prod | Connector health status |
| Identity risk remediation | P0-P4 triage framework, start with zombies and ghosts | AGIRS score improvement |
| Least privilege | PIM for T0, scope to RG, owner assignment | GEI components |
| Credential rotation | 6-month Azure, 90-day AWS/GCP, annual platform keys | Credential expiry count |
| Drift monitoring | Real-time alerts, daily review, quarterly access review | Drift event count trending down |

---

## References

- [Risk Scoring Model](risk-scoring.md) -- Understanding AGIRS for prioritization
- [Connectors](connectors.md) -- Connector setup and credential details
- [Discovery Engine](discovery-engine.md) -- Scan modes and scheduling
- [Security Features](security-features.md) -- Platform security controls
