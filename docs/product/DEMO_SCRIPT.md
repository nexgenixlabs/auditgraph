# AuditGraph Demo Script — 6-Plane Identity Risk Posture

## Pre-Demo Checklist

1. Seed data loaded (`scripts/seed_demo_tenant.py`)
2. Backend running (`python3 -m flask run --port 5001`)
3. Frontend running (`npm start` on port 3000)
4. Login as `nexgenadmin` / `changeme`

---

## Flow 1: CISO Dashboard (3 min)

**Open**: `http://localhost:3000/dashboard`

### Talk Track
> "This is the executive dashboard showing real-time identity risk posture across your Azure tenant."

1. **Posture Score** — composite AGIRS score (0-100), computed from Human Identity Risk, Non-Human Identity Risk, and Governance Effectiveness
2. **Five Risk Blocks** — scroll to the 5-tile section:
   - Compute Identity Risk (App Services, Functions, VMs)
   - Container Identity Risk (AKS, ACR)
   - Data Identity Risk (SQL, PostgreSQL, CosmosDB)
   - Analytics Identity Risk (Databricks, Synapse, Azure ML)
   - DevOps & Integration Risk (ADO, APIM, Event Hub, Service Bus)
3. **DevOps Risk Banner** — red if pipeline privilege escalation paths exist
4. **Credential Health** — expiring/expired credential summary
5. **Quick Actions** — one-click counts for common audit tasks

### Key Metric to Highlight
> "Notice the DevOps risk banner — we discovered N service principals used in CI/CD pipelines with subscription-scope access. That's a blast radius amplifier."

---

## Flow 2: Identity Deep Dive (5 min)

**Navigate**: Click a high-risk identity from the dashboard, or go to `/identities`

### Talk Track
> "Let me show you what we know about this non-human identity."

1. **Overview Tab** — risk score, category, activity status
   - "Used in Pipelines" section (if SPN has ADO service connections)
   - Lineage verdict with confidence score
   - Analytics context (Databricks workspace access)
2. **Roles Tab** — RBAC + Entra directory roles, including group-inherited roles
3. **Access Graph Tab** — visual blast radius (executive mode) or ARM tree (technical mode)
   - Toggle to Attack Path mode for escalation chains
4. **Credentials Tab** — secret/certificate inventory with expiry tracking
5. **Lineage Tab** — identity origin, workload inference, verdict history

### Key Callout
> "This identity has a blast radius score of 78 — HIGH — because it's linked to a subscription-scope ADO service connection AND has Contributor role. If an attacker compromises this pipeline, they control the entire subscription."

---

## Flow 3: Six-Plane Resource Drill-Down (3 min)

### Compute Plane
**Navigate**: `/identities?plane=compute`
> "These are identities with system-assigned managed identities on compute resources. We scan App Service, Functions, VMs, and Logic Apps for exposed environment secrets."

### Container Plane
**Navigate**: `/identities?plane=container`
> "AKS clusters with federated credentials. We flag overly-broad OIDC subject claims — a misconfigured wildcard lets any workload in the cluster assume this identity."

### Data Plane
**Navigate**: Database servers in resources
> "We check every SQL Server, PostgreSQL, and CosmosDB for mixed authentication — if both AAD and local SQL auth are enabled, that's a governance gap."

### Analytics Plane
**Navigate**: Analytics workspaces in sidebar
> "Databricks, Synapse, Azure ML. We discover personal access tokens with no expiry date — those bypass Entra ID token lifecycle entirely."

### DevOps Plane
> "Azure DevOps service connections, APIM subscription keys, Event Hub/Service Bus SAS keys. Each one is a credential that can amplify blast radius."

### Long-tail
> "Azure Batch accounts with SharedKey auth, Static Web Apps. The long tail of Azure services that still have identity governance gaps."

---

## Flow 4: AGIRS Scoring Deep Dive (2 min)

### Talk Track
> "AGIRS is our three-axis composite score. Let me break it down."

1. **HIRI (40%)** — Human Identity Risk: ghost accounts, dormant privileged, over-privileged, external guests
2. **NHIRI (40%)** — Non-Human Identity Risk: 8 deduction factors including federated misconfiguration, PAT governance, and DevOps SPN exposure
3. **GEI (20%)** — Governance Effectiveness: ownership coverage, PIM adoption, access reviews, monitoring
4. **Confidence Score** — how complete is our data? Missing P2 telemetry reduces confidence.

### Key Callout
> "Our AGIRS score is X with Y% confidence. The NHIRI is the weakest axis because we found Z orphaned service principals with no owner."

---

## Flow 5: Remediation & Governance (2 min)

### Talk Track
> "Every finding has a recommended action."

1. **Remediation Tab** — matched playbooks per identity
2. **SA Governance** — attestation workflows for service accounts
3. **Reports** — one-click executive PDF (landscape) or full audit PDF

---

## Objection Handling

**Q: "How is this different from Defender for Identity?"**
> A: Defender focuses on threat detection (lateral movement, credential theft). AuditGraph focuses on posture — who has access to what, why, and whether that access is justified. We're the audit layer, not the SOC layer.

**Q: "How do you handle multi-subscription?"**
> A: Every identity is mapped to all subscriptions where it has RBAC. The junction table tracks primary and additional subscriptions.

**Q: "What about multi-tenant?"**
> A: Full multi-tenant with Row Level Security. Each tenant sees only their data. Superadmin portal for MSP management.

**Q: "Can I get alerts?"**
> A: Slack and Teams webhook integrations, anomaly detection with 6 anomaly types, SOAR playbooks for automated response.
