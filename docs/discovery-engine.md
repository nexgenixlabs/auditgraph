# Section 6 -- Discovery Engine

## Overview

The discovery engine is AuditGraph's core data collection system. It connects to cloud provider APIs, extracts identity and entitlement data, builds access relationships, and produces a complete snapshot of the cloud environment's identity posture.

---

## Discovery Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│  Stage 1: Connector Authentication                              │
│                                                                 │
│  • Decrypt stored credentials (Fernet)                          │
│  • Authenticate with cloud provider API                         │
│  • Circuit breaker check (if open, skip discovery)              │
│  • Verify API permissions                                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stage 2: Cloud API Scanning                                    │
│                                                                 │
│  Azure: Graph API + ARM API (21 discovery stages)               │
│  AWS: IAM API (4 discovery stages)                              │
│  GCP: IAM API + CRM API (4 discovery stages)                   │
│                                                                 │
│  • Paginated API calls (e.g., 999 items/page for Graph API)    │
│  • Retry with exponential backoff on transient failures         │
│  • Rate limit awareness (429 handling)                          │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stage 3: Identity Extraction                                   │
│                                                                 │
│  • Classify each identity by category                           │
│    (human_user, service_principal, managed_identity, etc.)      │
│  • Filter Microsoft system identities from custom identities    │
│  • Extract display name, object ID, UPN, app ID, metadata      │
│  • Determine activity status (active/inactive/stale/never_used) │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stage 4: Entitlement Discovery                                 │
│                                                                 │
│  • Azure RBAC role assignments (ARM API)                        │
│  • Entra directory roles (Graph API)                            │
│  • Microsoft Graph API permissions (Application + Delegated)    │
│  • Custom application roles                                     │
│  • PIM eligible assignments                                     │
│  • Conditional access policy coverage                           │
│  • AWS IAM policies (inline + attached)                         │
│  • GCP IAM bindings (project-level)                             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stage 5: Access Relationship Mapping                           │
│                                                                 │
│  • Map identities → roles → scopes → resources                 │
│  • Resolve subscription → resource group → resource hierarchy   │
│  • Link SPNs to app registrations                               │
│  • Map app owners to identity records                           │
│  • Track credential associations (secrets, certs, federated)    │
│  • Cross-link identity subscription access (multi-subscription) │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stage 6: Risk Scoring                                          │
│                                                                 │
│  Per-identity:                                                  │
│  • Privilege tier assignment (T0/T1/T2/T3)                      │
│  • Risk score computation (0-100)                               │
│  • Blast radius calculation                                     │
│  • Risk level classification (critical/high/medium/low)         │
│                                                                 │
│  Per-organization:                                              │
│  • AGIRS composite score (HIRI + NHIRI + GEI)                  │
│  • Persist to risk_summary table                                │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stage 7: Graph Building + Snapshot Commit                      │
│                                                                 │
│  • Build access graph nodes and edges per identity              │
│  • Compute snapshot integrity hash (SHA-256)                    │
│  • Sign snapshot for tamper detection                           │
│  • Complete discovery run (status: completed)                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## How Discovery Runs Work

### Trigger Mechanisms

| Mechanism | Schedule | Description |
|-----------|----------|-------------|
| **Scheduled** | Every 12 hours (configurable via `DISCOVERY_INTERVAL_HOURS`) | Automatic full scan of all organizations and connectors |
| **Manual** | On-demand via `POST /api/runs/trigger` | User-initiated scan for a specific connector |
| **Continuous** | Every 5 minutes | Checks per-connection `discovery_interval_minutes` and runs if due |

### Orchestration Flow

```
Scheduler Trigger
    │
    ├── Query: SELECT * FROM organizations WHERE enabled = true
    │
    └── FOR EACH organization:
        │
        ├── Create snapshot_run (org_id, scan_mode, status: running)
        │
        ├── Query: SELECT * FROM cloud_connections
        │          WHERE organization_id = N AND status = 'connected'
        │
        └── FOR EACH connection:
            │
            ├── Create snapshot_job (connection_id, status: running)
            ├── Decrypt credentials from metadata JSONB
            ├── Instantiate cloud engine (Azure/AWS/GCP)
            ├── Start heartbeat thread (20-second intervals)
            │
            ├── Execute: engine.run_discovery()
            │   (circuit breaker protection wraps this call)
            │
            ├── Complete snapshot_job
            │   ├── Update snapshot_job_metrics (identity counts)
            │   ├── Update connection.last_discovery_at
            │   └── Status: completed or failed
            │
            └── Post-Discovery Pipeline:
                ├── Drift Detection (compare with previous run)
                ├── Anomaly Detection (6 anomaly types)
                ├── Risk Summary Computation (AGIRS)
                ├── Notification Dispatch (email/Slack/Teams)
                └── SOAR Playbook Evaluation
```

### Scan Modes

| Mode | Description | Stages Included | Typical Duration |
|------|-------------|-----------------|-----------------|
| **quick** | Lightweight identity check | Identities, basic roles | 1-2 minutes |
| **standard** | Recommended daily scan | + Credentials, permissions, activity | 3-5 minutes |
| **deep** | Full comprehensive audit | + PIM, CA policies, resources, app registrations | 5-15 minutes |

### Discovery Run States

```
queued ───► running ───► completed
                │
                └──────► failed
```

| State | Description |
|-------|-------------|
| `queued` | Run created, waiting for executor |
| `running` | Active discovery in progress, heartbeat active |
| `completed` | All stages finished, snapshot committed |
| `failed` | Error during discovery (credentials, API, timeout) |

---

## Post-Discovery Pipeline

After each connector discovery completes, a pipeline of analysis stages executes:

### Drift Detection

Compares the current discovery snapshot with the previous run for the same connector:

| Change Type | Example |
|-------------|---------|
| **New role assignments** | User gained Owner on production subscription |
| **Removed role assignments** | Service principal lost Contributor role |
| **Credential changes** | New secret added to app registration |
| **New identities** | Service principal appeared for the first time |
| **Removed identities** | User account disabled or deleted |

Drift reports are persisted and available via `GET /api/drift/history`.

### Anomaly Detection

Six anomaly types are evaluated after each run:

| Anomaly Type | Description | Severity |
|-------------|-------------|----------|
| `permission_escalation` | Identity gained high-privilege roles between scans | High |
| `risk_score_spike` | Risk score increased significantly between scans | Medium |
| `dormant_reactivation` | Stale identity (90+ days) suddenly became active | High |
| `credential_surge` | Multiple credentials added in short timeframe | Medium |
| `off_hours_pim` | PIM role activation outside business hours | Medium |
| `excessive_pim_usage` | Unusually high number of PIM activations | Medium |

### Risk Summary Computation

The AGIRS engine computes organizational risk scores:

1. Count risk factors (ghost accounts, orphaned SPNs, over-privileged, etc.)
2. Compute HIRI (Human Identity Risk Index)
3. Compute NHIRI (Non-Human Identity Risk Index)
4. Compute GEI (Governance Effectiveness Index)
5. Calculate composite AGIRS score
6. Persist to `risk_summary` table

### Notification Dispatch

If configured, notifications are sent via:
- Email (SendGrid)
- Slack (Block Kit messages)
- Microsoft Teams (Adaptive Cards)

Notification events: `scan_complete`, `scan_failed`, `anomaly_detected`, `drift_detected`.

---

## Incremental Discovery

AuditGraph uses a snapshot-based model where each discovery run produces a complete picture of the environment. This is not incremental in the traditional sense -- every run discovers all identities.

However, the platform optimizes in several ways:

1. **Scan modes**: Quick scans skip expensive stages (PIM, CA, resources)
2. **Drift detection**: Only changes between snapshots are analyzed, not the full dataset
3. **Continuous discovery**: Per-connection intervals allow staggered scanning
4. **API pagination**: Large directories are scanned in pages (999 items/page for Graph API)
5. **Heartbeat monitoring**: Long-running scans are monitored; zombie jobs are detected and restarted

---

## Pipeline Validation

After discovery, a validation step checks snapshot completeness:

**Required components** (snapshot invalid if count = 0):
- Identities
- Role assignments
- Entra role assignments (Azure only)

**Optional components** (logged but do not invalidate):
- Storage accounts
- Key vaults
- Attack paths
- Risk summary

Validation functions compare discovered counts against expected ranges and log discrepancies.

---

## Activity Tracking

AuditGraph determines the activity status of each identity:

| Status | Definition | Source |
|--------|-----------|--------|
| `active` | Sign-in within last 30 days | Graph API sign-in logs |
| `inactive` | Sign-in 30-90 days ago | Graph API sign-in logs |
| `stale` | No sign-in in 90+ days | Graph API sign-in logs |
| `never_used` | Created 30+ days ago, never authenticated | Graph API + creation date |
| `unknown` | No sign-in data available (missing AuditLog.Read.All permission) | Fallback |

**P2 Telemetry**: If Azure AD P2 licensing is available and the `p2_telemetry_enabled` setting is active, AuditGraph ingests workload sign-in events for higher-confidence activity tracking (95% confidence vs 40% heuristic).

---

## Credential Expiration Tracking

For each non-human identity, AuditGraph checks credential health:

| Status | Definition | Action |
|--------|-----------|--------|
| `expired` | Credential past expiration date | Immediate rotation required |
| `critical` | Expiring within 7 days | Urgent rotation |
| `warning` | Expiring within 30 days | Schedule rotation |
| `good` | More than 30 days until expiry | No action needed |
| `no_expiration` | No credentials or federated-only | N/A |

---

## Snapshot Integrity

Each discovery snapshot is cryptographically hashed and signed to ensure data integrity. This enables tamper detection and supports audit validation of historical identity data.

**Implementation:**

1. Compute SHA-256 hash of run metadata (ID, timestamps, identity counts)
2. Sign with HMAC using platform key
3. Store hash and signature in `discovery_runs` table
4. Integrity can be verified via `GET /api/system/integrity-check`

---

## References

- [Connectors](connectors.md) -- Connector setup and credential management
- [Risk Scoring Model](risk-scoring.md) -- How risk scores are computed
- [Architecture](architecture.md) -- System architecture overview
- [Operations](operations.md) -- Scheduler configuration and troubleshooting
