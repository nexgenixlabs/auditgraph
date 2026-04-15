# AuditGraph System Architecture

> **Purpose**: Single-source-of-truth engineering reference for the AuditGraph platform.
> Generated from codebase audit — no assumptions, no fixes, analysis only.
>
> **Last updated**: 2026-04-08

---

## Table of Contents

1. [Data Model](#1-data-model)
2. [Data Flow](#2-data-flow)
3. [SSOT Definitions](#3-ssot-definitions)
4. [API Contracts](#4-api-contracts)
5. [Known Issues & Inconsistencies](#5-known-issues--inconsistencies)
6. [Recommended Fixes](#6-recommended-fixes)
7. [Guardrails for Future Development](#7-guardrails-for-future-development)

---

## 1. Data Model

### 1.1 Core Tables

#### `cloud_connections` — Tenant Cloud Configuration
```sql
CREATE TABLE cloud_connections (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    cloud VARCHAR(20) NOT NULL DEFAULT 'azure',
    connection_type VARCHAR(30) NOT NULL DEFAULT 'entra',
    label VARCHAR(255) NOT NULL,
    azure_directory_id VARCHAR(100),
    client_id VARCHAR(100),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'connected' | 'pending' | 'failed'
    display_order INTEGER NOT NULL DEFAULT 0,
    last_test_at TIMESTAMPTZ,
    last_test_status VARCHAR(20),
    last_discovery_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',
    credential_last_rotated TIMESTAMPTZ,
    credential_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, cloud, azure_directory_id)
);
```
**Role**: Root isolation entity. Every discovery chain starts from a cloud_connection. Status `'connected'` = active.

#### `cloud_subscriptions` — Subscription Inventory
```sql
CREATE TABLE cloud_subscriptions (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    cloud VARCHAR(20) NOT NULL,
    account_id VARCHAR(255) NOT NULL,           -- Azure subscription ID
    account_name VARCHAR(500),
    status VARCHAR(20) DEFAULT 'discovered',
    monitored BOOLEAN DEFAULT false,
    activated_at TIMESTAMPTZ,
    activated_by INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    cloud_connection_id INTEGER NOT NULL,
    rate_cents INTEGER NOT NULL DEFAULT 6900,
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    deleted BOOLEAN DEFAULT false,
    deleted_at TIMESTAMPTZ,
    UNIQUE(cloud_connection_id, account_id)
);
```
**Role**: SSOT for "what subscriptions exist". Scoped by `cloud_connection_id` + `organization_id`.

#### `discovery_runs` — Scan Execution Records
```sql
-- DDL spread across create_discovery_run() and migrations
-- Key columns:
    id BIGSERIAL PRIMARY KEY,
    subscription_id VARCHAR,
    subscription_name VARCHAR,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    status VARCHAR,                              -- 'running' | 'completed' | 'failed'
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    total_identities INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    snapshot_hash VARCHAR,
    tenant_id INTEGER
```
**Role**: Audit trail for every scan. Links cloud_connection → identities. `cloud_connection_id` is required (enforced in `create_discovery_run()`).

#### `identities` — Identity Inventory
```sql
-- 43+ columns. Key columns:
    id BIGSERIAL PRIMARY KEY,
    identity_id VARCHAR,                         -- Azure object_id
    display_name VARCHAR,
    identity_category VARCHAR,                   -- human_user | guest | service_principal | managed_identity_system | managed_identity_user | microsoft_internal
    risk_level VARCHAR,                          -- critical | high | medium | low | info
    risk_score NUMERIC,
    activity_status VARCHAR,                     -- active | inactive | stale | never_used | recently_created | unknown
    privilege_tier VARCHAR,                      -- T0 | T1 | T2 | T3
    blast_radius_score NUMERIC,
    discovery_run_id INTEGER NOT NULL,           -- FK → discovery_runs.id
    deleted_at TIMESTAMPTZ,
    is_microsoft_system BOOLEAN,
    recommended_action VARCHAR,                  -- ORPHANED | ...
    credential_risk VARCHAR,                     -- expired | expiring_soon | healthy
    -- NOTE: NO cloud_connection_id column. NO tenant_id column.
    -- Scoped transitively via discovery_run_id → discovery_runs.cloud_connection_id
```
**Role**: Central identity store. Scoped via `discovery_run_id` (NOT directly by org or connection).

#### `role_assignments` — RBAC Bindings
```sql
-- Key columns:
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER NOT NULL,             -- FK → identities.id
    role_name VARCHAR,
    scope VARCHAR,                               -- ARM path: /subscriptions/{id}/...
    scope_type VARCHAR,                          -- subscription | resource_group | resource | management_group
    -- Scoped transitively via identity_db_id → identities.discovery_run_id
```

#### `risk_summary` — Persisted Risk Metrics
```sql
CREATE TABLE risk_summary (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    discovery_run_id INTEGER NOT NULL,
    ghost_accounts INTEGER NOT NULL DEFAULT 0,
    orphaned_spns INTEGER NOT NULL DEFAULT 0,
    over_privileged INTEGER NOT NULL DEFAULT 0,
    dormant_privileged INTEGER NOT NULL DEFAULT 0,
    high_blast_radius INTEGER NOT NULL DEFAULT 0,
    external_exposure INTEGER NOT NULL DEFAULT 0,
    attack_paths INTEGER NOT NULL DEFAULT 0,
    total_identities INTEGER NOT NULL DEFAULT 0,
    customer_identities INTEGER NOT NULL DEFAULT 0,
    microsoft_identities INTEGER NOT NULL DEFAULT 0,
    total_resources INTEGER NOT NULL DEFAULT 0,
    storage_accounts INTEGER NOT NULL DEFAULT 0,
    key_vaults INTEGER NOT NULL DEFAULT 0,
    subscriptions INTEGER NOT NULL DEFAULT 0,
    privileged_roles INTEGER NOT NULL DEFAULT 0,
    agirs_score NUMERIC(6,2),
    agirs_tier VARCHAR(2),                       -- A | B | C | D | F
    hiri_score NUMERIC(5,2),
    nhiri_score NUMERIC(5,2),
    gei_score NUMERIC(5,2),
    hiri_breakdown JSONB,
    nhiri_breakdown JSONB,
    gei_breakdown JSONB,
    dangerous_identities JSONB,                  -- Top 5 by blast_radius_score
    human_count INTEGER DEFAULT 0,
    nhi_count INTEGER DEFAULT 0,
    identity_risk_score INTEGER,
    computed_at TIMESTAMPTZ DEFAULT NOW(),
    tenant_id INTEGER,
    UNIQUE(organization_id, discovery_run_id)
);
```
**Role**: Persisted output of `RiskSummaryEngine.compute()`. One row per (org, run). Recomputed on each scan.

#### `anomalies` — Anomaly Detection Results
```sql
-- Key columns:
    id SERIAL PRIMARY KEY,
    discovery_run_id INTEGER,
    identity_db_id INTEGER,
    type VARCHAR,                                -- permission_escalation | risk_score_spike | dormant_reactivation | ...
    severity VARCHAR,                            -- critical | high | medium | low
    resolved BOOLEAN DEFAULT false,
    -- Scoped via discovery_run_id
```

#### `remediation_actions` — Remediation Queue
```sql
-- Key columns:
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    identity_db_id INTEGER,
    action_type VARCHAR,
    execution_status VARCHAR,
    -- Scoped via organization_id
```

### 1.2 Isolation Chain

```
cloud_connections.id (SSOT root)
    ↓ cloud_connection_id
cloud_subscriptions (subscription inventory)

cloud_connections.id
    ↓ cloud_connection_id
discovery_runs.id (scan records)
    ↓ discovery_run_id
identities.id (identity inventory)
    ↓ identity_db_id
role_assignments (RBAC bindings)
anomalies (detection results)
pim_eligible_assignments / pim_activations
entra_role_assignments

discovery_runs.id
    ↓ discovery_run_id
risk_summary (one per org+run, UNIQUE constraint)
```

**Key invariant**: `identities` has NO `cloud_connection_id` column. All connection scoping is transitive: `conn_id → discovery_runs → run_ids → identities WHERE discovery_run_id = ANY(run_ids)`.

---

## 2. Data Flow

### 2.1 CISO Summary Pipeline

The CISO dashboard is powered by a single endpoint: `GET /api/ciso/summary`.

#### Request Flow
```
Browser → GET /api/ciso/summary?connection_id=X
  ↓
get_ciso_summary()                    [outer shell — guarantees JSON on ANY error]
  ↓
_ciso_summary_inner()                 [main logic]
  │
  ├─ 1. RESOLVE CONNECTION
  │   └─ _resolve_connection_id(cursor, org_id)
  │       Priority: query param → X-Connection-Id header → auth context → DB default → HARD FAIL
  │
  ├─ 2. VALIDATE ISOLATION
  │   └─ _require_isolation_context(org_id, conn_id, require_conn=True)
  │       Checks: org_id > 0, conn_id present
  │
  ├─ 3. CHECK CACHE
  │   └─ _ciso_cache_get(org_id, conn_id)
  │       In-memory dict, 30-second TTL, thread-safe (threading.Lock)
  │
  ├─ 4. RESOLVE RUN IDs
  │   └─ _scoped_run_ids(cursor, org_id, conn_id)
  │       Validates conn_id ownership (cross-org guard)
  │       Delegates to _latest_run_ids() — one run per active connection
  │
  ├─ 5. COLLECT 6 SOURCES (via _safe_collect wrapper)
  │   ├─ _collect_risk_summary(db, org_id, conn_id, run_ids)
  │   │   ├─ db.get_latest_risk_summaries() → persisted risk_summary row
  │   │   ├─ If missing: RiskSummaryEngine(db, org_id, run_ids).compute()
  │   │   ├─ Live SQL: risk_level_dist from identities
  │   │   ├─ Live SQL: total_subscriptions from cloud_subscriptions (SSOT)
  │   │   └─ Live SQL: active_subscriptions from role_assignments (exposure metric)
  │   ├─ _collect_trends(db, org_id, conn_id) → last 10 discovery_runs
  │   ├─ _collect_anomalies(db, run_ids)
  │   ├─ _collect_remediation(db, run_ids)
  │   ├─ _collect_drift(db, conn_id)
  │   └─ _collect_spn_stats(db, org_id, conn_id, run_ids)
  │
  ├─ 6. BUILD 6 DATA SECTIONS
  │   ├─ _build_risk_summary_data(sources)  → data.riskSummary
  │   ├─ _build_trends_data(sources)         → data.trends
  │   ├─ _build_anomaly_data(sources)        → data.anomalies
  │   ├─ _build_remediation_data(sources)    → data.remediation
  │   ├─ _build_drift_data(sources)          → data.drift
  │   └─ _build_spn_data(sources)            → data.spn
  │
  └─ 7. BUILD ENVELOPE
      └─ _build_ciso_envelope(sources, gaps, data, run_ids, db)
          ├─ _has_real_data(sources) → boolean
          ├─ _count_usable_sources(sources) → (usable, total=6)
          ├─ Status: DISCOVERY_REQUIRED | PARTIAL | READY
          ├─ Coverage: round(usable/6 * 100)
          ├─ Confidence: high (≥85%) | medium (≥50%) | low
          └─ lastUpdated: computed_at → discovery_runs.completed_at → None
```

### 2.2 RiskSummaryEngine Pipeline

```
RiskSummaryEngine(db, org_id, run_ids)
  ↓
compute()
  ├─ Phase 1: _compute_identity_counts(summary)
  │   └─ SQL: COUNT(*) FILTER for ghost, orphaned, over_priv, dormant, etc.
  │
  ├─ Phase 2: _compute_agirs(summary)
  │   └─ AGIRSEngine.compute()
  │       ├─ HIRI: Human Identity Risk Index (ghost + dormant + over_priv + ext_guest + zombie)
  │       ├─ NHIRI: Non-Human Identity Risk Index (phantom breakdown)
  │       ├─ GEI: Governance Effectiveness Index
  │       └─ AGIRS = 0.40 * HIRI + 0.40 * NHIRI + 0.20 * GEI
  │
  ├─ Phase 3: _compute_remaining_metrics(summary)
  │   ├─ attack_paths (from attack_paths + graph_attack_findings tables)
  │   ├─ total_resources, storage_accounts, key_vaults
  │   ├─ subscriptions (from cloud_subscriptions — SSOT)
  │   └─ privileged_roles
  │
  └─ Phase 4: _validate_and_fix_agirs(summary)
      ├─ Critical inflation cap (if >50% critical → recalculate)
      └─ AGIRS contradiction check
  │
  └─ summary['computed_at'] = datetime.now(UTC).isoformat()
  │
  ↓
persist(summary)
  └─ INSERT INTO risk_summary ... ON CONFLICT DO UPDATE
     computed_at = NOW()  (PostgreSQL server time)
```

**AGIRS Tier Mapping:**
| Score Range | Tier | Status Label |
|-------------|------|-------------|
| ≥ 92        | A    | resilient   |
| ≥ 80        | B    | controlled  |
| ≥ 65        | C    | elevated    |
| ≥ 45        | D    | high        |
| < 45        | F    | critical    |

### 2.3 Frontend Data Flow

```
CISODashboard.tsx
  └─ useCISOSummary() hook
      ├─ useConnection() → withConnection('/api/ciso/summary')
      ├─ fetch(url, { signal, timeout: 15s })
      ├─ Status gating:
      │   ├─ ERROR → empty VM + error card
      │   ├─ usableSources === 0 || DISCOVERY_REQUIRED → empty VM + CTA
      │   └─ PARTIAL | READY → mapSummaryToViewModel(json) → full dashboard
      └─ Returns { vm, status, primaryGap, usableSources, totalSources }

mapSummaryToViewModel(response)
  ├─ Destructures: response.data.{riskSummary, trends, anomalies, remediation, drift, spn}
  ├─ Maps each section to intermediate format
  ├─ Calls buildExtendedCISOViewModel(riskData, null, trendsData, ...)
  │   └─ buildCISOViewModel(riskData, attackData=null)
  │       └─ Produces 40+ field CISOViewModel from riskSummary data
  ├─ SSOT overrides from envelope:
  │   ├─ vm.coverage_pct = response.coverage
  │   ├─ vm.last_updated = formatRelativeTime(lastUpdated || computed_at)
  │   └─ vm.data_confidence = response.confidence
  └─ Returns CISOViewModel

Component Tree:
  CISODashboard
    ├─ Header strip: vm.last_updated + vm.monitored.subscriptions + active_subscriptions
    ├─ ExecutiveSummaryHero (grid: 5-4-3 columns)
    │   ├─ NarrativePanel: vm.status, vm.top_risk_drivers[0]
    │   ├─ RiskScorePanel: vm.agirs_display.score, vm.trend_history, vm.risk_exposure
    │   └─ ConfidencePanel: vm.coverage_pct, vm.monitored.{subscriptions,identities}, vm.last_updated
    ├─ Row 2 cards: ImmediateRisks, BlastRadius, ActiveThreats, ActivityDrift
    ├─ Row 3 cards: RemediationImpact, BusinessImpact
    └─ Findings table: vm.findings
```

### 2.4 Subscription Count Data Flow

This is the most complex SSOT chain — subscriptions appear in 4 locations:

```
1. INVENTORY (how many subscriptions exist)
   SSOT: cloud_subscriptions table
   Backend: _collect_risk_summary() → COUNT(*) FROM cloud_subscriptions WHERE cloud_connection_id = conn_id
   Envelope: data.riskSummary.exposure.subscriptions
   Frontend: vm.monitored.subscriptions

2. EXPOSURE (how many subscriptions have identity role assignments)
   SSOT: role_assignments.scope parsed for /subscriptions/{id}
   Backend: _collect_risk_summary() → COUNT(DISTINCT SPLIT_PART(scope, '/', 3))
   Envelope: data.riskSummary.exposure.active_subscriptions
   Frontend: vm.monitored.active_subscriptions

3. PERSISTED (risk_summary table snapshot from last engine run)
   Source: RiskSummaryEngine._compute_remaining_metrics()
   Stored in: risk_summary.subscriptions column
   Used by: risk_summary row (historical comparison only)
   NOT used by CISO envelope — envelope uses live query (see #1)

4. DISCOVERY_RUNS (per-run subscription context)
   Source: discovery_runs.subscription_id / subscription_name
   Used by: run-level context (which subscription was scanned)
   NOT used for count — this is a scan identifier, not inventory
```

### 2.5 Last Updated Timestamp Flow

```
Backend cascade (in _build_ciso_envelope):
  1. risk_summary.computed_at (via _build_risk_summary_data → data.riskSummary.computed_at)
  2. discovery_runs.completed_at (fallback SQL query)
  3. None

Envelope field: lastUpdated (string ISO timestamp or null)

Frontend cascade (in mapSummaryToViewModel):
  1. response.lastUpdated (envelope)
  2. riskSummary.computed_at (data section)
  3. null → vm.last_updated stays "Never"

Guard: INVALID_TIMESTAMPS = ['', 'None', 'null', 'undefined']
  Rejects Python str(None) = "None" and empty strings
```

---

## 3. SSOT Definitions

| Entity | SSOT Source | Table/Column | Used By |
|--------|-----------|--------------|---------|
| **Subscription inventory** | `cloud_subscriptions` | `COUNT(*) WHERE deleted = false` | CISO envelope, ConfidencePanel, header strip |
| **Subscription exposure** | `role_assignments.scope` | `COUNT(DISTINCT subscription_id)` via SPLIT_PART | RiskScorePanel, header strip |
| **Identity count** | `identities` table | `COUNT(*) WHERE discovery_run_id = ANY(run_ids)` | All dashboard cards |
| **Identity risk level** | `identities.risk_level` | Per-row VARCHAR | risk_level_distribution, snapshot.risk_distribution |
| **AGIRS score** | `RiskSummaryEngine` | `risk_summary.agirs_score` | ScoreRing, posture badge, tier label |
| **AGIRS formula** | `AGIRSEngine` | `0.40*HIRI + 0.40*NHIRI + 0.20*GEI` | Single computation path |
| **AGIRS tier** | `_agirs_status()` | Threshold mapping (92/80/65/45) | Status label (resilient/controlled/elevated/high/critical) |
| **Risk counts** | `RiskSummaryEngine Phase 1` | `risk_summary.{ghost_accounts, orphaned_spns, ...}` | Top risk drivers, risk cards |
| **Blast radius** | `AGIRSEngine._get_top_dangerous()` | `identities.blast_radius_score` | BlastRadiusSection, dangerous_identities |
| **Last scan time** | `risk_summary.computed_at` → `discovery_runs.completed_at` | Cascade with fallback | Header strip, ConfidencePanel |
| **Coverage %** | `_count_usable_sources()` | `usable / 6 * 100` | ConfidencePanel, envelope |
| **Data confidence** | `_build_ciso_envelope()` | Derived from coverage (≥85 high, ≥50 medium, else low) | ConfidencePanel |
| **Drift data** | `drift_reports` table | `db.get_latest_drift_report(connection_id)` | ActivityDriftSection |
| **Anomaly data** | `anomalies` table | `db.get_anomaly_stats(run_ids)` | ActiveThreatsSection |
| **SPN stats** | Live SQL on `identities` | Filtered by SPN_CATEGORIES | SPNExposure section |

---

## 4. API Contracts

### 4.1 Response Envelope: `GET /api/ciso/summary`

```json
{
  "status": "READY | PARTIAL | DISCOVERY_REQUIRED | ERROR",
  "ready": true,
  "coverage": 83,
  "confidence": "high | medium | low",
  "lastUpdated": "2026-04-08T12:30:00+00:00",
  "generatedAt": "2026-04-08T12:30:05Z",
  "data": {
    "riskSummary": { ... },
    "trends": { "available": true, "runs": [...], "postureScores": [...], "direction": "improving" },
    "anomalies": { "available": true, "unresolved": 3, "bySeverity": {}, "topAnomalies": [] },
    "remediation": { "available": true, "open": 5, "completed": 12, "total": 17, "completionPct": 70 },
    "drift": { "available": true, "totalChanges": 4, "permissionChanges": 2, "roleChanges": 1, "credentialChanges": 1 },
    "spn": { "available": true, "totalCustom": 24, "critical": 3, "expiredCreds": 2, "orphanedPrivileged": 1 }
  },
  "gaps": ["ANOMALY_DISABLED"],
  "primaryGap": "ANOMALY_DISABLED",
  "usableSources": 5,
  "totalSources": 6
}
```

### 4.2 `data.riskSummary` Shape

```json
{
  "agirs": {
    "score": 72.5, "tier": "C", "status": "elevated",
    "grade": "C", "delta": -2.3, "pillars": {}
  },
  "risk_counts": {
    "ghost_accounts": 5, "orphaned_spns": 8, "over_privileged": 12,
    "dormant_privileged": 3, "high_blast_radius": 2, "external_exposure": 4
  },
  "risk_level_distribution": { "critical": 3, "high": 12, "medium": 45, "low": 180 },
  "identity_counts": {
    "total": 240, "customer": 215, "microsoft": 25,
    "human": 180, "nhi": 60
  },
  "exposure": {
    "total_resources": 350, "storage_accounts": 12, "key_vaults": 5,
    "subscriptions": 4, "active_subscriptions": 3, "privileged_roles": 15
  },
  "attack_paths": {
    "total": 5, "confirmed": 5, "graph_findings": 5,
    "severity": "medium"
  },
  "blast_radius": {
    "severity": "high",
    "top_identity_name": "svc-deploy-prod",
    "top_identity_id": 42,
    "description": ""
  },
  "dangerous_identities": [ ... ],
  "hiri": { "score": 68.5, "human_count": 180, ... },
  "nhiri": { "score": 74.2, "nhi_count": 60, ... },
  "gei": { "score": 80.1, ... },
  "previous": { "agirs": 74.8, "hiri": 70.0, "nhiri": 76.0, "gei": 80.0 },
  "attack_surface": { "total": 215, "privileged": 0, "machine": 60, "external": 4 },
  "top_risks": [
    { "id": "over_privileged", "label": "Over-Privileged", "count": 12, "severity": "high" },
    ...
  ],
  "computed_at": "2026-04-08T12:30:00+00:00",
  "source": "ciso_summary",
  "data_origin": "tenant_scan"
}
```

### 4.3 Frontend ViewModel Key Fields

```typescript
interface CISOViewModel {
  // Status & posture
  status: 'low' | 'moderate' | 'high' | 'critical' | 'no_data';
  total_identities: number;

  // Subscription counts
  monitored: {
    identities: number;
    subscriptions: number | null;        // ← from exposure.subscriptions
    active_subscriptions: number;        // ← from exposure.active_subscriptions
  };

  // AGIRS
  agirs_display: {
    score: number | null;
    tier: string | null;
    nav: string;
    identities_at_risk: number;
  };

  // Metadata
  last_updated: string;                  // "2h ago" | "Never"
  data_confidence: 'high' | 'medium' | 'low';
  coverage_pct: number;                  // from envelope.coverage

  // Risk drivers
  top_risk_drivers: Array<{ title, count, pct, severity, narrative, nav }>;
  risk_exposure: { count, pct, level, nav };
  blast_radius: { level, identity_name, identity_id, summary, consequences };

  // Extended sections
  trend_history: TrendHistory;
  anomaly_summary: AnomalySummary;
  remediation_progress: RemediationProgress;
  drift_summary: DriftSummary;
  spn_exposure: SPNExposure;
}
```

---

## 5. Known Issues & Inconsistencies

### 5.1 Dual Subscription Computation (REDUNDANT, NOT CONTRADICTING)

**Locations that compute subscription count:**
1. `_collect_risk_summary()` in handlers.py — **live SQL** against `cloud_subscriptions` (SSOT)
2. `RiskSummaryEngine._compute_remaining_metrics()` — **live SQL** against `cloud_subscriptions` (persisted to `risk_summary.subscriptions`)

**Risk**: Both query the same SSOT table with the same logic. The CISO envelope uses #1 (live). The `risk_summary.subscriptions` column (from #2) is NOT used by the envelope. However, if someone reads `risk_summary.subscriptions` directly, they get a stale snapshot that could differ from the live count.

**Severity**: Low. No current consumer reads the stale value.

### 5.2 `attack_surface.privileged` Always 0

In `_build_risk_summary_data()`:
```python
"attack_surface": {
    "total": customer_ids, "privileged": 0,  # ← hardcoded
    "machine": nhi_count, "external": ext_exposure,
}
```
Never computed. Frontend doesn't currently render this field, so no visible impact.

### 5.3 `agirs.pillars` Always Empty

```python
"agirs": {
    ...
    "pillars": {},  # ← never populated
}
```
The AGIRS pillar breakdown (effective_privilege, ownership_governance, etc.) is computed in `AGIRSEngine` but not propagated to the envelope. Frontend `AGIRSBreakdownPanel` uses a separate endpoint or derives from HIRI/NHIRI/GEI breakdowns.

### 5.4 `blast_radius.description` Always Empty String

```python
"blast_radius": {
    ...
    "description": "",  # ← never populated
}
```
Frontend `BlastRadiusSection` generates its own narrative from the dangerous identity data.

### 5.5 `computed_at` Dual Timestamp

- `RiskSummaryEngine.compute()` sets `summary['computed_at'] = datetime.now(UTC).isoformat()` — Python app server time
- `persist()` does `computed_at = NOW()` — PostgreSQL server time

If the clocks are slightly different, the persisted value differs from the in-memory value. The in-memory value is used when `compute()` is called fresh (no persisted row). The persisted value is used on subsequent reads.

**Severity**: Low. Typically <1 second drift. No functional impact.

### 5.6 `_collect_trends()` SQL Computes posture_score Differently Than Engine

Trends collector computes posture_score as:
```sql
(total_identities - critical - high - medium) / total_identities * 100
```
This is "percentage of low-risk identities" — NOT the AGIRS score.

The `risk_summary.agirs_score` is the real posture score. These are different metrics with the same name `posture_score` in the trends output.

**Severity**: Medium. The trend chart shows a different metric than the ScoreRing. Both are valid but measure different things.

### 5.7 `_agirs_status()` vs Frontend Status Mapping

Backend `_agirs_status()` returns: `resilient | controlled | elevated | high | critical | no_data`

Frontend `buildCISOViewModel()` maps AGIRS score to `vm.status` using different thresholds:
- `low` (≥80), `moderate` (≥60), `high` (≥40), `critical` (<40)

The backend `agirs.status` field and frontend `vm.status` field use **different threshold scales** and **different label names**. Both are valid but they're not the same metric.

**Severity**: Medium. If both are displayed, users see contradictory labels.

### 5.8 `identities` Table Has No Direct Connection Scoping

The `identities` table lacks `cloud_connection_id`. All isolation is transitive via `discovery_run_id`. This means any query on identities MUST first resolve run_ids.

**Risk**: If a code path queries identities without going through `_scoped_run_ids()`, it could return cross-connection data. The enforced isolation system (`_require_isolation_context`, `_scoped_run_ids`) mitigates this, but only for paths that use it.

**Severity**: Architecture risk. All CISO paths are protected. Other endpoints (e.g., `/api/identities`) use `_latest_run_ids()` directly — which still scopes by org+connection but without the cross-org guard of `_scoped_run_ids()`.

---

## 6. Recommended Fixes

### 6.1 Unify posture_score in Trends

Replace the ad-hoc posture_score formula in `_collect_trends()` with `risk_summary.agirs_score` for each run:

```sql
SELECT dr.id, dr.completed_at, rs.agirs_score as posture_score, ...
FROM discovery_runs dr
LEFT JOIN risk_summary rs ON rs.discovery_run_id = dr.id
WHERE ...
```

This ensures the trend chart tracks the same metric as the ScoreRing.

### 6.2 Populate `agirs.pillars` in Envelope

Pass HIRI/NHIRI/GEI breakdowns through to `agirs.pillars`:
```python
"pillars": {
    "hiri": hiri_bd,
    "nhiri": nhiri_bd,
    "gei": gei_bd,
}
```

### 6.3 Compute `attack_surface.privileged`

```python
"privileged": risk_latest.get('over_privileged', 0) + risk_latest.get('dormant_privileged', 0),
```

### 6.4 Standardize Status Labels

Either:
- A) Use backend `agirs.status` everywhere (resilient/controlled/elevated/high/critical)
- B) Use frontend-mapped status everywhere (low/moderate/high/critical)

Don't mix both. The frontend `vm.status` drives all UI color/label decisions, so option B is simpler.

### 6.5 Add `_scoped_run_ids()` to All Identity Endpoints

Currently, only the CISO path uses `_scoped_run_ids()` (with cross-org validation). Other endpoints like `/api/identities`, `/api/risks`, `/api/stats` use `_latest_run_ids()` directly. These should also go through `_scoped_run_ids()` for consistent isolation enforcement.

---

## 7. Guardrails for Future Development

### 7.1 Isolation Rules

1. **NEVER query `identities` without run_ids**. Always resolve run_ids first via `_scoped_run_ids()` or `_latest_run_ids()`.
2. **NEVER use `identities.tenant_id`** — the column doesn't exist. Scope via `discovery_run_id`.
3. **NEVER query `cloud_subscriptions` without `organization_id`** — even when `cloud_connection_id` is present. Defense-in-depth.
4. **NEVER relax `_resolve_connection_id()`** — the hard-fail is intentional. If it raises, fix the caller, don't remove the guard.
5. **NEVER bypass `_require_isolation_context()`** — it exists to prevent silent data leaks.

### 7.2 SSOT Rules

1. **Subscription inventory** → Always query `cloud_subscriptions`. Never derive from `risk_summary.subscriptions` (stale snapshot).
2. **Last scan time** → Always use the cascade: `computed_at` → `discovery_runs.completed_at`. Never hardcode.
3. **AGIRS score** → Single source: `RiskSummaryEngine.compute()`. Never recompute in collectors or builders.
4. **Risk counts** → Single source: `risk_summary` table (persisted by engine). Never recount in builders.
5. **Identity risk_level** → Single source: `identities.risk_level` column. The `risk_level_distribution` must query this live, not read stale values.

### 7.3 Frontend Rules

1. **CISOViewModel is the ONLY data contract** between API response and UI components. Components MUST NOT read raw API response fields.
2. **`mapSummaryToViewModel()` is the ONLY mapping function**. Never create alternate mapping paths.
3. **Status gating**: Frontend MUST gate on `usableSources > 0` before rendering data. Never render the dashboard with an empty VM in READY/PARTIAL state.
4. **Timestamp validation**: Always check against `INVALID_TIMESTAMPS` set. Python's `str(None)` returns `"None"` — a truthy string that is NOT a valid timestamp.
5. **Never derive risk in frontend**. All risk scores, levels, and counts come from the backend VM. Frontend only transforms for display.

### 7.4 Cache Rules

1. **CISO cache TTL is 30 seconds**. Don't increase without load testing.
2. **Invalidate on mutations**: Any endpoint that changes identity state (remediation, anomaly resolution) must call `_ciso_cache_invalidate(org_id)`.
3. **Cache key is `(org_id, conn_id)`**. If a user switches connections, they get a fresh cache entry.

### 7.5 Adding New Data Sources

To add a 7th data source to the CISO pipeline:

1. Add collector: `_collect_new_source(db, org_id, conn_id, run_ids)` — follow existing pattern
2. Add builder: `_build_new_source_data(sources)` — return `{'available': False}` on failure
3. Add to `_ciso_summary_inner()`: `sources['new'] = _safe_collect(...)` + gap tracking
4. Add to `_count_usable_sources()`: update `total = 7` and add usability check
5. Add to envelope: `data['newSource'] = new_data`
6. Add to `CISOViewModel` interface + `buildEmptyCISOViewModel()` + `mapSummaryToViewModel()`
7. Add to `_ciso_empty_envelope()` + `_ciso_system_error_envelope()` for consistent shape
8. Create component: read from `vm.new_field`, never from raw response

### 7.6 Debugging Checklist

When the CISO dashboard shows wrong data:

1. **Check backend logs**: Search for `CISO ISOLATION CONTEXT`, `SCOPED_RUN_IDS`, `CISO SUBSCRIPTIONS`
2. **Check envelope**: `curl /api/ciso/summary` → verify `status`, `usableSources`, `lastUpdated`, `data.riskSummary.exposure.subscriptions`
3. **Check frontend console**: `CISO SUMMARY RESPONSE`, `CISO subscriptions mapping`, `CISO lastUpdated resolution`
4. **Check isolation chain**: `_resolve_connection_id` log → `conn_id` → `_scoped_run_ids` log → `run_ids`
5. **Check cache**: If data is stale, wait 30s or trigger `_ciso_cache_invalidate()`

---

## Appendix A: Isolation Functions Reference

| Function | File | Line | Purpose |
|----------|------|------|---------|
| `_resolve_connection_id()` | handlers.py | 371 | Resolve conn_id with priority fallback chain |
| `_require_isolation_context()` | handlers.py | 438 | Validate org_id + conn_id are present and valid |
| `_scoped_run_ids()` | handlers.py | 466 | Resolve run_ids with cross-org validation |
| `_latest_run_ids()` | handlers.py | 615 | Core run_id query (one per active connection) |
| `_connection_id()` | handlers.py | 354 | Read conn_id from query param or header |
| `_org_id()` | handlers.py | ~340 | Read org_id from JWT (g.current_user) |
| `IsolationError` | handlers.py | 433 | Exception for isolation violations |
| `_ciso_cache_get/set/invalidate()` | handlers.py | 32890 | Thread-safe in-memory cache |
| `_safe_collect()` | handlers.py | ~33400 | Exception-safe wrapper for collectors |

## Appendix B: CISO Status State Machine

```
                    ┌──────────────────────┐
                    │     NOT_CONNECTED     │  (frontend-only: no connections array)
                    └──────────┬───────────┘
                               │ connections.length > 0
                    ┌──────────▼───────────┐
                    │       LOADING        │  (frontend-only: fetch in progress)
                    └──────────┬───────────┘
                               │ response received
              ┌────────────────┼────────────────┐
              │                │                 │
    ┌─────────▼────────┐ ┌────▼──────────┐ ┌───▼────┐
    │ DISCOVERY_REQUIRED│ │ PARTIAL/READY │ │ ERROR  │
    │ (no runs or       │ │ (usable > 0)  │ │ (crash)│
    │  usable === 0)    │ └────┬──────────┘ └────────┘
    └───────────────────┘      │
                          ┌────▼──────┐
                          │  PARTIAL  │  coverage < 100%: yellow banner
                          ├───────────┤
                          │   READY   │  coverage = 100%: no banner
                          └───────────┘
```

## Appendix C: File Index

| File | Role | Lines |
|------|------|-------|
| `backend/app/api/handlers.py` | API routes + CISO pipeline | ~33,700 |
| `backend/app/database.py` | DDL + data access layer | ~28,000 |
| `backend/app/engines/risk/risk_summary_engine.py` | RiskSummaryEngine (4-phase compute) | ~400 |
| `backend/app/engines/risk/agirs_engine.py` | AGIRSEngine (HIRI+NHIRI+GEI) | ~850 |
| `frontend/src/utils/cisoViewModel.ts` | CISOViewModel + mapSummaryToViewModel | ~1,250 |
| `frontend/src/pages/CISODashboard.tsx` | CISO page + useCISOSummary hook | ~400 |
| `frontend/src/components/ciso/ExecutiveSummaryHero.tsx` | Hero panels (Narrative + Score + Confidence) | 224 |
| `frontend/src/components/ciso/BusinessImpactSection.tsx` | Business impact cards | ~80 |
| `frontend/src/components/ciso/ActiveThreatsSection.tsx` | Anomaly + findings widgets | ~80 |
| `frontend/src/components/ciso/BlastRadiusSection.tsx` | Blast radius + attack paths | ~170 |
| `frontend/src/components/ciso/ActivityDriftSection.tsx` | Drift detection widget | ~60 |
| `frontend/src/components/ciso/RemediationImpactSection.tsx` | Priority actions widget | ~80 |
| `frontend/src/components/ciso/ImmediateRisksSection.tsx` | Top risk drivers widget | ~40 |
