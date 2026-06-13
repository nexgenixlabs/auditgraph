# Section 9 -- API Reference

## Overview

AuditGraph exposes a REST API at `https://api.auditgraph.ai/api/`. All endpoints require authentication unless marked as public. Responses are JSON with appropriate HTTP status codes.

### Base URLs

| Environment | Base URL |
|-------------|----------|
| Production | `https://api.auditgraph.ai/api` |
| Development | `https://dev.api.auditgraph.ai/api` |
| Local | `http://localhost:5001/api` |

### Versioning

| Path | Status |
|------|--------|
| `/api/` | Current (v0). All production endpoints. |
| `/api/v1/` | Versioned mirror. Identical to `/api/` but explicitly versioned for forward compatibility. |

---

## Authentication

All authenticated requests require a `Bearer` token in the `Authorization` header:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

Alternatively, API keys can be used via:

```http
X-API-Key: ag_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p
```

### Login

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin@company.com",
  "password": "MyStr0ng!Pass99"
}
```

**Response (200):**

```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiIsInVzZXJuYW1lIjoiYWRtaW5AY29tcGFueS5jb20iLCJyb2xlIjoiYWRtaW4iLCJvcmdfaWQiOjcsIm9yZ19uYW1lIjoiQWNtZSBDb3JwIiwiaWF0IjoxNzEwNjAwMDAwLCJleHAiOjE3MTA2MDM2MDB9.signature",
  "refresh_token": "rt_abc123...",
  "user": {
    "id": 42,
    "username": "admin@company.com",
    "role": "admin",
    "display_name": "Jane Admin",
    "org_id": 7,
    "org_name": "Acme Corp"
  }
}
```

**Error (401):**

```json
{
  "error": "Invalid credentials"
}
```

### Refresh Token

```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refresh_token": "rt_abc123..."
}
```

**Response (200):**

```json
{
  "token": "eyJ...",
  "refresh_token": "rt_new..."
}
```

### Current User

```http
GET /api/auth/me
Authorization: Bearer eyJ...
```

**Response (200):**

```json
{
  "id": 42,
  "username": "admin@company.com",
  "role": "admin",
  "display_name": "Jane Admin",
  "org_id": 7,
  "org_name": "Acme Corp",
  "permissions": {
    "canManageUsers": true,
    "canManageConnections": true,
    "canExecuteRemediation": true
  }
}
```

---

## Connector Management

### List Connectors

```http
GET /api/client/connections
Authorization: Bearer eyJ...
```

**Response (200):**

```json
[
  {
    "id": 1,
    "label": "Production Azure",
    "cloud": "azure",
    "status": "connected",
    "azure_directory_id": "abc-123-def",
    "last_discovery_at": "2026-03-16T00:00:00Z",
    "discovery_enabled": true,
    "discovery_interval_minutes": 360,
    "created_at": "2026-01-15T10:00:00Z"
  },
  {
    "id": 2,
    "label": "AWS Production",
    "cloud": "aws",
    "status": "connected",
    "last_discovery_at": "2026-03-16T01:00:00Z",
    "created_at": "2026-02-01T10:00:00Z"
  }
]
```

### Create Connector

```http
POST /api/client/connections
Authorization: Bearer eyJ...
Idempotency-Key: conn_create_abc123
Content-Type: application/json

{
  "label": "Production Azure",
  "cloud": "azure",
  "azure_directory_id": "abc-123-def-456",
  "client_id": "app-id-here",
  "client_secret": "secret-value-here"
}
```

**Response (201):**

```json
{
  "id": 3,
  "label": "Production Azure",
  "cloud": "azure",
  "status": "pending",
  "azure_directory_id": "abc-123-def-456",
  "created_at": "2026-03-16T14:00:00Z"
}
```

### Test Connection

```http
POST /api/client/connections/test
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "cloud": "azure",
  "azure_directory_id": "abc-123-def-456",
  "client_id": "app-id-here",
  "client_secret": "secret-value-here"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "Connection test successful",
  "details": {
    "tenant_name": "Acme Corp",
    "subscription_count": 12
  }
}
```

### Rotate Credentials

```http
POST /api/connectors/1/rotate-credentials
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "client_secret": "new-secret-value"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "Credentials rotated successfully",
  "connection_id": 1,
  "rotated_at": "2026-03-16T14:30:00Z"
}
```

---

## Discovery Runs

### Trigger Discovery

```http
POST /api/runs/trigger
Authorization: Bearer eyJ...
Idempotency-Key: run_trigger_abc123
Content-Type: application/json

{
  "connection_id": 1,
  "scan_mode": "deep"
}
```

**Response (202):**

```json
{
  "message": "Discovery run triggered",
  "run_id": 108,
  "connection_id": 1,
  "scan_mode": "deep"
}
```

### List Discovery Runs

```http
GET /api/runs?limit=10&offset=0
Authorization: Bearer eyJ...
```

**Response (200):**

```json
{
  "runs": [
    {
      "id": 108,
      "status": "completed",
      "started_at": "2026-03-16T00:00:00Z",
      "completed_at": "2026-03-16T00:08:45Z",
      "total_identities": 248,
      "critical_count": 12,
      "high_count": 34,
      "medium_count": 89,
      "low_count": 113,
      "cloud_connection_id": 1
    }
  ],
  "total": 108
}
```

### Scheduler Status

```http
GET /api/scheduler
Authorization: Bearer eyJ...
```

**Response (200):**

```json
{
  "running": true,
  "next_run": "2026-03-16T12:00:00Z",
  "last_run": "2026-03-16T00:00:00Z",
  "interval_hours": 12
}
```

---

## Identity Queries

### List Identities

```http
GET /api/identities?limit=20&offset=0&risk_level=critical&cloud=azure
Authorization: Bearer eyJ...
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | integer | Max results (default 50, max 500) |
| `offset` | integer | Pagination offset |
| `cloud` | string | Filter by cloud provider (`azure`, `aws`, `gcp`) |
| `risk_level` | string | Filter by risk level (`critical`, `high`, `medium`, `low`) |
| `identity_category` | string | Filter by category (`human_user`, `service_principal`, etc.) |
| `search` | string | Search display name or identity ID |
| `connection_id` | integer | Filter by connector |

**Response (200):**

```json
{
  "identities": [
    {
      "id": 1234,
      "identity_id": "abc-def-123",
      "display_name": "prod-automation-sp",
      "identity_category": "service_principal",
      "cloud": "azure",
      "risk_level": "critical",
      "risk_score": 85,
      "tier": "T0",
      "activity_status": "stale",
      "owner_count": 0,
      "credential_count": 2,
      "blast_radius_score": 90.0,
      "additional_subscription_count": 1
    }
  ],
  "total": 12,
  "limit": 20,
  "offset": 0
}
```

### Identity Detail

```http
GET /api/identities/abc-def-123
Authorization: Bearer eyJ...
```

**Response (200):**

```json
{
  "id": 1234,
  "identity_id": "abc-def-123",
  "display_name": "prod-automation-sp",
  "identity_category": "service_principal",
  "cloud": "azure",
  "risk_level": "critical",
  "risk_score": 85,
  "tier": "T0",
  "activity_status": "stale",
  "last_sign_in": "2025-11-15T10:00:00Z",
  "created_date": "2024-06-01T00:00:00Z",
  "owner_count": 0,
  "credential_count": 2,
  "roles": [
    {
      "role_name": "Global Administrator",
      "scope": "directory",
      "scope_type": "entra",
      "source": "entra"
    },
    {
      "role_name": "Owner",
      "scope": "/subscriptions/prod-sub-id",
      "scope_type": "subscription",
      "source": "rbac"
    }
  ],
  "credentials": [
    {
      "type": "client_secret",
      "expiration": "2026-09-15T00:00:00Z",
      "status": "warning"
    }
  ],
  "owners": [],
  "risk_factors": [
    "T0 Privilege (Global Administrator)",
    "Stale (120 days no activity)",
    "No owner assigned",
    "Credential expiring within 30 days"
  ]
}
```

### Advanced Query

```http
POST /api/identities/query
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "groups": [
    {
      "conditions": [
        { "field": "risk_level", "operator": "equals", "value": "critical" },
        { "field": "activity_status", "operator": "in", "value": ["stale", "never_used"] }
      ]
    }
  ],
  "limit": 50,
  "offset": 0,
  "sort_by": "risk_score",
  "sort_order": "desc"
}
```

---

## Risk Reports

### Risk Summary

```http
GET /api/risk/summary
Authorization: Bearer eyJ...
```

**Response (200):**

```json
{
  "agirs_score": 72.08,
  "agirs_tier": "C",
  "hiri_score": 74.2,
  "nhiri_score": 68.5,
  "gei_score": 75.0,
  "total_identities": 248,
  "critical_count": 12,
  "high_count": 34,
  "ghost_accounts": 44,
  "orphaned_spns": 16,
  "over_privileged": 73,
  "dormant_privileged": 5,
  "high_blast_radius": 1,
  "computed_at": "2026-03-16T00:08:45Z"
}
```

### Full Risk Summary

```http
GET /api/risk/summary/full
Authorization: Bearer eyJ...
```

**Response (200):**

```json
{
  "agirs": {
    "score": 72.08,
    "tier": "C",
    "status": "elevated"
  },
  "hiri": {
    "score": 74.2,
    "human_count": 116,
    "h1_ghost": 44,
    "h2_dormant_priv": 5,
    "h3_over_priv": 73,
    "h4_ext_guest": 0,
    "h5_zombie": 0
  },
  "nhiri": {
    "score": 68.5,
    "nhi_count": 24,
    "phantom_breakdown": {
      "orphaned": 16,
      "dormant": 2,
      "zombie_nhi": 0,
      "expired_creds": 0,
      "ownerless_apps": 0
    }
  },
  "gei": {
    "score": 75.0,
    "components": [
      { "name": "Ownership Coverage", "score": 65, "configured": true },
      { "name": "PIM Adoption", "score": 72, "configured": true },
      { "name": "Access Reviews", "score": 75, "configured": true },
      { "name": "Monitoring (P2)", "score": 88, "configured": true }
    ]
  },
  "identity_counts": {
    "total": 248,
    "human": 116,
    "nhi": 24,
    "customer": 140,
    "microsoft": 108
  },
  "dangerous_identities": [
    {
      "id": 1234,
      "display_name": "prod-automation-sp",
      "identity_category": "service_principal",
      "blast_radius_score": 90.0,
      "risk_score": 85,
      "tier": "T0",
      "key_risk_factors": ["T0 Privilege", "Stale", "No owner"]
    }
  ],
  "computed_at": "2026-03-16T00:08:45Z"
}
```

---

## Data Trust Zones (AG-193)

### List Zones

```http
GET /api/data-trust-zones
```

Returns active zones for the calling tenant. Revoked zones (`revoked_at IS NOT NULL`) are excluded by default.

**Response (200):**

```json
{
  "zones": [
    {
      "id": 1,
      "classification": "PHI",
      "scope_type": "resource_group",
      "scope_value": "carehub-centus-prd-rg",
      "asserted_by": "admin@example.com",
      "asserted_at": "2026-06-12T18:20:00Z",
      "revoked_at": null,
      "notes": null
    }
  ]
}
```

### Create Zone

```http
POST /api/data-trust-zones
Content-Type: application/json

{
  "classification": "PHI",
  "scope_type": "resource_name_pattern",
  "scope_value": "*claims*",
  "notes": "Claims pipeline storage"
}
```

`scope_type` ∈ `subscription` | `resource_group` | `subscription_pattern` | `resource_group_pattern` | `resource_name_pattern`.

### Update Zone

```http
PATCH /api/data-trust-zones/<id>
```

### Revoke Zone

```http
DELETE /api/data-trust-zones/<id>
```

Soft-delete — sets `revoked_at`. The row stays for audit; re-creating the same scope creates a new row.

### Zone Coverage

```http
GET /api/data-trust-zones/<id>/coverage
```

Per-table count of resources currently classified by this zone.

### Recompute

```http
POST /api/data-trust-zones/recompute
```

Re-runs the classification engine + reach attribution against the current discovery snapshot. Returns updated row counts.

### Audit Log

```http
GET /api/data-trust-zones/audit
```

Every create / edit / revoke event for this org from `activity_log`.

---

## Classified Resources

### List Classified Resources

```http
GET /api/resources/classified
   ?classification=PHI         (optional filter)
   &source=scope_rule          (optional filter)
   &confidence_min=85          (optional filter)
   &limit=500                  (default 500)
```

Unions five resource tables (`azure_storage_accounts`, `azure_key_vaults`, `azure_sql_databases`, `azure_cosmos_databases`, `discovered_resources`) filtered to `data_classification IS NOT NULL`.

**Response (200):**

```json
{
  "resources": [
    {
      "resource_id": "/subscriptions/…/storageAccounts/…",
      "name": "process-claims-outbound",
      "kind": "Storage",
      "classification": "PHI",
      "source": "scope_rule",
      "confidence": 100,
      "rule_id": 1,
      "asserted_by": "admin@example.com",
      "subscription_id": "…",
      "resource_group": "carehub-centus-prd-rg"
    }
  ],
  "count": 286,
  "by_classification": { "PHI": 286, "PII": 40 },
  "by_source": { "scope_rule": 326 }
}
```

---

## Exposure (AG-193 Sprint B)

### Exposure Derivation (per class)

```http
GET /api/exposure/derivation/<classification>
```

`classification` ∈ `PHI` | `PCI` | `PII` | `SOURCE` | `HR` | `FINANCIAL` | `CONFIDENTIAL`.

Returns zones in force, resource count, by-source and by-confidence-band breakdowns, per-asset rate, dollar value.

### Exposure Lineage

```http
GET /api/exposure/derivation/<classification>/lineage
```

Returns reachable identity count, attack paths terminating, internet-reachable resources — the chain that ends at this classification.

### Exposure By Entity

```http
GET /api/exposure/by-entity
   ?type=identity|ai_model     (default identity)
   &limit=10                   (1..200)
```

Top entities ranked by `reachable_classified_exposure`.

**Response (200):**

```json
{
  "type": "identity",
  "rows": [
    {
      "id": 619409,
      "name": "Diego Jimenez",
      "category": "human_user",
      "exposure": 113760000,
      "phi": 143,
      "pci": 0,
      "pii": 20,
      "computed_at": "2026-06-13T05:23:53Z"
    }
  ],
  "totals": {
    "entities_with_reach": 682,
    "top_exposure": 113760000
  }
}
```

AI model rows additionally carry `attribution_method` ∈ `mi_principal_id` | `name_match` | `rbac_upper_bound` | `unresolved`.

### Reach Summary

```http
GET /api/exposure/reach-summary
```

Single-call payload for the Executive Posture hero decorator.

**Response (200):**

```json
{
  "reachable_identities": 682,
  "reachable_ai_models": 0,
  "attack_paths_total": 115,
  "orphan_nhi_count": 951,
  "top_identity":  { "name": "SVC_Forensit", "exposure": 113760000, "phi": 143 },
  "top_ai_model": null
}
```

### Business Impact (rollup with AI attribution)

```http
GET /api/dashboard/business-impact
```

Includes the additive PHI / PCI / PII contribution to `total_exposure`, the non-additive `ai_attribution` block (and `ai_models.with_reach_count` / `ai_models.attributable_exposure` for back-compat consumers), and a string `source` indicating whether tenant overrides are active.

### Argus Classification Suggestions

```http
GET /api/argus/classification-suggestions
```

Proposes Data Trust Zone candidates from RG name keyword matches in the current discovery. Used by the Argus card on the Data Trust Zones settings page.

### Purview Integration Status

```http
GET /api/purview/status
```

Returns the feature-flag state + Purview classifier cache stats.

---

## Settings — Exposure Defaults

Backed by the generic `/api/settings` endpoint. Four exposure-related keys are accepted:

| Key | Default (USD) |
|---|---:|
| `exposure_phi_per_asset` | 720000 |
| `exposure_pci_per_asset` | 1200000 |
| `exposure_pii_per_asset` | 540000 |
| `exposure_ai_per_asset`  | 0 *(deprecated — AI is reach-derived)* |

Set a value to override; clear (empty string) to revert to the IBM default. Changes take effect on the next dashboard load.

---

## Health

### Health Check

```http
GET /api/health
```

**Response (200):**

```json
{
  "status": "healthy",
  "database": {
    "connected": true,
    "latency_ms": 3.2
  },
  "scheduler": {
    "running": true,
    "next_run": "2026-03-16T12:00:00Z"
  },
  "system": {
    "pid": 1234,
    "uptime_sec": 86400,
    "memory_mb": 256,
    "cpu_percent": 12.5
  },
  "external_apis": {
    "graph_api": { "reachable": true, "latency_ms": 45 },
    "azure_login": { "reachable": true, "latency_ms": 32 }
  },
  "encryption": { "available": true },
  "circuit_breakers": {
    "graph_api": { "state": "closed" },
    "aws_api": { "state": "closed" },
    "llm_api": { "state": "closed" }
  }
}
```

### Kubernetes Probes

| Endpoint | Purpose | Returns |
|----------|---------|---------|
| `GET /health/live` | Liveness probe | Always 200 |
| `GET /health/ready` | Readiness probe | 200 if ready, 503 if not |

---

## Endpoint Categories

| Category | Count | Base Path |
|----------|-------|-----------|
| Authentication | 21 | `/api/auth/` |
| Identity | 35+ | `/api/identities/` |
| Dashboard & Stats | 20+ | `/api/dashboard/`, `/api/stats` |
| Risk & Findings | 15+ | `/api/risk/`, `/api/findings/` |
| Discovery & Runs | 12+ | `/api/runs/`, `/api/discovery/` |
| Connectors | 8 | `/api/client/connections/` |
| Resources | 15+ | `/api/resources/` |
| Remediation | 12+ | `/api/remediation/` |
| Anomalies | 8 | `/api/anomalies/` |
| SOAR | 8 | `/api/soar/` |
| Reports | 9+ | `/api/reports/` |
| Compliance | 5 | `/api/compliance/` |
| Settings | 5+ | `/api/settings/` |
| System | 10+ | `/api/system/` |
| Health | 6 | `/health`, `/api/health` |
| Admin | 20+ | `/api/admin/` |

**Total: 535+ endpoints**

---

## Common Response Codes

| Code | Meaning | When |
|------|---------|------|
| 200 | Success | GET, PUT, PATCH success |
| 201 | Created | POST created a resource |
| 202 | Accepted | Async operation started (e.g., discovery trigger) |
| 400 | Bad Request | Validation error, malformed JSON |
| 401 | Unauthorized | Missing or invalid token |
| 403 | Forbidden | Insufficient role or wrong portal |
| 404 | Not Found | Resource does not exist |
| 413 | Payload Too Large | Request exceeds 5 MB |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Unexpected server error |

---

## References

- [Security Architecture](security-architecture.md) -- Authentication details
- [Connectors](connectors.md) -- Connector setup
- [Risk Scoring Model](risk-scoring.md) -- Score interpretation
- [Operations](operations.md) -- API monitoring
