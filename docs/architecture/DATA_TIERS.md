# AuditGraph — Platform Data Tiers

## Tier Definitions

### Tier 1: Inventory (always available)

Data that exists as soon as a cloud connection is configured, before any
analytics scan has run.

| Table | Description |
|-------|-------------|
| `cloud_connections` | Configured cloud tenants (Azure, AWS, GCP) |
| `cloud_subscriptions` | Discovered subscriptions/accounts/projects |
| `tenants` / `organizations` | Platform tenants |

**API surface:** `GET /api/inventory/summary`

**Characteristics:**
- Populated during connection setup and subscription discovery
- Independent of `discovery_runs` completion
- Safe to query even when no scans have ever run
- Source of truth for "how many subscriptions exist"

### Tier 2: Analytics (requires completed discovery)

Data that is produced by the discovery + risk engines after at least one
successful scan.

| Table | Description |
|-------|-------------|
| `identities` | Discovered identities (scoped via `discovery_run_id`) |
| `risk_summary` | Per-run risk scores and pillar breakdowns |
| `anomalies` | Detected behavioral anomalies |
| `drift_reports` | Configuration drift between runs |
| `role_assignments` | RBAC role data |
| `remediation_actions` | Remediation execution history |

**API surface:** `GET /api/ciso/summary`, `GET /api/risk/summary/full`, etc.

**Characteristics:**
- Empty until first `discovery_runs` row with `status = 'completed'`
- Scoped via `discovery_run_id` → `cloud_connection_id` chain
- CISO dashboard shows `DISCOVERY_REQUIRED` when no Tier 2 data exists

---

## Semantic Naming Rules

| Term | Tier | Meaning |
|------|------|---------|
| `inventory_subscriptions` | 1 | Subscriptions known from cloud connection |
| `monitored_subscriptions` | 1 | Subset with `monitored = true` |
| `active_inventory_subscriptions` | 1 | Subset with `status = 'active'` |
| `subscription_count` | 2 | Per-identity subscription count from analytics |
| `monitored.subscriptions` (VM) | 2 | CISO view-model field from risk summary |

**Rule:** Never use Tier 2 analytics fields to represent Tier 1 inventory
counts. The CISO header subtitle must use `GET /api/inventory/summary`,
not `vm.monitored.subscriptions`.

---

## Isolation Rules

Both tiers enforce tenant isolation:

- **Tier 1:** `cloud_connections.organization_id` + `cloud_subscriptions.organization_id`
- **Tier 2:** `discovery_run_id` → `discovery_runs.cloud_connection_id` → `cloud_connections.organization_id`

All queries MUST include `organization_id` guards (defense-in-depth), even
when filtering by `cloud_connection_id`.

---

## Phase 2 Risk: `identities` missing `cloud_connection_id`

The `identities` table has no direct `cloud_connection_id` column. Tenant
scoping relies on the transitive path through `discovery_run_id`. A future
migration should add:

```sql
ALTER TABLE identities ADD cloud_connection_id INTEGER REFERENCES cloud_connections(id);
```

This would simplify isolation queries and enable direct Tier 1 ↔ Tier 2
cross-referencing without joining through `discovery_runs`.
