# Tenant Isolation Architecture

## Overview

AuditGraph enforces multi-tenant data isolation at three layers:

1. **PostgreSQL RLS (primary)** — Row-Level Security policies on all tenant tables
2. **Application-layer org_id scoping** — `@requires_org_id` decorator + explicit WHERE clauses
3. **Schema constraints** — NOT NULL, FK, consistency triggers

## Database Users

| User | Role | RLS Behavior |
|------|------|-------------|
| `auditgraph_app` | NOBYPASSRLS | Session var `app.current_organization_id` set per-connection; RLS filters all queries |
| `auditgraph_admin` | BYPASSRLS | Used only for DDL, migrations, scheduler system ops |

## RLS Policies

Every tenant table has four strict policies:

```sql
-- SELECT: only rows matching session org
org_strict_sel: organization_id = current_setting('app.current_organization_id', true)::integer

-- INSERT: auto-fill trigger sets organization_id from session if NULL
org_strict_ins: (with auto-fill trigger trg_auto_organization_id)

-- UPDATE: cannot modify rows outside current org
org_strict_upd: organization_id = current_setting('app.current_organization_id', true)::integer

-- DELETE: cannot delete rows outside current org
org_strict_del: organization_id = current_setting('app.current_organization_id', true)::integer
```

NULL session context → `current_setting` returns NULL → `organization_id = NULL` → always false → zero rows visible.

## Identities Table

`identities` is a first-class tenant-scoped table with:
- `organization_id INTEGER NOT NULL` — direct tenant key
- `FOREIGN KEY (organization_id) REFERENCES organizations(id)` — referential integrity
- `idx_identities_org_id`, `idx_identities_org_risk`, `idx_identities_org_run` — performance indexes
- Consistency trigger `trg_identities_org_id_consistency` — ensures `identities.organization_id` matches the `organization_id` on the referenced `discovery_runs` row

AG-129 closed this as of 2026-04-28. The table previously relied on transitive scoping via `discovery_run_id → discovery_runs.organization_id`. This is no longer the case.

## Schema Rules

1. Every new tenant-data table MUST have `organization_id INTEGER NOT NULL` as a direct column
2. Never use transitive scoping (FK to another tenant table) as the sole isolation mechanism
3. Every tenant table MUST be listed in `docs/security/tenant_tables.txt`
4. Every tenant table MUST appear in `TENANT_TABLES` (lint) and `_BASELINE_TENANT_TABLES` (tenant_scope.py)
5. RLS policies MUST be strict (no NULL-context bypass)

## Application Layer

- `Database(organization_id=tid)` — sets session variable, connects as `auditgraph_app`
- `@requires_org_id` decorator — validates org_id is a positive integer, keyword-only, no default
- `TenantScopeError` — raised on missing/invalid org_id (never silent fallback)
- Belt-and-suspenders: explicit `WHERE organization_id = %s` in SQL even though RLS handles it

## Lint Enforcement

`scripts/lint_tenant_scope.py` statically analyzes all `cursor.execute()` calls:
- Detects queries on tenant tables missing `organization_id` filter
- Baseline file: `.sql-lint-baseline.json` (suppresses known RLS-protected sites)
- CI exit code 1 on new violations

## Connection Model

```
HTTP Request → JWT auth → _org_id() → Database(organization_id=tid) → SET app.current_organization_id → RLS active
```

No handler can accidentally bypass RLS because `_db()` always creates a tenant-scoped connection.
