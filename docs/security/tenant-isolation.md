# Tenant Isolation — Security Architecture

**AG-94** | CWE-639, CWE-284 | OWASP A01:2021 — Broken Access Control

## Threat Model

AuditGraph is a multi-tenant SaaS platform. Each tenant (organization) must only see their own data. A discovery run from org=Acme appearing in org=Globex's report is the worst possible product failure.

### Attack Vectors

| ID | Vector | Impact | Defense |
|----|--------|--------|---------|
| CWE-639 | Authorization bypass via user-controlled key | Cross-tenant data exposure | `@requires_org_id` enforcement |
| CWE-284 | Missing access control on tenant-scoped queries | Data leak to wrong org | Application-layer org_id filter |
| T1078.004 | Cloud account compromise | Lateral access to other tenants | RLS + app scope + audit |
| T1530 | Data from cloud storage | Unauthorized read of tenant data | org_id in every query |

## Defense in Depth

Three layers, all required:

```
Layer 1: Application Scope (PRIMARY)
  @requires_org_id decorator + explicit WHERE organization_id = %s
  ↓ fail-closed: TenantScopeError → 403/422

Layer 2: PostgreSQL RLS (DEFENSE IN DEPTH)
  Database(organization_id=N) sets session context
  RLS policies auto-filter all 48 tenant tables
  ↓ fail-closed: unset context → zero rows

Layer 3: Audit Trail
  TenantScopeError logged at WARN with SIEM fields
  @cross_org emits structured audit log per call
  ↓ detect and investigate
```

**Why app-layer scope matters even with RLS:**
- Admin connections (`Database()`) bypass RLS intentionally
- RLS bugs or misconfig could silently return all rows
- Application-layer org_id makes intent explicit and testable
- Static analysis can verify org_id presence; RLS context is runtime-only

## The One Approved Pattern

Every Database method that queries a tenant-scoped table:

```python
from app.security.tenant_scope import requires_org_id

@requires_org_id
def get_latest_discovery_run(self, *, org_id: int) -> Optional[Dict]:
    cursor.execute("""
        SELECT * FROM discovery_runs
        WHERE status = 'completed' AND organization_id = %s
        ORDER BY completed_at DESC LIMIT 1
    """, (org_id,))
```

Rules:
1. `org_id` is **keyword-only** (`*, org_id: int`)
2. `org_id` has **no default** value (not `Optional`, not `None`)
3. `org_id` is type `int` (validated at runtime)
4. Every SQL query explicitly includes `WHERE organization_id = %s`
5. Subqueries on tenant tables also include org_id filter

## The One Approved Escape Hatch

For legitimate cross-org operations (superadmin analytics, billing):

```python
from app.security.tenant_scope import cross_org

@cross_org(reason="superadmin platform analytics",
           audit_event="cross_org_analytics_query")
def admin_global_run_count(self) -> int:
    ...
```

Rules:
1. Must have `reason` string (human-readable justification)
2. Must have `audit_event` string (machine-parseable for SIEM)
3. Every call emits a structured audit log entry
4. Code review required for new `@cross_org` methods

## Forbidden Patterns

```python
# FORBIDDEN: Optional org_id allows None to slip through
def bad_method(self, org_id: Optional[int] = None):

# FORBIDDEN: Conditional skip defeats the purpose
if org_id is not None:
    query += " AND organization_id = %s"

# FORBIDDEN: Header-derived scope outside auth middleware
org_id = request.headers.get('X-Organization-Id')  # Only in auth middleware!

# FORBIDDEN: Unscoped MAX(id) on tenant table
"SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'"
# CORRECT:
"SELECT MAX(id) FROM discovery_runs WHERE status = 'completed' AND organization_id = %s"
```

## Schema Rule

Every new tenant-scoped table must:
1. Have an `organization_id` column (NOT NULL)
2. Have RLS policies (see migration_017 pattern)
3. Be added to `RLS_PROTECTED_TABLES` in `integrity.py`
4. Be added to `_BASELINE_TENANT_TABLES` in `tenant_scope.py`
5. Pass the CI schema-drift test

## Code Review Checklist

- [ ] New query on tenant table has `WHERE organization_id = %s`?
- [ ] Method signature includes `*, org_id: int` (keyword-only, no default)?
- [ ] `@requires_org_id` decorator applied?
- [ ] Handler passes `org_id=_org_id()` from authenticated context?
- [ ] Subqueries on tenant tables also scoped?
- [ ] No `Optional[int]` or default `None` for org_id?
- [ ] `scripts/lint_tenant_scope.py` passes?
- [ ] Cross-tenant test added for new method?

## Tenant-Scoped Tables (48)

See `backend/app/api/integrity.py:RLS_PROTECTED_TABLES` for the authoritative list.

## Compliance Mapping

| Standard | Control | Artifact |
|----------|---------|----------|
| CWE-639 | Authorization Bypass | `@requires_org_id` decorator |
| CWE-284 | Improper Access Control | Application-layer org_id filter |
| OWASP A01 | Broken Access Control | tenant_scope.py module |
| NIST AC-3 | Access Enforcement | RLS + app scope |
| NIST AC-4 | Information Flow | org_id in every query |
| NIST AC-6 | Least Privilege | `@cross_org` audit trail |
| NIST AU-2 | Audit Events | TenantScopeError WARN logs |
| CIS 3.3 | Data Access Control | tenant_tables registry |
| CIS 6.8 | Role-Based Access | JWT org_id → query scope |
