# AuditGraph Database Schema Reference

## Overview

- **49 tables** across `database.py` (7,725 lines) and 16 SQL migration files
- **PostgreSQL 16** with Row-Level Security (RLS)
- Tenant isolation via `set_config('app.current_tenant_id', value, FALSE)`
- RLS on 43 tables (4 explicit policy blocks + 39 via migration DO block in `016_rls_tenant_isolation.sql`)
- 7 seed/migration methods, 25 `_ensure_*` DDL methods
- No connection pooling (fresh `psycopg2` connection per `Database()` instance)
- 7 class-level DDL guard flags: `_risk_factors_col_ensured`, `_users_ensured`, `_tenants_ensured`, `_sa_attestations_ensured`, `_governance_decisions_ensured`, `_copilot_ensured`, `_isa_ensured`
- 2 SQL views: `v_latest_identities`, `v_critical_identities`

---

## Connection Management

| Method | Description |
|--------|-------------|
| `Database.__init__(tenant_id=None)` | Opens fresh connection via `psycopg2.connect()`. Calls `set_tenant_context(tenant_id)` if provided. |
| `Database.connect()` | Reads `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_SSLMODE` from env. |
| `Database.close()` | Closes connection. |
| `Database.set_tenant_context(tenant_id)` | Executes `SELECT set_config('app.current_tenant_id', %s, FALSE)` for RLS. |

No pooling -- each HTTP request creates and destroys a `Database()` instance.

---

## Tables

### 1. discovery_runs

- **Created by**: Migration `001_create_identity_roles.sql`
- **RLS**: Yes (explicit in `016_rls_tenant_isolation.sql`)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `tenant_id` references `tenants(id)` (added by `_ensure_tenants_table()`)

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | BIGSERIAL | PRIMARY KEY |
| subscription_id | TEXT | NOT NULL |
| subscription_name | TEXT | |
| started_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| completed_at | TIMESTAMPTZ | |
| status | TEXT | NOT NULL (running/completed/failed) |
| total_identities | INTEGER | |
| critical_count | INTEGER | |
| high_count | INTEGER | |
| medium_count | INTEGER | |
| low_count | INTEGER | |
| tenant_id | INTEGER | FK tenants(id) (added by `_ensure_tenants_table()`) |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

**Indexes**: `idx_discovery_runs_status(status)`, `idx_discovery_runs_started_at(started_at DESC)`, `idx_discovery_runs_tenant(tenant_id)`

---

### 2. identities

- **Created by**: Migration `001_create_identity_roles.sql`, extended by migrations 002, 006, 007, 008, 010, 011, 016 and `save_identity()` at line 150
- **RLS**: No (scoped via `discovery_run_id` FK to `discovery_runs`). Has `tenant_id` column (added by `016_rls_tenant_isolation.sql`) but identity RLS policy is in the DO block.
- **Unique constraints**: `UNIQUE(discovery_run_id, identity_id)`
- **Foreign keys**: `discovery_run_id` references `discovery_runs(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults | Added By |
|--------|------|----------------------|----------|
| id | BIGSERIAL | PRIMARY KEY | 001 |
| discovery_run_id | BIGINT | FK discovery_runs(id) ON DELETE CASCADE | 001 |
| identity_id | TEXT | NOT NULL | 001 |
| display_name | TEXT | NOT NULL | 001 |
| source | TEXT | NOT NULL DEFAULT 'azure' | 001 |
| identity_type | TEXT | NOT NULL | 001 |
| identity_category | TEXT | NOT NULL DEFAULT 'service_principal' | 001 |
| app_id | TEXT | | 001 |
| object_id | TEXT | | 001 |
| entra_object_type | TEXT | | 001 |
| service_principal_type | TEXT | | 001 |
| publisher_name | TEXT | | 001 |
| app_owner_organization_id | TEXT | | 001 |
| alternative_names | JSONB | | 001 |
| created_datetime | TIMESTAMPTZ | | 001 |
| enabled | BOOLEAN | DEFAULT TRUE | 001 |
| is_microsoft_system | BOOLEAN | DEFAULT FALSE | 001 |
| risk_level | TEXT | | 001 |
| risk_reasons | TEXT[] | | 001 |
| credential_expiration | TIMESTAMPTZ | | 001 |
| credential_status | TEXT | | 001 |
| last_sign_in | TIMESTAMPTZ | | 001 |
| activity_status | TEXT | | 001 |
| tags | JSONB | | 001 |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | 001 |
| credential_count | INTEGER | DEFAULT 0 | 002 |
| next_expiry | TIMESTAMPTZ | | 002 |
| credential_risk | TEXT | | 002 |
| cloud | TEXT | DEFAULT 'azure' | 006 |
| identity_type_normalized | TEXT | | 006 |
| canonical_name | TEXT | | 006 |
| principal_id | TEXT | | 006 |
| tenant_or_org_id | TEXT | | 006 |
| source_normalized | TEXT | | 006 |
| is_federated | BOOLEAN | DEFAULT FALSE | 006 |
| status | TEXT | DEFAULT 'active' | 006 |
| last_seen_auth | TIMESTAMPTZ | | 006 |
| owner_display_name | TEXT | | 007 |
| owner_count | INTEGER | DEFAULT 0 | 007 |
| risk_score | INTEGER | DEFAULT 0 | 008 |
| api_permission_count | INTEGER | DEFAULT 0 | 008 |
| app_role_count | INTEGER | DEFAULT 0 | 008 |
| days_since_last_use | INTEGER | | 008 |
| last_activity_source | TEXT | | 008 |
| pim_eligible_count | INTEGER | DEFAULT 0 | 010 |
| pim_active_count | INTEGER | DEFAULT 0 | 010 |
| has_permanent_assignment | BOOLEAN | DEFAULT FALSE | 010 |
| ca_coverage_status | TEXT | | 011 |
| ca_mfa_enforced | BOOLEAN | | 011 |
| tenant_id | INTEGER | | 016 |
| risk_factors | JSONB | DEFAULT '[]' | `save_identity()` |
| primary_subscription_id | TEXT | | `_ensure_identity_subscription_access_table()` |
| additional_subscription_count | INTEGER | DEFAULT 0 | `_ensure_identity_subscription_access_table()` |

**Indexes**: `idx_identities_run_id`, `idx_identities_risk_level`, `idx_identities_identity_type`, `idx_identities_identity_category`, `idx_identities_microsoft_system`, `idx_identities_source`, `idx_identities_cloud`, `idx_identities_type_normalized`, `idx_identities_principal_id`, `idx_identities_status`, `idx_identities_tenant_org`, `idx_identities_next_expiry`, `idx_identities_credential_risk`, `idx_identities_risk_score`, `idx_identities_api_perm_count`, `idx_identities_app_role_count`, `idx_identities_days_since_use`, `idx_identities_tenant`

---

### 3. role_assignments

- **Created by**: Migration `001_create_identity_roles.sql`, extended by `009_role_usage_intelligence.sql`
- **RLS**: Yes (via DO block in `016_rls_tenant_isolation.sql`)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `identity_db_id` references `identities(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults | Added By |
|--------|------|----------------------|----------|
| id | BIGSERIAL | PRIMARY KEY | 001 |
| identity_db_id | BIGINT | FK identities(id) ON DELETE CASCADE | 001 |
| role_name | TEXT | NOT NULL | 001 |
| scope | TEXT | NOT NULL | 001 |
| scope_type | TEXT | NOT NULL | 001 |
| principal_id | TEXT | NOT NULL | 001 |
| assignment_id | TEXT | | 001 |
| created_on | TIMESTAMPTZ | | 001 |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | 001 |
| scope_exists | BOOLEAN | DEFAULT TRUE | 009 |
| usage_status | TEXT | DEFAULT 'unknown' | 009 |
| days_since_assigned | INTEGER | | 009 |
| redundant_with | TEXT | | 009 |
| role_type | TEXT | DEFAULT 'azure' | 009 |
| risk_level | TEXT | | 009 |
| why_critical | TEXT | | 009 |
| resource_type | TEXT | | 009 |
| resource_name | TEXT | | 009 |
| tenant_id | INTEGER | | 016 |

**Indexes**: `idx_role_assignments_identity_db_id`, `idx_role_assignments_role_name`, `idx_role_assignments_usage_status`, `idx_role_assignments_scope_exists`, `idx_role_assignments_risk_level`, `idx_role_assignments_tenant`

---

### 4. entra_role_assignments

- **Created by**: Migration `001_create_identity_roles.sql`, extended by `009_role_usage_intelligence.sql`
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `identity_db_id` references `identities(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults | Added By |
|--------|------|----------------------|----------|
| id | BIGSERIAL | PRIMARY KEY | 001 |
| identity_db_id | BIGINT | FK identities(id) ON DELETE CASCADE | 001 |
| role_name | TEXT | NOT NULL | 001 |
| role_definition_id | TEXT | | 001 |
| directory_scope | TEXT | | 001 |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | 001 |
| usage_status | TEXT | DEFAULT 'unknown' | 009 |
| assigned_on | TIMESTAMPTZ | | 009 |
| days_since_assigned | INTEGER | | 009 |
| redundant_with | TEXT | | 009 |
| role_type | TEXT | DEFAULT 'entra' | 009 |
| risk_level | TEXT | | 009 |
| why_critical | TEXT | | 009 |
| tenant_id | INTEGER | | 016 |

**Indexes**: `idx_entra_roles_identity_db_id`, `idx_entra_roles_role_name`, `idx_entra_roles_usage_status`, `idx_entra_roles_risk_level`, `idx_entra_role_assignments_tenant`

---

### 5. credentials

- **Created by**: Migration `002_create_credentials.sql`
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(identity_db_id, key_id)`
- **Foreign keys**: `identity_db_id` references `identities(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | BIGSERIAL | PRIMARY KEY |
| identity_db_id | BIGINT | NOT NULL, FK identities(id) ON DELETE CASCADE |
| credential_type | TEXT | NOT NULL (secret/certificate/federated) |
| key_id | TEXT | NOT NULL |
| display_name | TEXT | |
| start_datetime | TIMESTAMPTZ | |
| end_datetime | TIMESTAMPTZ | |
| thumbprint | TEXT | |
| issuer | TEXT | |
| subject | TEXT | |
| discovered_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| tenant_id | INTEGER | (added by 016) |

**Indexes**: `idx_credentials_identity_db_id`, `idx_credentials_end_datetime`, `idx_credentials_type`, `idx_credentials_tenant`

---

### 6. graph_api_permissions

- **Created by**: Migration `003_create_graph_api_permissions.sql`
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(identity_db_id, permission_name)`
- **Foreign keys**: `identity_db_id` references `identities(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | BIGSERIAL | PRIMARY KEY |
| identity_db_id | BIGINT | NOT NULL, FK identities(id) ON DELETE CASCADE |
| permission_name | TEXT | NOT NULL |
| permission_description | TEXT | |
| resource_name | TEXT | DEFAULT 'Microsoft Graph' |
| risk_level | TEXT | |
| discovered_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| tenant_id | INTEGER | (added by 016) |

**Indexes**: `idx_graph_perms_identity_db_id`, `idx_graph_perms_risk_level`, `idx_graph_perms_permission_name`, `idx_graph_api_permissions_tenant`

---

### 7. sp_app_roles

- **Created by**: Migration `004_create_sp_app_roles.sql`
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(identity_db_id, app_role_id, resource_id)`
- **Foreign keys**: `identity_db_id` references `identities(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | BIGSERIAL | PRIMARY KEY |
| identity_db_id | BIGINT | NOT NULL, FK identities(id) ON DELETE CASCADE |
| app_role_id | TEXT | NOT NULL |
| resource_id | TEXT | NOT NULL |
| resource_display_name | TEXT | |
| principal_display_name | TEXT | |
| created_date_time | TIMESTAMPTZ | |
| risk_level | TEXT | |
| discovered_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| tenant_id | INTEGER | (added by 016) |

**Indexes**: `idx_sp_app_roles_identity_db_id`, `idx_sp_app_roles_risk_level`, `idx_sp_app_roles_resource_name`, `idx_sp_app_roles_tenant`

---

### 8. sp_ownership

- **Created by**: Migration `007_create_sp_ownership.sql`
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(identity_db_id, owner_object_id)`
- **Foreign keys**: `identity_db_id` references `identities(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | BIGSERIAL | PRIMARY KEY |
| identity_db_id | BIGINT | NOT NULL, FK identities(id) ON DELETE CASCADE |
| owner_object_id | TEXT | NOT NULL |
| owner_display_name | TEXT | |
| owner_upn | TEXT | |
| owner_type | TEXT | DEFAULT 'user' |
| ownership_type | TEXT | DEFAULT 'application' |
| is_primary_owner | BOOLEAN | DEFAULT FALSE |
| discovered_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| tenant_id | INTEGER | (added by 016) |

**Indexes**: `idx_sp_ownership_identity_db_id`, `idx_sp_ownership_owner_object_id`, `idx_sp_ownership_owner_upn`, `idx_sp_ownership_tenant`

---

### 9. pim_eligible_assignments

- **Created by**: Migration `010_create_pim_tables.sql`
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(identity_db_id, role_definition_id, directory_scope)`
- **Foreign keys**: `identity_db_id` references `identities(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| identity_db_id | INTEGER | NOT NULL, FK identities(id) ON DELETE CASCADE |
| role_name | TEXT | NOT NULL |
| role_definition_id | TEXT | |
| directory_scope | TEXT | DEFAULT '/' |
| assignment_type | TEXT | DEFAULT 'eligible' |
| start_datetime | TIMESTAMPTZ | |
| end_datetime | TIMESTAMPTZ | NULL = permanent eligible |
| member_type | TEXT | (Direct/Group) |
| discovered_at | TIMESTAMPTZ | DEFAULT NOW() |
| tenant_id | INTEGER | (added by 016) |

**Indexes**: `idx_pim_eligible_tenant`

---

### 10. pim_activations

- **Created by**: Migration `010_create_pim_tables.sql`
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `identity_db_id` references `identities(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| identity_db_id | INTEGER | NOT NULL, FK identities(id) ON DELETE CASCADE |
| role_name | TEXT | NOT NULL |
| role_definition_id | TEXT | |
| directory_scope | TEXT | DEFAULT '/' |
| status | TEXT | (Active/Expired/Revoked) |
| activation_start | TIMESTAMPTZ | |
| activation_end | TIMESTAMPTZ | |
| justification | TEXT | |
| ticket_number | TEXT | |
| ticket_system | TEXT | |
| is_approval_required | BOOLEAN | DEFAULT FALSE |
| created_datetime | TIMESTAMPTZ | |
| discovered_at | TIMESTAMPTZ | DEFAULT NOW() |
| tenant_id | INTEGER | (added by 016) |

**Indexes**: `idx_pim_activations_tenant`

---

### 11. ca_policies

- **Created by**: Migration `011_create_ca_tables.sql`
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(discovery_run_id, policy_id)`
- **Foreign keys**: `discovery_run_id` references `discovery_runs(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| discovery_run_id | INTEGER | NOT NULL, FK discovery_runs(id) ON DELETE CASCADE |
| policy_id | TEXT | NOT NULL |
| display_name | TEXT | NOT NULL |
| state | TEXT | NOT NULL (enabled/disabled/enabledForReportingButNotEnforced) |
| include_users | JSONB | DEFAULT '[]' |
| exclude_users | JSONB | DEFAULT '[]' |
| include_applications | JSONB | DEFAULT '[]' |
| client_app_types | JSONB | DEFAULT '[]' |
| grant_controls | JSONB | DEFAULT '{}' |
| session_controls | JSONB | DEFAULT '{}' |
| requires_mfa | BOOLEAN | DEFAULT FALSE |
| targets_all_users | BOOLEAN | DEFAULT FALSE |
| has_exclusions | BOOLEAN | DEFAULT FALSE |
| allows_legacy_auth | BOOLEAN | DEFAULT FALSE |
| modified_datetime | TIMESTAMPTZ | |
| tenant_id | INTEGER | (added by 016) |

**Indexes**: `idx_ca_policies_tenant`

---

### 12. ca_identity_coverage

- **Created by**: Migration `011_create_ca_tables.sql`
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(identity_db_id)`
- **Foreign keys**: `identity_db_id` references `identities(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| identity_db_id | INTEGER | NOT NULL, FK identities(id) ON DELETE CASCADE |
| coverage_status | TEXT | NOT NULL (covered/partial/excluded/no_coverage) |
| mfa_enforced | BOOLEAN | DEFAULT FALSE |
| applicable_policy_count | INTEGER | DEFAULT 0 |
| excluded_from_count | INTEGER | DEFAULT 0 |
| risk_flags | JSONB | DEFAULT '[]' |
| tenant_id | INTEGER | (added by 016) |

**Indexes**: `idx_ca_identity_coverage_tenant`

---

### 13. remediation_playbooks

- **Created by**: `_ensure_remediation_playbooks()` at line 1197
- **RLS**: Yes (via DO block -- `tenant_id` added by `_ensure_compliance_tables()` core loop)
- **Unique constraints**: None beyond PK
- **Foreign keys**: None
- **Seeded**: 20 playbooks (access_control, credential_hygiene, governance categories)

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| risk_pattern | VARCHAR(255) | NOT NULL |
| pattern_type | VARCHAR(20) | DEFAULT 'contains' |
| title | VARCHAR(255) | NOT NULL |
| description | TEXT | |
| steps | JSONB | NOT NULL |
| impact | VARCHAR(10) | DEFAULT 'high' |
| effort | VARCHAR(10) | DEFAULT 'medium' |
| priority_score | INTEGER | DEFAULT 50 |
| compliance_refs | JSONB | |
| category | VARCHAR(50) | |
| created_at | TIMESTAMP | DEFAULT NOW() |

> Note: `tenant_id` column is added via the `_ensure_compliance_tables()` ALTER TABLE loop on core discovery tables.

---

### 14. remediation_actions

- **Created by**: `_ensure_remediation_actions_table()` at line 2034
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(identity_id, playbook_id)`
- **Foreign keys**: None explicit (playbook_id is logical FK)

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| identity_id | TEXT | NOT NULL |
| playbook_id | INTEGER | NOT NULL |
| status | VARCHAR(20) | NOT NULL DEFAULT 'open' |
| notes | TEXT | |
| execution_status | VARCHAR(20) | DEFAULT NULL (Phase 58) |
| execution_log | JSONB | DEFAULT NULL (Phase 58) |
| executed_at | TIMESTAMPTZ | DEFAULT NULL (Phase 58) |
| executed_by | INTEGER | DEFAULT NULL (Phase 58) |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| updated_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

**Indexes**: `idx_remediation_actions_identity`, `idx_remediation_actions_status`, `idx_remediation_actions_tenant`

---

### 15. drift_reports

- **Created by**: Migration `013_create_drift_reports.sql`
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(current_run_id, previous_run_id)`
- **Foreign keys**: `current_run_id` FK `discovery_runs(id) ON DELETE CASCADE`, `previous_run_id` FK `discovery_runs(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| current_run_id | INTEGER | NOT NULL, FK discovery_runs(id) ON DELETE CASCADE |
| previous_run_id | INTEGER | NOT NULL, FK discovery_runs(id) ON DELETE CASCADE |
| new_identities_count | INTEGER | NOT NULL DEFAULT 0 |
| removed_identities_count | INTEGER | NOT NULL DEFAULT 0 |
| permission_changes_count | INTEGER | NOT NULL DEFAULT 0 |
| risk_changes_count | INTEGER | NOT NULL DEFAULT 0 |
| credential_changes_count | INTEGER | NOT NULL DEFAULT 0 |
| total_changes | INTEGER | NOT NULL DEFAULT 0 |
| changes | JSONB | NOT NULL |
| tenant_id | INTEGER | (added by 016) |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

**Indexes**: `idx_drift_reports_current_run`, `idx_drift_reports_created_at(created_at DESC)`, `idx_drift_reports_tenant`

---

### 16. settings

- **Created by**: Migration `014_create_settings.sql`
- **RLS**: Yes (explicit in `016_rls_tenant_isolation.sql`, includes `tenant_id IS NULL` bypass)
- **Unique constraints**: `UNIQUE(tenant_id, key)` (composite, migrated from single-column PK)
- **Foreign keys**: `tenant_id` FK `tenants(id)`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| key | VARCHAR(255) | Part of composite unique (was PK) |
| value | TEXT | |
| tenant_id | INTEGER | FK tenants(id), part of composite unique |
| updated_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

> Note: Original PK was `key` alone; migrated to composite `UNIQUE(tenant_id, key)` by `_ensure_tenants_table()`.

---

### 17. activity_log

- **Created by**: `_ensure_activity_log_table()` at line 1822
- **RLS**: Yes (explicit in `016_rls_tenant_isolation.sql`, includes `tenant_id IS NULL` bypass)
- **Unique constraints**: None beyond PK
- **Foreign keys**: None (append-only audit trail)

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| action_type | VARCHAR(50) | NOT NULL |
| description | TEXT | NOT NULL |
| metadata | JSONB | |
| user_id | INTEGER | (Phase 46) |
| tenant_id | INTEGER | (Phase 46) |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

**Indexes**: `idx_activity_log_created_at(created_at DESC)`, `idx_activity_log_action_type`, `idx_activity_log_tenant_id`, `idx_activity_log_user_id`

---

### 18. users

- **Created by**: `_ensure_users_table()` at line 3054 (guard: `_users_ensured`)
- **RLS**: Yes (explicit in `016_rls_tenant_isolation.sql`, includes `tenant_id IS NULL` bypass)
- **Unique constraints**: `UNIQUE(username)`
- **Foreign keys**: `tenant_id` FK `tenants(id)`, `created_by` is logical (no FK constraint)

| Column | Type | Constraints / Defaults | Added By |
|--------|------|----------------------|----------|
| id | SERIAL | PRIMARY KEY | Base |
| username | VARCHAR(100) | UNIQUE NOT NULL | Base |
| password_hash | VARCHAR(255) | NOT NULL | Base |
| display_name | VARCHAR(255) | NOT NULL | Base |
| role | VARCHAR(20) | NOT NULL DEFAULT 'viewer' | Base |
| enabled | BOOLEAN | DEFAULT true | Base |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Base |
| updated_at | TIMESTAMPTZ | DEFAULT NOW() | Base |
| last_login_at | TIMESTAMPTZ | | Base |
| created_by | INTEGER | | Base |
| tenant_id | INTEGER | FK tenants(id) | Phase 45 |
| is_superadmin | BOOLEAN | DEFAULT false | Phase 45 |
| portal_role | VARCHAR(20) | (superadmin/poweradmin/billing/reader) | Phase 46 |
| auth_provider | VARCHAR(20) | DEFAULT 'local' | Phase 54 |
| external_id | VARCHAR(500) | | Phase 54 |
| force_password_change | BOOLEAN | DEFAULT false | Phase 78 |
| is_root_user | BOOLEAN | DEFAULT false | Phase 84 |
| password_reset_token | TEXT | | Phase 84 |
| password_reset_expires | TIMESTAMPTZ | | Phase 84 |
| failed_login_attempts | INTEGER | DEFAULT 0 | Phase 84 |
| locked_until | TIMESTAMPTZ | | Phase 84 |
| email | VARCHAR(255) | | Phase 77 |
| phone | VARCHAR(50) | | Phase 77 |

**Indexes**: `idx_users_username(username)`, `idx_users_external_id(external_id)`

---

### 19. refresh_tokens

- **Created by**: `_ensure_users_table()` at line 3054
- **RLS**: No
- **Unique constraints**: None beyond PK
- **Foreign keys**: `user_id` FK `users(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| user_id | INTEGER | NOT NULL, FK users(id) ON DELETE CASCADE |
| token_hash | VARCHAR(255) | NOT NULL |
| expires_at | TIMESTAMPTZ | NOT NULL |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| revoked | BOOLEAN | DEFAULT false |

**Indexes**: `idx_refresh_tokens_user(user_id)`, `idx_refresh_tokens_hash(token_hash)`

---

### 20. sso_auth_codes

- **Created by**: `_ensure_users_table()` at line 3054 (Phase 54)
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(code)`
- **Foreign keys**: `user_id` FK `users(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| code | VARCHAR(128) | UNIQUE NOT NULL |
| user_id | INTEGER | NOT NULL, FK users(id) ON DELETE CASCADE |
| tenant_id | INTEGER | |
| used | BOOLEAN | DEFAULT false |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |
| expires_at | TIMESTAMPTZ | NOT NULL |

**Indexes**: `idx_sso_codes_code(code)`

---

### 21. admin_audit_log

- **Created by**: `_ensure_users_table()` at line 3054 (Phase 84)
- **RLS**: No
- **Unique constraints**: None beyond PK
- **Foreign keys**: None (logical refs to users)

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| admin_user_id | INTEGER | |
| action | TEXT | NOT NULL |
| target_user_id | INTEGER | |
| target_tenant_id | INTEGER | |
| details | JSONB | DEFAULT '{}' |
| ip_address | TEXT | |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |

**Indexes**: `idx_admin_audit_action(action)`, `idx_admin_audit_target_user(target_user_id)`

---

### 22. tenants

- **Created by**: `_ensure_tenants_table()` at line 6249 (guard: `_tenants_ensured`)
- **RLS**: No (root scoping table -- never tenant-filtered)
- **Unique constraints**: `UNIQUE(slug)`
- **Foreign keys**: None

| Column | Type | Constraints / Defaults | Added By |
|--------|------|----------------------|----------|
| id | SERIAL | PRIMARY KEY | Base |
| name | VARCHAR(255) | NOT NULL | Base |
| slug | VARCHAR(100) | UNIQUE NOT NULL | Base |
| plan | VARCHAR(20) | NOT NULL DEFAULT 'free' | Base |
| settings | JSONB | NOT NULL DEFAULT '{}' | Base |
| enabled | BOOLEAN | DEFAULT true | Base |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Base |
| updated_at | TIMESTAMPTZ | DEFAULT NOW() | Base |
| license_activated_at | TIMESTAMPTZ | | Phase 77 |
| license_expires_at | TIMESTAMPTZ | | Phase 77 |
| logo_url | TEXT | | Phase 78 |
| subscription_term | INTEGER | NOT NULL DEFAULT 0 | Phase 78 |
| primary_cloud | VARCHAR(20) | | Phase 85 |
| industry | VARCHAR(100) | | Phase 85 |
| compliance_framework | VARCHAR(100) | | Phase 85 |
| status | VARCHAR(20) | NOT NULL DEFAULT 'active' | Phase 85 |

**Indexes**: `idx_tenants_slug(slug)`

---

### 23. compliance_frameworks

- **Created by**: `_ensure_compliance_tables()` at line 3509
- **RLS**: No
- **Unique constraints**: `UNIQUE(key)`
- **Foreign keys**: None
- **Seeded**: 6 frameworks (SOC2, HIPAA, PCI-DSS, NIST, CIS, ISO 27001) via `seed_compliance_frameworks()`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| key | VARCHAR(50) | UNIQUE NOT NULL |
| name | VARCHAR(100) | NOT NULL |
| description | TEXT | |
| version | VARCHAR(50) | |
| enabled | BOOLEAN | DEFAULT true |
| display_order | INT | DEFAULT 100 |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |

---

### 24. compliance_controls

- **Created by**: `_ensure_compliance_tables()` at line 3509
- **RLS**: No
- **Unique constraints**: `UNIQUE(framework_id, control_id)`
- **Foreign keys**: `framework_id` FK `compliance_frameworks(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| framework_id | INTEGER | NOT NULL, FK compliance_frameworks(id) ON DELETE CASCADE |
| control_id | VARCHAR(50) | NOT NULL |
| name | VARCHAR(255) | NOT NULL |
| description | TEXT | |
| metric | VARCHAR(50) | NOT NULL |
| pass_operator | VARCHAR(10) | NOT NULL |
| pass_value | NUMERIC | NOT NULL |
| warn_operator | VARCHAR(10) | |
| warn_value | NUMERIC | |
| drilldown_url | VARCHAR(255) | |
| display_order | INT | DEFAULT 100 |
| severity | VARCHAR(20) | DEFAULT 'medium' (V2) |
| weight | INTEGER | DEFAULT 5 (V2) |
| cloud | VARCHAR(20) | DEFAULT 'azure' (V2) |
| pillar | VARCHAR(50) | (V2) |
| root_cause_id | INTEGER | (V2) |

**Indexes**: `idx_compliance_controls_framework(framework_id)`

---

### 25. compliance_root_causes

- **Created by**: `_ensure_compliance_tables()` at line 3509
- **RLS**: No
- **Unique constraints**: `UNIQUE(code)`
- **Foreign keys**: None
- **Seeded**: 7 root causes via `seed_compliance_root_causes()`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| code | VARCHAR(50) | UNIQUE NOT NULL |
| title | VARCHAR(255) | NOT NULL |
| description | TEXT | |
| category | VARCHAR(50) | |
| recommendation | TEXT | |
| display_order | INT | DEFAULT 100 |

---

### 26. compliance_snapshots

- **Created by**: `_ensure_compliance_snapshots_table()` at line 3640
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(run_id, framework_key)`
- **Foreign keys**: `run_id` FK `discovery_runs(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| run_id | INTEGER | NOT NULL, FK discovery_runs(id) ON DELETE CASCADE |
| framework_key | VARCHAR(50) | NOT NULL |
| framework_name | VARCHAR(100) | NOT NULL |
| score | INTEGER | NOT NULL |
| pass_count | INTEGER | NOT NULL DEFAULT 0 |
| warn_count | INTEGER | NOT NULL DEFAULT 0 |
| fail_count | INTEGER | NOT NULL DEFAULT 0 |
| total_controls | INTEGER | NOT NULL DEFAULT 0 |
| metrics | JSONB | |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |

**Indexes**: `idx_compliance_snapshots_run(run_id)`, `idx_compliance_snapshots_fw(framework_key)`, `idx_compliance_snapshots_tenant`

---

### 27. azure_storage_accounts

- **Created by**: `_ensure_azure_storage_accounts_table()` at line 3728
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(discovery_run_id, resource_id)`
- **Foreign keys**: `discovery_run_id` FK `discovery_runs(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| discovery_run_id | INTEGER | NOT NULL, FK discovery_runs(id) ON DELETE CASCADE |
| resource_id | TEXT | NOT NULL |
| name | TEXT | NOT NULL |
| location | TEXT | |
| resource_group | TEXT | |
| subscription_id | TEXT | |
| subscription_name | TEXT | |
| sku | TEXT | |
| kind | TEXT | |
| access_tier | TEXT | |
| public_blob_access | BOOLEAN | DEFAULT FALSE |
| https_only | BOOLEAN | DEFAULT TRUE |
| minimum_tls_version | TEXT | DEFAULT 'TLS1_2' |
| shared_key_access | BOOLEAN | DEFAULT TRUE |
| allow_cross_tenant_replication | BOOLEAN | DEFAULT FALSE |
| default_network_action | TEXT | DEFAULT 'Allow' |
| ip_rules_count | INTEGER | DEFAULT 0 |
| vnet_rules_count | INTEGER | DEFAULT 0 |
| private_endpoint_count | INTEGER | DEFAULT 0 |
| bypass_settings | TEXT | |
| network_rules | JSONB | DEFAULT '{}' |
| infrastructure_encryption | BOOLEAN | DEFAULT FALSE |
| customer_managed_keys | BOOLEAN | DEFAULT FALSE |
| key_vault_uri | TEXT | |
| encryption_details | JSONB | DEFAULT '{}' |
| key1_created_at | TIMESTAMPTZ | |
| key2_created_at | TIMESTAMPTZ | |
| key_rotation_stale | BOOLEAN | DEFAULT FALSE |
| sas_policy_enabled | BOOLEAN | |
| sas_expiration_period | TEXT | |
| diagnostic_logging_enabled | BOOLEAN | (Phase 73) |
| logging_destinations | JSONB | DEFAULT '[]' (Phase 73) |
| risk_level | TEXT | DEFAULT 'info' |
| risk_score | INTEGER | DEFAULT 0 |
| risk_reasons | JSONB | DEFAULT '[]' |
| tags | JSONB | DEFAULT '{}' |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |

**Indexes**: `idx_sa_run(discovery_run_id)`, `idx_sa_risk(risk_level)`

---

### 28. azure_key_vaults

- **Created by**: `_ensure_azure_key_vaults_table()` at line 3789
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(discovery_run_id, resource_id)`
- **Foreign keys**: `discovery_run_id` FK `discovery_runs(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| discovery_run_id | INTEGER | NOT NULL, FK discovery_runs(id) ON DELETE CASCADE |
| resource_id | TEXT | NOT NULL |
| name | TEXT | NOT NULL |
| location | TEXT | |
| resource_group | TEXT | |
| subscription_id | TEXT | |
| subscription_name | TEXT | |
| sku | TEXT | |
| soft_delete_enabled | BOOLEAN | DEFAULT FALSE |
| soft_delete_retention_days | INTEGER | DEFAULT 0 |
| purge_protection | BOOLEAN | DEFAULT FALSE |
| enable_rbac_authorization | BOOLEAN | DEFAULT FALSE |
| public_network_access | TEXT | DEFAULT 'Enabled' |
| default_network_action | TEXT | DEFAULT 'Allow' |
| ip_rules_count | INTEGER | DEFAULT 0 |
| vnet_rules_count | INTEGER | DEFAULT 0 |
| private_endpoint_count | INTEGER | DEFAULT 0 |
| network_rules | JSONB | DEFAULT '{}' |
| secrets_total | INTEGER | DEFAULT 0 |
| secrets_expired | INTEGER | DEFAULT 0 |
| secrets_expiring_soon | INTEGER | DEFAULT 0 |
| keys_total | INTEGER | DEFAULT 0 |
| keys_expired | INTEGER | DEFAULT 0 |
| keys_expiring_soon | INTEGER | DEFAULT 0 |
| certs_total | INTEGER | DEFAULT 0 |
| certs_expired | INTEGER | DEFAULT 0 |
| certs_expiring_soon | INTEGER | DEFAULT 0 |
| access_policy_count | INTEGER | DEFAULT 0 |
| access_policies | JSONB | DEFAULT '[]' |
| secrets_detail | JSONB | DEFAULT '[]' (Phase 69) |
| keys_detail | JSONB | DEFAULT '[]' (Phase 69) |
| certs_detail | JSONB | DEFAULT '[]' (Phase 69) |
| risk_level | TEXT | DEFAULT 'info' |
| risk_score | INTEGER | DEFAULT 0 |
| risk_reasons | JSONB | DEFAULT '[]' |
| tags | JSONB | DEFAULT '{}' |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |

**Indexes**: `idx_kv_run(discovery_run_id)`, `idx_kv_risk(risk_level)`

---

### 29. app_registrations

- **Created by**: `_ensure_app_registrations_table()` at line 4020
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(discovery_run_id, app_id)`
- **Foreign keys**: `discovery_run_id` FK `discovery_runs(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| discovery_run_id | INTEGER | NOT NULL, FK discovery_runs(id) ON DELETE CASCADE |
| app_object_id | TEXT | NOT NULL |
| app_id | TEXT | NOT NULL |
| display_name | TEXT | NOT NULL |
| created_datetime | TIMESTAMPTZ | |
| sign_in_audience | TEXT | |
| publisher_domain | TEXT | |
| app_owner_organization_id | TEXT | |
| is_third_party | BOOLEAN | DEFAULT FALSE |
| required_permissions | JSONB | DEFAULT '[]' |
| permission_count | INTEGER | DEFAULT 0 |
| application_permission_count | INTEGER | DEFAULT 0 |
| delegated_permission_count | INTEGER | DEFAULT 0 |
| high_risk_permissions | TEXT[] | DEFAULT '{}' |
| secret_count | INTEGER | DEFAULT 0 |
| certificate_count | INTEGER | DEFAULT 0 |
| credential_details | JSONB | DEFAULT '[]' |
| next_expiry | TIMESTAMPTZ | |
| has_expired_credential | BOOLEAN | DEFAULT FALSE |
| has_expiring_soon | BOOLEAN | DEFAULT FALSE |
| owner_count | INTEGER | DEFAULT 0 |
| owners | JSONB | DEFAULT '[]' |
| primary_owner | TEXT | |
| has_service_principal | BOOLEAN | DEFAULT FALSE |
| linked_spn_id | INTEGER | |
| spn_last_sign_in | TIMESTAMPTZ | |
| spn_activity_status | TEXT | |
| redirect_uris | JSONB | DEFAULT '[]' |
| redirect_uri_count | INTEGER | DEFAULT 0 |
| has_localhost_redirect | BOOLEAN | DEFAULT FALSE |
| has_http_redirect | BOOLEAN | DEFAULT FALSE |
| risk_level | TEXT | DEFAULT 'info' |
| risk_score | INTEGER | DEFAULT 0 |
| risk_reasons | JSONB | DEFAULT '[]' |
| approval_status | TEXT | DEFAULT 'unknown' |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |

**Indexes**: `idx_appreg_run(discovery_run_id)`, `idx_appreg_risk(risk_level)`, `idx_appreg_appid(app_id)`

---

### 30. webhooks

- **Created by**: `_ensure_webhook_tables()` at line 2532
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: None

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| name | VARCHAR(255) | NOT NULL |
| url | TEXT | NOT NULL |
| secret | VARCHAR(255) | |
| event_types | TEXT[] | NOT NULL DEFAULT '{}' |
| headers | JSONB | |
| enabled | BOOLEAN | DEFAULT true |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |
| updated_at | TIMESTAMPTZ | DEFAULT NOW() |

---

### 31. webhook_deliveries

- **Created by**: `_ensure_webhook_tables()` at line 2532
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `webhook_id` FK `webhooks(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| webhook_id | INTEGER | FK webhooks(id) ON DELETE CASCADE |
| event_type | VARCHAR(50) | NOT NULL |
| payload | JSONB | NOT NULL |
| status | VARCHAR(20) | DEFAULT 'pending' |
| http_status | INTEGER | |
| response_body | TEXT | |
| attempts | INTEGER | DEFAULT 0 |
| next_retry_at | TIMESTAMPTZ | |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |
| delivered_at | TIMESTAMPTZ | |

**Indexes**: `idx_webhook_deliveries_status(status)`, `idx_webhook_deliveries_webhook(webhook_id)`

---

### 32. custom_risk_rules

- **Created by**: `_ensure_custom_risk_rules_table()` at line 2727
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: None

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| name | VARCHAR(255) | NOT NULL |
| description | TEXT | |
| conditions | JSONB | NOT NULL |
| action_type | VARCHAR(20) | NOT NULL DEFAULT 'adjust_points' |
| points_adjustment | INTEGER | DEFAULT 0 |
| force_level | VARCHAR(20) | |
| reason_text | TEXT | |
| enabled | BOOLEAN | DEFAULT true |
| priority | INTEGER | DEFAULT 100 |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |
| updated_at | TIMESTAMPTZ | DEFAULT NOW() |

---

### 33. notifications

- **Created by**: `_ensure_notifications_table()` at line 2854
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `tenant_id` FK `tenants(id)`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| event_type | VARCHAR(50) | NOT NULL |
| category | VARCHAR(30) | NOT NULL |
| severity | VARCHAR(20) | NOT NULL DEFAULT 'info' |
| title | VARCHAR(255) | NOT NULL |
| description | TEXT | NOT NULL |
| payload | JSONB | |
| related_identity_id | TEXT | |
| related_identity_name | VARCHAR(255) | |
| related_run_id | INTEGER | |
| read | BOOLEAN | DEFAULT false |
| read_at | TIMESTAMPTZ | |
| actioned | BOOLEAN | DEFAULT false |
| action_type | VARCHAR(50) | |
| action_at | TIMESTAMPTZ | |
| tenant_id | INTEGER | FK tenants(id) |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

**Indexes**: `idx_notifications_read_created(read, created_at DESC)`, `idx_notifications_severity`, `idx_notifications_category`, `idx_notifications_tenant`

---

### 34. saved_views

- **Created by**: `_ensure_saved_views_table()` at line 4386
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `user_id` FK `users(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| name | VARCHAR(255) | NOT NULL |
| description | TEXT | |
| filters | JSONB | NOT NULL DEFAULT '{}' |
| sort_field | VARCHAR(50) | |
| sort_direction | VARCHAR(10) | DEFAULT 'desc' |
| is_default | BOOLEAN | DEFAULT false |
| is_shared | BOOLEAN | DEFAULT false |
| user_id | INTEGER | NOT NULL, FK users(id) ON DELETE CASCADE |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| updated_at | TIMESTAMPTZ | DEFAULT NOW() |

**Indexes**: `idx_saved_views_user(user_id)`

---

### 35. access_review_campaigns

- **Created by**: `_ensure_access_review_tables()` at line 4528
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `created_by` FK `users(id)`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| name | VARCHAR(255) | NOT NULL |
| description | TEXT | |
| status | VARCHAR(20) | NOT NULL DEFAULT 'active' |
| scope_filters | JSONB | NOT NULL DEFAULT '{}' |
| deadline | TIMESTAMPTZ | |
| created_by | INTEGER | NOT NULL, FK users(id) |
| campaign_type | VARCHAR(100) | DEFAULT 'general' (V2) |
| scope_clouds | TEXT[] | (V2) |
| scope_description | VARCHAR(500) | (V2) |
| risk_focus | VARCHAR(100) | (V2) |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| updated_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| completed_at | TIMESTAMPTZ | |

**Indexes**: `idx_campaigns_status`, `idx_campaigns_created_by`, `idx_campaigns_tenant`, `idx_campaigns_type`

---

### 36. campaign_reviews

- **Created by**: `_ensure_access_review_tables()` at line 4528
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `campaign_id` FK `access_review_campaigns(id) ON DELETE CASCADE`, `reviewer_id` FK `users(id)`, `decision_by` FK `users(id)`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| campaign_id | INTEGER | NOT NULL, FK access_review_campaigns(id) ON DELETE CASCADE |
| identity_id | TEXT | NOT NULL |
| identity_display_name | TEXT | |
| identity_risk_level | VARCHAR(20) | |
| identity_category | VARCHAR(100) | |
| reviewer_id | INTEGER | FK users(id) |
| decision | VARCHAR(20) | |
| notes | TEXT | |
| decided_at | TIMESTAMPTZ | |
| identity_db_id | INTEGER | (V2) |
| identity_type | VARCHAR(100) | (V2) |
| access_role | VARCHAR(255) | (V2) |
| access_scope | VARCHAR(500) | (V2) |
| cloud_provider | VARCHAR(50) | (V2) |
| risk_score | INTEGER | (V2) |
| risk_factors | JSONB | DEFAULT '[]' (V2) |
| last_used_date | TIMESTAMPTZ | (V2) |
| last_used_days | INTEGER | (V2) |
| privilege_level | VARCHAR(50) | (V2) |
| credential_risk | VARCHAR(255) | (V2) |
| credential_risk_level | VARCHAR(50) | (V2) |
| ai_recommendation | VARCHAR(100) | (V2) |
| ai_recommendation_reason | TEXT | (V2) |
| decision_by | INTEGER | FK users(id) (V2) |
| review_due_date | TIMESTAMPTZ | (V2) |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| updated_at | TIMESTAMPTZ | DEFAULT NOW() (V2) |

**Indexes**: `idx_campaign_reviews_campaign`, `idx_campaign_reviews_identity`, `idx_campaign_reviews_decision`, `idx_campaign_reviews_risk(risk_score DESC)`, `idx_campaign_reviews_reviewer`, `idx_campaign_reviews_tenant`

---

### 37. campaign_audit_log

- **Created by**: `_ensure_access_review_tables()` at line 4528
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `campaign_id` FK `access_review_campaigns(id) ON DELETE CASCADE`, `review_id` FK `campaign_reviews(id) ON DELETE SET NULL`, `actor_id` FK `users(id)`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| campaign_id | INTEGER | NOT NULL, FK access_review_campaigns(id) ON DELETE CASCADE |
| review_id | INTEGER | FK campaign_reviews(id) ON DELETE SET NULL |
| action | VARCHAR(100) | NOT NULL |
| actor_id | INTEGER | FK users(id) |
| old_value | TEXT | |
| new_value | TEXT | |
| metadata | JSONB | DEFAULT '{}' |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |

**Indexes**: `idx_audit_campaign(campaign_id)`

---

### 38. identity_groups

- **Created by**: `_ensure_identity_group_tables()` at line 5115
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `created_by` FK `users(id)`
- **Seeded**: 4 auto groups via `seed_auto_groups()`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| name | VARCHAR(255) | NOT NULL |
| description | TEXT | |
| color | VARCHAR(20) | DEFAULT '#3B82F6' |
| group_type | VARCHAR(10) | NOT NULL DEFAULT 'custom' |
| auto_criteria | JSONB | |
| created_by | INTEGER | FK users(id) |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| updated_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

**Indexes**: `idx_identity_groups_type(group_type)`, `idx_identity_groups_name(name)`

---

### 39. identity_group_members

- **Created by**: `_ensure_identity_group_tables()` at line 5115
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE INDEX(group_id, identity_id)`
- **Foreign keys**: `group_id` FK `identity_groups(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| group_id | INTEGER | NOT NULL, FK identity_groups(id) ON DELETE CASCADE |
| identity_id | TEXT | NOT NULL |
| tenant_id | INTEGER | |
| added_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

**Indexes**: `idx_group_members_unique(group_id, identity_id)` UNIQUE, `idx_group_members_identity(identity_id)`

---

### 40. anomalies

- **Created by**: `_ensure_anomalies_table()` at line 5528
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `discovery_run_id` FK `discovery_runs(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| discovery_run_id | INTEGER | FK discovery_runs(id) ON DELETE CASCADE |
| anomaly_type | VARCHAR(50) | NOT NULL |
| severity | VARCHAR(20) | NOT NULL DEFAULT 'medium' |
| identity_id | TEXT | |
| identity_name | VARCHAR(255) | |
| title | VARCHAR(255) | NOT NULL |
| description | TEXT | NOT NULL |
| details | JSONB | |
| resolved | BOOLEAN | DEFAULT false |
| resolved_at | TIMESTAMPTZ | |
| resolved_by | VARCHAR(100) | |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

**Indexes**: `idx_anomalies_run_id`, `idx_anomalies_type`, `idx_anomalies_severity`, `idx_anomalies_identity`, `idx_anomalies_created(created_at DESC)`, `idx_anomalies_resolved`, `idx_anomalies_tenant`

---

### 41. api_keys

- **Created by**: `_ensure_api_keys_table()` at line 5732
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE INDEX(key_hash)`
- **Foreign keys**: `created_by` FK `users(id) ON DELETE SET NULL`, `tenant_id` FK `tenants(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| key_prefix | VARCHAR(12) | NOT NULL |
| key_hash | VARCHAR(64) | NOT NULL |
| name | VARCHAR(255) | NOT NULL |
| description | TEXT | |
| role | VARCHAR(20) | NOT NULL DEFAULT 'viewer' |
| enabled | BOOLEAN | DEFAULT true |
| created_by | INTEGER | FK users(id) ON DELETE SET NULL |
| tenant_id | INTEGER | FK tenants(id) ON DELETE CASCADE |
| expires_at | TIMESTAMPTZ | |
| usage_count | INTEGER | NOT NULL DEFAULT 0 |
| last_used_at | TIMESTAMPTZ | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

**Indexes**: `idx_api_keys_hash(key_hash)` UNIQUE, `idx_api_keys_prefix(key_prefix)`, `idx_api_keys_tenant(tenant_id)`

---

### 42. soar_playbooks

- **Created by**: `_ensure_soar_tables()` at line 5912
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: None

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| name | VARCHAR(255) | NOT NULL |
| description | TEXT | |
| enabled | BOOLEAN | DEFAULT true |
| trigger_type | VARCHAR(30) | NOT NULL |
| trigger_conditions | JSONB | NOT NULL DEFAULT '{}' |
| action_type | VARCHAR(30) | NOT NULL |
| action_config | JSONB | NOT NULL DEFAULT '{}' |
| integration | VARCHAR(30) | NOT NULL DEFAULT 'internal' |
| cooldown_minutes | INTEGER | DEFAULT 60 |
| created_by | VARCHAR(100) | |
| tenant_id | INTEGER | |
| last_triggered_at | TIMESTAMPTZ | |
| trigger_count | INTEGER | DEFAULT 0 |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |
| updated_at | TIMESTAMPTZ | DEFAULT NOW() |

**Indexes**: `idx_soar_playbooks_trigger(trigger_type)`, `idx_soar_playbooks_enabled(enabled)`, `idx_soar_playbooks_tenant`

---

### 43. soar_actions

- **Created by**: `_ensure_soar_tables()` at line 5912
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `playbook_id` FK `soar_playbooks(id) ON DELETE SET NULL`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| playbook_id | INTEGER | FK soar_playbooks(id) ON DELETE SET NULL |
| identity_id | TEXT | |
| anomaly_id | INTEGER | |
| trigger_event | JSONB | |
| action_type | VARCHAR(30) | NOT NULL |
| integration | VARCHAR(30) | NOT NULL |
| status | VARCHAR(20) | DEFAULT 'pending' |
| result | JSONB | |
| executed_at | TIMESTAMPTZ | |
| completed_at | TIMESTAMPTZ | |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |

**Indexes**: `idx_soar_actions_playbook`, `idx_soar_actions_status`, `idx_soar_actions_created(created_at DESC)`, `idx_soar_actions_identity`, `idx_soar_actions_tenant`

---

### 44. dashboard_preferences

- **Created by**: `_ensure_dashboard_preferences_table()` at line 6172
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(user_id)` (column-level + index)
- **Foreign keys**: `user_id` FK `users(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| user_id | INTEGER | NOT NULL UNIQUE, FK users(id) ON DELETE CASCADE |
| preferences | JSONB | NOT NULL DEFAULT '{}' |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| updated_at | TIMESTAMPTZ | DEFAULT NOW() |

**Indexes**: `idx_dashboard_prefs_user(user_id)` UNIQUE

---

### 45. sa_attestations

- **Created by**: `_ensure_sa_attestations_table()` at line 6602 (guard: `_sa_attestations_ensured`)
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `attested_by` FK `users(id)`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| identity_db_id | INTEGER | NOT NULL |
| identity_id | TEXT | NOT NULL |
| attested_by | INTEGER | NOT NULL, FK users(id) |
| status | VARCHAR(30) | NOT NULL |
| justification | TEXT | |
| attested_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| next_due | TIMESTAMPTZ | |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

**Indexes**: `idx_sa_att_identity(identity_id)`, `idx_sa_att_tenant(tenant_id)`, `idx_sa_att_attested(attested_at DESC)`

---

### 46. governance_decisions

- **Created by**: `_ensure_governance_decisions_table()` at line 6691 (guard: `_governance_decisions_ensured`)
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: `decided_by` FK `users(id)`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| identity_db_id | INTEGER | NOT NULL |
| identity_id | TEXT | NOT NULL |
| decision | VARCHAR(50) | NOT NULL |
| reason | TEXT | |
| risk_score_snapshot | INTEGER | |
| risk_band_snapshot | VARCHAR(20) | |
| risk_factors_snapshot | JSONB | DEFAULT '[]' |
| access_snapshot | JSONB | DEFAULT '[]' |
| decided_by | INTEGER | NOT NULL, FK users(id) |
| exception_expiry | TIMESTAMPTZ | |
| tenant_id | INTEGER | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

**Indexes**: `idx_gov_dec_identity(identity_id)`, `idx_gov_dec_tenant(tenant_id)`, `idx_gov_dec_created(created_at DESC)`

---

### 47. copilot_conversations

- **Created by**: `_ensure_copilot_tables()` at line 6892 (guard: `_copilot_ensured`)
- **RLS**: Yes (via DO block)
- **Unique constraints**: None beyond PK
- **Foreign keys**: None

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| user_id | INT | |
| tenant_id | INT | |
| title | TEXT | |
| messages | JSONB | DEFAULT '[]' |
| created_at | TIMESTAMP | DEFAULT NOW() |
| updated_at | TIMESTAMP | DEFAULT NOW() |

---

### 48. cloud_subscriptions

- **Created by**: `_ensure_cloud_subscriptions_table()` at line 6969
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(tenant_id, cloud, account_id)`
- **Foreign keys**: None explicit (`tenant_id` is logical FK)

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | SERIAL | PRIMARY KEY |
| tenant_id | INTEGER | NOT NULL |
| cloud | VARCHAR(20) | NOT NULL |
| account_id | VARCHAR(255) | NOT NULL |
| account_name | VARCHAR(500) | |
| status | VARCHAR(20) | DEFAULT 'discovered' |
| monitored | BOOLEAN | DEFAULT false |
| activated_at | TIMESTAMPTZ | |
| activated_by | INTEGER | |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |

**Indexes**: `idx_cloud_subs_tenant(tenant_id)`, `idx_cloud_subs_cloud(cloud)`

---

### 49. identity_subscription_access

- **Created by**: `_ensure_identity_subscription_access_table()` at line 7201 (guard: `_isa_ensured`)
- **RLS**: Yes (via DO block)
- **Unique constraints**: `UNIQUE(identity_db_id, subscription_id, rbac_role, scope)`
- **Foreign keys**: `identity_db_id` FK `identities(id) ON DELETE CASCADE`, `discovery_run_id` FK `discovery_runs(id) ON DELETE CASCADE`

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | BIGSERIAL | PRIMARY KEY |
| identity_db_id | BIGINT | NOT NULL, FK identities(id) ON DELETE CASCADE |
| identity_id | TEXT | NOT NULL |
| subscription_id | TEXT | NOT NULL |
| subscription_name | TEXT | |
| rbac_role | TEXT | NOT NULL |
| scope | TEXT | |
| scope_type | TEXT | |
| risk_level | TEXT | |
| last_activity | TIMESTAMPTZ | |
| discovered_at | TIMESTAMPTZ | DEFAULT NOW() |
| discovery_run_id | BIGINT | FK discovery_runs(id) ON DELETE CASCADE |
| tenant_id | INTEGER | |

**Indexes**: `idx_isa_identity(identity_db_id)`, `idx_isa_sub(subscription_id)`, `idx_isa_identity_id(identity_id)`, `idx_isa_run(discovery_run_id)`, `idx_isa_tenant(tenant_id)`

---

## Migration-Only Tables (created by SQL migrations, not by `_ensure_*` methods)

### identity_roles

- **Created by**: Migration `001_create_identity_roles.sql`
- **Status**: Created but unused by current code paths
- **Intended for**: Future unified role table

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | BIGSERIAL | PRIMARY KEY |
| identity_db_id | BIGINT | NOT NULL, FK identities(id) ON DELETE CASCADE |
| role_name | TEXT | NOT NULL |
| role_type | TEXT | NOT NULL ('azure_rbac' / 'entra_directory_role') |
| scope | TEXT | |
| inherited | BOOLEAN | DEFAULT FALSE |
| tenant_id | INTEGER | (added by 016) |
| created_at | TIMESTAMPTZ | DEFAULT NOW() |

### role_permissions

- **Created by**: Migration `005_create_role_intelligence.sql`
- **Purpose**: Role metadata and intelligence

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | BIGSERIAL | PRIMARY KEY |
| role_name | TEXT | NOT NULL |
| role_type | TEXT | NOT NULL (azure / entra) |
| privileged | BOOLEAN | DEFAULT FALSE |
| risk_level | TEXT | |
| description | TEXT | |
| why_critical | TEXT | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| UNIQUE | | (role_name, role_type) |

### role_activity_log

- **Created by**: Migration `005_create_role_intelligence.sql`
- **RLS**: Yes (via DO block)

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | BIGSERIAL | PRIMARY KEY |
| identity_db_id | BIGINT | NOT NULL, FK identities(id) ON DELETE CASCADE |
| role_name | TEXT | NOT NULL |
| last_activity_date | TIMESTAMPTZ | |
| days_since_last_use | INTEGER | |
| tenant_id | INTEGER | (added by 016) |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |
| UNIQUE | | (identity_db_id, role_name) |

### role_attack_patterns

- **Created by**: Migration `005_create_role_intelligence.sql`
- **RLS**: No

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | BIGSERIAL | PRIMARY KEY |
| role_name | TEXT | NOT NULL |
| attack_scenario | TEXT | NOT NULL |
| real_world_example | TEXT | |
| company_affected | TEXT | |
| breach_year | INTEGER | |
| estimated_cost_usd | BIGINT | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

### role_hipaa_mappings

- **Created by**: Migration `005_create_role_intelligence.sql`
- **RLS**: No

| Column | Type | Constraints / Defaults |
|--------|------|----------------------|
| id | BIGSERIAL | PRIMARY KEY |
| role_name | TEXT | NOT NULL |
| hipaa_section | TEXT | NOT NULL |
| violation_explanation | TEXT | |
| violation_risk | TEXT | |
| typical_penalty_min | BIGINT | |
| typical_penalty_max | BIGINT | |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() |

---

## Views

### v_latest_identities
```sql
CREATE OR REPLACE VIEW v_latest_identities AS
SELECT i.*
FROM identities i
INNER JOIN (
    SELECT MAX(id) as run_id FROM discovery_runs WHERE status = 'completed'
) latest ON i.discovery_run_id = latest.run_id;
```

### v_critical_identities
```sql
CREATE OR REPLACE VIEW v_critical_identities AS
SELECT * FROM v_latest_identities WHERE risk_level = 'critical';
```

---

## RLS Policy Pattern

All 43 RLS-enabled tables use four policies (SELECT, INSERT, UPDATE, DELETE) following this pattern:

```sql
-- SELECT / UPDATE / DELETE
CREATE POLICY tenant_iso_select ON tablename FOR SELECT
USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER
);

-- INSERT
CREATE POLICY tenant_iso_insert ON tablename FOR INSERT
WITH CHECK (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER
);
```

**Behavior**:
- `NULL` context (`current_setting` returns NULL) = superadmin bypass (sees all tenants)
- `NULL` `tenant_id` on a row = visible to all tenants (system-level data)
- Explicit match = tenant-scoped access

**4 tables with explicit policy blocks** (written out individually in the migration):
1. `discovery_runs`
2. `settings`
3. `users`
4. `activity_log`

**39 tables via DO block** (generated dynamically):
`identities`, `role_assignments`, `entra_role_assignments`, `credentials`, `graph_api_permissions`, `sp_ownership`, `sp_app_roles`, `identity_roles`, `role_activity_log`, `pim_eligible_assignments`, `pim_activations`, `ca_policies`, `ca_identity_coverage`, `drift_reports`, `compliance_snapshots`, `anomalies`, `soar_playbooks`, `soar_actions`, `identity_groups`, `identity_group_members`, `saved_views`, `dashboard_preferences`, `identity_subscription_access`, `remediation_actions`, `webhooks`, `webhook_deliveries`, `custom_risk_rules`, `campaign_reviews`, `campaign_audit_log`, `notifications`, `api_keys`, `azure_storage_accounts`, `azure_key_vaults`, `app_registrations`, `access_review_campaigns`, `sa_attestations`, `governance_decisions`, `copilot_conversations`, `cloud_subscriptions`, `sso_auth_codes`

---

## Seed Methods

| Method | What It Seeds | Count |
|--------|--------------|-------|
| `_ensure_remediation_playbooks()` | Remediation playbooks (access_control, credential_hygiene, governance) | 20 |
| `seed_compliance_frameworks()` | Compliance frameworks (SOC2, HIPAA, PCI-DSS, NIST, CIS, ISO 27001) | 6 frameworks, ~30 controls |
| `seed_compliance_root_causes()` | Root cause codes for compliance failures | 7 |
| `seed_auto_groups()` | Auto identity groups (by category/risk) | 4 |
| `ensure_default_admin()` | Default admin user from `ADMIN_USERNAME`/`ADMIN_PASSWORD` env vars | 1 |
| `_migrate_compliance_controls_v2()` | Updates controls with severity, weight, pillar, root_cause_id | Migration only |
| `_ensure_tenants_table()` | Default tenant ("Acme Organization") if none exist | 1 |

---

## Class-Level DDL Guard Flags

These prevent repeated DDL execution within the same Python process (especially important with gunicorn `--preload`):

| Flag | Guards Method | Line |
|------|--------------|------|
| `_risk_factors_col_ensured` | `save_identity()` (ALTER TABLE identities ADD risk_factors) | 148 |
| `_users_ensured` | `_ensure_users_table()` | 3052 |
| `_tenants_ensured` | `_ensure_tenants_table()` | 6247 |
| `_sa_attestations_ensured` | `_ensure_sa_attestations_table()` | 6600 |
| `_governance_decisions_ensured` | `_ensure_governance_decisions_table()` | 6689 |
| `_copilot_ensured` | `_ensure_copilot_tables()` | 6890 |
| `_isa_ensured` | `_ensure_identity_subscription_access_table()` | 7199 |

---

## Design Gaps

1. **No connection pooling** -- A fresh `psycopg2.connect()` is opened per `Database()` instance. No `psycopg2.pool` or PgBouncer integration.

2. **No migration runner** -- No Alembic or similar tool. Schema is managed via `_ensure_*` methods (CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD COLUMN IF NOT EXISTS) and raw SQL migration files run manually.

3. **identities table has NO tenant_id column for scoping** -- While a `tenant_id` column exists (added by migration 016), the application does NOT use it for queries. Identity scoping is done via `discovery_run_id` which belongs to a tenant-scoped `discovery_runs` row. Never use `i.tenant_id` in WHERE clauses.

4. **risk_scores table referenced in some queries but not in _ensure methods** -- Some handler queries reference a `risk_scores` table that is not created by any `_ensure_*` method or migration file in the repository.

5. **Migration-only tables** -- `role_permissions`, `role_activity_log`, `role_attack_patterns`, `role_hipaa_mappings` are created by migration `005_create_role_intelligence.sql` only. They have no corresponding `_ensure_*` method.

6. **identity_roles table created but unused** -- Created in migration 001 as a future unified role table, but current code uses `role_assignments` and `entra_role_assignments` separately.

7. **Computed query fields** -- `has_write_permissions`, `has_entra_role`, and `has_rbac_role` are NOT database columns. They are computed in the query builder (`QUERY_COMPUTED_FIELDS` in `handlers.py`) via subqueries at query time.

---

## Migration Files

| File | Purpose |
|------|---------|
| `001_create_identity_roles.sql` | Core schema: discovery_runs, identities, role_assignments, entra_role_assignments, identity_roles, views |
| `002_create_credentials.sql` | credentials table + identity credential summary columns |
| `003_create_graph_api_permissions.sql` | graph_api_permissions table |
| `004_create_sp_app_roles.sql` | sp_app_roles table |
| `005_create_role_intelligence.sql` | role_permissions, role_activity_log, role_attack_patterns, role_hipaa_mappings |
| `006_multi_cloud_identity_schema.sql` | Multi-cloud normalized columns on identities |
| `007_create_sp_ownership.sql` | sp_ownership table + owner denorm columns on identities |
| `008_enhanced_risk_scoring.sql` | risk_score, api_permission_count, app_role_count columns on identities |
| `009_role_usage_intelligence.sql` | Usage intelligence columns on role_assignments + entra_role_assignments |
| `010_create_pim_tables.sql` | pim_eligible_assignments, pim_activations + PIM columns on identities |
| `011_create_ca_tables.sql` | ca_policies, ca_identity_coverage + CA columns on identities |
| `012_create_remediation_playbooks.sql` | (superseded by `_ensure_remediation_playbooks()`) |
| `013_create_drift_reports.sql` | drift_reports table |
| `014_create_settings.sql` | settings table with seed defaults |
| `015_create_activity_log.sql` | (superseded by `_ensure_activity_log_table()`) |
| `016_rls_tenant_isolation.sql` | tenant_id columns, backfill, indexes, RLS policies on all 43 tables |
