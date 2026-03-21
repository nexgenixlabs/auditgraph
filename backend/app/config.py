"""
AuditGraph — Centralized Environment Configuration

Single source of truth for all environment variable loading.
Replaces scattered load_dotenv() calls across the codebase.

APP_ENV tiers:
    local  → .env.local   (default, safe for development)
    dev    → .env.dev     (Azure dev database)
    qa     → .env.qa      (Azure QA)
    stg    → .env.stg     (Azure staging)
    prod   → no file loaded (env vars injected by container runtime)

Secret Injection (prod/stg):
    In production, secrets are injected by the container runtime from
    Azure Key Vault via Container Apps secret references. This module
    never reads from Key Vault directly — the platform handles injection.
    See _KEY_VAULT_ARCHITECTURE at the bottom of this file for the
    full integration design.
"""

import logging
import os
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote, quote_plus
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. Determine environment tier
# ---------------------------------------------------------------------------
APP_ENV = os.getenv("APP_ENV", "local")

# ---------------------------------------------------------------------------
# 2. Load the correct .env file (once, at import time)
# ---------------------------------------------------------------------------
_ENV_FILE_MAP = {
    "local": ".env.local",
    "dev": ".env.dev",
    "qa": ".env.qa",
    "stg": ".env.stg",
    # prod: no file — env vars come from the container runtime
}

_backend_dir = Path(__file__).resolve().parent.parent  # backend/
_env_file = _ENV_FILE_MAP.get(APP_ENV)
if _env_file:
    _env_path = _backend_dir / _env_file
    if _env_path.exists():
        # override=False: explicit env vars (docker-compose environment:,
        # shell exports) take precedence over .env file values.  The .env
        # file fills in anything not already set.
        load_dotenv(_env_path, override=False)
    else:
        logger.warning("config.py: %s not found at %s", _env_file, _env_path)

# ---------------------------------------------------------------------------
# 3. Export database constants (DATABASE_URL takes precedence, individual
#    DB_* vars override parsed components, admin vars always separate)
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    _parsed = urlparse(DATABASE_URL)
    _query = parse_qs(_parsed.query)
    DB_HOST = os.getenv("DB_HOST", _parsed.hostname or "localhost")
    DB_PORT = os.getenv("DB_PORT", str(_parsed.port or 5432))
    DB_NAME = os.getenv("DB_NAME", _parsed.path.lstrip("/") or "auditgraph")
    DB_USER = os.getenv("DB_USER", unquote(_parsed.username or "auditgraph_app"))
    DB_PASSWORD = os.getenv("DB_PASSWORD", unquote(_parsed.password or ""))
    DB_SSLMODE = os.getenv("DB_SSLMODE", _query.get("sslmode", ["require"])[0])
    DB_CONNECT_TIMEOUT = int(os.getenv(
        "DB_CONNECT_TIMEOUT", _query.get("connect_timeout", ["10"])[0]
    ))
else:
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "auditgraph")
    DB_USER = os.getenv("DB_USER", "auditgraph_app")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_SSLMODE = os.getenv("DB_SSLMODE", "require")
    DB_CONNECT_TIMEOUT = int(os.getenv("DB_CONNECT_TIMEOUT", "10"))

# Dual-user RLS: admin credentials are always separate env vars
DB_ADMIN_USER = os.getenv("DB_ADMIN_USER", os.getenv("DB_USER", "auditgraph_admin"))
DB_ADMIN_PASSWORD = os.getenv("DB_ADMIN_PASSWORD", os.getenv("DB_PASSWORD", ""))

# Azure SSL enforcement — if host is Azure Flex Server, force sslmode=require
_is_azure_pg = "postgres.database.azure.com" in (DB_HOST or "").lower()
if _is_azure_pg and DB_SSLMODE != "require":
    logger.warning(
        "config.py: Azure PostgreSQL detected but sslmode=%s; forcing sslmode=require",
        DB_SSLMODE,
    )
    DB_SSLMODE = "require"

# Construct admin DATABASE_URL for dual-user RLS architecture.
# database.py uses individual vars (DB_HOST, DB_ADMIN_USER, etc.) directly,
# but this URL is exported for tooling, health checks, and documentation.
if DATABASE_URL:
    ADMIN_DATABASE_URL = (
        f"postgresql://{quote_plus(DB_ADMIN_USER)}:{quote_plus(DB_ADMIN_PASSWORD)}"
        f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        f"?sslmode={DB_SSLMODE}&connect_timeout={DB_CONNECT_TIMEOUT}"
    )
else:
    ADMIN_DATABASE_URL = None

# ---------------------------------------------------------------------------
# 4. Safety guard — prevent local dev from hitting Azure
# ---------------------------------------------------------------------------
IS_LOCAL = APP_ENV == "local"
IS_DEV = APP_ENV in ("local", "dev")
IS_PRODUCTION = APP_ENV == "prod"

if IS_LOCAL:
    _all_hosts = (DB_HOST or "") + (DATABASE_URL or "")
    if "postgres.database.azure.com" in _all_hosts.lower():
        raise RuntimeError(
            "SAFETY GUARD: APP_ENV=local but database points at Azure "
            f"(DB_HOST={DB_HOST}, DATABASE_URL={'set' if DATABASE_URL else 'unset'}). "
            "Refusing to start. Set APP_ENV=dev to use Azure, or fix .env.local."
        )

# ---------------------------------------------------------------------------
# 5. Cloud discovery toggles
# ---------------------------------------------------------------------------
# Discovery is enabled when credentials are present (works in any tier)
AZURE_DISCOVERY_ENABLED = bool(os.getenv("AZURE_TENANT_ID") and os.getenv("AZURE_CLIENT_ID"))
AWS_DISCOVERY_ENABLED = bool(os.getenv("AWS_ACCESS_KEY_ID"))
GCP_DISCOVERY_ENABLED = bool(os.getenv("GCP_PROJECT_ID"))

# ---------------------------------------------------------------------------
# 5b. Connection pooling
# ---------------------------------------------------------------------------
# DB_POOL_ENABLED: When True, Database class uses psycopg2.pool.ThreadedConnectionPool
# instead of creating a new connection per request. Reduces connection overhead.
# Default: enabled in non-local environments.
DB_POOL_ENABLED = os.getenv("DB_POOL_ENABLED", str(not IS_LOCAL)).lower() in ("true", "1", "yes")
DB_POOL_MIN = int(os.getenv("DB_POOL_MIN", "2"))
DB_POOL_MAX = int(os.getenv("DB_POOL_MAX", "20"))
# Slow query threshold in milliseconds. Queries exceeding this are logged.
DB_SLOW_QUERY_MS = int(os.getenv("DB_SLOW_QUERY_MS", "100"))

# ---------------------------------------------------------------------------
# 5c. AI Agent Governance feature flag
# ---------------------------------------------------------------------------
# FEATURE_AI_AGENT_GOVERNANCE: Global kill switch for the AI Agent Identity
# Governance module. When False, all agent governance UI elements, API routes,
# and background jobs are completely invisible / inactive.
# Default: True in local/dev (for development), False in prod/stg/qa.
FEATURE_AI_AGENT_GOVERNANCE = os.getenv(
    "FEATURE_AI_AGENT_GOVERNANCE", str(IS_DEV)
).lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
# 5d. Enterprise isolation guards
# ---------------------------------------------------------------------------
# ENFORCE_ADMIN_GUARD: When True, Database() calls inside Flask request
# context without _admin_reason raise RuntimeError (hard block).
# When False, they only log a warning. Default: True for non-local envs.
ENFORCE_ADMIN_GUARD = os.getenv("ENFORCE_ADMIN_GUARD", str(not IS_LOCAL)).lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
# 6. Sync FLASK_ENV for backward compat (auth.py, main.py read it)
# ---------------------------------------------------------------------------
if IS_DEV:
    os.environ.setdefault("FLASK_ENV", "development")
else:
    os.environ.setdefault("FLASK_ENV", "production")

# ---------------------------------------------------------------------------
# 7. Startup banner
# ---------------------------------------------------------------------------
def log_startup_banner():
    """Log environment diagnostics at server boot."""
    _on_off = lambda flag: "ENABLED" if flag else "DISABLED"
    _env_file_loaded = _ENV_FILE_MAP.get(APP_ENV, "(none -- container runtime)")
    # Mask DATABASE_URL: show scheme + host only
    if DATABASE_URL:
        _p = urlparse(DATABASE_URL)
        _masked_url = f"{_p.scheme}://***@{_p.hostname}:{_p.port or 5432}/{_p.path.lstrip('/')}"
    else:
        _masked_url = "(not set -- using individual DB_* vars)"
    logger.info("=" * 60)
    logger.info("  AuditGraph -- Environment Configuration")
    logger.info("=" * 60)
    logger.info("  APP_ENV:           %s", APP_ENV)
    logger.info("  ENV_FILE:          %s", _env_file_loaded)
    logger.info("  DATABASE_URL:      %s", _masked_url)
    logger.info("  DB_HOST:           %s", DB_HOST)
    logger.info("  DB_PORT:           %s", DB_PORT)
    logger.info("  DB_NAME:           %s", DB_NAME)
    logger.info("  DB_USER:           %s", DB_USER)
    logger.info("  DB_ADMIN_USER:     %s", DB_ADMIN_USER)
    logger.info("  DB_SSLMODE:        %s", DB_SSLMODE)
    logger.info("  CONNECT_TIMEOUT:   %ss", DB_CONNECT_TIMEOUT)
    logger.info("  AZURE_DISCOVERY:   %s", _on_off(AZURE_DISCOVERY_ENABLED))
    logger.info("  AWS_DISCOVERY:     %s", _on_off(AWS_DISCOVERY_ENABLED))
    logger.info("  GCP_DISCOVERY:     %s", _on_off(GCP_DISCOVERY_ENABLED))
    logger.info("  ADMIN_GUARD:       %s", "ENFORCE (RuntimeError)" if ENFORCE_ADMIN_GUARD else "WARN (log only)")
    logger.info("  CONN_POOL:         %s", f"ON (min={DB_POOL_MIN}, max={DB_POOL_MAX})" if DB_POOL_ENABLED else "OFF (1 conn/request)")
    logger.info("  SLOW_QUERY_MS:     %s", DB_SLOW_QUERY_MS)
    logger.info("  FLASK_ENV:         %s", os.getenv("FLASK_ENV"))
    logger.info("  AI_AGENT_GOV:      %s", _on_off(FEATURE_AI_AGENT_GOVERNANCE))
    logger.info("  SECRET_SOURCE:     %s", "env vars (container runtime)" if IS_PRODUCTION else ".env file")
    logger.info("=" * 60)


# ==========================================================================
# PRODUCTION OPERATIONAL HARDENING BLUEPRINT
# ==========================================================================
#
# ┌─────────────────────────────────────────────────────────────────────┐
# │                  ARCHITECTURE OVERVIEW                              │
# │                                                                     │
# │  ┌──────────────┐    ┌──────────────────────┐                       │
# │  │ Azure Key    │───▶│ Container Apps       │                       │
# │  │ Vault        │    │ (secret references)  │                       │
# │  │              │    │                      │                       │
# │  │ DB_PASSWORD  │    │  ┌────────────────┐  │   ┌──────────────┐   │
# │  │ JWT_SECRETs  │    │  │ gunicorn       │  │──▶│ PostgreSQL   │   │
# │  │ API_KEYs     │    │  │ (2 workers,    │  │   │ Flex Server  │   │
# │  │              │    │  │  --preload)    │  │   │              │   │
# │  └──────┬───────┘    │  └───────┬────────┘  │   │ Primary (RW) │   │
# │         │            │          │           │   │ Replica (RO) │   │
# │         │ rotate     │          │           │   └──────────────┘   │
# │         │ (90-day)   │    ┌─────▼────────┐  │                      │
# │         ▼            │    │ config.py    │  │   ┌──────────────┐   │
# │  ┌──────────────┐    │    │ (reads env   │  │──▶│ Azure Monitor│   │
# │  │ Rotation     │    │    │  vars only)  │  │   │ + Log        │   │
# │  │ Policy       │    │    └──────────────┘  │   │ Analytics    │   │
# │  │ (automated)  │    │                      │   └──────────────┘   │
# │  └──────────────┘    └──────────────────────┘                       │
# │                                                                     │
# │  Security Layers:                                                   │
# │    1. Key Vault → env var injection (no file on disk)               │
# │    2. SecretRedactionFilter (prevents creds in logs)                │
# │    3. SecurityEventLogger (structured SIEM events)                  │
# │    4. RLS + FORCE RLS (tenant isolation)                            │
# │    5. Dual DB roles (app=NOBYPASSRLS, admin=BYPASSRLS)             │
# │    6. Connection pool with context reset (5-layer defense)          │
# └─────────────────────────────────────────────────────────────────────┘
#
# ═══════════════════════════════════════════════════════════════════════
# 1. SECRET MANAGEMENT — Azure Key Vault Integration
# ═══════════════════════════════════════════════════════════════════════
#
# PRINCIPLE: Application code NEVER reads from Key Vault directly.
# Secrets are injected as environment variables by the container runtime.
#
# Key Vault Name: auditgraph-kv (or auditgraph-kv-{env})
# Location: Same region as Container Apps (eastus)
# SKU: Standard (HSM not required for app secrets)
#
# Secrets stored in Key Vault:
#   ┌────────────────────────┬──────────────────────────────────────┐
#   │ Key Vault Secret Name  │ Maps to Env Var                     │
#   ├────────────────────────┼──────────────────────────────────────┤
#   │ db-password            │ DB_PASSWORD                         │
#   │ db-admin-password      │ DB_ADMIN_PASSWORD                   │
#   │ admin-jwt-secret       │ ADMIN_JWT_SECRET                    │
#   │ client-jwt-secret      │ CLIENT_JWT_SECRET                   │
#   │ copilot-api-key        │ COPILOT_API_KEY (Anthropic)         │
#   │ azure-client-secret    │ AZURE_CLIENT_SECRET (SP for discovery)│
#   │ stripe-secret-key      │ STRIPE_SECRET_KEY                   │
#   │ slack-webhook-url      │ SLACK_WEBHOOK_URL                   │
#   │ teams-webhook-url      │ TEAMS_WEBHOOK_URL                   │
#   └────────────────────────┴──────────────────────────────────────┘
#
# Container Apps Configuration (az CLI):
#   az containerapp secret set \
#     --name auditgraph-api \
#     --resource-group auditgraph-dev-rg \
#     --secrets \
#       db-password=keyvaultref:https://auditgraph-kv.vault.azure.net/secrets/db-password,identityref:/subscriptions/.../userAssignedIdentities/auditgraph-uai \
#       admin-jwt-secret=keyvaultref:https://auditgraph-kv.vault.azure.net/secrets/admin-jwt-secret,identityref:...
#
#   az containerapp update \
#     --name auditgraph-api \
#     --set-env-vars \
#       DB_PASSWORD=secretref:db-password \
#       ADMIN_JWT_SECRET=secretref:admin-jwt-secret
#
# ROTATION STRATEGY:
#   - Secrets rotate every 90 days (Key Vault expiration policy)
#   - DB passwords: rotate via Azure Flexible Server admin API
#     1. Generate new password in Key Vault (new version)
#     2. ALTER ROLE auditgraph_app PASSWORD 'new_pw' on Flex Server
#     3. Container Apps auto-pulls new secret version on next restart
#     4. Rolling restart: az containerapp revision restart
#   - JWT secrets: rotate by creating new KV version + restart
#     (old tokens remain valid until they expire — 15min access, 7d refresh)
#   - Rotation events logged via SecurityEventLogger.secret_rotation()
#
# WHAT MUST NEVER HAPPEN:
#   - DB_PASSWORD in .env files committed to git (gitignore enforces)
#   - Secrets in Dockerfile ENV or docker-compose.yml
#   - Secrets in CI/CD workflow YAML (use GitHub Secrets → KV only)
#   - Secrets in log output (SecretRedactionFilter prevents this)
#
# ═══════════════════════════════════════════════════════════════════════
# 2. BACKUP & RESTORE SAFETY
# ═══════════════════════════════════════════════════════════════════════
#
# Azure Flexible Server provides automated backups:
#
# BACKUP SCHEDULE:
#   - Full backup: Daily (automated by Azure, 35-day retention)
#   - WAL archiving: Continuous (every few minutes)
#   - Point-in-time recovery: Any second within the 35-day window
#   - Geo-redundant backup: ENABLED (replicates to paired region)
#
# az postgres flexible-server update \
#   --name auditgraph-db-dev \
#   --resource-group auditgraph-dev-rg \
#   --backup-retention 35 \
#   --geo-redundant-backup Enabled
#
# RESTORE PROCEDURE:
#   1. Identify the target timestamp (from activity_log or Azure Metrics)
#   2. Create a new Flex Server from the PITR backup:
#      az postgres flexible-server restore \
#        --name auditgraph-db-restored \
#        --source-server auditgraph-db-dev \
#        --restore-time "2026-03-03T10:30:00Z"
#   3. Validate restored data (run test_isolation_stress.py against restored DB)
#   4. Swap DNS / update DB_HOST to point at restored server
#
# MULTI-TENANT RESTORE SAFETY:
#   - PITR restores ALL tenants to the same point in time (no partial restore)
#   - For single-tenant restore: use pg_dump with WHERE organization_id = N
#   - CROSS-TENANT RESTORE RISK: If Tenant A requests a restore,
#     restoring the full DB also reverts Tenant B. Mitigations:
#       a) Logical backup per tenant (pg_dump + COPY ... WHERE org_id = N)
#       b) Table-level restore into a staging schema, then MERGE
#       c) Never restore full DB for a single-tenant request
#   - After any restore, run validate_rls_drift() to confirm RLS intact
#
# ═══════════════════════════════════════════════════════════════════════
# 3. DISASTER RECOVERY PLAN
# ═══════════════════════════════════════════════════════════════════════
#
# RPO (Recovery Point Objective): < 5 minutes
#   - WAL archiving is continuous (~minutes of lag)
#   - Geo-redundant backup provides cross-region protection
#
# RTO (Recovery Time Objective): < 30 minutes
#   - PITR restore: ~10-15 minutes (Azure)
#   - Container Apps redeploy: ~5 minutes
#   - DNS propagation: ~5 minutes
#   - Health check + validation: ~5 minutes
#
# REPLICA PROMOTION WORKFLOW:
#   1. Primary becomes unreachable (Azure auto-detects within 30s)
#   2. Azure promotes read replica to primary (if configured)
#   3. DB_HOST DNS updates automatically (Flex Server HA)
#   4. Container Apps reconnect on next pool refresh
#   5. Verify: run health check, validate_rls_drift()
#
# FAILOVER VALIDATION CHECKLIST:
#   [ ] Database responds to SELECT 1 on new primary
#   [ ] RLS policies intact (validate_rls_drift returns ok=True)
#   [ ] FORCE RLS enabled on all tenant tables
#   [ ] DB_USER has NOBYPASSRLS confirmed
#   [ ] Connection pool re-initialized (_PoolManager.close_all() + init)
#   [ ] Scheduler restarted and jobs running
#   [ ] Health endpoint returns 200 with all checks passing
#   [ ] Run test_isolation_stress.py against new primary
#   [ ] Notify ops team via Slack/Teams webhook
#   [ ] Document the incident in activity_log (manual admin entry)
#
# ═══════════════════════════════════════════════════════════════════════
# 4. INFRASTRUCTURE GUARDRAILS
# ═══════════════════════════════════════════════════════════════════════
#
# 4a. Azure Policy (enforce via ARM/Terraform):
#
#   - DENY: PostgreSQL Flex Server without SSL enforcement
#   - DENY: PostgreSQL Flex Server in public access mode (must use VNET)
#   - DENY: Container Apps without managed identity
#   - DENY: Key Vault without soft-delete + purge protection
#   - AUDIT: PostgreSQL roles with BYPASSRLS (should only be admin)
#
# 4b. Database Role Safety (enforced at startup by validate_rls_startup):
#
#   - DB_USER (auditgraph_app): NOBYPASSRLS, NOSUPERUSER, LOGIN
#   - DB_ADMIN_USER (auditgraph_admin): BYPASSRLS, NOSUPERUSER, LOGIN
#   - No role should have SUPERUSER except the Azure-managed admin
#   - validate_rls_startup() runs at every boot and fails fast on violation
#
# 4c. FORCE RLS Policy (enforced at startup by enforce_force_rls):
#
#   - All 44+ tables with organization_id have FORCE ROW LEVEL SECURITY
#   - This makes RLS apply even to the table owner
#   - enforce_force_rls() runs at every boot (idempotent)
#   - validate_rls_drift() runs nightly at 04:30 UTC
#
# 4d. CI/CD Isolation Test Gate (deploy.yml):
#
#   - test-guardrails job runs BEFORE build-backend/build-frontend
#   - Spins up ephemeral PostgreSQL 15 service container
#   - Runs test_production_guardrails.py + test_isolation_stress.py
#   - Build is BLOCKED if any isolation test fails
#   - Zero tolerance: any leakage = pipeline abort
#
# ═══════════════════════════════════════════════════════════════════════
# 5. OBSERVABILITY HARDENING
# ═══════════════════════════════════════════════════════════════════════
#
# 5a. Structured Security Events (app/security_events.py):
#   - SecurityEventLogger emits JSON events for SIEM ingestion
#   - Event types: TENANT_CONTEXT_VIOLATION, RLS_DRIFT_DETECTED,
#     ADMIN_GUARD_BLOCKED, POOL_EXHAUSTION, SLOW_QUERY,
#     AUTH_FAILURE, SECRET_ROTATION, MIGRATION_APPLIED
#   - All events include: severity, tenant_id, correlation_id, timestamp
#   - Routed to auditgraph.security logger for separate alerting
#
# 5b. Secret Redaction (app/logging_config.py):
#   - SecretRedactionFilter scans ALL log output before emission
#   - Patterns: password=, secret=, Bearer tokens, ag_ API keys,
#     Azure connection strings (AccountKey=, SharedAccessSignature=)
#   - Applied in both development AND production formatters
#
# 5c. Slow Query Alerting:
#   - Threshold: DB_SLOW_QUERY_MS (default 100ms)
#   - execute_safe() logs WARNING + SecurityEventLogger.slow_query()
#   - Includes: elapsed_ms, org_id, Flask endpoint, SQL preview
#   - Alert rule: Azure Monitor → query auditgraph.security for
#     event_type=SLOW_QUERY, count > 10 in 5min window
#
# 5d. Tenant Skew Detection:
#   - Database.detect_tenant_skew() checks row distribution
#   - Alerts when any tenant owns >25% of total rows in a table
#   - Runs as part of nightly RLS audit job
#   - SecurityEventLogger.tenant_skew() for SIEM
#
# 5e. Pool Exhaustion Alerting:
#   - _PoolManager.stats() checks low-water mark (<10% available)
#   - Pool fallback to direct connection → POOL_EXHAUSTION event
#   - Health check includes pool utilization_pct
#   - Alert rule: utilization_pct > 90% for 5 consecutive checks
#
# ═══════════════════════════════════════════════════════════════════════
# 6. PRODUCTION READINESS CHECKLIST
# ═══════════════════════════════════════════════════════════════════════
#
# HEALTH ENDPOINTS:
#   [x] GET /health/live        — Always 200 (liveness probe)
#   [x] GET /health/ready       — 503 during migration, startup, DB down
#   [x] GET /api/health         — Alias for /health/ready
#   [x] GET /api/health/detailed — Full diagnostics (DB latency, scheduler, pool)
#   [x] GET /api/metrics        — Prometheus text format (public)
#   [x] GET /api/system/health  — Admin dashboard (auth required)
#
# LIVENESS vs READINESS:
#   - Liveness: "Is the process alive?" → restart if not
#   - Readiness: "Can it serve traffic?" → stop routing if not
#   - Readiness returns 503 when:
#       * _migration_in_progress = True (DDL running)
#       * _startup_complete = False (still initializing)
#       * Database unreachable
#       * Scheduler not running
#
# ROLLING DEPLOY SAFETY:
#   - Container Apps uses rolling update (1 new → 1 old)
#   - New revision starts, runs DDL migrations during startup
#   - Readiness probe returns 503 until _migration_in_progress = False
#   - Load balancer only routes to old revision during this window
#   - After readiness passes, traffic shifts to new revision
#   - Old revision drains (in-flight requests complete)
#   - gunicorn --preload ensures DDL runs once (in master, before fork)
#
# MIGRATION DURING DEPLOY:
#   - All DDL is idempotent (CREATE TABLE IF NOT EXISTS, ADD COLUMN IF NOT EXISTS)
#   - schema_migrations table tracks applied versions (no double-apply)
#   - _migration_in_progress flag gates readiness probe
#   - Backward-compatible migrations only (additive, never destructive)
#   - If migration fails, startup continues but logs CRITICAL
#   - Never rename/drop columns in the same deploy as code that uses them
#     → two-phase: (1) add new column + backfill, (2) next deploy removes old
#
# FEATURE FLAG STRATEGY:
#   - Settings table (key-value) serves as feature flag store
#   - Pattern: setting key like 'feature_flag_{name}' = 'true'/'false'
#   - Checked at request time via Database.get_setting(key)
#   - No external feature flag service needed at current scale
#   - For per-tenant flags: settings table already has organization_id
#   - For global flags: NULL organization_id = applies to all
#
# ═══════════════════════════════════════════════════════════════════════
# RISK ASSESSMENT
# ═══════════════════════════════════════════════════════════════════════
#
# MITIGATED RISKS (by this hardening):
#   [LOW]  Secret exposure in logs       → SecretRedactionFilter
#   [LOW]  Cross-tenant data leakage     → 5-layer RLS defense
#   [LOW]  Admin connection misuse       → ENFORCE_ADMIN_GUARD
#   [LOW]  Pool exhaustion under load    → Fallback + alerting
#   [LOW]  Migration breaks live traffic → Readiness gate
#
# RESIDUAL RISKS (require ongoing attention):
#   [MED]  Single-region deployment      → Geo-redundant backup covers data,
#                                          but RTO is ~30min for full region fail
#   [MED]  JWT secret rotation gap       → Tokens valid until natural expiry
#                                          (15min access, 7d refresh)
#   [MED]  Tenant restore isolation      → Full PITR affects all tenants;
#                                          per-tenant restore is manual
#   [LOW]  Replication lag on reads      → Not yet implemented (design only)
#   [LOW]  PgBouncer misconfiguration    → Detected at startup, but only
#                                          if PgBouncer identifies itself
#
# ACCEPTED RISKS:
#   [LOW]  Single Flex Server (no HA)    → Acceptable for current scale;
#                                          Azure provides 99.9% SLA
#   [LOW]  No WAF                        → Container Apps ingress handles
#                                          basic DDoS; WAF add when needed
# ==========================================================================
