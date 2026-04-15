# Section 10 -- Operations

## Deployment Architecture

### Production Deployment (Azure Container Apps)

```
┌──────────────────────────────────────────────────────────────────┐
│  Azure Container Apps Environment                                │
│  (auditgraph-env, eastus, static IP: 13.92.66.67)              │
│                                                                  │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │ auditgraph-api│  │auditgraph-web │  │auditgraph-    │       │
│  │ (Backend)     │  │ (Client Portal)│  │admin          │       │
│  │               │  │               │  │ (Admin Portal) │       │
│  │ Python 3.11   │  │ nginx:alpine  │  │ nginx:alpine  │       │
│  │ Gunicorn      │  │               │  │               │       │
│  │ 2 workers     │  │               │  │               │       │
│  │ Port 5000     │  │ Port 3000     │  │ Port 3000     │       │
│  └───────┬───────┘  └───────────────┘  └───────────────┘       │
│          │                                                       │
│          ▼                                                       │
│  ┌───────────────┐                                              │
│  │ PostgreSQL 15 │  auditgraph-db-dev.postgres.database.azure  │
│  │ (Flexible)    │  SSL: require                                │
│  │ 54 tables     │                                              │
│  └───────────────┘                                              │
│                                                                  │
│  ┌───────────────┐                                              │
│  │ Azure CR      │  auditgraphcr.azurecr.io                    │
│  │ (Basic tier)  │                                              │
│  └───────────────┘                                              │
└──────────────────────────────────────────────────────────────────┘
```

### Domain Mapping

| Service | URL |
|---------|-----|
| API | `https://api.auditgraph.ai` |
| Client Portal | `https://app.auditgraph.ai` |
| Admin Portal | `https://admin.auditgraph.ai` |
| Dev API | `https://dev.api.auditgraph.ai` |
| Dev Client | `https://dev.app.auditgraph.ai` |
| Dev Admin | `https://dev.admin.auditgraph.ai` |

### Backend Container

```
Base image:     python:3.11-slim
Runtime:        Gunicorn + Flask
Workers:        2 (with --preload to avoid DDL deadlock)
Timeout:        120 seconds
Port:           5000
Health check:   GET /health every 30 seconds
User:           auditgraph (non-root)
```

**The `--preload` flag is critical**: Without it, multiple Gunicorn workers call `create_app()` simultaneously, each running DDL migrations that deadlock on shared tables.

---

## Environment Configuration

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `APP_ENV` | Environment tier | `prod`, `dev`, `local` |
| `DB_HOST` | PostgreSQL hostname | `auditgraph-db.postgres.database.azure.com` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_NAME` | Database name | `auditgraph` |
| `DB_USER` | App user (NOBYPASSRLS) | `auditgraph_app` |
| `DB_PASSWORD` | App user password | (secret) |
| `DB_ADMIN_USER` | Admin user (BYPASSRLS) | `auditgraph_admin` |
| `DB_ADMIN_PASSWORD` | Admin user password | (secret) |
| `DB_SSLMODE` | SSL mode | `require` (Azure), `disable` (local) |
| `ADMIN_JWT_SECRET` | Admin portal JWT signing key | (secret, 256+ bits) |
| `CLIENT_JWT_SECRET` | Client portal JWT signing key | (secret, 256+ bits) |
| `ENCRYPTION_KEY` | Fernet encryption key | (base64-encoded 32 bytes) |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENCRYPTION_KEYS` | (none) | Multi-key rotation (comma-separated, newest first) |
| `DB_POOL_MIN` | 2 | Minimum pool connections |
| `DB_POOL_MAX` | 20 | Maximum pool connections |
| `DB_SLOW_QUERY_MS` | 100 | Slow query threshold |
| `DISCOVERY_INTERVAL_HOURS` | 12 | Scheduled discovery interval |
| `SENDGRID_API_KEY` | (none) | Email notification service |
| `COPILOT_API_KEY` | (none) | AI Copilot (Anthropic Claude) |
| `SLACK_WEBHOOK_URL` | (none) | Slack notifications |
| `TEAMS_WEBHOOK_URL` | (none) | Teams notifications |

### Generating Secrets

```bash
# Generate JWT secret
python3 -c "import secrets; print(secrets.token_hex(32))"

# Generate Fernet encryption key
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## Secret Management

### Azure Key Vault Integration

In production, secrets are stored in Azure Key Vault and injected as environment variables by Azure Container Apps:

| Key Vault Secret | Environment Variable |
|-----------------|---------------------|
| `db-password` | `DB_PASSWORD` |
| `db-admin-password` | `DB_ADMIN_PASSWORD` |
| `admin-jwt-secret` | `ADMIN_JWT_SECRET` |
| `client-jwt-secret` | `CLIENT_JWT_SECRET` |
| `encryption-key` | `ENCRYPTION_KEY` |
| `copilot-api-key` | `COPILOT_API_KEY` |

### Key Rotation Procedures

#### JWT Secret Rotation

```
1. Generate new secret:
   python3 -c "import secrets; print(secrets.token_hex(32))"

2. Update Key Vault secret

3. Deploy updated environment

4. Active sessions using the old secret will fail on next refresh.
   Users will need to log in again.

5. No data migration needed (JWTs are stateless).
```

#### Encryption Key Rotation

```
1. Generate new Fernet key:
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

2. Set ENCRYPTION_KEYS with new key first, old key second:
   ENCRYPTION_KEYS=NEW_KEY,OLD_KEY

3. Deploy updated environment.
   - New encryptions use NEW_KEY
   - Old encrypted values decrypt via OLD_KEY (MultiFernet fallback)

4. (Optional) Rotate existing values:
   Call rotate_encrypted_field() on stored encrypted values.

5. After rotation is complete, remove old key:
   ENCRYPTION_KEYS=NEW_KEY
```

#### Database Password Rotation

```
1. Create new password in PostgreSQL:
   ALTER USER auditgraph_app PASSWORD 'new-password';

2. Update Key Vault secret

3. Deploy updated environment

4. Connection pool will refresh with new credentials.
```

---

## Monitoring

### Health Endpoints

| Endpoint | Purpose | Auth | Returns |
|----------|---------|------|---------|
| `GET /health` | Basic liveness | None | Always 200 |
| `GET /health/live` | Kubernetes liveness | None | Always 200 |
| `GET /health/ready` | Kubernetes readiness | None | 200 or 503 |
| `GET /api/health` | Detailed diagnostics | None | DB, scheduler, system, external APIs |
| `GET /api/system/health` | Admin health dashboard | Portal role | API stats, top endpoints, table sizes |
| `GET /api/metrics` | Prometheus metrics | Admin | Counter/histogram text format |

### Health Check Response

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

### Status Meanings

| Status | Condition | Action |
|--------|-----------|--------|
| `healthy` | All systems operational | None |
| `degraded` | Non-critical component down (e.g., external API unreachable) | Monitor, may self-recover |
| `unhealthy` | Critical component down (DB, scheduler) | Investigate immediately |

### Prometheus Metrics

Available at `GET /api/metrics`:

```
# HELP requests_total Total HTTP requests
# TYPE requests_total counter
requests_total{method="GET",status="200"} 15234.0

# HELP request_duration_seconds Request duration histogram
# TYPE request_duration_seconds histogram
request_duration_seconds_bucket{endpoint="/api/identities",le="0.1"} 1000.0

# HELP active_requests Current in-flight requests
# TYPE active_requests gauge
active_requests 3.0
```

---

## Logging

### Log Format

**Development** (human-readable):
```
[2026-03-16 14:30:00] [INFO] [app.scheduler] Discovery run completed: org=7, run=108, identities=248
```

**Production** (structured JSON):
```json
{
  "timestamp": "2026-03-16T14:30:00.123Z",
  "level": "INFO",
  "logger": "app.scheduler",
  "message": "Discovery run completed",
  "request_id": "req_abc123",
  "organization_id": 7,
  "run_id": 108,
  "total_identities": 248
}
```

### Log Levels

| Level | When | Examples |
|-------|------|---------|
| `DEBUG` | Detailed trace (dev only) | SQL queries, API response bodies |
| `INFO` | Normal operations | Discovery started/completed, user login |
| `WARNING` | Potential issues | Slow query, credential expiring soon |
| `ERROR` | Errors | API call failed, database error |
| `CRITICAL` | System failure | RLS violation, pool exhaustion |

### Secret Redaction

All log output passes through a redaction filter:

| Pattern | Replacement |
|---------|-------------|
| `password=mysecret` | `password=[REDACTED]` |
| `Bearer eyJhbG...` | `Bearer [REDACTED]` |
| `ag_1234567890abcdef...` | `[REDACTED_API_KEY]` |
| `client_secret=abc123` | `client_secret=[REDACTED]` |
| `AccountKey=base64...` | `AccountKey=[REDACTED]` |

---

## Data Retention

### Retention Policy

Automated cleanup runs daily at 03:00 UTC:

| Data Type | Default Retention | Setting Key |
|-----------|-------------------|-------------|
| Discovery runs | 90 days | `retention_discovery_days` |
| Drift reports | 90 days | `retention_drift_days` |
| Activity log | 180 days | `retention_activity_days` |
| Anomalies | 180 days | `retention_anomalies_days` |
| SOAR actions | 90 days | `retention_soar_days` |
| Notifications | 90 days | `retention_notifications_days` |

### Manual Cleanup

```http
POST /api/system/cleanup
Authorization: Bearer eyJ... (admin)
```

### Storage Stats

```http
GET /api/system/storage
Authorization: Bearer eyJ... (admin)
```

Returns table sizes, row counts, and oldest records for capacity planning.

---

## Troubleshooting

### Common Issues

#### Database Connection Failures

**Symptom**: `GET /api/health` returns `unhealthy`, database shows `connected: false`

**Causes and fixes**:
1. **Wrong credentials**: Verify `DB_USER`/`DB_PASSWORD` in environment
2. **SSL mode mismatch**: Azure requires `DB_SSLMODE=require`
3. **Network access**: Ensure the database allows connections from the Container Apps VNet
4. **Pool exhaustion**: Check `active_requests` metric; increase `DB_POOL_MAX` if consistently at capacity

#### Discovery Failures

**Symptom**: Discovery runs fail with status `failed`

**Diagnosis**:
1. Check `GET /api/runs` for the failed run's error message
2. Check circuit breaker status at `GET /api/health` — if `graph_api` is `open`, Microsoft Graph is unreachable
3. Verify connector credentials haven't expired
4. Check the connector's Azure directory ID matches the app registration's tenant

#### RLS Context Errors

**Symptom**: `TENANT_CONTEXT_VIOLATION` security events

**Causes**:
1. Code calling `Database()` without `organization_id` inside a request handler
2. Connection pool returning a connection with stale context (should be extremely rare due to RESET on checkout)

**Fix**: Ensure all request-scoped database calls use `Database(organization_id=g.current_user['org_id'])`.

#### Scheduler Not Running

**Symptom**: `GET /api/scheduler` returns `running: false`

**Causes**:
1. Worker process crashed and didn't restart
2. Gunicorn without `--preload` (multiple workers trying to start scheduler)
3. Database migrations blocking startup

**Fix**: Check container logs. Restart the container. Verify `--preload` flag in Gunicorn command.

#### Slow Queries

**Symptom**: `SLOW_QUERY` security events, high latency on `/api/identities`

**Diagnosis**:
1. Check `GET /api/metrics` for `request_duration_seconds` by endpoint
2. Review slow query threshold: `DB_SLOW_QUERY_MS` (default 100ms)
3. Large organizations with 1000+ identities may need query optimization

**Fix**: Ensure database indices are up to date. Consider increasing `DB_POOL_MAX` for concurrent access.

---

## CI/CD Pipeline

### Production Deploy

```
1. Push to main branch (or workflow_dispatch)
2. GitHub Actions: deploy.yml
   a. Run guardrail tests (pip-audit, production checks)
   b. Build backend image: az acr build --platform linux/amd64
   c. Build frontend image: az acr build --platform linux/amd64
   d. Deploy to Azure Container Apps
3. Container Apps pulls new images
4. Health check passes → traffic routes to new containers
```

### Build Notes

- Always build with `--platform linux/amd64` (avoids arm64/amd64 cross-compile issues on Mac)
- Use `az acr build` (not local `docker build`) to build in Azure Container Registry directly
- Frontend builds with `REACT_APP_API_URL` baked in at compile time

---

## References

- [Architecture](architecture.md) -- System architecture overview
- [Security Architecture](security-architecture.md) -- Security configuration
- [Security Features](security-features.md) -- Monitoring and circuit breakers
- [API Reference](api-reference.md) -- Health and system endpoints
