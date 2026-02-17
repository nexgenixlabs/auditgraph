# AuditGraph Frontend & Deployment Reference

## Frontend Architecture

### Technology Stack
- React 19 + TypeScript
- Tailwind CSS for styling
- React Router v6 for routing
- @xyflow/react v12 for graph visualization
- Recharts for charts
- jsPDF + autoTable for PDF generation
- No Redux/Zustand — hooks + context only

### State Management Patterns
- `AuthContext` — JWT token management, global fetch interceptor, role-based permissions
- `TenantContext` — Subdomain/portal detection
- `useState` + `useEffect` hooks throughout
- `useDashboardPreferences` — Widget customization hook
- `useTheme` — Dark mode toggle hook
- `useToast` — Toast notification hook
- No centralized state store

### API Communication
- Direct `fetch()` calls to `/api/*` endpoints
- Global fetch interceptor in AuthContext auto-attaches Bearer token
- Auto-refreshes expired tokens (401 -> refresh -> retry)
- Many pages use `AbortController` for request cancellation
- Parallel fetches with `Promise.all` on Dashboard mount (11 concurrent)

### Routing Structure
```
/                      -> Overview (attack surface score, risk drivers)
/dashboard             -> 6-tab operational dashboard
/identities            -> Identity inventory table
/identities/:id        -> 13-tab identity detail
/reports               -> PDF report generation
/drift                 -> Drift history timeline
/settings              -> 13-section settings
/activity              -> Activity log
/login                 -> Login page
/sso-callback          -> SSO code exchange
/forgot-password       -> Password reset request
/reset-password        -> Password reset form
/spns                  -> SPN dashboard
/app-registrations     -> App registration audit
/resources             -> Azure resources (storage + KV)
/resources/detail      -> Resource detail (5 tabs)
/compliance            -> Compliance intelligence (dark, 3 tabs)
/identity-governance   -> NHI governance
/role-mining           -> Role optimization
/access-reviews        -> Access review campaigns
/identity-groups       -> Identity groups
/subscriptions         -> Cloud subscription management
/notifications         -> Notification center
/system-health         -> Platform monitoring
/compare               -> Identity side-by-side comparison
/exports               -> Centralized export page
/admin                 -> Admin portal (own layout)
/admin/overview        -> Platform overview
/admin/tenants         -> Tenant management
/admin/users           -> Portal user management
/admin/onboarding      -> Client onboarding wizard
/admin/monitoring      -> Infrastructure monitoring
/admin/billing         -> Revenue dashboard
/admin/profile         -> Admin self-service profile
```

### Page Inventory (38+ pages)

| Page | File | Lines | API Calls | Key Features |
|------|------|-------|-----------|--------------|
| Overview | Overview.tsx | ~500 | 5 | ArcGauge, risk drivers, credential snapshot |
| Dashboard | Dashboard.tsx | ~800 | 11 | 6 tabs, 20+ widgets, discovery trigger |
| Identities | Identities.tsx | 1572 | 8+ | QueryBuilder, IdentityDrawer, 4 exports |
| IdentityDetail | IdentityDetail.tsx | 2000+ | 10+ | 13 tabs, lazy loading |
| Reports | Reports.tsx | ~200 | 2 | 3 PDF types |
| DriftHistory | DriftHistory.tsx | ~400 | 2 | Expandable rows, 5 change sections |
| ActivityLog | ActivityLog.tsx | ~300 | 1 | 16 action type badges |
| Settings | Settings.tsx | 2000+ | 20+ | 13+ config sections |
| Login | Login.tsx | ~400 | 4 | SSO, tenant picker, forced password change |
| SPNDashboard | SPNDashboard.tsx | ~800 | 3 | Drill-down panel, blast radius, PDF |
| AppRegistrations | AppRegistrations.tsx | ~600 | 3 | Drill-down panel, CSV export |
| Resources | Resources.tsx | ~500 | 2 | Storage+KV, audit posture bar |
| ResourceDetail | ResourceDetail.tsx | ~600 | 2 | 5 tabs (Overview/Security/Network/Access/Compliance) |
| Compliance | Compliance.tsx | ~700 | 2 | Dark theme, 3 tabs, RiskGauge |
| ServiceAccountGovernance | ServiceAccountGovernance.tsx | ~800 | 4 | Dark theme, governance decisions |
| SystemHealth | SystemHealth.tsx | ~400 | 2 | 30s auto-refresh |
| AccessReviews | AccessReviews.tsx | ~700 | 5+ | AI recommendations, bulk decisions |
| IdentityGroups | IdentityGroups.tsx | ~500 | 3 | Group comparison, member management |
| RoleMining | RoleMining.tsx | ~400 | 1 | Toxic combos, role bundles |
| CrossTenantAnalytics | CrossTenantAnalytics.tsx | ~300 | 1 | Superadmin only |
| OnboardingWizard | OnboardingWizard.tsx | ~300 | 3 | 5-step wizard |
| NotificationCenter | NotificationCenter.tsx | ~300 | 3 | Severity/category filters |
| Exports | Exports.tsx | ~200 | 4 | 4 export types x 2 formats |
| Subscriptions | Subscriptions.tsx | ~300 | 4 | Activate/deactivate |
| IdentityComparison | IdentityComparison.tsx | ~400 | 2 | Side-by-side diff |
| AdminConsole | AdminConsole.tsx | ~300 | 0 | Own login, 7 sub-pages |
| AdminOverview | AdminOverview.tsx | ~300 | 1 | Plan distribution, tenant health |
| AdminTenants | AdminTenants.tsx | 883 | 6 | Cloud config, pricing, logo |
| AdminUsers | AdminUsers.tsx | ~400 | 3 | Profile panel, password reset |
| AdminBilling | AdminBilling.tsx | ~400 | 1 | MRR/ARR, revenue by cloud |
| AdminMonitoring | AdminMonitoring.tsx | ~500 | 4 | Login session audit, health checks |
| AdminOnboarding | AdminOnboarding.tsx | ~400 | 1 | 6-section wizard |
| AdminProfile | AdminProfile.tsx | ~200 | 3 | Self-service profile |

### Dashboard Widget Components (20+)

All located in `components/dashboard/`:

- **PostureScore** — SVG arc gauge, grade A-F
- **CredentialHealth** — Stacked bar + 2x2 legend cards
- **QuickActions** — 4 navigation buttons with counts
- **RecentChanges** — 5 change type counts
- **RiskHeatMap** — Categories x risk levels intensity grid
- **RiskDonutChart** — SVG donut with hover + legend
- **ComplianceScorecard** — Framework cards with ScoreRing
- **ConditionalAccessCard** — Coverage %, MFA count
- **CloudContextBanner** — Connected providers banner
- **RemediationProgress** — Progress bar + status grid
- **RiskTrendChart** — Recharts AreaChart (4 stacked areas)
- **RoleUsageChart** — Horizontal bar + mini pie
- **AnomalyAlerts** — Anomaly list with severity dots
- **RiskVelocityChart** — Recharts BarChart (inflow/outflow)
- **SOARActivity** — Self-fetching, integration badges
- **ServiceAccountGovernance** — Self-fetching, compliance bar
- **PlatformHealth** — Self-fetching, 2x2 status grid
- **CustomizePanel** — Slide-out widget toggles
- **ExpiryTracker** — Self-fetching, expiry timeline
- **ResourceOverview** — Self-fetching, risk/compliance rings
- **CredentialIntelligence** — Self-fetching, 3-column layout
- **TrustAccessPanel** — Self-fetching, 4 summary cards

### Graph Components
- `nodes.tsx` — 13 custom ReactFlow node types
- `AccessGraphTab.tsx` — 3 view modes (executive/technical/attack_paths)
- `AttackPathView.tsx` — 5 attack path types, animated edges
- `ExposureGraph.tsx` — Multi-identity graph, 6 presets

### Utility Files
- `pdfGenerator.ts` — Full audit + executive + compliance PDFs
- `spnPdfGenerator.ts` — SPN privilege report PDF
- `exportUtils.ts` — CSV/JSON export utilities
- `maskCredential.ts` — HIPAA credential masking
- `complianceMapping.ts` — Risk-to-compliance framework mapping

### Constants Files
- `metrics.ts` — Identity categories, risk levels, thresholds, labels
- `pricing.ts` — Cloud pricing, tiers, discounts, calculations
- `design.ts` — Colors, risk colors, dashboard tabs, score helpers

### Known Frontend Issues
1. Settings.tsx (2000+ lines) should be split into sub-components
2. IdentityDetail.tsx (2000+ lines) is very large
3. CopilotPanel uses dangerouslySetInnerHTML (XSS risk)
4. IdentityDrawer uses `any` type for usage data
5. URL param sync uses different approaches across pages
6. Several silent error catches (`catch { /* ignore */ }`)
7. Self-fetching dashboard widgets cause many concurrent API requests

---

## Deployment Architecture

### Container Apps (Azure)

```
+-----------------------------------------------+
|           Azure Container Apps                 |
|  Environment: auditgraph-env                   |
|  Resource Group: auditgraph-dev-rg             |
|                                                |
|  +-------------------+  +-------------------+  |
|  |  auditgraph-api   |  |  auditgraph-web   |  |
|  |  python:3.11-slim  |  |  nginx:alpine     |  |
|  |  gunicorn (2w)     |  |  static SPA       |  |
|  |  port 5000         |  |  port 3000        |  |
|  +--------+-----------+  +--------+----------+  |
|           |                       |              |
|  api.auditgraph.ai      app.auditgraph.ai      |
|                          admin.auditgraph.ai    |
|                                                 |
|           Static IP: 13.92.66.67                |
+-----------+-------------------------------------+
            |
+-----------+-------------------------------------+
|  Azure DB for PostgreSQL (Flexible Server)      |
|  Host: auditgraph-db-dev.postgres.database.azure|
|  DB_SSLMODE=require                             |
+-------------------------------------------------+
```

### Container Registry

```
+-------------------------------------------------+
|  Azure Container Registry (ACR)                 |
|  Registry: auditgraphcr.azurecr.io             |
|  Tier: Basic                                    |
|  Region: eastus                                 |
|                                                 |
|  Images:                                        |
|    auditgraphcr.azurecr.io/auditgraph-api      |
|    auditgraphcr.azurecr.io/auditgraph-web      |
|                                                 |
|  Tags: SHA-based + latest                       |
+-------------------------------------------------+
```

### Docker Configuration

**Backend Dockerfile** (`backend/Dockerfile`, base: python:3.11-slim):

```
System deps: gcc, libpq-dev, libxml2-dev, libxmlsec1-dev (for python3-saml)

CMD: gunicorn --bind 0.0.0.0:5000 \
              --workers 2 \
              --timeout 120 \
              --preload \
              --access-logfile - \
              wsgi:app

Health check:
  python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')"
```

The `--preload` flag is critical. Without it, each gunicorn worker forks and independently calls `create_app()`, which triggers DDL statements (like `CREATE TABLE IF NOT EXISTS`) in parallel. These concurrent DDL calls deadlock against each other on PostgreSQL. With `--preload`, the app is loaded once in the master process before forking.

**Frontend Dockerfile** (`frontend/Dockerfile`, base: node:20-alpine -> nginx:alpine):

```
Stage 1 (build):
  npm ci
  npm run build
  Build arg: REACT_APP_API_URL

Stage 2 (serve):
  Copy build output to /usr/share/nginx/html
  Copy nginx.prod.conf to /etc/nginx/conf.d/default.conf

Health check:
  wget -q -O - http://localhost:3000/
```

### CI/CD Pipeline (GitHub Actions)

File: `.github/workflows/deploy.yml`

**Trigger**: Push to `main` branch or manual `workflow_dispatch`

**Pipeline flow**:

```
Push to main
     |
     v
+----+----+          +----+----+
| Build   |          | Build   |
| Backend |          | Frontend|
| (ACR)   |          | (ACR)   |
+---------+          +---------+
     |                    |
     +--------+-----------+
              |
              v
      +-------+-------+
      |    Deploy      |
      | Container Apps |
      | (both images)  |
      +-------+--------+
              |
              v
      +-------+--------+
      | Post-deploy    |
      | 30s sleep +    |
      | health check   |
      +----------------+
```

**Job details**:

1. `build-backend` — Uses `docker/build-push-action` to build on ACR with SHA + `latest` tags
2. `build-frontend` — Same pattern, passes `REACT_APP_API_URL=https://api.auditgraph.ai` as build arg
3. `deploy` — Uses `azure/login` + `azure/container-apps-deploy-action` for both containers
4. Post-deploy — 30s sleep followed by health check request

**Required secrets**:

| Secret | Purpose |
|--------|---------|
| ACR_LOGIN_SERVER | `auditgraphcr.azurecr.io` |
| ACR_USERNAME | ACR admin username |
| ACR_PASSWORD | ACR admin password |
| AZURE_CREDENTIALS | Service principal JSON (`auditgraph-cicd`) |

**Build note**: Always use `az acr build --platform linux/amd64` for ACR builds, not local `docker build`. Local builds on Mac produce arm64 images that fail on Azure Container Apps (which runs amd64).

### Nginx Configuration

**nginx.prod.conf** (production):
- Serves static SPA files from `/usr/share/nginx/html`
- Enables gzip compression
- 1-year cache TTL for `/static/` assets (hashed filenames)
- `try_files $uri $uri/ /index.html` for React Router client-side routing
- Listens on port 3000
- No /api/ proxy — frontend calls `https://api.auditgraph.ai` directly (baked in at build time)

**nginx.conf** (local dev / docker-compose):
- Proxies `/api/` requests to `backend:5000`
- Used when running frontend and backend together in Docker Compose

### Local Development

```bash
# Backend (port 5001)
cd backend
./venv/bin/python -m app.main

# Frontend (port 3000, Vite/CRA proxy forwards /api to localhost:5001)
cd frontend
npm start
```

The frontend dev server proxies `/api` requests to `localhost:5001`, matching the backend's local port. In production, the backend listens on port 5000 (gunicorn default inside the container).

### Environment Variables

**Backend** (Container App environment):

| Variable | Value | Notes |
|----------|-------|-------|
| DATABASE_URL | postgres://...@auditgraph-db-dev... | Full connection string |
| DB_SSLMODE | require | Required for Azure PG |
| JWT_SECRET | (secret) | Token signing key |
| ADMIN_USERNAME | admin | Default admin account |
| ADMIN_PASSWORD | (secret) | Default admin password |
| FLASK_ENV | production | Disables debug mode |

**Frontend** (build-time):

| Variable | Value | Notes |
|----------|-------|-------|
| REACT_APP_API_URL | https://api.auditgraph.ai | Baked into JS bundle |

### Deployment Gaps

1. **No non-root container user** — Both containers run as root inside the container. Should add a non-root user for security hardening.

2. **No nginx security headers** — Missing X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options headers in nginx.prod.conf.

3. **No rollback strategy on failed deploys** — If a new image is broken, there is no automated rollback. Manual intervention required via Azure CLI to revert to previous image tag.

4. **No staging environment** — Only one environment (`auditgraph-env`). Changes deploy directly to production on push to main.

5. **30s fixed sleep instead of polling health check** — The post-deploy step sleeps for a fixed 30 seconds rather than polling the health endpoint with retries and a timeout.

6. **No frontend health verification post-deploy** — Only the backend health endpoint is checked after deployment. The frontend container could be unhealthy without detection.

7. **Backend comment says "4 workers" but uses 2** — A code comment references 4 gunicorn workers, but the actual CMD specifies `--workers 2`.

8. **Metrics not shared across gunicorn workers** — The `MetricsCollector` singleton is in-memory and per-process. With `--preload` and 2 workers, each worker has its own copy, so request metrics are split across workers and incomplete.
