# Phase 4 Build Log — Enterprise Operations & Revenue Infrastructure

**Version:** v3.4.0
**Branch:** dev
**Commit:** `0131a62`
**Date:** 2026-02-26

---

## Phase 3 Gap Fixes (Completed First)

### Gate 29: Snapshot Immutability Enforcement

**Problem:** No explicit protection against mutation of point-in-time audit snapshots via API.

**Fix:**
- Added 405 Method Not Allowed routes for DELETE/PUT/PATCH on `/api/snapshots` and `/api/snapshots/<path>`
- Added 405 protection on `/api/runs/<id>` for DELETE/PUT/PATCH
- Snapshots remain read-only via GET only; data retention cleanup happens internally via scheduler (not API)

**Files:** `backend/app/main.py`

---

### Gate 32: JSON Export for GRC Tools

**Problem:** No single comprehensive JSON export suitable for SIEM/GRC tool integration.

**Built:**
- `GET /api/export/evidence-json` — comprehensive GRC-compatible evidence package
- Schema: `auditgraph-grc-evidence-v1`
- Sections: discovery runs metadata, identity inventory (risk + category distribution, top 25 risks), compliance posture (all frameworks evaluated), drift summary (latest), remediation status (by status), credential health, sensitive data classifications
- Tenant-scoped, connection-scoped, activity-logged

**Files:** `backend/app/api/handlers.py` (new `_export_evidence_json()` function)

---

## Phase 4 Tasks

### Task 1: Multi-Tenant Onboarding Flow

**What changed:**
- Rewrote `OnboardingWizard.tsx` from 5 steps to 6 steps: Welcome → Cloud Provider → Credentials → Test → Configure → Launch
- Added cloud provider selection step (Azure active, AWS/GCP marked "Coming Soon")
- Dark theme (`#0B1220` background) matching the rest of the portal
- Added required permissions info box on credentials step
- Added onboarding checklist view (shown when onboarding already completed) with 5 milestones:
  1. Set organization name
  2. Connect a cloud provider
  3. Run first discovery scan
  4. Review discovered identities
  5. Configure notifications

**Backend changes:**
- Enhanced `GET /api/onboarding/status` to return `checklist` array with `done` status per item, `checklist_progress`, `checklist_total`

**Files:** `frontend/src/pages/OnboardingWizard.tsx`, `backend/app/api/handlers.py`

---

### Task 2: Client Portal RBAC Enforcement

**What changed:**
- Added 5 new permission booleans to `AuthContext`:
  - `canManageSettings` — admin only
  - `canExportData` — admin, security_admin, compliance
  - `canManageRemediation` — admin, security_admin
  - `canTriggerScans` — admin, security_admin
  - `canViewCompliance` — admin, security_admin, compliance
- Added `@require_role('admin', 'security_admin', 'compliance')` guards on export endpoints (`/api/export/<type>`, `/api/export/evidence-zip`)

**Files:** `frontend/src/contexts/AuthContext.tsx`, `backend/app/main.py`

---

### Task 3: Entitlement-Based Subscription Management

**What changed:**
- New endpoint: `GET /api/tenant/entitlements`
- Returns: plan name, plan limits (max_active_subs, max_identities), current usage (active subscriptions), blocked features list, subscription term
- Free plan blocks: soar, api_keys, advanced_query, custom_risk_rules, ai_copilot, scheduled_reports, compliance_export, sso
- Trial/Pro/Enterprise: no blocked features

**Files:** `backend/app/api/handlers.py`, `backend/app/main.py`

---

### Task 4: Billing Integration Enhancements

**What changed:**
- New endpoint: `GET /api/client/billing/usage`
- Returns: plan, identity_count vs identity_limit (with percentage), subscription_count vs subscription_limit (with percentage), discovery_runs_last_30d
- Enables frontend usage meters and plan limit warnings

**Files:** `backend/app/api/handlers.py`, `backend/app/main.py`

---

### Task 5: Admin Portal Enhancements

**Status:** Already comprehensive — verified existing implementation covers:
- AdminOverview with plan distribution donut, client health table, status bars
- AdminTenants with configure/delete/edit
- AdminUsers with 4-role RBAC
- AdminBilling with MRR/ARR, revenue breakdowns
- AdminMonitoring with health checks, system metrics
- AdminOnboarding with full client creation form
- AdminProfile with user settings

No additional changes needed.

---

### Task 6: Cloud Integration Guide

**What built:**
- New page: `CloudIntegrationGuide.tsx` at `/integration-guide`
- 3-tab layout: Azure (7 steps), AWS (4 steps), GCP (3 steps)
- Each step has title, description, and optional code block
- Azure tab includes full permissions summary table (5 permissions with type and purpose)
- Prerequisites section per cloud provider
- AWS/GCP tabs marked "Preview"
- Added to Sidebar under Administration section

**Files:** `frontend/src/pages/CloudIntegrationGuide.tsx` (new), `frontend/src/App.tsx`, `frontend/src/components/layout/Sidebar.tsx`

---

### Task 7: Tenant-Branded Portal

**Status:** Already fully implemented — verified existing infrastructure:
- `GET /api/auth/tenant-branding?slug=<slug>` returns company name, slug, logo URL
- Login page fetches and displays tenant branding (logo or initials)
- Settings > Organization has logo upload (drag & drop, base64 encoding)
- Admin portal tenant configuration includes logo management

No additional changes needed.

---

### Task 8: SSO Integration (Azure AD) Enhancements

**What changed:**
- Added "Quick Setup" presets section above the IdP Metadata URL field in Settings > SSO
- Azure AD / Entra ID button: prompts for Azure AD Tenant ID and auto-generates the metadata URL
- Okta and "Other SAML 2.0" buttons for future expansion
- Existing SSO infrastructure (Phase 54) unchanged — SAML flow, JIT provisioning, role mapping, force-SSO all continue to work

**Files:** `frontend/src/pages/Settings.tsx`

---

### Task 9: Welcome Email + Onboarding Checklist

**What built:**
- New method: `EmailService.send_welcome_email(to_email, org_name, portal_url, username)`
- Branded HTML email template with:
  - Gradient header with AuditGraph branding
  - Portal URL and username display
  - 4-step "Getting Started" guide
  - CTA button linking to portal
- Auto-triggered on tenant creation when root_email is provided in `create_tenant_handler()`
- Graceful failure (logs warning, doesn't block tenant creation)

**Onboarding checklist:** Built in Task 1 (see above)

**Files:** `backend/app/services/email_service.py`, `backend/app/api/handlers.py`

---

### Task 10: SLA Monitoring Dashboard

**What built:**

**Backend:**
- New endpoint: `GET /api/system/sla` (portal access required)
- Computes: uptime_pct, total_requests, error_count, avg/p95 latency, scan stats (30-day window)
- SLA targets with compliance check:
  - Availability: 99.9% target
  - API Latency P95: 500ms target
  - Scan Success Rate: 95% target

**Frontend:**
- New page: `AdminSLA.tsx` at `/admin/sla`
- 3 SLA target cards with progress bars and met/breach indicators
- Overall SLA status badge (ALL MET / BREACH DETECTED)
- API Performance grid: avg latency, P95, total requests, errors
- Discovery Scans grid: total runs, completed, failed, avg duration
- Added to AdminConsole nav and routes (superadmin/poweradmin/reader access)

**Files:** `backend/app/api/handlers.py`, `backend/app/main.py`, `frontend/src/pages/admin/AdminSLA.tsx` (new), `frontend/src/pages/AdminConsole.tsx`

---

### Task 11: Docker Containerization Improvements

**What changed:**

**Backend Dockerfile:**
- Added non-root user (`auditgraph:auditgraph`) for security
- `USER auditgraph` directive before CMD
- Proper ownership of `/app` directory

**Production Compose:**
- New `docker-compose.prod.yml` with:
  - Resource limits (backend: 2 CPU / 2GB RAM, frontend: 0.5 CPU / 256MB)
  - Resource reservations (backend: 0.5 CPU / 512MB)
  - Restart policies (on-failure, max 5 attempts, 5s delay)
  - JSON file logging with rotation (50MB/5 files for backend, 20MB/3 files for frontend)
  - Health checks with production-appropriate intervals (30s)
  - Start period for backend (15s)

**Files:** `backend/Dockerfile`, `docker-compose.prod.yml` (new)

---

### Task 12: Validation

| Check | Result |
|-------|--------|
| Python syntax (main.py) | OK |
| Python syntax (handlers.py) | OK |
| Python syntax (email_service.py) | OK |
| Python syntax (pricing.py) | OK |
| TypeScript compile (`tsc --noEmit`) | 0 errors |
| Production build (`react-scripts build`) | Success |
| Handler imports in main.py | 264 verified |

---

## Summary

| Metric | Value |
|--------|-------|
| Files modified | 10 |
| Files created | 3 |
| Lines added | 1,179 |
| Lines removed | 82 |
| New API endpoints | 5 |
| New frontend pages | 2 |
| New backend methods | 6 |
| TypeScript errors | 0 |
| Python syntax errors | 0 |

### New API Endpoints
1. `GET /api/export/evidence-json` — GRC evidence package
2. `GET /api/tenant/entitlements` — plan limits & feature gates
3. `GET /api/client/billing/usage` — usage metering
4. `GET /api/system/sla` — SLA monitoring metrics
5. `DELETE/PUT/PATCH /api/snapshots/*` — 405 immutability guard
6. `DELETE/PUT/PATCH /api/runs/<id>` — 405 immutability guard

### New Frontend Pages
1. `/integration-guide` — Cloud Integration Guide
2. `/admin/sla` — SLA Monitoring Dashboard
