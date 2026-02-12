# Week 11 Summary: v3.0 Spec Alignment, Admin Portal, Pricing & Subscription Terms

**Date:** February 12, 2026
**Scope:** Admin portal RBAC, v3.0 prototype alignment, pricing model overhaul, subscription terms, bug fixes

---

## Overview

Week 11 focused on maturing the AuditGraph SaaS platform for production readiness. The admin portal gained granular role-based access control (4 roles), the entire UI was aligned to the v3.0 JSX prototype, pricing was restructured to a primary/add-on cloud model with multi-year term discounts, and several critical bugs were fixed including portal user isolation and tenant health data.

### Commits This Week

| Commit | Description |
|--------|-------------|
| `0ebda15` | Phase 76: Admin Portal RBAC — 4 granular portal roles |
| `e0610c0` | Replace AG placeholder with actual AuditGraph logo in admin portal |
| `6b086bc` | Fix portal role access errors, add superadmin password reset |
| `92236ac` | Phase 77: Admin Portal v3.0 spec alignment — Overview, Tenants, Users, Billing |
| `4282ab1` | Phase 78b: Portal separation & cloud connection fixes |
| `0983540` | v3.0 Spec Alignment — JSX Prototype Match |
| `39212dd` | Dark mode slate migration + AWS/GCP cloud credential forms |
| `5c901ac` | Pricing model: primary cloud $799/mo + add-on clouds $699/mo |
| `75dec66` | Fix portal users leaking into client portal user list |
| `70b6e55` | Fix tenant health table: cloud providers, actual dates for scan/license |
| `781e119` | Subscription terms: Monthly/1yr/3yr/5yr with progressive discounts |
| `1e1436f` | Billing card shows total contract value for term commitments |

---

## Phase 76: Admin Portal RBAC — 4 Granular Roles

### What
Replaced the single `superadmin` boolean with a proper role hierarchy for the admin portal.

### Portal Roles

| Role | Permissions |
|------|-------------|
| **superadmin** | Full access — create/delete tenants, manage portal users, billing, analytics |
| **poweradmin** | Create/edit tenants, provision users, view analytics — cannot delete tenants |
| **billing** | View billing & revenue data only |
| **reader** | Read-only access to overview and analytics |

### Implementation
- `VALID_PORTAL_ROLES` constant in `auth.py`
- `require_portal_role(*roles)` decorator for granular route protection
- `require_portal_access()` accepts all 4 roles for general admin portal access
- `support` → `poweradmin` DB migration in `_ensure_users_table()`
- AdminConsole.tsx uses `allowedRoles` array per nav item
- AdminTenants.tsx has `canWrite`/`isReadOnly` guards
- AdminUsers.tsx shows 4-role dropdown + color-coded badges

### Files Modified
- `backend/app/api/auth.py` — Role constants, decorators
- `backend/app/main.py` — Granular route decorators
- `backend/app/database.py` — Role migration
- `frontend/src/pages/admin/AdminConsole.tsx` — Role-based nav visibility
- `frontend/src/pages/admin/AdminTenants.tsx` — Write guards
- `frontend/src/pages/admin/AdminUsers.tsx` — 4-role management
- `frontend/src/contexts/AuthContext.tsx` — Updated User type
- `frontend/src/pages/Login.tsx` — Portal redirect logic

---

## Phase 77: Admin Portal v3.0 Spec Alignment

### What
Aligned the admin portal to the v3.0 JSX prototype specification.

### Changes
- **AdminOverview**: Reduced to 2 summary cards (Total Tenants, Active Tenants) + tenant health table
- **Tenants table**: `license_activated_at`/`license_expires_at` columns, License Status display
- **AdminUsers**: Replaced edit modal with Profile side panel, added `email`/`phone` fields
- **AdminBilling**: Active Users by Tenant chart, License Status/Activated/Expires columns
- **Trial tier**: Accepted as valid plan tier across all dropdowns and displays

### Database Changes
- `tenants` table gains `license_activated_at` and `license_expires_at` TIMESTAMPTZ columns
- `users` table gains `email` and `phone` columns

---

## v3.0 Spec Alignment — JSX Prototype Match

### What
Cross-validated the running app against the provided JSX prototype and fixed 12 identified gaps.

### Key Changes

#### Phase 1: Remove "Starter" Sub-Tier
- Plans are now ONLY: Free / Trial / Pro / Enterprise
- `PLAN_TIERS` reduced to `['pro']` — no per-cloud sub-tiers
- All fallbacks changed from `'starter'` to `'pro'` across 7 files

#### Phase 2: Admin Portal Fixes
- AdminOverview: Card grid → proper HTML table
- AdminTenants: Removed "Provisioned" column, split License into Activated/Expiry
- AdminOnboarding: Wizard step refactor (Step 0 = "Next" only, "Create Organization" on Step 3)
- AdminUsers: Removed "Remove Access" from Actions column

#### Phase 3: Client Portal Fixes
- CloudComparison: Add Cloud Provider modal shows Lock icons on disabled clouds + amber warning box with support contact
- Settings: Removed superadmin tenant management table, added scan mode section, fixed client user role labels

#### Phase 4: Settings Enhancement
- Section 1: Two-column layout with logo upload zone + org name/timezone/theme selector
- Email notification toggles: 6 toggle switches for different alert types

---

## Dark Mode Slate Migration

### What
Migrated all client-facing components from Tailwind `dark:*-gray-*` to `dark:*-slate-*` palette for a more modern, blue-tinted dark mode matching the v3.0 prototype.

### Scope
- 10 client-facing files modified
- 5 replacement passes: `dark:bg-gray-` → `dark:bg-slate-`, `dark:text-gray-` → `dark:text-slate-`, `dark:border-gray-` → `dark:border-slate-`, `dark:hover:bg-gray-` → `dark:hover:bg-slate-`, `dark:divide-gray-` → `dark:divide-slate-`
- Special cases: Sidebar `dark:bg-slate-950`, active items `dark:bg-blue-900/50`

### Files Modified
- `App.tsx`, `SsoCallback.tsx`, `Sidebar.tsx`, `TopBar.tsx`, `Login.tsx`, `ServiceAccountGovernance.tsx` (page + dashboard), `ResourceDetail.tsx`, `ResourceOverview.tsx`, `ExpiryTracker.tsx`

---

## AWS/GCP Cloud Credential Forms

### What
Replaced "Coming Soon" placeholder sections for AWS and GCP in client Settings with full credential input forms.

### AWS Fields
- Access Key ID, Secret Access Key, Region dropdown (10 AWS regions)
- "IAM Access Key" badge, "Configured" status indicator

### GCP Fields
- Project ID, Service Account JSON textarea
- "Service Account" badge, "Configured" status indicator

---

## Pricing Model Overhaul

### What
Restructured from per-cloud tiered pricing to a primary/add-on model.

### New Model

| Component | Price |
|-----------|-------|
| Primary Cloud (first cloud signed up) | $799/mo |
| Add-on Cloud (each additional) | $699/mo |
| Extended Data Retention (365 days) | $149/mo |
| All features | Included with Pro |

### Implementation
- `PRIMARY_CLOUD_PRICE = 799`, `ADDON_CLOUD_PRICE = 699` constants
- `getEnabledClouds(cfg)` — returns ordered list; first = primary
- `getCloudPrice(cfg, cloudKey)` — returns primary or addon price based on position
- `calculateMonthlyTotal()` / `calculateCloudBaseTotal()` rewritten for new model
- "excl. tax" labels on all price displays
- Tax disclaimer: "All prices are in USD and exclude applicable taxes (GST, VAT, Sales Tax, etc.)"

### Files Modified
- `frontend/src/constants/pricing.ts` — New constants + helper functions
- `frontend/src/pages/admin/AdminTenants.tsx` — Configure panel + billing summary
- `frontend/src/pages/admin/AdminBilling.tsx` — Revenue calculation + tax labels

---

## Subscription Terms & Progressive Discounts

### What
Added multi-year subscription commitment options with progressive discounts.

### Term Options

| Term | Discount | Example (Primary Cloud Only) |
|------|----------|------------------------------|
| Monthly | 0% | $799/mo |
| 1 Year | 10% | $719/mo → $8,628/yr total |
| 3 Years | 20% | $639/mo → $23,004 total |
| 5 Years | 30% | $559/mo → $33,540 total |

### Implementation

#### Backend
- `subscription_term` column on `tenants` table (0=monthly, 1/3/5=years)
- Auto-computes `license_expires_at` from `license_activated_at + term years`
- Term accepted in both create and update tenant APIs
- Analytics endpoint returns `subscription_term` per tenant

#### Frontend — Admin Portal
- **Onboarding**: Term selector (Monthly/1yr/3yr/5yr) with discount badges, shown for Pro/Enterprise
- **Tenants → Configure**: Term selector section, billing card shows:
  - Monthly: simple `$X/mo`
  - Term: strikethrough base price → discounted monthly → total contract value → total savings
- **Tenants table**: New "Term" column with badge
- **Billing**: MRR/ARR reflects per-tenant term discounts, Term column in licenses table
- **Overview**: Term column in tenant health table

#### Frontend — Client Portal
- **Settings**: Read-only "Subscription" card showing Plan, Term (with discount %), Activated date, Expiry date

### Key Constants
```typescript
export const SUBSCRIPTION_TERMS = [
  { value: 0, label: 'Monthly',  discount: 0 },
  { value: 1, label: '1 Year',   discount: 0.10 },
  { value: 3, label: '3 Years',  discount: 0.20 },
  { value: 5, label: '5 Years',  discount: 0.30 },
];
```

---

## Bug Fixes

### Portal Users Leaking into Client Portal
**Problem**: Users created in the admin portal (with portal_role like "reader") appeared in the client portal user list.

**Root Causes**:
1. `GET /api/users` didn't always set `exclude_portal=True` when a superadmin was viewing
2. Portal users created from AdminUsers.tsx got assigned the superadmin's `tenant_id` instead of `NULL`

**Fix**:
- `GET /api/users` now always excludes portal users (they have `/api/portal-users`)
- When `portal_role` is set during user creation, `tenant_id` is forced to `NULL`

### Tenant Health Table Missing Data
**Problem**: Cloud Providers column was empty, Last Scan showed relative time ("2h ago"), license dates were poorly formatted.

**Root Causes**:
- Analytics query didn't fetch `settings`, `license_activated_at`, `license_expires_at` from tenants table
- Frontend used relative time formatters instead of actual dates

**Fix**:
- Backend analytics query now extracts `clouds_enabled` from tenant settings JSON and returns license dates
- Frontend shows cloud provider badges (AZURE/AWS/GCP), full date/time for last scan, formatted dates for license fields

---

## Files Modified This Week

| File | Changes |
|------|---------|
| `backend/app/api/auth.py` | Portal roles, decorators |
| `backend/app/api/handlers.py` | User separation, analytics clouds/dates, subscription term support |
| `backend/app/database.py` | subscription_term column, update_tenant allowed fields |
| `backend/app/main.py` | Granular route decorators |
| `frontend/src/constants/pricing.ts` | Primary/addon pricing, subscription terms, discount helpers |
| `frontend/src/pages/admin/AdminOverview.tsx` | Tenant health table with dates, term, clouds |
| `frontend/src/pages/admin/AdminTenants.tsx` | Term selector, contract billing, configure panel |
| `frontend/src/pages/admin/AdminBilling.tsx` | Term-based MRR, term column, tax labels |
| `frontend/src/pages/admin/AdminOnboarding.tsx` | Term selector in wizard |
| `frontend/src/pages/admin/AdminUsers.tsx` | 4-role management, profile panel |
| `frontend/src/pages/admin/AdminConsole.tsx` | Role-based nav |
| `frontend/src/pages/Settings.tsx` | Subscription card, AWS/GCP credential forms, pricing import |
| `frontend/src/pages/Login.tsx` | Portal redirect, slate dark mode |
| `frontend/src/components/layout/Sidebar.tsx` | Slate dark mode |
| `frontend/src/components/layout/TopBar.tsx` | Slate dark mode |
| `frontend/src/components/overview/CloudComparison.tsx` | Lock icons, amber warning |
| `frontend/src/contexts/AuthContext.tsx` | Updated User type |
| + 5 more files | Dark mode slate migration |

---

## Database Schema Changes

| Table | Column | Type | Description |
|-------|--------|------|-------------|
| `tenants` | `license_activated_at` | TIMESTAMPTZ | When license was activated |
| `tenants` | `license_expires_at` | TIMESTAMPTZ | Auto-computed from activated + term |
| `tenants` | `subscription_term` | INTEGER (default 0) | 0=monthly, 1/3/5=year commitment |
| `tenants` | `logo_url` | TEXT | Tenant logo (base64) |
| `users` | `email` | VARCHAR(255) | Portal user email |
| `users` | `phone` | VARCHAR(50) | Portal user phone |

---

## Verification Checklist

- [x] TypeScript: `npx tsc --noEmit` passes clean after every change
- [x] Backend starts without errors
- [x] Portal users do not appear in client user list
- [x] Admin Overview shows cloud badges, actual dates, term column
- [x] Configure panel shows correct primary/addon pricing
- [x] Term selector computes correct contract totals and savings
- [x] Client Settings shows read-only subscription card
- [x] Onboarding wizard includes term selection
- [x] Billing page MRR reflects per-tenant term discounts
- [x] All dark mode classes use slate palette (0 remaining gray-* classes)
- [x] AWS/GCP credential forms functional in Settings
- [x] "excl. tax" labels on all price displays
