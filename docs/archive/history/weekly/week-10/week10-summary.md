# Week 10 Summary: 6 Pillars Audit - Complete Implementation

**Date:** February 8, 2026
**Scope:** 6 non-negotiable product quality pillars enforced across the entire AuditGraph frontend and backend

---

## Overview

All 6 Pillars have been implemented and verified. These pillars establish the foundational quality standards that every feature in AuditGraph must satisfy. The implementation touches 12 files across frontend and backend, introduces 8 new helper functions, 2 new component types, and extends 3 API endpoints.

### Files Modified

| Layer | File | Pillars |
|-------|------|---------|
| Frontend | `src/constants/metrics.ts` | 1, 3 |
| Frontend | `src/pages/Dashboard.tsx` | 2, 3, 6 |
| Frontend | `src/pages/Identities.tsx` | 2, 3, 6 |
| Frontend | `src/pages/IdentityDetail.tsx` | 2, 3, 4, 5, 6 |
| Frontend | `src/components/StatsCard.tsx` | 6 |
| Frontend | `src/components/dashboard/CredentialHealth.tsx` | 2 |
| Frontend | `src/components/dashboard/PostureScore.tsx` | 2 |
| Frontend | `src/components/dashboard/ComplianceScorecard.tsx` | 2 |
| Frontend | `src/components/dashboard/ConditionalAccessCard.tsx` | 2 |
| Backend | `app/api/handlers.py` | 5, 6 |
| Backend | `app/database.py` | 5 |
| Backend | `tools/patches/seed_verified_attacks.py` | 5 |

---

## Pillar 1: Single Source of Truth

**Principle:** Every type, label, color, threshold, and helper is defined once in `constants/metrics.ts`. Components import from this file instead of re-declaring their own copies.

### What Was Done

- **Central metric registry** (`constants/metrics.ts`) serves as the canonical source for:
  - `IdentityCategory` type union and `IDENTITY_CATEGORIES` metadata (label, shortLabel, description)
  - `CATEGORY_DISPLAY_ORDER` and `CATEGORY_FILTER_OPTIONS` for consistent ordering
  - `RiskLevel` type, `RISK_LEVELS`, `RISK_ORDER` for sorting
  - `RISK_HEX` (SVG charts), `RISK_SOLID` (buttons/heatmap), `RISK_BADGE` (pill badges)
  - `CLOUD_BADGE` colors per provider
  - `THRESHOLDS` constants (credential expiry 30d, dormant 90d, idle 30d)
  - `DormantStatus` type and `getDormantStatus()` normalizer
  - `DORMANT_LABELS` with label, color, and tooltip for all 6 states
  - `DATA_EXPLANATIONS` for missing data reasons
  - Helper functions: `safeLower()`, `normalizeCategoryFromBackend()`, `getCategoryLabel()`, `getCategoryShortLabel()`

### Impact

All 8 page/component files import from `metrics.ts` instead of maintaining local copies. Category labels, risk colors, and thresholds are guaranteed consistent across Dashboard, Identities table, IdentityDetail, Overview, and all dashboard cards.

---

## Pillar 2: Universal Drill-Down

**Principle:** Every displayed number must be clickable, navigating to a filtered view of the underlying identities.

### What Was Done

#### Dashboard StatsCards
- **Total Identities** card clicks -> `/identities`
- **Critical** card clicks -> `/identities?risk_level=critical`
- **High** card clicks -> `/identities?risk_level=high`
- **Discovery Runs** card toggles run history panel

#### CredentialHealth Component
| Segment | Drill-Down URL |
|---------|---------------|
| Expired | `/identities?credential_status=expired` |
| Expiring <30d | `/identities?credential_status=expiring_soon` |
| Healthy | `/identities?credential_status=valid` |
| No Credentials | `/identities?credential_status=none` |

#### PostureScore Component
- Entire card is clickable -> `/identities?risk_level=critical`
- Tooltip hint: "Click to drill down"

#### ComplianceScorecard Component (15 controls mapped)
| Framework | Control | Drill-Down URL |
|-----------|---------|---------------|
| SOC 2 | CC6.1 | `/identities?privilege_tier=0` |
| SOC 2 | CC6.2 | `/identities?activity_status=dormant&privilege_tier=0,1` |
| SOC 2 | CC6.3 | `/identities?owner_status=unowned&identity_category=service_principal` |
| SOC 2 | CC7.2 | `/identities?credential_status=expired` |
| HIPAA | 164.312(a) | `/identities?privilege_tier=0` |
| HIPAA | 164.312(d) | `/identities?credential_status=expired` |
| HIPAA | 164.308(a)(3) | `/identities?activity_status=dormant&privilege_tier=0,1` |
| HIPAA | 164.312(b) | `/identities?risk_level=high` |
| PCI-DSS | Req 7.1 | `/identities?privilege_tier=0` |
| PCI-DSS | Req 8.1 | `/identities?credential_status=expired` |
| PCI-DSS | Req 8.6 | `/identities?owner_status=unowned&identity_category=service_principal` |
| NIST | AC-2 | `/identities?activity_status=dormant&privilege_tier=0,1` |
| NIST | AC-6 | `/identities?privilege_tier=0` |
| NIST | IA-5 | `/identities?credential_status=expired` |
| NIST | CM-8 | `/identities?owner_status=unowned` |

#### ConditionalAccessCard Component
- **Covered** count clicks -> `/identities?ca_coverage=covered`
- **Not Covered** count clicks -> `/identities?ca_coverage=not_covered`

#### Identities Page Filter Support
New URL parameter handlers added:
- `credential_status` filter: `expired`, `expiring_soon`, `valid`, `none`
- `ca_coverage` filter: `covered`, `not_covered`
- Filter chips display active filters with clear buttons

---

## Pillar 3: Telemetry Truth

**Principle:** "Unknown" is a visible state. Never hide missing data behind zeros, dashes, or blank spaces. Always explain why data may be missing.

### What Was Done

#### DATA_EXPLANATIONS Constant
Standard explanations for missing data, used consistently across all pages:

| Key | Message |
|-----|---------|
| `SIGN_IN` | Sign-in logs require Azure AD Premium P1/P2 |
| `PIM` | PIM requires Azure AD Premium P2 license |
| `CA_POLICY` | CA analysis requires Policy.Read.All permission |
| `AUDIT_LOG` | Audit logs require AuditLog.Read.All permission |
| `CREDENTIAL_NA` | Human users authenticate via Entra ID (password/MFA), not app secrets |
| `NO_DATA` | Not yet collected - run a discovery scan |

#### DORMANT_LABELS with Tooltips
All 6 dormancy states now have descriptive tooltips:

| Status | Label | Tooltip |
|--------|-------|---------|
| yes | Stale 90d+ | No sign-in activity for 90+ days |
| idle | Idle 30-90d | No sign-in activity for 30-90 days |
| never | Never Used | Created 30+ days ago with no recorded sign-in |
| new | New | Created within the last 30 days |
| no | Active | Sign-in activity within the last 30 days |
| unknown | Unknown | No sign-in data - requires Azure AD Premium P1/P2 license |

#### Identities Table Enhancements
- **DormantBadge**: Always shows colored badge with tooltip (never silent dash)
- **CA shield icon**: Always visible - green when covered, gray with explanatory tooltip when unknown
- **Last Used column**: Shows "Unknown (P1/P2)" instead of dash when no sign-in data
- **Credential column**: Shows "N/A" with CREDENTIAL_NA tooltip for human users

#### IdentityDetail Enhancements
- **Created date**: Shows "Unknown" with tooltip instead of dash
- **Last Sign-in**: Shows "Unknown - P1/P2 required" with explanation
- **Owner**: Shows "Unowned" in orange instead of hiding
- **CA section**: Always visible with explanation when no data
- **Credentials tab**: Identity-type-aware explanations (human users see N/A message, SPNs with 0 creds see "No secrets")
- **PIM tab**: Uses DATA_EXPLANATIONS.PIM for empty state

#### Dashboard
- **Data freshness**: Shows "Data as of [timestamp] - Run #N" below dashboard header

---

## Pillar 4: Identity-Centric

**Principle:** Every page resolves to specific identities. Each identity gets a complete security picture in one view.

### What Was Done

#### Privilege Tier Classification
New `computePrivilegeTier()` function derives T0-T3 classification:

| Tier | Name | Criteria |
|------|------|----------|
| T0 | Control Plane | Global Administrator, Privileged Role Administrator, tenant-wide Owner |
| T1 | Management Plane | User Administrator, Exchange Administrator, subscription Owner/Contributor |
| T2 | Data/App Plane | Scoped roles, risky Graph API permissions (Mail.ReadWrite, Files.ReadWrite.All, etc.) |
| T3 | Standard | No privileged roles |

Returns both the tier number and up to 5 classification reasons.

#### Effective Access Scope Parser
New `parseEffectiveAccessScope()` function extracts:
- Azure subscriptions from role scope paths
- Resource groups from scope paths
- Tenant-wide access detection (scope = `/`)
- Entra directory scopes

#### Identity Security Posture (4-Quadrant View)
Overview tab reworked with four assessment quadrants:

| Quadrant | Displays |
|----------|----------|
| Activity | Dormancy status badge + last sign-in date or P1/P2 explanation |
| Credentials | Status badge (expired/expiring/valid) + count + countdown |
| CA Coverage | Coverage status + MFA enforcement state |
| PIM | Eligible role count + always-active pattern detection |

#### Header Card Enhancements
- Privilege tier badge (T0/T1/T2/T3) displayed next to risk badge with tooltip
- Quick stats (roles, permissions, credentials, owners) are clickable buttons that switch tabs

#### Effective Access Scope Section
Three-column layout showing:
- **Entra Directory**: Directory-level roles
- **Azure RBAC**: Subscriptions and resource groups in scope
- **Graph API**: API permissions count

#### Identities Table
- `getPrivilegeTier()` function with backend-computed tier and frontend fallback
- `TierBadge` component with color-coded tier labels and tooltips

---

## Pillar 5: Evidence-First

**Principle:** Every displayed fact must cite its source API and collection timestamp. No unattributed claims.

### What Was Done

#### Backend: Evidence Metadata in API
`get_identity_details()` endpoint now returns:
```json
{
  "evidence": {
    "run_id": 115,
    "collected_at": "2026-02-08T22:19:02.730572",
    "sources": {
      "identity": "Microsoft Graph API /servicePrincipals or /users",
      "roles_azure": "Azure Resource Manager /roleAssignments",
      "roles_entra": "Microsoft Graph API /roleManagement/directory",
      "permissions": "Microsoft Graph API /servicePrincipals/{id}/appRoleAssignments",
      "credentials": "Microsoft Graph API /applications/{id}/passwordCredentials + keyCredentials",
      "owners": "Microsoft Graph API /servicePrincipals/{id}/owners",
      "pim": "Microsoft Graph API /roleManagement/directory/roleEligibilityScheduleInstances",
      "ca_policies": "Microsoft Graph API /identity/conditionalAccess/policies"
    }
  }
}
```

SQL query joins `identities` with `discovery_runs` to get `run_completed_at`.

#### Frontend: DataSource Component
Reusable `DataSource` component displays source attribution:
```
Source: [label] [apiSource] - Collected [date]
```

Applied to all 6 data tabs:

| Tab | Source Label | API Endpoint |
|-----|-------------|-------------|
| Roles | Azure Resource Manager + Microsoft Graph API | /roleAssignments, /roleManagement/directory |
| Permissions | Microsoft Graph API | /servicePrincipals/{id}/appRoleAssignments |
| Credentials | Microsoft Graph API | /applications/{id}/passwordCredentials + keyCredentials |
| Ownership | Microsoft Graph API | /servicePrincipals/{id}/owners |
| PIM | Microsoft Graph API | /roleManagement/directory/roleEligibilityScheduleInstances |
| Compliance | AuditGraph Intelligence Engine | Role-based GRC mapping |

#### Header Card Evidence Trail
Shows Run #, collection timestamp, and expandable API source list.

#### Verified Attack Patterns
Replaced all fabricated breach examples with 14 verified, publicly documented incidents. Added `source` column to `role_attack_patterns` table for authoritative citations.

| Role | Company | Year | Source |
|------|---------|------|--------|
| Global Administrator | Change Healthcare (UnitedHealth Group) | 2024 | UnitedHealth SEC 8-K filing, HHS OCR investigation |
| Global Administrator | SolarWinds (18,000+ customers) | 2020 | CISA Alert AA21-008A, SEC filings |
| Global Administrator | MGM Resorts International | 2023 | MGM SEC 10-Q filing, FBI/CISA advisory |
| Owner | Capital One | 2019 | DOJ indictment, OCC $80M consent order |
| Owner | Scripps Health | 2021 | HHS breach notification |
| Exchange Administrator | Microsoft Exchange / Hafnium | 2021 | CISA Emergency Directive 21-02 |
| Exchange Administrator | Storm-0558 / Microsoft | 2023 | CISA advisory, CSRB review report |
| User Access Administrator | Caesars Entertainment | 2023 | SEC 8-K filing |
| Privileged Role Administrator | SolarWinds / NOBELIUM | 2020 | CISA Alert AA21-008A, FireEye M-Trends |
| Privileged Role Administrator | Colonial Pipeline | 2021 | DOJ recovery filing, Senate testimony |
| Application Administrator | Midnight Blizzard / Microsoft | 2024 | Microsoft Security Blog, SEC 8-K |
| Security Administrator | Okta / Lapsus$ | 2022 | Okta post-incident report |
| Conditional Access Administrator | MGM Resorts International | 2023 | MGM SEC 10-Q filing |
| Authentication Administrator | Uber / Lapsus$ | 2022 | Uber security update blog, DOJ indictment |

---

## Pillar 6: Change & Trend

**Principle:** Every metric should show direction of change. Users need to know if things are getting better or worse.

### What Was Done

#### Backend: Previous Run Comparison
- **`get_stats()`**: Now returns `previous_run` object alongside `latest_run` with previous counts for total_identities, critical_count, high_count, medium_count
- **`get_identity_details()`**: New `trend` object comparing this identity's risk state against the previous discovery run:
  ```json
  {
    "trend": {
      "previous_risk_level": "high",
      "previous_risk_score": 450,
      "risk_direction": "worsened",
      "is_new": false
    }
  }
  ```
  Possible values for `risk_direction`: `worsened`, `improved`, `unchanged`, `new`

#### Dashboard: Stats Card Trend Arrows
- **Total Identities**: Neutral gray trend arrow with delta ("+3 from last run")
- **Critical**: Red/green trend with delta (risk-aware: up = bad)
- **High**: Red/green trend with delta

#### IdentityDetail: Risk Trend Badges
Three new badges in the header card:
- **NEW** (indigo badge): Identity first seen in this discovery run
- **WORSENED** (red badge with ↑): Risk score increased since previous run, tooltip shows previous level
- **IMPROVED** (green badge with ↓): Risk score decreased, tooltip shows previous level
- Risk score displays "(was X)" comparison when trend data is available

#### Credential Countdown
New `credentialCountdown()` and `credentialCountdownText()` functions showing days until expiry:

| Days Remaining | Display | Color |
|----------------|---------|-------|
| Expired | "Expired Xd ago" | Red |
| 0 | "Expires today" | Red |
| 1-7 | "Xd remaining" | Red |
| 8-30 | "Xd remaining" | Orange |
| 31-90 | "Xd remaining" | Yellow |
| 90+ | "Xd remaining" | Green |

Applied in:
- **Identities table**: Credential column shows countdown instead of static date
- **IdentityDetail Credentials tab**: Next Expiration field shows countdown below date
- **IdentityDetail Overview**: Credentials quadrant shows inline countdown

#### StatsCard Component Enhancements
New props added:
- `trendDelta?: number` - Numeric delta from previous value
- `trendNeutral?: boolean` - Use gray instead of red/green (for non-risk metrics like total count)

---

## Verification Checklist

- [x] TypeScript: `npx tsc --noEmit` passes clean
- [x] All DATA_EXPLANATIONS referenced where data may be missing
- [x] Every dashboard number is clickable with proper drill-down URL
- [x] DORMANT_LABELS show "Unknown" instead of dashes for missing sign-in data
- [x] DataSource component present on all 6 detail tabs
- [x] Evidence metadata returned in identity detail API
- [x] Trend arrows on dashboard stats cards
- [x] NEW/WORSENED/IMPROVED badges on identity detail header
- [x] Credential countdown displayed in table and detail pages
- [x] All 14 attack patterns are verified with authoritative source citations
- [x] Zero fabricated breach examples in database
- [x] Backend restarts cleanly with all changes
