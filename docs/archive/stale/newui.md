# AuditGraph — Enterprise UI Refactoring Log

## Constraints (Guardrails)
- Do NOT modify backend logic
- Do NOT modify database schema
- Do NOT remove existing APIs
- Do NOT introduce new features
- Do NOT introduce provisioning, ticketing, or CSPM features
- Do NOT redesign connectors or discovery engine
- Scope: Frontend information architecture, layout consistency, visual simplification, enterprise polish only

---

## PHASE 0 — Structural Analysis (No Changes Made)

**Date:** 2026-02-27

### Objective
Analyze the current frontend structure before making changes. Summarize navigation tree, page structure, reused components, and redundant views.

### Findings

#### 1. Current Navigation Tree (7 sidebar sections)

```
COMMAND CENTER (blue #2563eb)
├── Risk Dashboard          → / (CISODashboard.tsx)
└── Risk Monitoring         → /dashboard (Dashboard.tsx)

IDENTITY (purple #8b5cf6)
├── Identity Inventory      → /identities (Identities.tsx)
└── Data & Resource Exposure → /data-security (DataSecurity.tsx)

GOVERNANCE (cyan #0891b2)
├── Governance Coverage     → /service-accounts (ServiceAccountGovernance.tsx)
├── Role Optimization       → /role-mining (RoleMining.tsx)
└── Access Reviews          → /access-reviews (AccessReviews.tsx)

REMEDIATION (green #16a34a)
└── Action Plan             → /remediation (RemediationCenter.tsx)

DATA SECURITY (orange #ea580c)
├── Secrets & Keys          → /key-vaults (KeyVaultSecurity.tsx)
└── Storage Exposure        → /storage-accounts (StorageSecurity.tsx)

COMPLIANCE (amber #ca8a04)
├── Frameworks & Controls   → /compliance (Compliance.tsx)
└── Evidence Center         → /exports (Exports.tsx)

OPERATIONS (slate #64748b)
├── Drift & Changes         → /drift (DriftHistory.tsx)
├── Activity Log            → /activity (ActivityLog.tsx)
└── Reports                 → /reports (Reports.tsx)
```

Plus: 8 admin portal routes (`/admin/*`), 7 public routes (login, SSO, legal), redirect aliases (`/spns` → `/workload-identities?type=spn`, `/app-registrations` → `/workload-identities?type=app_reg`).

**Total: 60+ routes across client portal, admin portal, and public pages.**

#### 2. Page Inventory (54 pages total)

| Category | Count | Key Pages |
|----------|-------|-----------|
| Dashboards | 3 | CISODashboard (2,813 lines), Overview (2,450 lines), Dashboard (720 lines) |
| Identity management | 6 | Identities, IdentityDetail (13 tabs), WorkloadIdentities, AppRegistrations, ServiceAccountGovernance, RoleMining |
| Resource/data views | 5 | Resources, KeyVaultSecurity (11-line wrapper), StorageSecurity (12-line wrapper), DataSecurity, ResourceDetail |
| Compliance & reporting | 4 | Compliance, Reports, DriftHistory, Exports |
| Operations & monitoring | 3 | ActivityLog, SystemHealth, NotificationCenter |
| Settings & config | 3 | Settings (10 tabs), OnboardingWizard, CloudIntegrationGuide |
| Admin portal | 7 | AdminOverview, AdminTenants, AdminUsers, AdminBilling, AdminMonitoring, AdminSLA, AdminProfile |
| Auth & legal | 6 | Login, ForgotPassword, ResetPassword, SsoCallback, TermsOfService, PrivacyPolicy |
| Advanced | 6 | IdentityCorrelation, IdentityGroups, IdentityComparison, CrossTenantAnalytics, Subscriptions, Invoices |
| Governance workflows | 2 | AccessReviews, RemediationCenter |
| Standalone dashboards | 2 | SPNDashboard, RbacHygiene |

Component library: 23 widgets in `components/dashboard/`, 15 components in `components/overview/`.

#### 3. Components Reused Across Screens

**High reuse (3+ pages):** StatsCard, ViewAllButton, Sparkline, RiskMethodology, DrillableNumber, StaleDataBanner

**Moderate reuse (2 pages):** AccessGraphTab, IdentityDrawer, QueryBuilder, SearchModal

**Critical finding:** Dashboard.tsx uses 24 reusable widget components. CISODashboard.tsx and Overview.tsx use zero shared components — they reimplement everything with inline styles.

#### 4. Redundancies Identified

| Issue | Severity | Detail |
|-------|----------|--------|
| Overview.tsx ≈ CISODashboard.tsx | Critical | 99% duplicate logic (same 6 tabs, same APIs). Overview is unreachable — no route renders it as landing page. 5,263 combined lines. |
| KeyVaultSecurity.tsx + StorageSecurity.tsx | Low | 11-line and 12-line wrappers that call `<Resources lockedType="...">`. Pure route aliases. |
| AppRegistrations.tsx → WorkloadIdentities | Medium | Already redirects via `/app-registrations` → `/workload-identities?type=app_reg`. AppRegistrations.tsx is standalone but redundant. |
| SPNDashboard.tsx → WorkloadIdentities | Medium | Already redirects via `/spns` → `/workload-identities?type=spn`. SPNDashboard.tsx is standalone but redundant. |
| DataSecurity.tsx ≈ Resources.tsx | Medium | 70% data overlap (same API, same resources). DataSecurity adds classification layer. |
| Settings "Scoring" ≈ "Compliance" tab | Low | Risk rule editor duplicated across two settings tabs. |
| No API caching | Medium | `/api/stats` called independently by 3 pages with no React Query or context sharing. |

---

## PHASE 1 — Navigation Restructure (Analysis Only, No Code Changes Yet)

**Date:** 2026-02-27

### Objective
Map existing screens to a new 5-section enterprise navigation structure. Identify merges, removals, and preserve all routing paths.

### Target Navigation Structure

```
COMMAND CENTER
├── Executive Posture
├── Risk Monitoring
└── Drift History

IDENTITY TRUTH
├── Identity Inventory
├── Non-Human Identities
└── Privileged Access

ACCESS EXPLAINABILITY
├── Role Analysis
├── Data Exposure
└── (Access Graph — drill-down from Identity Inventory, not top-level)

EVIDENCE
├── Compliance Evidence
├── Snapshots
└── Export Center

PLATFORM
├── Connectors
├── Audit Log
└── Tenant Settings
```

### Mapping Table: Old → New

| Old Route | Old Sidebar Label | Old Section | New Section | New Label | Action |
|-----------|-------------------|-------------|-------------|-----------|--------|
| `/` | Risk Dashboard | COMMAND CENTER | COMMAND CENTER | Executive Posture | **Keep** (CISODashboard.tsx) |
| `/dashboard` | Risk Monitoring | COMMAND CENTER | COMMAND CENTER | Risk Monitoring | **Keep** (Dashboard.tsx) |
| `/drift` | Drift & Changes | OPERATIONS | COMMAND CENTER | Drift History | **Move** section |
| `/identities` | Identity Inventory | IDENTITY | IDENTITY TRUTH | Identity Inventory | **Keep** |
| `/workload-identities` | *(no sidebar entry)* | — | IDENTITY TRUTH | Non-Human Identities | **Add** to sidebar |
| `/rbac-hygiene` | *(no sidebar entry)* | — | IDENTITY TRUTH | Privileged Access | **Add** to sidebar |
| `/role-mining` | Role Optimization | GOVERNANCE | ACCESS EXPLAINABILITY | Role Analysis | **Move** section |
| `/data-security` | Data & Resource Exposure | IDENTITY | ACCESS EXPLAINABILITY | Data Exposure | **Move** section |
| `/compliance` | Frameworks & Controls | COMPLIANCE | EVIDENCE | Compliance Evidence | **Move** section |
| `/reports` | Reports | OPERATIONS | EVIDENCE | Snapshots | **Move** section |
| `/exports` | Evidence Center | COMPLIANCE | EVIDENCE | Export Center | **Move** section |
| `/settings/connections` | *(Settings sub-tab)* | — | PLATFORM | Connectors | **Add** direct link |
| `/activity` | Activity Log | OPERATIONS | PLATFORM | Audit Log | **Move** section |
| `/settings` | Settings | *(bottom)* | PLATFORM | Tenant Settings | **Move** to section |

### Screens Removed from Sidebar (routes preserved)

| Screen | Old Sidebar Location | Reason | Route Kept |
|--------|---------------------|--------|------------|
| `RemediationCenter.tsx` | REMEDIATION → Action Plan | Accessible from CISO dashboard Action Plan tab | `/remediation` |
| `ServiceAccountGovernance.tsx` | GOVERNANCE → Governance Coverage | Overlaps with Non-Human Identities; keep as deep link | `/service-accounts` |
| `AccessReviews.tsx` | GOVERNANCE → Access Reviews | Niche workflow; accessible from identity governance links | `/access-reviews` |
| `KeyVaultSecurity.tsx` | DATA SECURITY → Secrets & Keys | 11-line wrapper of Resources.tsx; can redirect | `/key-vaults` |
| `StorageSecurity.tsx` | DATA SECURITY → Storage Exposure | 12-line wrapper of Resources.tsx; can redirect | `/storage-accounts` |
| `Resources.tsx` | *(general)* | Subsumed by Data Exposure view | `/resources` |

### Screens Not in Sidebar (unchanged — already hidden)

These pages were never in the sidebar and remain accessible via direct route only:

| Screen | Route | Access Method |
|--------|-------|---------------|
| IdentityDetail | `/identities/:id` | Click from Identity Inventory |
| IdentityComparison | `/identities/compare` | Button from Identity Inventory |
| WorkloadIdentityDetail | `/workload-identities/:id` | Click from Non-Human Identities |
| ResourceDetail | `/resources/detail` | Click from Data Exposure |
| IdentityGroups | `/groups` | Deep link |
| IdentityCorrelation | `/identity-correlation` | Deep link |
| SystemHealth | *(no route in sidebar)* | Settings link |
| NotificationCenter | `/notifications` | TopBar bell icon |
| CrossTenantAnalytics | `/analytics` | Admin/superadmin only |
| Subscriptions | `/subscriptions` | Settings/billing |
| Invoices | `/invoices` | Settings/billing |
| CloudIntegrationGuide | `/integration-guide` | Onboarding flow |
| OnboardingWizard | `/onboarding` | First-run only |

### Screens Identified for Future Merge (not yet executed)

| Screen | Merge Target | Rationale |
|--------|-------------|-----------|
| `Overview.tsx` | `CISODashboard.tsx` | 99% duplicate — same 6 tabs, same APIs, different inline styles. CISODashboard is the active `/` route. Overview is unreachable. |
| `KeyVaultSecurity.tsx` | `Resources.tsx` route param | 11-line wrapper — sidebar can link to `/resources?type=key_vault` instead. |
| `StorageSecurity.tsx` | `Resources.tsx` route param | 12-line wrapper — sidebar can link to `/resources?type=storage_account` instead. |
| `AppRegistrations.tsx` | `WorkloadIdentities.tsx` | Route already redirects. Standalone file is dead code. |
| `SPNDashboard.tsx` | `WorkloadIdentities.tsx` | Route already redirects. Standalone file is dead code. |

### Route Preservation (Zero Breaking Changes)

All existing routes preserved. No routes deleted. No redirects changed. Changes are sidebar-only:
- 7 sections → 5 sections
- 15 sidebar items → 15 sidebar items
- 7 section colors → 5 section colors

### Section Color Mapping (Proposed)

| Section | Color | Hex |
|---------|-------|-----|
| COMMAND CENTER | Blue | #2563eb |
| IDENTITY TRUTH | Purple | #8b5cf6 |
| ACCESS EXPLAINABILITY | Cyan | #0891b2 |
| EVIDENCE | Amber | #ca8a04 |
| PLATFORM | Slate | #64748b |

---

---

## PHASE 2 — Remove Visual Noise (Analysis + Proposed Removals)

**Date:** 2026-02-27

### Objective
Identify and propose removal of non-essential UI elements across all pages. Prioritize tables over charts. Keep only metrics supporting: (a) effective access clarity, (b) non-human visibility, (c) sensitive data exposure.

### Rules Applied
- Remove decorative donut charts
- Remove blast radius animated bars
- Remove duplicated metric cards
- Prioritize tables over charts
- Do not remove functional logic — only adjust presentation

---

### Page-by-Page Analysis

#### Dashboard.tsx (`/dashboard` — Risk Monitoring)

**Current widgets:** 20+ components across 6 tabs (exposure, credential, trust, usage, governance, platform)

| Widget | Visual Type | Verdict | Rationale |
|--------|-----------|---------|-----------|
| 4x Summary Cards + sparklines | Stat cards + 28px micro charts | **REMOVE sparklines** | Trend arrow on card is sufficient; sparklines are too small to read |
| RiskDonutChart | SVG donut chart | **REMOVE** | Decorative; RiskHeatMap table shows same data with drill-down |
| RiskHeatMap | Interactive table (category × risk) | **KEEP** | Core cross-drill capability, high information density |
| RiskTrendChart | 4-layer stacked area chart | **SIMPLIFY** | Reduce to critical+high lines only; 4-layer stacked areas obscure individual trends |
| RiskVelocityChart | Bar chart (inflow/outflow) | **KEEP** | Unique metric — risk escalation/de-escalation flow |
| RoleUsageChart | Bar chart + mini donut pie | **SIMPLIFY** | Remove mini-pie (duplicates risk tab data); keep bar chart only |
| AnomalyAlerts | Alert list panel | **KEEP** | Critical incident detection |
| RecentChanges | Summary card + badges | **KEEP** | Drift summary essential |
| CredentialHealth | Stacked bar + legend cards | **KEEP** | Core credential posture |
| ExpiryTracker | Countdown widget | **KEEP** | Operational urgency |
| CredentialIntelligence | Intelligence panel | **KEEP** | Credential trend data |
| TrustAccessPanel | Cards + tables | **KEEP** | Federated/guest risk — all metrics unique |
| QuickActions | 4-button grid | **KEEP** | Action-oriented, minimal |
| SOARActivity | List widget (6 items) | **KEEP** | Automation workflow visibility |
| ComplianceScorecard | Framework cards | **KEEP** | Compliance posture |
| ConditionalAccessCard | CA coverage stats | **KEEP** | Azure CA policy gaps |
| RemediationProgress | Progress bar + status | **KEEP** | Remediation tracking |
| ServiceAccountGovernance | Attestation summary | **KEEP** | Non-human governance |
| CloudContextBanner | Info banner | **KEEP** | Cloud inventory context |
| PlatformHealth | 2×2 status grid | **MOVE to Settings** | Infrastructure concern, not security; link to SystemHealth page instead |
| IdentityCorrelationWidget | 2×2 stat cards | **REMOVE** | Niche forensics feature; not core operational metric |
| ResourceOverview | Resource summary | **KEEP** | Azure resource security |

**Dashboard summary:** Remove 3 widgets (DonutChart, IdentityCorrelation, sparklines), simplify 2 (RiskTrend, RoleUsage), move 1 (PlatformHealth).

---

#### CISODashboard.tsx (`/` — Executive Posture)

**Current:** 6 tabs, ~2,813 lines, inline styles throughout

| Element | Tab | Verdict | Rationale |
|---------|-----|---------|-----------|
| HeroPanel ScoreRing (48pt) | Executive Summary | **KEEP** | Core AGIRS posture indicator |
| Industry/Target benchmark gradient bar | Executive Summary | **SIMPLIFY** | Remove gradient; show benchmarks as text labels |
| 6 Pillar RiskDriverRow progress bars | Executive Summary | **KEEP** | Essential pillar breakdown |
| Sparkline (320×80) | Executive Summary | **KEEP** | 30-day trend — readable at this size |
| Projection cards (No Action vs Remediated) | Executive Summary | **KEEP** | Decision-support comparison |
| Pulsing red animation on Ghost Accounts | Identity Risk | **REMOVE** | Anxiety-inducing; use static red background |
| Emoji icons (🐷🔑👻🧟🌐) | Identity Risk | **REMOVE** | Accessibility issue; replace with letter codes in colored boxes |
| Blast Radius stacked bar (10px) | Identity Risk | **SIMPLIFY** | Keep bar, remove animation transition |
| Blast Radius 5-category progress bars (4px) | Identity Risk | **KEEP** | Compact, data-driven |
| Remediation card gradient buttons | Action Plan | **REMOVE** | Use solid accent color |
| Remediation card rotating chevron | Action Plan | **SIMPLIFY** | Use static +/− toggle |
| Rollback risk badge | Action Plan | **KEEP** (show "—" when null) | Status metadata |
| ScoreRing stroke-dashoffset animation | Governance | **SIMPLIFY** | Animate on initial mount only, not re-render |
| Control Failures collapsible groups | Governance | **KEEP** | Progressive disclosure |
| Framework mini ScoreRings (44px) | Compliance | **KEEP** | Compact score display |
| Box shadows on modals/panels | Multiple | **REMOVE** | Use `border: 1px solid` instead |
| Linear gradient on "Apply Changes" button | Multiple | **REMOVE** | Use solid color |
| Random SVG gradient IDs (`Math.random()`) | Multiple | **SIMPLIFY** | Use deterministic IDs to avoid DOM churn |

**Duplicated metrics in CISODashboard (show once, not multiple times):**

| Metric | Appears In | Keep Where |
|--------|-----------|------------|
| Risk Score (AGIRS) | Exec hero (48pt), Risk Movement (36pt), Projection cards | Exec hero only; reference elsewhere |
| Tier badge | Exec hero, AGIRS card, Risk Movement, Governance | Exec hero only |
| Blast radius | Identity Risk (summary bar), Identity Risk (category bars) | Category bars only |
| Governance effectiveness | Governance tab (ring), Exec tab (GEI sub-card) | Governance tab only |

---

#### Overview.tsx (unreachable — no active route)

| Element | Verdict | Rationale |
|---------|---------|-----------|
| AttackSurfaceRadar (Recharts spider chart) | **REMOVE** | Decorative — same data duplicated in pillar cards below |
| ArcGauge (270° arc animation) | **REMOVE** | Single number + grade displayable as text badge |
| 6x PillarCard with CircularGauge | **SIMPLIFY** | Remove mini circular gauges; keep text score + label |
| DataFreshnessBar | **REMOVE** | Low-priority metadata cluttering header |
| Multiple TrendArrow + numeric delta | **SIMPLIFY** | Show one or the other, not both |

**Note:** Overview.tsx is 99% duplicate of CISODashboard.tsx and unreachable. Recommended for full removal in Phase 3. This analysis included for completeness.

---

#### WorkloadIdentities.tsx (`/workload-identities`)

| Element | Verdict | Rationale |
|---------|---------|-----------|
| ExposureRing (36px SVG circle per row) | **REMOVE** | Circular gauge shows same data as numeric exposure_score column; replace with colored badge |
| Summary stat cards (Total, Critical, etc.) | **KEEP** | Essential KPI summary |
| Sortable table | **KEEP** | Core data view |
| Lifecycle badges | **KEEP** | Status indicators |

---

#### SPNDashboard.tsx (`/spns` redirect target)

| Element | Verdict | Rationale |
|---------|---------|-----------|
| ExposureRing (34px per table row) | **REMOVE** | Same issue — 8px text inside 34px SVG; use badge instead |
| 5 summary cards | **KEEP** | Essential KPI summary |
| Drill-down side panel | **KEEP** | Detail view |
| Blast radius text column | **KEEP** | Text label (Low/Med/High/Crit), not animated |

---

#### DataSecurity.tsx (`/data-security`)

| Element | Verdict | Rationale |
|---------|---------|-----------|
| 8 component progress bars (6px) | **SIMPLIFY** | Show in ONE location only — currently repeated in summary cards, detail panel, table rows, and row mini-charts (4×) |
| Color coding without legend | **FIX** | Add visible legend or use text labels alongside bars |
| Resource table | **KEEP** | Core data view |
| Classification stats | **KEEP** | PHI/PCI/PII data labeling |

---

#### PostureScore.tsx (Dashboard widget)

| Element | Verdict | Rationale |
|---------|---------|-----------|
| Half-circle arc gauge | **SIMPLIFY** | Remove 700ms arc animation; keep static arc |
| Grade letter below score | **REMOVE** | Redundant — grade encoded in score number |
| Delta badge (↑/↓ arrow) | **KEEP** | Essential trend indicator |

---

#### RiskDonutChart.tsx (Dashboard widget)

| Element | Verdict | Rationale |
|---------|---------|-----------|
| Entire donut chart | **REMOVE** | Decorative; RiskHeatMap table provides same data with interactive drill-down. Donut center "Total" label distracts from actual risk counts in legend |

---

#### AttackSurfaceRadar.tsx (Overview component)

| Element | Verdict | Rationale |
|---------|---------|-----------|
| Entire Recharts radar/spider chart | **REMOVE** | 6-pillar data already shown in PillarCard grid directly below; radar adds visual complexity without new information |

---

#### ArcGauge.tsx (Overview component)

| Element | Verdict | Rationale |
|---------|---------|-----------|
| 270-degree arc with animation | **REMOVE** | Single number (e.g., "72.5 Grade B") clearer as text card; arc animation (1s ease-in-out) is purely decorative |

---

### Simplified Layout Structures (Per Page)

#### Dashboard.tsx — Simplified

```
BEFORE (6 tabs, 20+ widgets):
┌─────────────────────────────────────────────┐
│ [Summary Cards + sparklines] [Run] [Alerts] │
├─────────────────────────────────────────────┤
│ Tab: Exposure                               │
│ ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
│ │ Anomaly  │ │ Donut    │ │ Risk Trend   │ │
│ │ Alerts   │ │ Chart    │ │ (4-layer)    │ │
│ ├──────────┤ ├──────────┤ ├──────────────┤ │
│ │ Velocity │ │ HeatMap  │ │ Recent       │ │
│ │ Chart    │ │          │ │ Changes      │ │
│ └──────────┘ └──────────┘ └──────────────┘ │
│ ┌──────────────────────┐ ┌────────────────┐ │
│ │ Platform Health      │ │ ID Correlation │ │
│ └──────────────────────┘ └────────────────┘ │
└─────────────────────────────────────────────┘

AFTER:
┌─────────────────────────────────────────────┐
│ [Summary Cards (no sparklines)] [Run] [Alrt]│
├─────────────────────────────────────────────┤
│ Tab: Exposure                               │
│ ┌──────────┐ ┌──────────────────────────┐   │
│ │ Anomaly  │ │ Risk Trend (crit+high    │   │
│ │ Alerts   │ │ lines only)              │   │
│ ├──────────┤ ├──────────────────────────┤   │
│ │ Velocity │ │ RiskHeatMap (interactive  │   │
│ │ Chart    │ │ table — kept as-is)      │   │
│ ├──────────┤ ├──────────────────────────┤   │
│ │ Recent   │ │ Role Usage (bar only,    │   │
│ │ Changes  │ │ no mini-pie)             │   │
│ └──────────┘ └──────────────────────────┘   │
└─────────────────────────────────────────────┘
```

**Removed:** DonutChart, sparklines, PlatformHealth, IdentityCorrelation, mini-pie from RoleUsage
**Result:** 6 fewer widgets. Table-first layout. Higher signal density.

---

#### CISODashboard.tsx — Simplified

```
BEFORE (Executive Summary tab):
┌─────────────────────────────────────────────┐
│ ┌─────────────────┐  ┌────────────────────┐ │
│ │ ScoreRing 48pt  │  │ Gradient benchmark │ │
│ │ + tier badge    │  │ bar with 3 dots    │ │
│ ├─────────────────┤  ├────────────────────┤ │
│ │ 🐷 Dormant: 12  │  │ 👻 Ghost: 4       │ │
│ │ 🔑 Over-priv: 8 │  │ 🧟 Zombie: 2      │ │
│ ├─────────────────┤  ├────────────────────┤ │
│ │ Sparkline       │  │ Projections        │ │
│ │ (gradient fill) │  │ (no action/fixed)  │ │
│ └─────────────────┘  └────────────────────┘ │
└─────────────────────────────────────────────┘

AFTER:
┌─────────────────────────────────────────────┐
│ ┌─────────────────┐  ┌────────────────────┐ │
│ │ ScoreRing 48pt  │  │ Industry: 72       │ │
│ │ + tier badge    │  │ Target: 80 (text)  │ │
│ ├─────────────────┤  ├────────────────────┤ │
│ │ [D] Dormant: 12 │  │ [G] Ghost: 4       │ │
│ │ [P] Over-priv: 8│  │ [Z] Zombie: 2      │ │
│ ├─────────────────┤  ├────────────────────┤ │
│ │ Sparkline       │  │ Projections        │ │
│ │ (no gradient)   │  │ (no action/fixed)  │ │
│ └─────────────────┘  └────────────────────┘ │
└─────────────────────────────────────────────┘
```

**Removed:** Emojis → letter codes, gradient benchmark bar → text, pulse animation, box shadows, gradient buttons
**Result:** Calmer, more accessible, same information.

---

### Summary: Proposed Removals

| Category | Items | Files Affected |
|----------|-------|----------------|
| **Donut charts** | RiskDonutChart (entire component hidden from dashboard) | Dashboard.tsx |
| **Radar/spider charts** | AttackSurfaceRadar (entire component) | Overview.tsx |
| **Arc gauges** | ArcGauge (entire component) | Overview.tsx |
| **Circular mini-gauges** | ExposureRing in table rows | WorkloadIdentities.tsx, SPNDashboard.tsx |
| **Animated elements** | Pulse animation, arc draw animation, chevron rotate, gradient transitions | CISODashboard.tsx, PostureScore.tsx |
| **Decorative styling** | Box shadows, gradient buttons, gradient backgrounds, emoji icons | CISODashboard.tsx |
| **Duplicated metrics** | Risk score shown 3×, tier badge shown 4×, blast radius shown 2× | CISODashboard.tsx |
| **Low-value widgets** | PlatformHealth (move), IdentityCorrelation (remove), sparklines (remove) | Dashboard.tsx |
| **Redundant chart parts** | RoleUsageChart mini-pie, RiskTrendChart 4→2 layers | Dashboard.tsx |
| **Grade letter** | PostureScore grade below number | PostureScore.tsx |

### What Is NOT Being Removed

- All tables (RiskHeatMap, identity lists, drift timeline, activity log)
- All stat cards with real KPI data
- All drill-down navigation (clickable numbers → `/identities?filter=value`)
- All compliance scorecards and framework cards
- All credential health and expiry tracking
- All trust/federation panels
- All anomaly alerts
- All SOAR activity tracking
- All remediation progress tracking
- ScoreRing on CISODashboard (core posture metric)
- Sparkline on CISODashboard (readable at 320×80 size)
- Progress bars (compact, data-driven)
- Badges (semantic status labels)

---

---

## PHASE 3 — Executive Posture Refactor (Implemented)

**Date:** 2026-02-27

### Objective
Strip down the overloaded Executive Summary tab (Tab 1) in CISODashboard.tsx to a focused "Executive Posture" view with exactly 5 top metrics and 3 tables. No charts, no compliance wheels, no decorative elements.

### Changes Made

**File:** `frontend/src/pages/CISODashboard.tsx` — replaced `ExecSummaryTab` function (was lines 1883-2078)

#### Removed from ExecSummaryTab:
- `execView` toggle state + button (Executive View On/Off)
- `autoFixItem` state + AutoFixDialog
- `HeroPanel` call (gradient bar/benchmark comparison)
- `RiskDriverRow` pillar breakdown card
- Identity Exposure Snapshot card (human/workload/guest counts + exposure signals)
- Immediate Actions section (top 3 remediations with auto-fix)
- Risk Trend sparkline + net delta chart
- Governance & Compliance Health card (governance metrics + worst frameworks)
- Computed values: `worstFrameworks`, `netDelta`, `top3`, `totalGain`, `sortedPillars`

#### New Layout (5 Metrics + 3 Tables):

```
┌─────────────────────────────────────────────────────┐
│  [AGIRS Ring]  Total IDs  Privileged  NHI  T0 Admin │  ← 5 metric cards
├─────────────────────────────────────────────────────┤
│  Human Identity Risk (HIRI)  │  Phantom Exposure    │  ← 2-column grid
│  (5-row breakdown table)     │  (NHIRI breakdown)   │
├─────────────────────────────────────────────────────┤
│  Governance Effectiveness (GEI components)           │  ← full-width
└─────────────────────────────────────────────────────┘
```

#### 5 Metric Cards:
| Card | Source | Drill-Down |
|------|--------|------------|
| AGIRS Score (ScoreRing size 64 + tier badge + delta) | `d.agirs.agirs` | — |
| Total Identities | `d.tenant.identityCount` | `/identities` |
| Privileged | `d.kpis.privilegedRoles.value` + subtitle | `/identities?pillar=effective-privilege` |
| Non-Human | workload count from `d.identityBreakdown` | `/identities?workload=true` |
| Sensitive Admin (T0) | `d.pillars[0]?.subMetrics?.[0]?.value` | `/identities?privilege_tier=0` |

#### 3 Tables (reused existing components):
| Table | Component | Data |
|-------|-----------|------|
| Human Identity Risk (HIRI) | `HIRIBreakdownCard` | 5 rows: ghost, dormant_priv, over_priv, ext_guest, zombie |
| Phantom Exposure (NHIRI) | `PhantomExposureCard` | 5 rows: orphaned, dormant, zombie_nhi, expired_creds, ownerless_apps |
| Governance Effectiveness (GEI) | `GEICard` | 4 rows with progress bars |

#### Components now unused but kept:
- `HeroPanel`, `RiskDriverRow`, `ExposureMetricRow` — can be deleted in a cleanup pass
- `onPreview`/`onTicket` params aliased as `_onPreview`/`_onTicket` (kept for call-site compatibility)

### Verification
- TypeScript: `npx tsc --noEmit` — zero errors
- Other 5 tabs unchanged (Identity Risk, Action Plan, Control & Governance, Compliance & Evidence, Risk Movement)

---

## PHASE 4 — Identity Inventory Hardening (Implemented)

**Date:** 2026-02-27

### Objective
Refactor Identity Inventory (`/identities`) to be a neutral canonical listing. Remove risk score gamification and unnecessary summary widgets. Add snapshot selector. Keep filters.

### File Modified
- `frontend/src/pages/Identities.tsx`

### Changes Made

#### Removed (Risk Gamification & Summary Widgets):
- **KPI Summary Strip** (was 7 stat cards: Total, Privileged, NHI, External, Zombie, Cred Risk, High/Crit) — replaced with comment placeholder
- **Risk column** (risk_level badge + numeric score + CA shield icon) — entire column removed
- **Credentials column** (credential_health badge + count) — entire column removed
- **PIM badge** on Privileged column — removed from cell rendering
- **Table footer legend** (Privileged = T0 Global Admin... explanatory text) — simplified to "Click any row to inspect"
- **Default sort by risk_level desc** — changed to `display_name asc` (neutral alphabetical)

#### Column Refactoring (10 → 9 columns):

| # | Old Column | New Column | Change |
|---|-----------|-----------|--------|
| 1 | Identity | Identity | Kept (name + type icon + ID) |
| 2 | Category | **Type** | Renamed header |
| 3 | Privileged | **Effective Access** | Renamed, PIM badge removed |
| 4 | Scope | **Sensitive Access** | Renamed |
| 5 | Risk | *(removed)* | Risk gamification removed |
| 6 | Credentials | *(removed)* | Not in required columns |
| 7 | Status | Status | Kept |
| 8 | Created | **First Seen** | Renamed |
| 9 | Last Used | **Last Seen** | Renamed |
| 10 | Cloud | Cloud | Kept, moved to position 3 |
| — | *(new)* | **Owner** | Added at position 4 |

#### New Column Order:
`Identity → Type → Cloud → Owner → Status → Effective Access → Sensitive Access → Last Seen → First Seen`

#### Added:
- **Owner column** — displays `owner_display_name` with truncation, "No owner" italic for nulls
- **`owner_display_name` sort support** — added to SortField type union and sort switch statement (nulls sort last)
- **Snapshot selector** (top-right) — fetches `/api/runs`, displays completed runs as dropdown with date + identity count. Display-only (API always returns latest run data, no backend modification needed).
- **Discovery runs state** — `discoveryRuns` state + `useEffect` fetching from `/api/runs`, filtered to `status=completed`, limited to 10

#### Preserved:
- All filter UI (simple filters, advanced query builder, category tabs, active chips)
- Saved Views bar
- Export functionality (CSV, PDF, Export All CSV, Export All JSON)
- Bulk actions (acknowledge, complete, skip, add to group)
- View toggle (Table/Graph)
- Identity drawer (click to inspect)
- Context banner (CISO drill-down)
- `colSpan` updated from 11 → 10

### Verification
- TypeScript: `npx tsc --noEmit` — zero errors
- No backend changes

---

## Next Steps

## PHASE 5 — Non-Human Identity First-Class Upgrade (Implemented)

**Date:** 2026-02-27

### Objective
Refactor the Workload Identity Exposure screen (`/workload-identities`) into an audit-ready Non-Human Identity Inventory. Remove duplicate monitoring elements, replace gamification with focused audit metrics, and standardize the table to 7 essential columns.

### File Modified
- `frontend/src/pages/WorkloadIdentities.tsx`

### Changes Made

#### Header Renamed:
- "Workload Identity Exposure" → **"Non-Human Identity Inventory"**
- Subtitle: "Service principals, app registrations, and managed identities — audit-ready view"

#### Removed (Duplicate Monitoring / Gamification):
- **P2 Telemetry Active banner** (green gradient — telemetry status)
- **Visibility Gap banner** (red/amber gradient — blind identity warning)
- **7-card Exposure Summary strip** (Critical Exposure, Orphaned, Stale Credentials, Can Escalate, Zombie, Risky Sign-Ins, Anomalies)
- **Risk Distribution panel** (risk level counts table + avg score)
- **Top Findings panel** (severity-ranked finding list with score impacts)
- **Exposure Ring column** (SVG ring with 0-100 score)
- **Credential Risk Score column** (score/25 with color coding)
- **Lifecycle column** (lifecycle state badge)
- **Created column** (created_datetime)
- **P2-conditional columns** (Sign-Ins 30d, Anomaly count)
- **Chevron column** (right arrow indicator)
- **Exposure formula footer** (scoring formula explanation)
- **ESC badge** on identity name (can-escalate indicator, moved to Admin Scope metric)
- **Default sort by exposure_score desc** → changed to `display_name asc`

#### New Top Metrics (4 cards, grid-cols-4):

| Metric | Source | Drill-Down |
|--------|--------|------------|
| **Orphaned** | `stats.orphaned_count` | → owner=orphaned filter |
| **Dormant > 30 Days** | `stats.zombie_count` | → lifecycle=likely_dormant filter |
| **Admin Scope** | `stats.can_escalate_count` | → escalate=true filter |
| **Sensitive Access** | `stats.exposure_critical` | → exposure=critical filter |

#### New Table Columns (7):

| # | Column | Source | Notes |
|---|--------|--------|-------|
| 1 | **Identity** | TypeBadge + display_name | Sortable, truncated to 260px |
| 2 | **Owner** | owner_display_name | "No owner" italic if null |
| 3 | **Purpose** | WORKLOAD_TYPE_CONFIG[identity_type].label | Service Principal / App Registration / Managed Identity |
| 4 | **Effective Privilege** | privilege_score/40 | Color: red ≥30, orange ≥15, gray <15. Sortable. |
| 5 | **Sensitive Scope** | SCOPE_FLAG_CONFIG badge | Tenant/Mgmt Group/Subscription/RG/Resource |
| 6 | **Last Used** | last_sign_in | formatDate, "Unknown" if null. Sortable. |
| 7 | **Ownership Confidence** | OWNER_STATUS_CONFIG badge | Owned/Single Owner/Orphaned/Resource Bound/Unknown |

#### Preserved:
- Type filter pills (All/SPNs/App Regs/Managed IDs)
- Active filter chips with Clear All
- Filter bar (exposure, lifecycle, owner, can escalate, search)
- Pagination (50 per page)
- Row click → detail page navigation
- Hide Microsoft checkbox
- URL param sync for all filters

### Verification
- TypeScript: `npx tsc --noEmit` — zero errors
- No backend changes
- colSpan updated from dynamic 10/12 → fixed 7

---

## Next Steps

## PHASE 6 — Merge Overlapping Access Views (Implemented)

**Date:** 2026-02-27

### Objective
Consolidate scattered access-related views (Risk Monitoring identity breakdown, privileged identity view, sensitive access summary, effective access exploration) into one coherent "Access Explainability" section with 3 dedicated pages. Remove duplicate views. Preserve all backend queries.

### Files Created
- `frontend/src/pages/AccessGraph.tsx` — standalone access graph exploration
- `frontend/src/pages/EffectiveAccessExplorer.tsx` — privilege/RBAC analysis (replaces RbacHygiene)
- `frontend/src/pages/SensitiveDataAccess.tsx` — resource exposure and data access (replaces DataSecurity)

### Files Modified
- `frontend/src/App.tsx` — added 3 new routes + 2 legacy redirects
- `frontend/src/components/layout/Sidebar.tsx` — added "Access Explainability" section, removed duplicate `/data-security` from Identity section

### New Sidebar Structure

```
COMMAND CENTER (blue #2563eb)
├── Risk Dashboard          → /
└── Risk Monitoring         → /dashboard

IDENTITY (purple #8b5cf6)
└── Identity Inventory      → /identities

ACCESS EXPLAINABILITY (cyan #0891b2)    ← NEW SECTION
├── Access Graph            → /access-graph
├── Effective Access Explorer → /effective-access
└── Sensitive Data Access   → /sensitive-access

GOVERNANCE (cyan #0891b2)
├── Governance Coverage     → /service-accounts
├── Role Optimization       → /role-mining
└── Access Reviews          → /access-reviews

REMEDIATION (green #16a34a)
└── Action Plan             → /remediation

DATA SECURITY (orange #ea580c)
├── Secrets & Keys          → /key-vaults
└── Storage Exposure        → /storage-accounts

COMPLIANCE (amber #ca8a04)
├── Frameworks & Controls   → /compliance
└── Evidence Center         → /exports

OPERATIONS (slate #64748b)
├── Drift & Changes         → /drift
├── Activity Log            → /activity
└── Reports                 → /reports
```

### 3 New Pages

#### 1. Access Graph (`/access-graph`)
- Identity search with debounced autocomplete (searches `/api/identities`)
- Renders existing `AccessGraphTab` component for selected identity
- Dual-mode: executive (blast radius) + technical (hierarchical ARM tree)
- Empty state with search prompt when no identity selected

#### 2. Effective Access Explorer (`/effective-access`)
- Replaces `/rbac-hygiene` (which now redirects here)
- Fetches from `/api/rbac-hygiene` (existing endpoint, no backend change)
- Shows: Hygiene Grade, Privilege Tier Distribution (T1-T4), Scope Breakdown
- Finding rules table with severity filter + expandable identity-level findings
- Drill-down links to `/identities?privilege_tier=N`

#### 3. Sensitive Data Access (`/sensitive-access`)
- Replaces `/data-security` (which now redirects here)
- Fetches from `/api/data-security` (existing endpoint, no backend change)
- Shows: Security Grade, 8 component scores (network, auth, logging, data protection, vault, identity access, secret hygiene, identity exposure)
- Component filter (click any component to filter findings)
- Risk distribution + Quick navigation to Secrets & Keys / Storage / Resources
- Findings table filtered by component

### Legacy Route Redirects
| Old Route | Redirects To | Reason |
|-----------|-------------|--------|
| `/rbac-hygiene` | `/effective-access` | Consolidated into Access Explainability |
| `/data-security` | `/sensitive-access` | Consolidated into Access Explainability |

### Duplicate Views Removed
- `/data-security` removed from Identity sidebar section (moved to Access Explainability as `/sensitive-access`)
- `/rbac-hygiene` was a hidden route (now canonical at `/effective-access`)

### Preserved (No Backend Changes)
- All existing API endpoints: `/api/rbac-hygiene`, `/api/data-security`, `/api/identities`, `/api/identities/:id/graph-data`
- All existing page files kept (RbacHygiene.tsx, DataSecurity.tsx) — only routes redirect
- All other sidebar sections unchanged

### Verification
- TypeScript: `npx tsc --noEmit` — zero errors
- No backend changes
- 3 new icons added to Sidebar (accessGraphIcon, effectiveAccessIcon, sensitiveDataIcon)

---

## Phase 7 — Snapshot Normalization

**Date:** 2026-02-27

### Objective
Rename "discovery runs" to "Snapshots" across the entire frontend UI. Add snapshot selector dropdown, snapshot comparison navigation, and immutable data label. No backend changes — UI naming and context handling only.

### Terminology Mapping

| Old Term | New Term |
|----------|----------|
| Discovery Run | Snapshot |
| Discovery Scan | Snapshot capture |
| Run Discovery | Capture Snapshot |
| Run Scan | Capture Snapshot |
| Run #N | Snapshot #N |
| Discovery Run History | Snapshot History |
| Discovery Runs (stat card) | Snapshots |
| Scan Now | Capture Now |
| Scan Triggered | Capturing... |

### Files Modified (35 files)

#### Core Pages
| File | Changes |
|------|---------|
| `pages/Dashboard.tsx` | Stat card "Snapshots", toast messages, "Capture Snapshot" button, "Snapshot History" panel, "Snapshot #N" labels, immutable badge + "Compare Snapshots →" link in header |
| `pages/CISODashboard.tsx` | "Capture Snapshot" button, "Last snapshot:" text, immutable badge, updated comments |
| `pages/Overview.tsx` | "Capture Snapshot" system action, snapshot-based empty state messages |
| `pages/Identities.tsx` | Enhanced snapshot selector (Snapshot #N format, "(latest)" tag), immutable lock badge |
| `pages/DriftHistory.tsx` | "Snapshot Comparison" column header, "Snapshot #N vs #N" rows, snapshot count badge + immutable badge in header |
| `pages/IdentityDetail.tsx` | "Score trend across snapshots", "Snapshot #N" evidence, "Cross-snapshot identity comparison" data source, timeline empty state |
| `pages/SystemHealth.tsx` | "Recent Snapshots" section header |
| `pages/ActivityLog.tsx` | "Snapshot Triggered" / "Snapshot Completed" action labels, empty state text |

#### Settings & Configuration
| File | Changes |
|------|---------|
| `pages/Settings.tsx` | "Snapshots (days)" retention label, "snapshots stored" count, "Capture Snapshot" connection button, "Capture Now" scheduler button, toast messages, role descriptions, notification labels, playbook/rule descriptions, P2 telemetry description |
| `pages/OnboardingWizard.tsx` | Welcome text, review step text, trigger comment |
| `pages/CloudIntegrationGuide.tsx` | "Test & Capture First Snapshot" step |

#### Empty States & Messages
| File | Changes |
|------|---------|
| `pages/LockedDashboard.tsx` | "Snapshots" placeholder card, "capture your first snapshot" message |
| `pages/Compliance.tsx` | "Capture a snapshot to generate compliance posture data" |
| `pages/SensitiveDataAccess.tsx` | "Capture a snapshot first" |
| `pages/EffectiveAccessExplorer.tsx` | "Capture a snapshot first" |
| `pages/RbacHygiene.tsx` | "Capture Snapshot" button, "Capture a snapshot to analyze" |
| `pages/SPNDashboard.tsx` | "Capture a snapshot to populate" |
| `pages/Resources.tsx` | "Capture a snapshot to populate" |
| `pages/Subscriptions.tsx` | "Capture a snapshot to detect cloud accounts" |
| `pages/ResourceDetail.tsx` | "completed snapshot" cross-reference, "2 snapshots required" trend |
| `pages/Reports.tsx` | "Latest snapshot (all identities)" |
| `pages/Exports.tsx` | "latest snapshot data" |
| `pages/NotificationCenter.tsx` | "after snapshots detect changes" |

#### Components
| File | Changes |
|------|---------|
| `components/dashboard/widgetRegistry.ts` | Widget descriptions updated to "snapshots" |
| `components/dashboard/RiskTrendChart.tsx` | "across snapshots" subtitle, "Snapshot #N" tooltip |
| `components/dashboard/RiskVelocityChart.tsx` | "Snapshot #N" tooltip |
| `components/dashboard/RecentChanges.tsx` | "Snapshot #N vs #N", "2+ snapshots" empty state |
| `components/dashboard/ResourceOverview.tsx` | "Capture a snapshot to populate" |
| `components/dashboard/TrustAccessPanel.tsx` | "Capture a snapshot first" |
| `components/PillarDrilldownPanel.tsx` | "Capture a snapshot to populate pillar metrics" |
| `components/ScanScheduleManager.tsx` | "automated snapshot intervals" |

#### Legal, Docs & Admin
| File | Changes |
|------|---------|
| `pages/Documentation.tsx` | "Snapshots" retention table, "Snapshot history" / "Trigger snapshot capture" API docs, Quick Start guide |
| `pages/PrivacyPolicy.tsx` | "snapshots" retention, "capture snapshots" data sharing |
| `pages/TermsOfService.tsx` | "Snapshot Success Rate" SLA |
| `pages/admin/AdminTenants.tsx` | "snapshots" in delete confirmation |
| `pages/admin/AdminSLA.tsx` | "Snapshots (Last 30 Days)" section |

#### Other
| File | Changes |
|------|---------|
| `utils/pdfGenerator.ts` | "Snapshot: #N" on PDF cover page |
| `services/api.ts` | Docstring comments updated |
| `types/index.ts` | Interface comment updated |
| `constants/metrics.ts` | `NO_DATA` explanation text |

### New UI Elements

#### 1. Immutable Badge
Added to: Identities (snapshot selector), Dashboard (header), DriftHistory (header), CISODashboard (top bar)
- Green lock icon + "IMMUTABLE" label
- Emerald color scheme (bg-emerald-50, border-emerald-200, text-emerald-700)
- Tooltip: "Snapshot data is immutable — it reflects the state at capture time"

#### 2. Enhanced Snapshot Selector (Identities.tsx)
- Format: `#ID · Date · N identities (latest)` for most recent
- Immutable badge adjacent to selector
- Display-only (API returns latest snapshot data)

#### 3. Compare Snapshots Navigation (Dashboard.tsx)
- "Compare Snapshots →" link in header next to immutable badge
- Navigates to `/drift` which has full comparison UI

#### 4. Snapshot Count Badge (DriftHistory.tsx)
- Shows total snapshot count in header
- Adjacent immutable badge

### Preserved (No Changes)
- Backend API endpoints (all still use `/api/runs`, `/api/runs/trigger`, etc.)
- Database schema (tables remain `discovery_runs`, etc.)
- Variable names in code (`discoveryRunning`, `discoveryRuns`, `triggerDiscovery`, etc.)
- Internal TypeScript types (`DiscoveryRun` interface kept as-is)
- API response field names
- `canTriggerScans` permission boolean in AuthContext

### Verification
- TypeScript: `npx tsc --noEmit` — zero errors
- Grep for `Run #` — zero user-facing matches
- Grep for `discovery run|Discovery Run|discovery scan|Discovery Scan|Run Discovery|Run Scan` — zero matches
- No backend changes
- 35 files modified, 0 new files created

---

## Phase 8 — Compliance De-Gamification

**Date:** 2026-02-27

### Objective
Remove decorative compliance visualizations (percentage arcs, maturity wheels, progress bars) and replace with a clean evidence-based framework table. Each control now shows: Control, Status, Evidence Source, Snapshot ID, and Export link. All existing compliance logic and API integration preserved.

### File Modified
- `frontend/src/pages/Compliance.tsx` — complete rewrite of presentation layer

### What Was Removed

| Component | Lines | Description |
|-----------|-------|-------------|
| `ScoreRing` | 97-117 | SVG percentage arc with animated stroke-dashoffset |
| `MiniBar` | 119-128 | Decorative horizontal progress bar |
| `FrameworkCard` | 130-185 | Card with ScoreRing, hover effects, expand arrow, glow shadows |
| `TierDivider` | 187-205 | Gradient-line section divider with emoji icon |
| `ControlExpansion` | 216-448 | Standalone expansion component (logic preserved inline) |
| `buildFrameworkCard` | 452-459 | Helper for card props |
| Bottom section | 628-730 | Remediation Progress bar + SA Governance bar + Overall Summary Bar with DrillableNumber |
| `DrillableNumber` import | line 4 | No longer needed |

### What Was Added

#### New Layout Structure
```
┌──────────────────────────────────────────────────┐
│  Compliance Evidence   [Identity Controls] [🔒]  │  ← header + immutable badge
├──────────────────────────────────────────────────┤
│  342 Controls │ 280 Pass │ 12 Warn │ 50 Fail    │  ← summary strip
│  8 Frameworks │ Snapshot #45 · Feb 27, 2026      │
│                                     [Export All]  │
├──────────────────────────────────────────────────┤
│  [All (342)] [Failing (50)] [Warnings (12)] ...  │  ← status filter tabs
├──────────────────────────────────────────────────┤
│  CORE GOVERNANCE  (3 frameworks)                  │  ← tier header
│  ▶ CIS Azure v2.0        252 pass  5 warn  8 fail│  ← framework row
│  ┌─────────────────────────────────────────────┐ │
│  │ Control │ Status │ Severity │ Evidence      │ │  ← expanded table
│  │         │        │          │ Source │ # │ ↗ │ │
│  │ CIS 1.1 │ FAIL   │ critical │ priv...│45│Exp│ │
│  │   └─ Impacted Identities (3)                │ │  ← evidence drill-down
│  │     [critical] john.doe  service_principal 82│ │
│  └─────────────────────────────────────────────┘ │
│  INDUSTRY SPECIFIC  (2 frameworks)                │
│  ...                                              │
└──────────────────────────────────────────────────┘
```

#### Framework Table Columns
| Column | Description |
|--------|-------------|
| **Control** | Control ID (monospace) + control name |
| **Status** | Pass/Warn/Fail badge with color coding |
| **Severity** | Critical/High/Medium/Low (for non-pass only) |
| **Evidence Source** | Derived from `ctrl.pillar`, `ctrl.cloud`, or `ctrl.metric` |
| **Impacted** | Count of affected identities |
| **Snapshot** | `#N` — the snapshot ID from `trend_mini` |
| **Export** | Link to `/exports` page |

#### New Features
1. **Status filter** — All / Failing / Warnings / Passing with live counts
2. **Collapsible framework rows** — click to expand control table
3. **Immutable badge** in header (consistent with Phase 7)
4. **Snapshot ID** in summary strip and per-control row
5. **Export All** button in summary strip
6. **Per-control Export** link in table
7. **`evidenceSource()` helper** — derives human-readable source from control metadata

### Preserved (No Changes)
- All TypeScript types (`IntelControl`, `IntelFramework`, `IntelligenceData`, `EvidenceIdentity`)
- API endpoint (`/api/compliance/intelligence`)
- `useConnection()` hook for multi-tenant support
- URL param sync (`?framework=X` for auto-expand from Overview)
- Evidence identity drill-down (click → navigate to `/identities/:id`)
- Identity risk badges, scores, and category display
- Framework tier grouping and sorting
- Status ordering (fail → warn → pass)
- `TIER_CONFIG` categories (Core Governance, Industry, Privacy, Benchmarks)
- Benchmark exclusion note

### Verification
- TypeScript: `npx tsc --noEmit` — zero errors
- No backend changes
- 1 file modified, 0 new files created

---

## Phase 9 — Export Hardening (Enterprise Export Standardization)

**Date**: 2026-02-27
**Scope**: Ensure all exports include Snapshot ID, Timestamp, Tenant ID, Schema version. Display metadata in UI before export. No backend changes.

### Core Changes

#### `utils/exportUtils.ts` — Schema version + metadata helpers
- Added `EXPORT_SCHEMA_VERSION = '1.0'` constant
- Added `ExportMetadata` interface (snapshot_id, timestamp, tenant_id, tenant_name, schema_version)
- Added `buildExportMeta()` helper to construct metadata from current context
- Enhanced `downloadCSV()` — optional `meta` param prepends 7 comment rows (`# AuditGraph Export`, `# Snapshot ID: N`, `# Timestamp: ISO`, `# Tenant ID: N`, `# Tenant: name`, `# Schema Version: 1.0`, `#`)
- Enhanced `downloadJSON()` — optional `meta` param wraps data in `{ _export_metadata: {...}, data: {...} }` envelope

#### `pages/Exports.tsx` — Central Export Center
- Added `useAuth` import for tenant context
- Added `useEffect` to fetch latest snapshot from `/api/runs`
- Added **Export Metadata Strip** panel (4-column grid: Snapshot ID, Timestamp, Tenant ID, Schema Version)
- "Included in all exports" badge
- All 7 export types (identities, compliance, drift, risk-summary, evidence-package, sensitive-data, evidence-zip) now inject metadata into CSV/JSON downloads
- Updated info section to describe metadata format (CSV comment rows, JSON envelope, ZIP manifest)

#### `pages/Identities.tsx` — Identity Inventory Exports
- Added `buildExportMeta` import
- Updated `useAuth` destructure to include `activeTenantId`, `activeTenantName`
- `exportAllCSV()` and `exportAllJSON()` now pass metadata to download functions
- Added **Export Metadata Strip** below header (Snapshot #ID, Captured timestamp, Tenant ID, Schema v1.0)
- Strip visible when `discoveryRuns.length > 0`

#### `pages/Resources.tsx` — Resource CSV Export
- Added `useAuth` + `buildExportMeta` imports
- Added `latestSnapshotId` state + snapshot fetch effect
- `handleCSVExport()` now passes metadata
- Added **Export Metadata Strip** below header

#### `pages/SPNDashboard.tsx` — Workload Identity Exports
- Added `useAuth` + `buildExportMeta` imports
- Added `latestSnapshotId` state + snapshot fetch effect
- `handleCSVExport()` now passes metadata
- Added **Export Metadata Strip** below header

#### `pages/AppRegistrations.tsx` — App Registration CSV Export
- Added `useAuth` + `buildExportMeta` imports
- Added `latestSnapshotId` state + snapshot fetch effect
- `handleCSVExport()` now passes metadata
- Added **Export Metadata Strip** below header (theme-aware CSS variables)

#### `pages/Reports.tsx` — PDF Report Generation
- Added `useAuth` + `EXPORT_SCHEMA_VERSION` imports
- Added snapshot fetch effect for latest snapshot
- Added **Report Metadata Strip** below report type selector (Snapshot, Captured, Tenant, Schema)

### Export Metadata Format

**CSV files** — metadata prepended as comment rows:
```
# AuditGraph Export
# Snapshot ID: 42
# Timestamp: 2026-02-27T14:30:00.000Z
# Tenant ID: 1
# Tenant: Acme Corp
# Schema Version: 1.0
#
"Display Name","Identity ID","Type",...
```

**JSON files** — envelope wrapper:
```json
{
  "_export_metadata": {
    "snapshot_id": 42,
    "timestamp": "2026-02-27T14:30:00.000Z",
    "tenant_id": 1,
    "tenant_name": "Acme Corp",
    "schema_version": "1.0"
  },
  "data": { ... }
}
```

### Files Modified (7)
1. `utils/exportUtils.ts` — schema version, metadata types, enhanced download functions
2. `pages/Exports.tsx` — metadata strip, metadata injection in all exports
3. `pages/Identities.tsx` — metadata strip, metadata in CSV/JSON exports
4. `pages/Resources.tsx` — metadata strip, metadata in CSV export
5. `pages/SPNDashboard.tsx` — metadata strip, metadata in CSV export
6. `pages/AppRegistrations.tsx` — metadata strip, metadata in CSV export
7. `pages/Reports.tsx` — metadata strip for PDF generation

### What Was NOT Changed
- No backend API modifications
- No export endpoint changes
- ZIP evidence package metadata (handled server-side in MANIFEST)
- PDF file metadata (already includes snapshot # on cover page from Phase 7)

### Verification
- TypeScript: `npx tsc --noEmit` — zero errors
- No backend changes
- 7 files modified, 0 new files created

---

## PHASE 10 — Enterprise Visual System Cleanup

**Date:** 2026-02-27

### Objective
Eliminate visual debt (gradients, glassmorphism, inconsistent density) and enforce a flat, signal-only design system across all screens.

### Design Rules Enforced
| Rule | Value |
|------|-------|
| Gradients | **None** — flat solid colors only |
| Glassmorphism | **None** — solid backgrounds only |
| Table cells | `px-3 py-2 text-xs` |
| Table headers | `px-3 py-2.5 text-xs font-medium uppercase` |
| Page spacing | `space-y-4` (was space-y-6) |
| Max shadow | `shadow-lg` (capped shadow-2xl to same value) |
| Modal overlays | `bg-black/60` (solid, no blur) |

### Changes Made

#### 1. CSS Theme Cleanup (`index.css`)
- Removed `--gradient-hero` variable
- `--ciso-bg-page` → flat `#0c1220` (was linear-gradient)
- `--ciso-panel-bg` → `var(--bg-raised)` (was linear-gradient)
- `--ciso-btn-gradient` → `var(--accent-primary)` (was linear-gradient)
- Removed `--ciso-backdrop: blur(12px)`
- `--shadow-2xl` capped to same value as `--shadow-lg`
- TopBar: solid `var(--bg-deep)` background (removed backdrop-filter blur)

#### 2. Gradient Removal (6 files)
- **CopilotPanel.tsx** — indigo→purple gradient header → `bg-blue-50`
- **PillarDrilldownPanel.tsx** — linear-gradient card bg → `var(--bg-raised)`
- **CISODashboard.tsx** — 3 linear-gradients (risk bar, 2 buttons) + 2 SVG linearGradients → flat fills
- **AdminTenants.tsx** — slate gradient header → `bg-gray-900`, blue→cyan button → `bg-blue-600`
- **AdminOnboarding.tsx** — 2 blue→cyan buttons → `bg-blue-600`
- **OnboardingWizard.tsx** — progress bar gradient → `bg-blue-600`

#### 3. Glassmorphism Removal (4 files)
- **CloudComparison.tsx** — `bg-black/40 backdrop-blur-sm` → `bg-black/60`
- **Settings.tsx** — `bg-black/50 backdrop-blur-sm` → `bg-black/60`
- **SPNDashboard.tsx** — `bg-black/30 backdrop-blur-sm` → `bg-black/60`
- **IdentityCorrelation.tsx** — `bg-black/30 backdrop-blur-sm` → `bg-black/60`

#### 4. Shadow Reduction (10 files, 17 occurrences)
All `shadow-2xl` → `shadow-lg`:
- IdentityDrawer, CustomizePanel, CopilotPanel, SearchModal, CloudComparison
- Settings (6×), SPNDashboard, AppRegistrations (2×), Identities (3×), ServiceAccountGovernance

#### 5. Table Density Standardization (3 files)
- **DriftHistory.tsx** — `text-sm` → `text-xs`, all th: `px-3 py-2.5 font-medium uppercase`, all td: `px-3 py-2`
- **ActivityLog.tsx** — `text-sm` → `text-xs`, all th: `px-3 py-2.5 font-medium uppercase`, all td: `px-3 py-2`
- **Identities.tsx** — placeholder cells: `px-4 py-8` → `px-3 py-6`

#### 6. Page Spacing Standardization (26 files)
All `space-y-6` → `space-y-4` at page container level:
- Dashboard, Reports, Exports, ActivityLog, DriftHistory, Settings, SPNDashboard
- IdentityCorrelation, SystemHealth, NotificationCenter, RoleMining
- CrossTenantAnalytics, IdentityComparison, RemediationCenter, IdentityGroups
- Subscriptions, Invoices, OnboardingWizard, CloudIntegrationGuide
- Admin: Overview, Users, SLA, Billing, Profile, Monitoring, Onboarding

### Verification
- `npx tsc --noEmit` — zero errors
- `grep linear-gradient|bg-gradient-to` in TSX — zero matches
- `grep backdrop-blur|backdrop-filter` in TSX — zero matches
- `grep shadow-2xl` in TSX — zero matches

---

## Next Steps

- **Phase 11**: Final enterprise polish and remaining consistency items
